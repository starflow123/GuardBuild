use std::collections::{HashMap, HashSet, VecDeque};
use std::path::{Path, PathBuf};
use std::process::{Child, Command, Stdio};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::mpsc::Sender;
use std::sync::{Arc, Mutex, OnceLock, RwLock};
use std::thread;
use std::time::Duration;

use serde::de::DeserializeOwned;
use serde::Deserialize;
use serde_json::{json, Value};
use url::Url;

use super::error::{HostError, HostResult};
use super::fsops;
use super::gitops;
use super::httpclient;
use super::procops::{self, ProcTable};
use super::redact::Redactor;
use super::rpc::{RpcConnection, RpcError};
use super::token::{
    now_ms, redact_docker_env_args, resolve_in_root_allow_missing, Scope, Token, TokenStore,
};
use super::vault::Vault;

pub const PROTOCOL_VERSION: &str = "guardbuild.rpc/1";
pub const CONSENT_TIMEOUT_SECS: u64 = 180;

#[derive(Debug, Clone)]
pub struct HostConfig {
    /// 运行时数据目录：worktrees / backups / 日志（SQLite 由 Sidecar 持有）
    pub data_dir: PathBuf,
    pub sidecar_path: PathBuf,
    pub node_bin: String,
    /// 无头测试模式：自动同意 confirm 级作用域
    pub auto_consent: bool,
    pub headless: bool,
    pub app_version: String,
    /// CI gate 模式：不弹用户授权，只批准「预声明作用域」；结构性禁止写回原工作区
    pub gate: bool,
    /// gate 模式下预声明允许的作用域 kind（来自 guardbuild.json.scopes）
    pub granted_scopes: Vec<String>,
    /// 报告输出目录（report.emit 的落盘位置）
    pub report_dir: Option<PathBuf>,
}

/// gate 模式缺省预声明作用域：覆盖「发现→复现→隔离补丁→验收」全链路，不含写回
pub const GATE_DEFAULT_SCOPES: [&str; 4] =
    ["project.read", "worktree.write", "proc.spawn", "net.probe"];

impl HostConfig {
    pub fn worktrees_root(&self) -> PathBuf {
        self.data_dir.join("worktrees")
    }
    pub fn backups_root(&self) -> PathBuf {
        self.data_dir.join("backups")
    }
}

pub trait UiSink: Send + Sync {
    fn emit_state(&self, v: &Value);
    fn emit_event(&self, v: &Value);
    fn emit_consent(&self, v: &Value);
    fn emit_log(&self, v: &Value);
}

pub struct SessionMeta {
    pub id: String,
    pub root: PathBuf,
    pub name: String,
    pub created_at: i64,
    pub root_token: String,
}

struct ConsentWaiter {
    tx: Mutex<Option<Sender<bool>>>,
}

pub struct Host {
    pub cfg: HostConfig,
    tokens: RwLock<TokenStore>,
    vault: Arc<Mutex<Vault>>,
    procs: Mutex<ProcTable>,
    redactor: Arc<Redactor>,
    sessions: RwLock<HashMap<String, SessionMeta>>,
    current_session: RwLock<Option<String>>,
    view: RwLock<Value>,
    events: Mutex<VecDeque<Value>>,
    consents: Mutex<HashMap<String, Arc<ConsentWaiter>>>,
    pending_consent: RwLock<Option<Value>>,
    last_backup: RwLock<HashMap<String, (String, Vec<String>)>>,
    writeback_authorized: RwLock<HashSet<String>>,
    conn: OnceLock<Arc<RpcConnection>>,
    child: Mutex<Option<Child>>,
    sidecar_ready: AtomicBool,
    ui: RwLock<Option<Arc<dyn UiSink>>>,
    pub started_at: i64,
}

fn jget<T: DeserializeOwned>(params: &Value) -> HostResult<T> {
    serde_json::from_value(params.clone()).map_err(|e| HostError::InvalidParams(e.to_string()))
}

#[derive(Deserialize)]
struct TokenParam {
    token: String,
}

impl Host {
    pub fn new(cfg: HostConfig) -> Arc<Self> {
        let _ = std::fs::create_dir_all(cfg.worktrees_root());
        let _ = std::fs::create_dir_all(cfg.backups_root());
        Arc::new(Host {
            cfg,
            tokens: RwLock::new(TokenStore::default()),
            vault: Arc::new(Mutex::new(Vault::default())),
            procs: Mutex::new(ProcTable::default()),
            redactor: Arc::new(Redactor::new()),
            sessions: RwLock::new(HashMap::new()),
            current_session: RwLock::new(None),
            view: RwLock::new(json!({
                "sessionId": null,
                "projectRoot": "",
                "projectName": "",
                "state": "idle",
                "stateLabel": "空闲",
                "startedAt": 0,
                "updatedAt": 0,
                "findings": [],
                "evidence": [],
            })),
            events: Mutex::new(VecDeque::new()),
            consents: Mutex::new(HashMap::new()),
            pending_consent: RwLock::new(None),
            last_backup: RwLock::new(HashMap::new()),
            writeback_authorized: RwLock::new(HashSet::new()),
            conn: OnceLock::new(),
            child: Mutex::new(None),
            sidecar_ready: AtomicBool::new(false),
            ui: RwLock::new(None),
            started_at: now_ms(),
        })
    }

    pub fn set_ui_sink(&self, sink: Arc<dyn UiSink>) {
        *self.ui.write().unwrap() = Some(sink);
    }

    pub fn sidecar_ready(&self) -> bool {
        self.sidecar_ready.load(Ordering::SeqCst)
    }

    pub fn data_dir(&self) -> &Path {
        &self.cfg.data_dir
    }

    // ---------- 日志与事件 ----------

    pub fn log(&self, level: &str, msg: &str) {
        let v = json!({ "ts": now_ms(), "level": level, "message": msg });
        if let Some(ui) = self.ui.read().unwrap().as_ref() {
            ui.emit_log(&v);
        }
        if self.cfg.headless {
            println!("GB_LOG [{level}] {msg}");
        }
    }

    pub fn push_event(&self, kind: &str, phase: &str, severity: &str, message: &str, data: Value) {
        let session_id = self
            .current_session
            .read()
            .unwrap()
            .clone()
            .unwrap_or_default();
        let ev = json!({
            "id": format!("ev_{}", uuid::Uuid::new_v4().simple()),
            "sessionId": session_id,
            "ts": now_ms(),
            "kind": kind,
            "phase": phase,
            "severity": severity,
            "message": message,
            "data": data,
        });
        {
            let mut ring = self.events.lock().unwrap();
            if ring.len() >= 800 {
                ring.pop_front();
            }
            ring.push_back(ev.clone());
        }
        if let Some(ui) = self.ui.read().unwrap().as_ref() {
            ui.emit_event(&ev);
        }
        if self.cfg.headless && severity != "info" {
            println!("GB_EVENT {}", serde_json::to_string(&ev).unwrap_or_default());
        }
    }

    pub fn events_snapshot(&self, limit: usize) -> Vec<Value> {
        let ring = self.events.lock().unwrap();
        let skip = ring.len().saturating_sub(limit);
        ring.iter().skip(skip).cloned().collect()
    }

    // ---------- 会话视图 ----------

    fn emit_view(&self) {
        let v = self.merged_view();
        if let Some(ui) = self.ui.read().unwrap().as_ref() {
            ui.emit_state(&v);
        }
        if self.cfg.headless {
            println!("GB_STATE {}", serde_json::to_string(&v).unwrap_or_default());
        }
    }

    pub fn merged_view(&self) -> Value {
        let mut view = self.view.read().unwrap().clone();
        let session_id = view
            .get("sessionId")
            .and_then(|s| s.as_str())
            .unwrap_or("")
            .to_string();
        if session_id.is_empty() {
            return view;
        }
        // Host 拥有的字段：令牌、待处理同意、写回授权、回滚信息
        let tokens: Vec<Value> = self
            .tokens
            .read()
            .unwrap()
            .list_session(&session_id)
            .iter()
            .map(|t| {
                json!({
                    "id": t.id,
                    "scopes": t.scopes.iter().map(|s| s.summary()).collect::<Vec<_>>(),
                    "kinds": t.scopes.iter().map(|s| s.kind()).collect::<Vec<_>>(),
                    "expiresAt": t.expires_at,
                    "via": t.via,
                })
            })
            .collect();
        let pending = self.pending_consent.read().unwrap().clone();
        let rollback = {
            let map = self.last_backup.read().unwrap();
            match map.get(&session_id) {
                Some((backup_id, files)) => json!({
                    "available": true,
                    "backupId": backup_id,
                    "files": files,
                }),
                None => json!({ "available": false }),
            }
        };
        let authorized = self.writeback_authorized.read().unwrap().contains(&session_id);
        if let Some(obj) = view.as_object_mut() {
            obj.insert("tokens".into(), json!(tokens));
            obj.insert("pendingConsent".into(), pending.unwrap_or(Value::Null));
            obj.insert("rollback".into(), rollback);
            obj.insert("writebackAuthorized".into(), json!(authorized));
            obj.insert("hostDataDir".into(), json!(self.cfg.data_dir.to_string_lossy()));
            obj.insert("sidecarReady".into(), json!(self.sidecar_ready()));
        }
        view
    }

    pub fn get_events(&self, limit: usize) -> Value {
        json!({ "events": self.events_snapshot(limit) })
    }

    // ---------- 启动 Sidecar ----------

    pub fn start(self: &Arc<Self>) -> HostResult<()> {
        let cfg = self.cfg.clone();
        if !cfg.sidecar_path.exists() {
            self.log("error", &format!("Sidecar 不存在: {:?}", cfg.sidecar_path));
            return Err(HostError::NotFound(format!(
                "sidecar 入口不存在: {:?}",
                cfg.sidecar_path
            )));
        }
        let mut cmd = Command::new(&cfg.node_bin);
        cmd.arg("--no-warnings")
            .arg(&cfg.sidecar_path)
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .stderr(Stdio::piped())
            .env_clear();
        if let Some(parent) = cfg.sidecar_path.parent() {
            cmd.current_dir(parent);
        }
        let mut extra = vec![
            ("GUARDBUILD_PROTOCOL_VERSION".to_string(), PROTOCOL_VERSION.to_string()),
            ("GUARDBUILD_APP_VERSION".to_string(), cfg.app_version.clone()),
            ("GUARDBUILD_DATA_DIR".to_string(), cfg.data_dir.to_string_lossy().to_string()),
            ("GUARDBUILD_AUTO_CONSENT".to_string(), if cfg.auto_consent { "1".into() } else { "0".into() }),
        ];
        // 接入侦察的可选配置：密钥只从宿主进程环境透传给 Sidecar（侧车再经 net.egress
        // 请求 Host 出站），绝不写入 cfg / 日志 / 报告，也不进入目标进程环境。
        for key in [
            "DEEPSEEK_API_KEY",
            "DEEPSEEK_BASE_URL",
            "DEEPSEEK_MODEL",
            "GUARDBUILD_LLM_SCOUT",
            "GUARDBUILD_BLACKBOX_URL",
            "GUARDBUILD_BLACKBOX_MUTATE",
        ] {
            if let Ok(v) = std::env::var(key) {
                if !v.trim().is_empty() {
                    extra.push((key.to_string(), v));
                }
            }
        }
        for (k, v) in procops::sanitized_env(&extra) {
            cmd.env(k, v);
        }
        #[cfg(windows)]
        {
            use std::os::windows::process::CommandExt;
            cmd.creation_flags(0x0800_0000);
        }

        let mut child = cmd
            .spawn()
            .map_err(|e| HostError::Proc(format!("无法启动 node sidecar: {e}")))?;
        let stdin = child.stdin.take().ok_or_else(|| HostError::Proc("sidecar stdin 不可用".into()))?;
        let stdout = child.stdout.take().ok_or_else(|| HostError::Proc("sidecar stdout 不可用".into()))?;
        let stderr = child.stderr.take();

        if let Some(err) = stderr {
            let me = self.clone();
            thread::spawn(move || {
                use std::io::BufRead;
                let br = std::io::BufReader::new(err);
                for line in br.lines().map_while(Result::ok) {
                    me.log("sidecar", &line);
                }
            });
        }

        let conn = RpcConnection::new(stdin, stdout);
        self.register_capabilities(&conn);
        self.register_sidecar_messages(&conn);
        self.conn
            .set(conn.clone())
            .map_err(|_| HostError::Internal("重复启动 sidecar".into()))?;
        *self.child.lock().unwrap() = Some(child);

        conn.notify(
            "host.hello",
            json!({
                "protocolVersion": PROTOCOL_VERSION,
                "appVersion": cfg.app_version,
                "dataDir": cfg.data_dir.to_string_lossy(),
                "worktreesRoot": cfg.worktrees_root().to_string_lossy(),
                "headless": cfg.headless,
                "autoConsent": cfg.auto_consent,
            }),
        )?;
        self.log("info", &format!("Sidecar 已启动，协议版本 {PROTOCOL_VERSION}"));
        Ok(())
    }

    pub fn shutdown(&self) {
        if let Some(conn) = self.conn.get() {
            let _ = conn.notify("host.shutdown", json!({}));
        }
        self.procs.lock().unwrap().kill_all();
        if let Some(mut child) = self.child.lock().unwrap().take() {
            thread::sleep(Duration::from_millis(150));
            let _ = child.kill();
        }
    }

    fn conn(&self) -> HostResult<Arc<RpcConnection>> {
        self.conn
            .get()
            .cloned()
            .ok_or_else(|| HostError::Protocol("sidecar 未启动".into()))
    }

    // ---------- Sidecar -> Host 能力处理 ----------

    fn register_capabilities(self: &Arc<Self>, conn: &Arc<RpcConnection>) {
        macro_rules! cap {
            ($name:expr, $method:ident) => {{
                let host = self.clone();
                conn.on_request($name, move |params| {
                    host.$method(params).map_err(RpcError::from)
                });
            }};
        }
        cap!("auth.requestScope", cap_auth_request_scope);
        cap!("auth.revoke", cap_auth_revoke);
        cap!("auth.listScopes", cap_auth_list);
        cap!("fs.list", cap_fs_list);
        cap!("fs.read", cap_fs_read);
        cap!("fs.stat", cap_fs_stat);
        cap!("fs.linkDir", cap_fs_link_dir);
        cap!("fs.write", cap_fs_write);
        cap!("git.status", cap_git_status);
        cap!("git.worktreeAdd", cap_git_worktree_add);
        cap!("git.worktreeRemove", cap_git_worktree_remove);
        cap!("git.diff", cap_git_diff);
        cap!("git.writeback", cap_git_writeback);
        cap!("git.rollback", cap_git_rollback);
        cap!("proc.spawn", cap_proc_spawn);
        cap!("proc.allocPort", cap_proc_alloc_port);
        cap!("proc.waitForOutput", cap_proc_wait_output);
        cap!("proc.waitExit", cap_proc_wait_exit);
        cap!("proc.logs", cap_proc_logs);
        cap!("proc.kill", cap_proc_kill);
        cap!("proc.list", cap_proc_list);
        cap!("http.request", cap_http_request);
        cap!("credential.list", cap_credential_list);
        cap!("credential.revoke", cap_credential_revoke);
        cap!("report.emit", cap_report_emit);
    }

    fn register_sidecar_messages(self: &Arc<Self>, conn: &Arc<RpcConnection>) {
        {
            let me = self.clone();
            conn.on_notification("sidecar.ready", move |params| {
                me.sidecar_ready.store(true, Ordering::SeqCst);
                let v: Value = params;
                me.log(
                    "info",
                    &format!(
                        "Sidecar 就绪 (node {}, 平台 {})",
                        v.get("node").and_then(|x| x.as_str()).unwrap_or("?"),
                        v.get("platform").and_then(|x| x.as_str()).unwrap_or("?")
                    ),
                );
                me.push_event("system", "idle", "success", "Sidecar 就绪，权限宿主在线", v);
                me.emit_view();
            });
        }
        {
            let me = self.clone();
            conn.on_notification("ui.event", move |params| {
                let mut ev = params;
                if let Some(obj) = ev.as_object_mut() {
                    obj.entry("id").or_insert(json!(format!("ev_{}", uuid::Uuid::new_v4().simple())));
                    obj.entry("ts").or_insert(json!(now_ms()));
                    let sid = me.current_session.read().unwrap().clone().unwrap_or_default();
                    obj.entry("sessionId").or_insert(json!(sid));
                }
                {
                    let mut ring = me.events.lock().unwrap();
                    if ring.len() >= 800 {
                        ring.pop_front();
                    }
                    ring.push_back(ev.clone());
                }
                if let Some(ui) = me.ui.read().unwrap().as_ref() {
                    ui.emit_event(&ev);
                }
            });
        }
        {
            let me = self.clone();
            conn.on_notification("ui.state", move |params| {
                *me.view.write().unwrap() = params;
                me.emit_view();
            });
        }
    }

    // ---------- 能力实现 ----------

    fn session_of_token(&self, token_id: &str) -> HostResult<String> {
        let tokens = self.tokens.read().unwrap();
        Ok(tokens.require(token_id)?.session_id.clone())
    }

    fn cap_auth_request_scope(&self, params: Value) -> HostResult<Value> {
        #[derive(Deserialize)]
        struct P {
            token: String,
            #[serde(rename = "kind")]
            kind: String,
            #[serde(default)]
            host: Option<String>,
            #[serde(default)]
            note: Option<String>,
            #[serde(default)]
            reason: Option<String>,
        }
        let p: P = jget(&params)?;
        let session_id = self.session_of_token(&p.token)?;
        let meta = self
            .sessions
            .read()
            .unwrap()
            .get(&session_id)
            .map(|m| (m.root.clone(), m.id.clone()))
            .ok_or(HostError::TokenInvalid)?;
        let worktree_root = self.cfg.worktrees_root().join(&meta.1);
        let reason = p.reason.unwrap_or_else(|| p.note.unwrap_or_default());

        let scope = match p.kind.as_str() {
            "project.read" => Scope::ProjectRead {
                root: meta.0.to_string_lossy().to_string(),
            },
            "worktree.write" => Scope::WorktreeWrite {
                root: worktree_root.to_string_lossy().to_string(),
            },
            "proc.spawn" => Scope::ProcSpawn {
                roots: vec![
                    meta.0.to_string_lossy().to_string(),
                    worktree_root.to_string_lossy().to_string(),
                ],
            },
            "net.probe" => Scope::NetProbe {},
            "net.egress" => {
                let raw = p.host.as_deref().unwrap_or("");
                let host = crate::core::token::normalize_egress_host(raw).ok_or_else(|| {
                    HostError::InvalidParams(format!(
                        "net.egress 需要合法的主机名（如 abc.supabase.co），收到: {raw:?}"
                    ))
                })?;
                Scope::NetEgress { host }
            }
            "workspace.write" | "workspace.rollback" => {
                self.push_event(
                    "security",
                    "consent",
                    "warn",
                    "已拦截 Sidecar 对特权作用域的申请（workspace.* 仅可由用户在界面批准后签发）",
                    json!({ "requested": p.kind }),
                );
                return Err(HostError::ScopeDenied(format!(
                    "{} 不可由编排层申请，只能由用户在 UI 批准后由 Host 签发",
                    p.kind
                )));
            }
            other => return Err(HostError::InvalidParams(format!("未知作用域: {other}"))),
        };

        let consent_class = match p.kind.as_str() {
            "project.read" => "auto",
            _ => "confirm",
        };

        // gate 预声明匹配键：net.egress 与具体主机绑定（net.egress:<host>），其余按 kind 匹配
        let grant_key = match &scope {
            Scope::NetEgress { host } => format!("net.egress:{host}"),
            _ => p.kind.clone(),
        };

        let approved = if consent_class == "auto" {
            true
        } else if self.cfg.gate {
            // CI gate：无人工交互，仅在预声明作用域内批准（策略授权）
            let granted = self.cfg.granted_scopes.iter().any(|s| s == &grant_key);
            if !granted {
                self.push_event(
                    "security",
                    "consent",
                    "warn",
                    &format!("CI gate 拒绝了未预声明的作用域: {grant_key}"),
                    json!({ "requested": &grant_key, "granted": self.cfg.granted_scopes }),
                );
            }
            granted
        } else {
            self.request_consent(&session_id, &scope, &reason)?
        };
        if !approved {
            self.push_event(
                "security",
                "consent",
                "warn",
                &format!("用户拒绝授予作用域: {}", scope.summary()),
                json!({}),
            );
            return Err(HostError::ConsentDenied);
        }

        let ttl_ms: i64 = match p.kind.as_str() {
            "project.read" => 2 * 3600 * 1000,
            _ => 45 * 60 * 1000,
        };
        let token = Token {
            id: format!("tok_{}", uuid::Uuid::new_v4().simple()),
            session_id: session_id.clone(),
            scopes: vec![scope.clone()],
            issued_at: now_ms(),
            expires_at: now_ms() + ttl_ms,
            via: if consent_class == "auto" {
                "auto".to_string()
            } else if self.cfg.gate {
                "policy".to_string()
            } else if self.cfg.auto_consent {
                "auto-consent".to_string()
            } else {
                "user-consent".to_string()
            },
        };
        let out = json!({
            "token": token.id,
            "scopes": [scope.summary()],
            "expiresAt": token.expires_at,
            "via": token.via,
        });
        self.tokens.write().unwrap().insert(token.clone());
        self.push_event(
            "security",
            "consent",
            "success",
            &format!("已签发作用域令牌: {}", token.scopes[0].summary()),
            json!({ "tokenId": token.id, "via": token.via, "expiresAt": token.expires_at }),
        );
        self.emit_view();
        Ok(out)
    }

    fn cap_auth_revoke(&self, params: Value) -> HostResult<Value> {
        let p: TokenParam = jget(&params)?;
        let ok = self.tokens.write().unwrap().revoke(&p.token);
        self.push_event("security", "consent", "info", "令牌已吊销", json!({ "tokenId": p.token, "ok": ok }));
        self.emit_view();
        Ok(json!({ "ok": ok }))
    }

    fn cap_auth_list(&self, params: Value) -> HostResult<Value> {
        let p: TokenParam = jget(&params)?;
        let session_id = self.session_of_token(&p.token)?;
        let list: Vec<Value> = self
            .tokens
            .read()
            .unwrap()
            .list_session(&session_id)
            .iter()
            .map(|t| {
                json!({
                    "id": t.id,
                    "scopes": t.scopes.iter().map(|s| s.summary()).collect::<Vec<_>>(),
                    "expiresAt": t.expires_at,
                    "via": t.via,
                })
            })
            .collect();
        Ok(json!({ "tokens": list }))
    }

    /// 用令牌的作用域根目录解析请求路径。
    fn resolve_for_token(&self, token: &Token, requested: &str) -> HostResult<PathBuf> {
        let mut roots: Vec<PathBuf> = Vec::new();
        for s in &token.scopes {
            match s {
                Scope::ProjectRead { root } | Scope::WorktreeWrite { root } => roots.push(PathBuf::from(root)),
                _ => {}
            }
        }
        for root in roots {
            if let Ok(p) = resolve_in_root_allow_missing(&root, requested) {
                return Ok(p);
            }
        }
        Err(HostError::PathOutOfScope(format!(
            "路径 {requested} 不在任何已授权根目录内"
        )))
    }

    fn cap_fs_list(&self, params: Value) -> HostResult<Value> {
        #[derive(Deserialize)]
        struct P {
            token: String,
            path: String,
            #[serde(default)]
            depth: Option<usize>,
        }
        let p: P = jget(&params)?;
        let tokens = self.tokens.read().unwrap();
        let token = tokens.require(&p.token)?;
        let abs = self.resolve_for_token(token, &p.path)?;
        token.require_read_path(&abs)?;
        drop(tokens);
        let entries = fsops::list_dir(&abs, p.depth.unwrap_or(2).clamp(1, 6))?;
        Ok(json!({ "entries": entries }))
    }

    fn cap_fs_read(&self, params: Value) -> HostResult<Value> {
        #[derive(Deserialize)]
        struct P {
            token: String,
            path: String,
            #[serde(default)]
            redact: Option<bool>,
        }
        let p: P = jget(&params)?;
        let tokens = self.tokens.read().unwrap();
        let token = tokens.require(&p.token)?;
        let abs = self.resolve_for_token(token, &p.path)?;
        token.require_read_path(&abs)?;
        drop(tokens);
        let (content, sha, size) = fsops::read_text(&abs)?;
        let redact = p.redact.unwrap_or(true);
        let (content_out, reports) = if redact {
            let vault = self.vault.lock().unwrap();
            self.redactor.redact(&content, &vault)
        } else {
            (content, Vec::new())
        };
        let redacted = !reports.is_empty();
        if redacted {
            self.push_event(
                "redaction",
                "reading",
                "info",
                &format!(
                    "读取 {} 时脱敏 {} 类敏感信息",
                    abs.file_name().map(|s| s.to_string_lossy().to_string()).unwrap_or_default(),
                    reports.len()
                ),
                json!({ "reports": reports }),
            );
        }
        Ok(json!({
            "path": abs.to_string_lossy(),
            "content": content_out,
            "sha256": sha,
            "size": size,
            "redacted": redacted,
            "redactions": reports,
        }))
    }

    fn cap_fs_stat(&self, params: Value) -> HostResult<Value> {
        #[derive(Deserialize)]
        struct P {
            token: String,
            path: String,
        }
        let p: P = jget(&params)?;
        let tokens = self.tokens.read().unwrap();
        let token = tokens.require(&p.token)?;
        let abs = self.resolve_for_token(token, &p.path)?;
        token.require_read_path(&abs)?;
        drop(tokens);
        Ok(json!(fsops::stat(&abs)?))
    }

    /// 创建目录链接（node_modules → worktree）。
    /// dst 必须落在 worktree.write 作用域内；src 可读（可用独立 readToken，如 project.read）。
    fn cap_fs_link_dir(&self, params: Value) -> HostResult<Value> {
        #[derive(Deserialize)]
        struct P {
            token: String,
            #[serde(default, rename = "readToken")]
            read_token: Option<String>,
            src: String,
            dst: String,
        }
        let p: P = jget(&params)?;
        let tokens = self.tokens.read().unwrap();
        let token = tokens.require(&p.token)?;
        let dst = self.resolve_for_token(token, &p.dst)?;
        token.require_worktree_write_path(&dst)?;
        let src = match self.resolve_for_token(token, &p.src) {
            Ok(s) => {
                token.require_read_path(&s)?;
                s
            }
            Err(e) => {
                let rt = p.read_token.as_deref().ok_or(e)?;
                let rtoken = tokens.require(rt)?;
                let s = self.resolve_for_token(rtoken, &p.src)?;
                rtoken.require_read_path(&s)?;
                s
            }
        };
        drop(tokens);
        fsops::link_dir(&src, &dst)?;
        self.push_event(
            "file",
            "patching",
            "info",
            "已建立目录链接（避免重复安装依赖）",
            json!({ "src": src.to_string_lossy(), "dst": dst.to_string_lossy() }),
        );
        Ok(json!({ "src": src.to_string_lossy(), "dst": dst.to_string_lossy() }))
    }

    fn cap_fs_write(&self, params: Value) -> HostResult<Value> {
        #[derive(Deserialize)]
        struct Op {
            find: String,
            replace: String,
            #[serde(default)]
            count: Option<usize>,
        }
        #[derive(Deserialize)]
        struct P {
            token: String,
            path: String,
            #[serde(default)]
            content: Option<String>,
            #[serde(default)]
            ops: Option<Vec<Op>>,
            #[serde(default)]
            reason: Option<String>,
        }
        let p: P = jget(&params)?;
        let tokens = self.tokens.read().unwrap();
        let token = tokens.require(&p.token)?;
        let abs = self.resolve_for_token(token, &p.path)?;
        token.require_worktree_write_path(&abs)?;
        drop(tokens);

        // 定向替换：模型只提供「意图」（替换锚点与内容），由 Host 在真实字节上执行，
        // 原始文件内容不必流出 Host。
        let (before_sha, final_content, applied): (String, String, usize) = match (&p.ops, &p.content) {
            (Some(ops), _) if !ops.is_empty() => {
                let (raw, before_sha, _) = fsops::read_text(&abs)?;
                let mut out = raw.clone();
                for (i, op) in ops.iter().enumerate() {
                    if op.find.is_empty() {
                        return Err(HostError::InvalidParams(format!("第 {} 个替换操作的锚点为空", i + 1)));
                    }
                    let occurrences = out.matches(&op.find).count();
                    if occurrences == 0 {
                        return Err(HostError::Conflict(format!(
                            "第 {} 个替换操作的锚点在文件中未找到（可能内容已变化）",
                            i + 1
                        )));
                    }
                    let limit = op.count.unwrap_or(occurrences).min(occurrences);
                    for _ in 0..limit {
                        match out.find(&op.find) {
                            Some(pos) => out.replace_range(pos..pos + op.find.len(), &op.replace),
                            None => break,
                        }
                    }
                }
                (before_sha, out, ops.len())
            }
            (_, Some(content)) => {
                let before = fsops::sha256_file(&abs).unwrap_or_default();
                (before, content.clone(), 0)
            }
            _ => return Err(HostError::InvalidParams("必须提供 content 或 ops".into())),
        };

        let sha = fsops::write_text(&abs, &final_content)?;
        self.push_event(
            "file",
            "patching",
            "info",
            &format!(
                "写入隔离副本: {}（{}）",
                abs.strip_prefix(&self.cfg.data_dir)
                    .map(|p| p.to_string_lossy().to_string())
                    .unwrap_or_else(|_| abs.to_string_lossy().to_string()),
                if applied > 0 { format!("定向替换 {applied} 处") } else { "整文件写入".into() }
            ),
            json!({ "sha256": sha, "beforeSha256": before_sha, "reason": p.reason, "ops": applied }),
        );
        Ok(json!({
            "path": abs.to_string_lossy(),
            "sha256": sha,
            "beforeSha256": before_sha,
            "appliedOps": applied,
        }))
    }

    fn cap_git_status(&self, params: Value) -> HostResult<Value> {
        #[derive(Deserialize)]
        struct P {
            token: String,
            #[serde(default)]
            dir: Option<String>,
        }
        let p: P = jget(&params)?;
        let session_id = self.session_of_token(&p.token)?;
        let meta = self.sessions.read().unwrap().get(&session_id).cloned_meta();
        let dir = match p.dir {
            Some(d) => {
                let cand = PathBuf::from(&d);
                let allowed = super::token::path_within(&meta, &cand)
                    || super::token::path_within(&self.cfg.worktrees_root(), &cand);
                if !allowed {
                    return Err(HostError::PathOutOfScope(d));
                }
                cand
            }
            None => meta,
        };
        if !gitops::is_git_repo(&dir) {
            return Ok(json!({ "isRepo": false, "entries": [] }));
        }
        let entries: Vec<Value> = gitops::status_porcelain(&dir)?
            .into_iter()
            .map(|(st, path)| json!({ "status": st, "path": path }))
            .collect();
        Ok(json!({ "isRepo": true, "entries": entries }))
    }

    fn cap_git_worktree_add(&self, params: Value) -> HostResult<Value> {
        #[derive(Deserialize)]
        struct P {
            token: String,
            name: String,
        }
        let p: P = jget(&params)?;
        let session_id = self.session_of_token(&p.token)?;
        let root = self
            .sessions
            .read()
            .unwrap()
            .get(&session_id)
            .map(|m| m.root.clone())
            .ok_or(HostError::TokenInvalid)?;
        // 校验令牌具备 worktree.write 作用域（根目录由 Host 决定）
        {
            let tokens = self.tokens.read().unwrap();
            let token = tokens.require(&p.token)?;
            let wt_root = self.cfg.worktrees_root().join(&session_id);
            let fake_path = wt_root.join(&p.name);
            if !token.scopes.iter().any(|s| matches!(s, Scope::WorktreeWrite { .. }))
                || !super::token::path_within(&wt_root, &fake_path)
            {
                return Err(HostError::ScopeDenied("需要 worktree.write 作用域".into()));
            }
        }
        let safe_name: String = p
            .name
            .chars()
            .map(|c| if c.is_ascii_alphanumeric() || c == '-' || c == '_' { c } else { '-' })
            .collect();
        let wt_dir = self.cfg.worktrees_root().join(&session_id).join(&safe_name);
        gitops::worktree_add(&root, &wt_dir)?;
        self.push_event(
            "git",
            "patching",
            "success",
            &format!("已创建隔离 worktree: {}", wt_dir.to_string_lossy()),
            json!({ "worktree": wt_dir.to_string_lossy() }),
        );
        Ok(json!({ "path": wt_dir.to_string_lossy() }))
    }

    fn cap_git_worktree_remove(&self, params: Value) -> HostResult<Value> {
        #[derive(Deserialize)]
        struct P {
            token: String,
            path: String,
        }
        let p: P = jget(&params)?;
        let session_id = self.session_of_token(&p.token)?;
        let root = self
            .sessions
            .read()
            .unwrap()
            .get(&session_id)
            .map(|m| m.root.clone())
            .ok_or(HostError::TokenInvalid)?;
        let dir = PathBuf::from(&p.path);
        // 仅允许删除本会话目录下的 worktree，且令牌需具备 worktree.write 作用域
        let wt_root = self.cfg.worktrees_root().join(&session_id);
        {
            let tokens = self.tokens.read().unwrap();
            let token = tokens.require(&p.token)?;
            if !token
                .scopes
                .iter()
                .any(|s| matches!(s, Scope::WorktreeWrite { .. }))
                || dir == wt_root
                || !super::token::path_within(&wt_root, &dir)
            {
                return Err(HostError::PathOutOfScope(p.path));
            }
        }
        gitops::worktree_remove(&root, &dir)?;
        Ok(json!({ "ok": true }))
    }

    fn cap_git_diff(&self, params: Value) -> HostResult<Value> {
        #[derive(Deserialize)]
        struct P {
            token: String,
            dir: String,
        }
        let p: P = jget(&params)?;
        let _ = self.session_of_token(&p.token)?;
        let dir = PathBuf::from(&p.dir);
        let wt_root = self.cfg.worktrees_root();
        let tokens = self.tokens.read().unwrap();
        let token = tokens.require(&p.token)?;
        let allowed = super::token::path_within(&wt_root, &dir)
            || token.scopes.iter().any(|s| match s {
                Scope::ProjectRead { root } => super::token::path_within(Path::new(root), &dir),
                _ => false,
            });
        drop(tokens);
        if !allowed {
            return Err(HostError::PathOutOfScope(p.dir));
        }
        let cap = gitops::diff_capture(&dir)?;
        Ok(json!({ "diff": cap.diff, "files": cap.files, "patchHash": cap.patch_hash }))
    }

    fn cap_git_writeback(&self, params: Value) -> HostResult<Value> {
        #[derive(Deserialize)]
        struct P {
            token: String,
            worktree: String,
            patch: String,
            #[serde(rename = "patchHash")]
            patch_hash: String,
        }
        let p: P = jget(&params)?;
        let session_id = self.session_of_token(&p.token)?;
        let root = self
            .sessions
            .read()
            .unwrap()
            .get(&session_id)
            .map(|m| m.root.clone())
            .ok_or(HostError::TokenInvalid)?;
        {
            let tokens = self.tokens.read().unwrap();
            let token = tokens.require(&p.token)?;
            token.require_workspace_write(&root, &p.patch_hash)?;
        }
        // 复核：worktree 当前 diff 必须与批准时的哈希一致（防止批准后又被改动）
        let wt = PathBuf::from(&p.worktree);
        if !super::token::path_within(&self.cfg.worktrees_root(), &wt) {
            return Err(HostError::PathOutOfScope(p.worktree.clone()));
        }
        let current = gitops::diff_capture(&wt)?;
        if current.patch_hash != p.patch_hash {
            return Err(HostError::Conflict(
                "补丁在批准后发生了变化，写回已中止；请重新审查 Diff".into(),
            ));
        }
        let manifest = gitops::writeback_patch(
            &root,
            &p.patch,
            &p.patch_hash,
            &session_id,
            &self.cfg.backups_root(),
        )?;
        let files: Vec<String> = manifest.files.iter().map(|f| f.path.clone()).collect();
        self.last_backup
            .write()
            .unwrap()
            .insert(session_id.clone(), (manifest.backup_id.clone(), files.clone()));
        self.push_event(
            "git",
            "applying",
            "success",
            &format!("补丁已写回工作区（{} 个文件），原文件已备份", files.len()),
            json!({ "backupId": manifest.backup_id, "files": files }),
        );
        self.emit_view();
        Ok(json!({ "backupId": manifest.backup_id, "files": files }))
    }

    fn cap_git_rollback(&self, params: Value) -> HostResult<Value> {
        #[derive(Deserialize)]
        struct P {
            token: String,
            #[serde(rename = "backupId")]
            backup_id: String,
        }
        let p: P = jget(&params)?;
        let _ = self.session_of_token(&p.token)?;
        {
            let tokens = self.tokens.read().unwrap();
            let token = tokens.require(&p.token)?;
            token.require_workspace_rollback(&p.backup_id)?;
        }
        let (restored, conflicts) = gitops::rollback(&self.cfg.backups_root(), &p.backup_id)?;
        self.push_event(
            "git",
            "applying",
            "success",
            &format!("已回滚 {} 个文件", restored.len()),
            json!({ "restored": restored, "conflicts": conflicts }),
        );
        Ok(json!({ "restored": restored, "conflicts": conflicts }))
    }

    fn cap_proc_spawn(&self, params: Value) -> HostResult<Value> {
        #[derive(Deserialize)]
        struct P {
            token: String,
            #[serde(default)]
            role: Option<String>,
            cmd: String,
            #[serde(default)]
            args: Vec<String>,
            cwd: String,
            #[serde(default)]
            env: HashMap<String, String>,
        }
        let p: P = jget(&params)?;
        let session_id = self.session_of_token(&p.token)?;
        let session_root = self
            .sessions
            .read()
            .unwrap()
            .get(&session_id)
            .map(|m| m.root.clone())
            .ok_or(HostError::TokenInvalid)?;
        let cwd = {
            let cand = PathBuf::from(&p.cwd);
            let cand = if cand.is_absolute() { cand } else { session_root.join(cand) };
            cand.canonicalize()
                .map_err(|e| HostError::NotFound(format!("cwd 不可用: {e}")))?
        };
        {
            let tokens = self.tokens.read().unwrap();
            let token = tokens.require(&p.token)?;
            token.require_spawn(&cwd, &p.cmd, &p.args, &self.cfg.node_bin)?;
        }
        let env_pairs: Vec<(String, String)> = p.env.into_iter().collect();
        let redactor = self.redactor.clone();
        let vault = self.vault.clone();
        let resolve_log = Arc::new(move |line: &str| {
            let (out, reports) = {
                let v = vault.lock().unwrap();
                redactor.redact(line, &v)
            };
            Some(procops::ProcLogLine {
                stream: "stdout".into(),
                line: out,
                ts: now_ms(),
                redacted: !reports.is_empty(),
            })
        });
        let rec = {
            let mut table = self.procs.lock().unwrap();
            procops::spawn(
                &mut table,
                &session_id,
                p.role.as_deref().unwrap_or("target"),
                &p.cmd,
                &p.args,
                &cwd,
                &env_pairs,
                resolve_log,
            )?
        };
        self.push_event(
            "process",
            "probing",
            "info",
            &format!("已启动目标进程 (pid {}) 于 {}", rec.pid, cwd.to_string_lossy()),
            json!({
                "pid": rec.pid,
                "cmd": p.cmd,
                "args": redact_docker_env_args(&p.cmd, &rec.args),
                "cwd": rec.cwd.to_string_lossy()
            }),
        );
        Ok(json!({ "pid": rec.pid, "cmd": rec.cmd, "cwd": rec.cwd.to_string_lossy() }))
    }

    fn cap_proc_alloc_port(&self, params: Value) -> HostResult<Value> {
        let p: TokenParam = jget(&params)?;
        let _ = self.session_of_token(&p.token)?;
        // 绑定 127.0.0.1:0 让内核挑选空闲端口后立即释放，交由目标进程使用
        let listener = std::net::TcpListener::bind(("127.0.0.1", 0))
            .map_err(|e| HostError::Proc(format!("无法分配空闲端口: {e}")))?;
        let port = listener
            .local_addr()
            .map_err(|e| HostError::Proc(format!("无法读取分配端口: {e}")))?
            .port();
        drop(listener);
        Ok(json!({ "port": port }))
    }

    fn cap_proc_wait_output(&self, params: Value) -> HostResult<Value> {
        #[derive(Deserialize)]
        struct P {
            token: String,
            pid: u32,
            pattern: String,
            #[serde(default, rename = "timeoutMs")]
            timeout_ms: Option<u64>,
        }
        let p: P = jget(&params)?;
        let session_id = self.session_of_token(&p.token)?;
        let table = self.procs.lock().unwrap();
        let rec = table.get(p.pid).ok_or(HostError::NotFound(format!("进程 {}", p.pid)))?;
        if rec.session_id != session_id {
            return Err(HostError::ScopeDenied("进程不属于当前会话".into()));
        }
        drop(table);
        let timeout = p.timeout_ms.unwrap_or(15_000).min(60_000);
        let matched = procops::wait_for_output(&self.procs.lock().unwrap(), p.pid, &p.pattern, timeout)?;
        Ok(json!({ "matched": matched.is_some(), "line": matched }))
    }

    fn cap_proc_wait_exit(&self, params: Value) -> HostResult<Value> {
        #[derive(Deserialize)]
        struct P {
            token: String,
            pid: u32,
            #[serde(default, rename = "timeoutMs")]
            timeout_ms: Option<u64>,
        }
        let p: P = jget(&params)?;
        let session_id = self.session_of_token(&p.token)?;
        let rec = {
            let table = self.procs.lock().unwrap();
            let rec = table.get(p.pid).ok_or(HostError::NotFound(format!("进程 {}", p.pid)))?;
            if rec.session_id != session_id {
                return Err(HostError::ScopeDenied("进程不属于当前会话".into()));
            }
            rec
        };
        let timeout = p.timeout_ms.unwrap_or(120_000).min(600_000);
        let code = procops::wait_exit(&rec, timeout);
        Ok(json!({ "exited": code.is_some(), "exitCode": code }))
    }

    fn cap_proc_logs(&self, params: Value) -> HostResult<Value> {
        #[derive(Deserialize)]
        struct P {
            token: String,
            pid: u32,
            #[serde(default)]
            tail: Option<usize>,
        }
        let p: P = jget(&params)?;
        let session_id = self.session_of_token(&p.token)?;
        let table = self.procs.lock().unwrap();
        let rec = table.get(p.pid).ok_or(HostError::NotFound(format!("进程 {}", p.pid)))?;
        if rec.session_id != session_id {
            return Err(HostError::ScopeDenied("进程不属于当前会话".into()));
        }
        let lines = rec.logs_tail(p.tail.unwrap_or(200).min(1000));
        Ok(json!({
            "lines": lines,
            "exited": rec.is_exited(),
            "exitCode": if rec.is_exited() { json!(rec.exit_code.load(Ordering::SeqCst)) } else { json!(null) },
        }))
    }

    fn cap_proc_kill(&self, params: Value) -> HostResult<Value> {
        #[derive(Deserialize)]
        struct P {
            token: String,
            pid: u32,
        }
        let p: P = jget(&params)?;
        let session_id = self.session_of_token(&p.token)?;
        let mut table = self.procs.lock().unwrap();
        let rec = table.get(p.pid).ok_or(HostError::NotFound(format!("进程 {}", p.pid)))?;
        if rec.session_id != session_id {
            return Err(HostError::ScopeDenied("进程不属于当前会话".into()));
        }
        rec.kill();
        table.remove(p.pid);
        drop(table);
        self.push_event("process", "probing", "info", &format!("已终止进程 {}", p.pid), json!({}));
        Ok(json!({ "ok": true }))
    }

    fn cap_proc_list(&self, params: Value) -> HostResult<Value> {
        let p: TokenParam = jget(&params)?;
        let session_id = self.session_of_token(&p.token)?;
        let table = self.procs.lock().unwrap();
        let list: Vec<Value> = table
            .list(Some(&session_id))
            .iter()
            .map(|r| {
                json!({
                    "pid": r.pid,
                    "role": r.role,
                    "cmd": r.cmd,
                    "args": redact_docker_env_args(&r.cmd, &r.args),
                    "cwd": r.cwd.to_string_lossy(),
                    "startedAt": r.started_at,
                    "exited": r.is_exited(),
                })
            })
            .collect();
        Ok(json!({ "processes": list }))
    }

    fn cap_http_request(&self, params: Value) -> HostResult<Value> {
        #[derive(Deserialize)]
        struct P {
            token: String,
            method: String,
            url: String,
            #[serde(default)]
            headers: HashMap<String, String>,
            #[serde(default)]
            body: Option<String>,
            #[serde(default, rename = "identityRef")]
            identity_ref: Option<String>,
            #[serde(default, rename = "storeCredentialAs")]
            store_credential_as: Option<String>,
            #[serde(default, rename = "storeCookieAs")]
            store_cookie_as: Option<String>,
            #[serde(default, rename = "credentialPath")]
            credential_path: Option<String>,
            #[serde(default, rename = "credentialHeader")]
            credential_header: Option<String>,
            #[serde(default, rename = "credentialPrefix")]
            credential_prefix: Option<String>,
            #[serde(default)]
            redact: Option<bool>,
            #[serde(default, rename = "timeoutMs")]
            timeout_ms: Option<u64>,
        }
        let p: P = jget(&params)?;
        let _ = self.session_of_token(&p.token)?;
        let url = Url::parse(&p.url).map_err(|e| HostError::InvalidParams(format!("非法 URL: {e}")))?;
        let host = url.host_str().unwrap_or("").to_string();
        let scheme = url.scheme().to_string();
        {
            let tokens = self.tokens.read().unwrap();
            let token = tokens.require(&p.token)?;
            // 回环 → net.probe；远程主机 → net.egress（宿主名精确绑定，且仅允许 https）
            if matches!(host.as_str(), "127.0.0.1" | "localhost" | "::1" | "[::1]") {
                token.require_net(&host)?;
            } else {
                if scheme != "https" {
                    return Err(HostError::ScopeDenied(format!(
                        "net.egress 仅支持 https（明文 http 仅限本机回环探测）: {scheme}://{host}"
                    )));
                }
                token.require_egress(&host)?;
            }
        }
        if p.method.eq_ignore_ascii_case("CONNECT") || p.method.eq_ignore_ascii_case("TRACE") {
            return Err(HostError::InvalidParams("不允许的 HTTP 方法".into()));
        }
        if let Some(b) = &p.body {
            if b.len() > 256 * 1024 {
                return Err(HostError::InvalidParams("请求体过大（>256KB）".into()));
            }
        }

        let mut headers: Vec<(String, String)> = p.headers.into_iter().collect();
        if let Some(identity) = &p.identity_ref {
            let vault = self.vault.lock().unwrap();
            let cred = vault
                .get(identity)
                .ok_or_else(|| HostError::NotFound(format!("身份 {identity} 无凭证（需先登录获取）")))?;
            headers.push((cred.header.clone(), cred.value.clone()));
        }

        let resp = httpclient::request(
            &url,
            &p.method.to_uppercase(),
            &headers,
            p.body.as_deref(),
            Duration::from_millis(p.timeout_ms.unwrap_or(15_000).clamp(1_000, 120_000)),
        )?;

        // 提取并入库身份凭证（响应中的凭证不会流出 Host）
        let mut stored_identity: Option<String> = None;
        let mut credential_kind: Option<&str> = None;
        if let Some(identity) = &p.store_cookie_as {
            // Cookie 会话：从 Set-Cookie 提取 name=value（丢弃 Path/HttpOnly 等属性）
            if let Some(cookie) = collect_cookie_header(&resp.headers) {
                self.vault
                    .lock()
                    .unwrap()
                    .store(identity, "Cookie", &cookie, &url.to_string());
                stored_identity = Some(identity.clone());
                credential_kind = Some("cookie");
                self.push_event(
                    "credential",
                    "probing",
                    "info",
                    &format!("已获取身份会话 Cookie [{identity}] 并存入保险库（密文不离开 Host）"),
                    json!({ "identity": identity, "header": "Cookie" }),
                );
            }
        } else if let Some(identity) = &p.store_credential_as {
            if let Some(path) = &p.credential_path {
                if let Some(value) = json_path(&resp.body, path) {
                    let header = p.credential_header.clone().unwrap_or_else(|| "Authorization".into());
                    let prefix = p.credential_prefix.clone().unwrap_or_default();
                    let full = format!("{prefix}{value}");
                    self.vault.lock().unwrap().store(identity, &header, &full, &url.to_string());
                    stored_identity = Some(identity.clone());
                    credential_kind = Some("token");
                    self.push_event(
                        "credential",
                        "probing",
                        "info",
                        &format!("已获取身份凭证 [{identity}] 并存入保险库（密文不离开 Host）"),
                        json!({ "identity": identity, "header": header }),
                    );
                }
            }
        }

        let redact = p.redact.unwrap_or(true);
        let (body_out, reports) = if redact {
            let vault = self.vault.lock().unwrap();
            self.redactor.redact(&resp.body, &vault)
        } else {
            (resp.body.clone(), Vec::new())
        };

        // Set-Cookie 只能在 Host 内入库，绝不回传给 Sidecar
        let headers_out: HashMap<String, String> = resp
            .headers
            .into_iter()
            .filter(|(k, _)| !k.eq_ignore_ascii_case("set-cookie"))
            .collect();

        Ok(json!({
            "status": resp.status,
            "statusText": resp.status_text,
            "headers": headers_out,
            "body": body_out,
            "redacted": !reports.is_empty(),
            "redactions": reports,
            "durationMs": resp.duration_ms,
            "truncated": resp.truncated,
            "storedIdentity": stored_identity,
            "credentialKind": credential_kind,
        }))
    }

    fn cap_credential_list(&self, params: Value) -> HostResult<Value> {
        let p: TokenParam = jget(&params)?;
        let _ = self.session_of_token(&p.token)?;
        let names = self.vault.lock().unwrap().names();
        Ok(json!({ "identities": names }))
    }

    fn cap_credential_revoke(&self, params: Value) -> HostResult<Value> {
        #[derive(Deserialize)]
        struct P {
            token: String,
            identity: String,
        }
        let p: P = jget(&params)?;
        let _ = self.session_of_token(&p.token)?;
        let ok = self.vault.lock().unwrap().remove(&p.identity);
        Ok(json!({ "ok": ok }))
    }

    /// 报告落盘：Sidecar 渲染 report.json/report.md，Host 校验大小与会话后写入 report_dir。
    /// Sidecar 以「请求-应答」方式调用，保证响应返回时文件已落盘（gate 退出前报告必达）。
    fn cap_report_emit(&self, params: Value) -> HostResult<Value> {
        #[derive(Deserialize)]
        struct P {
            #[serde(rename = "sessionId")]
            session_id: String,
            json: Value,
            markdown: String,
        }
        let p: P = jget(&params)?;
        let report_dir = match &self.cfg.report_dir {
            Some(d) => d.clone(),
            None => return Ok(json!({ "written": false, "reason": "report_dir_not_configured" })),
        };
        let current = self.current_session.read().unwrap().clone().unwrap_or_default();
        if p.session_id.is_empty() || p.session_id != current {
            return Err(HostError::InvalidParams("报告会话与当前会话不一致".into()));
        }
        if p.markdown.len() > 2 * 1024 * 1024 {
            return Err(HostError::InvalidParams("报告 markdown 超过 2MB 上限".into()));
        }
        let json_text = serde_json::to_string_pretty(&p.json)?;
        if json_text.len() > 8 * 1024 * 1024 {
            return Err(HostError::InvalidParams("报告 JSON 超过 8MB 上限".into()));
        }
        std::fs::create_dir_all(&report_dir)?;
        let json_path = report_dir.join("report.json");
        let md_path = report_dir.join("report.md");
        std::fs::write(&json_path, json_text.as_bytes())?;
        std::fs::write(&md_path, p.markdown.as_bytes())?;
        self.push_event(
            "report",
            "report",
            "success",
            "诊断报告已写入磁盘",
            json!({
                "json": json_path.to_string_lossy(),
                "markdown": md_path.to_string_lossy(),
                "jsonBytes": json_text.len(),
                "mdBytes": p.markdown.len(),
            }),
        );
        Ok(json!({
            "written": true,
            "jsonPath": json_path.to_string_lossy(),
            "mdPath": md_path.to_string_lossy(),
        }))
    }

    // ---------- 用户同意 ----------

    fn request_consent(&self, session_id: &str, scope: &Scope, reason: &str) -> HostResult<bool> {
        if self.cfg.auto_consent {
            self.push_event(
                "security",
                "consent",
                "info",
                &format!("自动同意（测试模式）: {}", scope.summary()),
                json!({ "scope": scope, "reason": reason }),
            );
            return Ok(true);
        }
        let consent_id = format!("cs_{}", uuid::Uuid::new_v4().simple());
        let payload = json!({
            "consentId": consent_id,
            "sessionId": session_id,
            "scope": scope,
            "reason": reason,
            "consentClass": "confirm",
            "requestedAt": now_ms(),
        });
        let (tx, rx) = std::sync::mpsc::channel::<bool>();
        let waiter = Arc::new(ConsentWaiter {
            tx: Mutex::new(Some(tx)),
        });
        self.consents.lock().unwrap().insert(consent_id.clone(), waiter);
        *self.pending_consent.write().unwrap() = Some(payload.clone());
        if let Some(ui) = self.ui.read().unwrap().as_ref() {
            ui.emit_consent(&payload);
        }
        if self.cfg.headless {
            println!("GB_CONSENT {}", serde_json::to_string(&payload).unwrap_or_default());
        }
        self.emit_view();
        let decision = rx.recv_timeout(Duration::from_secs(CONSENT_TIMEOUT_SECS));
        self.consents.lock().unwrap().remove(&consent_id);
        *self.pending_consent.write().unwrap() = None;
        self.emit_view();
        match decision {
            Ok(v) => Ok(v),
            Err(_) => {
                self.push_event("security", "consent", "warn", "授权请求超时（用户未操作）", json!({}));
                Ok(false)
            }
        }
    }

    pub fn resolve_consent(&self, consent_id: &str, approved: bool) -> HostResult<Value> {
        let waiter = self.consents.lock().unwrap().get(consent_id).cloned();
        match waiter {
            Some(w) => {
                if let Some(tx) = w.tx.lock().unwrap().take() {
                    let _ = tx.send(approved);
                }
                Ok(json!({ "ok": true }))
            }
            None => Err(HostError::NotFound("授权请求不存在或已过期".into())),
        }
    }

    // ---------- 会话控制（由 UI/前端调用） ----------

    fn session_start_failed(&self, reason: &str) {
        self.push_event(
            "session",
            "starting",
            "error",
            &format!("启动会话失败: {reason}"),
            json!({}),
        );
        if let Some(obj) = self.view.write().unwrap().as_object_mut() {
            obj.insert("state".into(), json!("error"));
            obj.insert("stateLabel".into(), json!("执行出错"));
        }
        self.emit_view();
    }

    pub fn start_session(self: &Arc<Self>, root: &str, blackbox_url: Option<&str>) -> HostResult<Value> {
        let root_path = PathBuf::from(root);
        if !root_path.is_dir() {
            return Err(HostError::NotFound(format!("目录不存在: {root}")));
        }
        let blackbox_url = normalize_blackbox_url(blackbox_url)?;
        let canon = root_path
            .canonicalize()
            .map_err(|e| HostError::NotFound(format!("目录不可访问: {e}")))?;
        if !self.sidecar_ready() {
            // 允许继续：Sidecar 可能稍后启动；但发出警告
            self.log("warn", "Sidecar 尚未就绪，会话启动可能延迟");
        }
        let session_id = format!("s_{}", uuid::Uuid::new_v4().simple());
        let name = canon
            .file_name()
            .map(|s| s.to_string_lossy().to_string())
            .unwrap_or_else(|| "project".into());

        let token = Token {
            id: format!("tok_{}", uuid::Uuid::new_v4().simple()),
            session_id: session_id.clone(),
            scopes: vec![Scope::ProjectRead {
                root: canon.to_string_lossy().to_string(),
            }],
            issued_at: now_ms(),
            expires_at: now_ms() + 2 * 3600 * 1000,
            via: "user-selected-project".into(),
        };
        self.tokens.write().unwrap().insert(token.clone());
        self.sessions.write().unwrap().insert(
            session_id.clone(),
            SessionMeta {
                id: session_id.clone(),
                root: canon.clone(),
                name: name.clone(),
                created_at: now_ms(),
                root_token: token.id.clone(),
            },
        );
        *self.current_session.write().unwrap() = Some(session_id.clone());
        self.writeback_authorized.write().unwrap().remove(&session_id);
        self.last_backup.write().unwrap().remove(&session_id);

        *self.view.write().unwrap() = json!({
            "sessionId": session_id,
            "projectRoot": canon.to_string_lossy(),
            "projectName": name,
            "state": "starting",
            "stateLabel": "初始化会话",
            "startedAt": now_ms(),
            "updatedAt": now_ms(),
            "findings": [],
            "evidence": [],
            "target": null,
            "patch": null,
            "acceptance": null,
            "blackboxUrl": blackbox_url.clone(),
        });
        self.push_event(
            "session",
            "starting",
            "info",
            &match &blackbox_url {
                Some(url) => format!(
                    "已创建黑盒扫描会话，外部目标: {}（项目目录: {}，仅用于契约与报告）",
                    url,
                    canon.to_string_lossy()
                ),
                None => format!("已创建诊断会话，目标: {}", canon.to_string_lossy()),
            },
            json!({ "sessionId": session_id, "blackboxUrl": blackbox_url.clone() }),
        );
        self.push_event(
            "security",
            "starting",
            "info",
            "已自动授予 project.read 令牌（用户选择目标目录）",
            json!({ "tokenId": token.id, "root": canon.to_string_lossy() }),
        );
        self.emit_view();

        let conn = self.conn()?;
        let sid = session_id.clone();
        let root_str = canon.to_string_lossy().to_string();
        let token_id = token.id.clone();
        let gate = self.cfg.gate;
        let blackbox_target = blackbox_url.clone();
        let me = self.clone();
        thread::spawn(move || {
            match conn.call(
                "session.start",
                json!({
                    "sessionId": sid,
                    "projectRoot": root_str,
                    "token": token_id,
                    "gate": gate,
                    "blackboxUrl": blackbox_target,
                }),
                Duration::from_secs(30),
            ) {
                Ok(res) if res.get("ok").and_then(|v| v.as_bool()) == Some(false) => {
                    let reason = res
                        .get("error")
                        .and_then(|v| v.as_str())
                        .unwrap_or("未知原因");
                    me.session_start_failed(reason);
                }
                Ok(_) => me.log("info", "Sidecar 已接收会话"),
                Err(e) => me.session_start_failed(&e.to_string()),
            }
        });
        Ok(json!({ "sessionId": session_id, "token": token.id }))
    }

    pub fn approve_patch(&self, patch_hash: &str) -> HostResult<Value> {
        let view = self.merged_view();
        let state = view.get("state").and_then(|s| s.as_str()).unwrap_or("");
        let current_hash = view
            .get("patch")
            .and_then(|p| p.get("hash"))
            .and_then(|h| h.as_str())
            .unwrap_or("");
        if state != "patch_review" {
            return Err(HostError::Conflict(format!("当前状态为 {state}，无法批准补丁")));
        }
        if !patch_hash.is_empty() && patch_hash != current_hash {
            return Err(HostError::Conflict("补丁已过期（哈希不匹配），请重新生成".into()));
        }
        self.push_event(
            "patch",
            "patch_review",
            "info",
            if self.cfg.gate {
                "CI gate 按策略自动批准补丁，进入隔离验收"
            } else {
                "用户已批准补丁，进入隔离验收"
            },
            json!({
                "patchHash": current_hash,
                "via": if self.cfg.gate { "gate-policy" } else { "user" },
            }),
        );
        let conn = self.conn()?;
        conn.call(
            "patch.approved",
            json!({ "patchHash": current_hash }),
            Duration::from_secs(30),
        )?;
        Ok(json!({ "ok": true }))
    }

    pub fn approve_writeback(&self, patch_hash: &str) -> HostResult<Value> {
        if self.cfg.gate {
            self.push_event(
                "security",
                "writeback_pending",
                "warn",
                "CI gate 模式禁止写回原工作区（仅输出已验证补丁供人工应用）",
                json!({}),
            );
            return Err(HostError::ScopeDenied(
                "CI gate 模式禁止写回原工作区：workspace.write 不在 CI 授权范围内".into(),
            ));
        }
        let view = self.merged_view();
        let state = view.get("state").and_then(|s| s.as_str()).unwrap_or("");
        let current_hash = view
            .get("patch")
            .and_then(|p| p.get("hash"))
            .and_then(|h| h.as_str())
            .unwrap_or("");
        let session_id = view
            .get("sessionId")
            .and_then(|s| s.as_str())
            .unwrap_or("")
            .to_string();
        if state != "writeback_pending" {
            return Err(HostError::Conflict(format!("当前状态为 {state}，无法写回")));
        }
        if !patch_hash.is_empty() && patch_hash != current_hash {
            return Err(HostError::Conflict("补丁已过期（哈希不匹配）".into()));
        }
        let root = self
            .sessions
            .read()
            .unwrap()
            .get(&session_id)
            .map(|m| m.root.to_string_lossy().to_string())
            .ok_or(HostError::TokenInvalid)?;

        // 关键安全边界：workspace.write 令牌只能在这里（用户批准 Diff 之后）签发
        let token = Token {
            id: format!("tok_{}", uuid::Uuid::new_v4().simple()),
            session_id: session_id.clone(),
            scopes: vec![Scope::WorkspaceWrite {
                root,
                patch_hash: current_hash.to_string(),
            }],
            issued_at: now_ms(),
            expires_at: now_ms() + 15 * 60 * 1000,
            via: "user-diff-approval".into(),
        };
        self.tokens.write().unwrap().insert(token.clone());
        self.writeback_authorized.write().unwrap().insert(session_id.clone());
        self.push_event(
            "security",
            "writeback_pending",
            "success",
            "用户批准写回：已签发与补丁哈希绑定的 workspace.write 令牌",
            json!({ "tokenId": token.id, "patchHash": current_hash }),
        );
        self.emit_view();
        let conn = self.conn()?;
        let r = conn.call(
            "writeback.approved",
            json!({ "token": token.id, "patchHash": current_hash }),
            Duration::from_secs(60),
        )?;
        Ok(r)
    }

    pub fn request_rollback(&self) -> HostResult<Value> {
        let view = self.merged_view();
        let session_id = view
            .get("sessionId")
            .and_then(|s| s.as_str())
            .unwrap_or("")
            .to_string();
        let backup_id = view
            .get("rollback")
            .and_then(|r| r.get("backupId"))
            .and_then(|b| b.as_str())
            .unwrap_or("")
            .to_string();
        if backup_id.is_empty() {
            return Err(HostError::NotFound("没有可回滚的写回记录".into()));
        }
        let root = self
            .sessions
            .read()
            .unwrap()
            .get(&session_id)
            .map(|m| m.root.to_string_lossy().to_string())
            .ok_or(HostError::TokenInvalid)?;
        let token = Token {
            id: format!("tok_{}", uuid::Uuid::new_v4().simple()),
            session_id: session_id.clone(),
            scopes: vec![Scope::WorkspaceRollback { root, backup_id: backup_id.clone() }],
            issued_at: now_ms(),
            expires_at: now_ms() + 15 * 60 * 1000,
            via: "user-rollback".into(),
        };
        self.tokens.write().unwrap().insert(token.clone());
        self.push_event(
            "security",
            "applied",
            "info",
            "用户触发回滚：已签发与备份绑定的 workspace.rollback 令牌",
            json!({ "tokenId": token.id, "backupId": backup_id }),
        );
        self.emit_view();
        let conn = self.conn()?;
        let r = conn.call(
            "rollback.approved",
            json!({ "token": token.id, "backupId": backup_id }),
            Duration::from_secs(60),
        )?;
        Ok(r)
    }

    pub fn cancel_session(&self) -> HostResult<Value> {
        let session_id = self.current_session.read().unwrap().clone().unwrap_or_default();
        if session_id.is_empty() {
            return Err(HostError::NotFound("没有进行中的会话".into()));
        }
        if let Ok(conn) = self.conn() {
            // 用请求而非通知发送：等待 Sidecar 确认已收到取消（通知可能被静默丢弃）
            if let Err(e) = conn.call(
                "session.cancel",
                json!({ "sessionId": session_id }),
                Duration::from_secs(5),
            ) {
                self.log("warn", &format!("取消未获 Sidecar 确认: {e}"));
            }
        }
        let killed = self.procs.lock().unwrap().kill_session(&session_id);
        self.tokens.write().unwrap().revoke_session(&session_id);
        self.vault.lock().unwrap().clear();
        self.push_event(
            "session",
            "aborted",
            "warn",
            &format!("会话已中止（清理 {killed} 个进程，吊销全部令牌）"),
            json!({ "sessionId": session_id }),
        );
        self.emit_view();
        Ok(json!({ "ok": true, "killed": killed }))
    }
}

// 便捷扩展：从会话元数据取根目录
trait SessionMetaExt {
    fn cloned_meta(&self) -> PathBuf;
}
impl SessionMetaExt for Option<&SessionMeta> {
    fn cloned_meta(&self) -> PathBuf {
        self.map(|m| m.root.clone()).unwrap_or_else(|| PathBuf::from("."))
    }
}

/// 极简 JSON 点路径取值（"data.token" / "token"）
///
/// 先剥协议信封（tRPC 成功信封 `{result:{data:…}}`、superjson 的 `{json,meta?}`），
/// 使契约里的 credentialPath 只写业务字段名（如 "token"），与服务端是否套 transformer 无关。
/// 判定严格：仅当顶层只有一个 `result` 键且其内含 `data` 时才解包，普通 REST 响应不受影响。
fn json_path(body: &str, path: &str) -> Option<String> {
    let v: Value = serde_json::from_str(body).ok()?;
    let mut cur = unwrap_wire_envelope(&v);
    for seg in path.split('.') {
        cur = cur.get(seg)?;
    }
    match cur {
        Value::String(s) => Some(s.clone()),
        _ => None,
    }
}

/// 反复剥去 `{result:{data:…}}` 与 `{json:…}` 信封，直到取到业务载荷
fn unwrap_wire_envelope<'a>(v: &'a Value) -> &'a Value {
    let mut cur = v;
    loop {
        if let Some(data) = cur
            .as_object()
            .filter(|o| o.len() == 1)
            .and_then(|o| o.get("result"))
            .and_then(|r| r.get("data"))
        {
            cur = data;
            continue;
        }
        let superjson_inner = cur.as_object().and_then(|o| {
            if o.contains_key("json") && o.keys().all(|k| k == "json" || k == "meta") {
                o.get("json")
            } else {
                None
            }
        });
        if let Some(inner) = superjson_inner {
            cur = inner;
            continue;
        }
        return cur;
    }
}

/// 从 Set-Cookie 响应头提取 `name=value; name2=value2` 形式的 Cookie 头值。
/// 同名 Cookie 以后出现的为准；`Max-Age=0` 视为清除。
fn collect_cookie_header(headers: &[(String, String)]) -> Option<String> {
    let mut pairs: Vec<(String, String)> = Vec::new();
    for (name, value) in headers {
        if !name.eq_ignore_ascii_case("set-cookie") {
            continue;
        }
        let mut parts = value.split(';');
        let pair = parts.next().unwrap_or("").trim();
        let Some((key, val)) = pair.split_once('=') else {
            continue;
        };
        let key = key.trim();
        if key.is_empty() {
            continue;
        }
        let cleared = parts.any(|attr| attr.trim().eq_ignore_ascii_case("max-age=0"));
        if cleared {
            pairs.retain(|(k, _)| k != key);
            continue;
        }
        if let Some(existing) = pairs.iter_mut().find(|(k, _)| k == key) {
            existing.1 = val.trim().to_string();
        } else {
            pairs.push((key.to_string(), val.trim().to_string()));
        }
    }
    if pairs.is_empty() {
        return None;
    }
    Some(
        pairs
            .into_iter()
            .map(|(k, v)| format!("{k}={v}"))
            .collect::<Vec<_>>()
            .join("; "),
    )
}

/// 黑盒目标只接受回环 http 或任意 https；返回归一化 URL。
fn normalize_blackbox_url(raw: Option<&str>) -> HostResult<Option<String>> {
    let Some(raw) = raw.map(str::trim).filter(|s| !s.is_empty()) else {
        return Ok(None);
    };
    let parsed = Url::parse(raw)
        .map_err(|e| HostError::InvalidParams(format!("黑盒目标 URL 非法: {e}")))?;
    if !matches!(parsed.scheme(), "http" | "https") {
        return Err(HostError::InvalidParams("黑盒目标仅支持 http/https".into()));
    }
    let host = parsed.host_str().unwrap_or("");
    if host.is_empty() {
        return Err(HostError::InvalidParams("黑盒目标缺少主机名".into()));
    }
    if parsed.scheme() == "http" && !matches!(host, "127.0.0.1" | "localhost" | "::1" | "[::1]") {
        return Err(HostError::InvalidParams(
            "远程目标必须使用 https（明文 http 仅限本机回环）".into(),
        ));
    }
    Ok(Some(parsed.to_string()))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn blackbox_url_accepts_loopback_http_and_https_remote() {
        assert_eq!(
            normalize_blackbox_url(Some("http://127.0.0.1:3000")).unwrap().as_deref(),
            Some("http://127.0.0.1:3000/")
        );
        assert_eq!(
            normalize_blackbox_url(Some(" https://staging.example.com/api ")).unwrap().as_deref(),
            Some("https://staging.example.com/api")
        );
        assert_eq!(normalize_blackbox_url(Some("   ")).unwrap(), None);
        assert_eq!(normalize_blackbox_url(None).unwrap(), None);
    }

    #[test]
    fn blackbox_url_rejects_remote_http_and_bad_scheme() {
        assert!(normalize_blackbox_url(Some("http://example.com")).is_err());
        assert!(normalize_blackbox_url(Some("ftp://example.com")).is_err());
        assert!(normalize_blackbox_url(Some("not a url")).is_err());
    }

    #[test]
    fn cookie_header_collects_pairs_and_dedupes() {
        let h = |name: &str, v: &str| (name.to_string(), v.to_string());
        let out = collect_cookie_header(&[
            h("Content-Type", "text/html"),
            h("Set-Cookie", "session=abc123; Path=/; HttpOnly"),
            h("Set-Cookie", "theme=dark; SameSite=Lax"),
            h("Set-Cookie", "session=fresh456; Path=/"),
        ]);
        assert_eq!(out.as_deref(), Some("session=fresh456; theme=dark"));
        assert_eq!(collect_cookie_header(&[h("X-Test", "1")]), None);
        assert_eq!(collect_cookie_header(&[h("Set-Cookie", "broken")]), None);
    }

    #[test]
    fn cookie_header_drops_cleared_cookies() {
        let h = |v: &str| ("Set-Cookie".to_string(), v.to_string());
        assert_eq!(
            collect_cookie_header(&[h("session=gone; Max-Age=0"), h("theme=dark")]).as_deref(),
            Some("theme=dark")
        );
        assert_eq!(collect_cookie_header(&[h("session=x; max-age=0")]), None);
    }

    #[test]
    fn json_path_reads_plain_and_nested_paths() {
        assert_eq!(json_path(r#"{"token":"abc"}"#, "token").as_deref(), Some("abc"));
        assert_eq!(
            json_path(r#"{"authentication":{"token":"abc"}}"#, "authentication.token").as_deref(),
            Some("abc")
        );
        assert_eq!(json_path(r#"{"token":123}"#, "token"), None);
    }

    #[test]
    fn json_path_unwraps_trpc_and_superjson_envelopes() {
        // tRPC + superjson：token 位于 result.data.json
        assert_eq!(
            json_path(
                r#"{"result":{"data":{"json":{"token":"t1","user":{"id":"u_1"}},"meta":{"values":{}}}}}"#,
                "token"
            )
            .as_deref(),
            Some("t1")
        );
        // tRPC 无 transformer
        assert_eq!(
            json_path(r#"{"result":{"data":{"token":"t2"}}}"#, "token").as_deref(),
            Some("t2")
        );
        // 业务字段自身叫 result：顶层不满足「仅一个 result 键且内含 data」，不解包
        assert_eq!(json_path(r#"{"result":{"a":1},"token":"keep"}"#, "token").as_deref(), Some("keep"));
    }
}
