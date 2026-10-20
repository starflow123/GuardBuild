use std::collections::HashMap;
use std::path::{Path, PathBuf};

use serde::{Deserialize, Serialize};

use super::error::{HostError, HostResult};

pub fn now_ms() -> i64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_millis() as i64)
        .unwrap_or(0)
}

/// 作用域：描述「允许对什么资源做什么」。所有字段都是资源约束。
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
#[serde(tag = "kind")]
pub enum Scope {
    #[serde(rename = "project.read")]
    ProjectRead { root: String },
    #[serde(rename = "worktree.write")]
    WorktreeWrite { root: String },
    #[serde(rename = "proc.spawn")]
    ProcSpawn { roots: Vec<String> },
    #[serde(rename = "net.probe")]
    NetProbe {},
    /// 向用户显式声明的主机发起 HTTPS 探测（Supabase/PostgREST 等远端数据接口）。
    #[serde(rename = "net.egress")]
    NetEgress { host: String },
    /// 仅能由用户在 UI 批准 Diff 后由 Host 下发，Sidecar 无法申请。
    #[serde(rename = "workspace.write")]
    WorkspaceWrite { root: String, patch_hash: String },
    /// 仅能由用户在 UI 触发回滚后由 Host 下发。
    #[serde(rename = "workspace.rollback")]
    WorkspaceRollback { root: String, backup_id: String },
}

impl Scope {
    pub fn kind(&self) -> &'static str {
        match self {
            Scope::ProjectRead { .. } => "project.read",
            Scope::WorktreeWrite { .. } => "worktree.write",
            Scope::ProcSpawn { .. } => "proc.spawn",
            Scope::NetProbe { .. } => "net.probe",
            Scope::NetEgress { .. } => "net.egress",
            Scope::WorkspaceWrite { .. } => "workspace.write",
            Scope::WorkspaceRollback { .. } => "workspace.rollback",
        }
    }

    /// 该作用域是否允许由 Sidecar 主动申请。
    pub fn requestable_by_sidecar(&self) -> bool {
        !matches!(
            self,
            Scope::WorkspaceWrite { .. } | Scope::WorkspaceRollback { .. }
        )
    }

    pub fn summary(&self) -> String {
        match self {
            Scope::ProjectRead { root } => format!("project.read @ {root}"),
            Scope::WorktreeWrite { root } => format!("worktree.write @ {root}"),
            Scope::ProcSpawn { roots } => format!("proc.spawn @ [{}]", roots.join(", ")),
            Scope::NetProbe {} => "net.probe @ loopback".to_string(),
            Scope::NetEgress { host } => format!("net.egress @ {host}"),
            Scope::WorkspaceWrite { root, patch_hash } => {
                format!("workspace.write @ {root} (patch {})", &patch_hash[..8.min(patch_hash.len())])
            }
            Scope::WorkspaceRollback { root, backup_id } => {
                format!("workspace.rollback @ {root} (backup {backup_id})")
            }
        }
    }
}

/// 归一化 egress 目标主机：仅接受 DNS 形态主机名（小写字母/数字/点/连字符，至少一个点），
/// 拒绝携带端口、协议、路径或空白的输入，防止把 "https://x/a" 或 "x:443" 当作主机声明。
pub fn normalize_egress_host(raw: &str) -> Option<String> {
    let h = raw.trim().to_lowercase();
    if h.is_empty() || h.len() > 253 || !h.contains('.') {
        return None;
    }
    if !h.chars().all(|c| c.is_ascii_alphanumeric() || c == '.' || c == '-') {
        return None;
    }
    if h.starts_with('.') || h.ends_with('.') || h.contains("..") {
        return None;
    }
    Some(h)
}

/// 作用域授权令牌：Host 签发的唯一凭证载体。
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Token {
    pub id: String,
    pub session_id: String,
    pub scopes: Vec<Scope>,
    pub issued_at: i64,
    pub expires_at: i64,
    /// 授权途径：user-selected-project / user-consent / user-diff-approval / auto-consent
    pub via: String,
}

impl Token {
    pub fn valid_now(&self) -> bool {
        now_ms() < self.expires_at
    }
}

/// 令牌表。线程安全由外层 RwLock 保证。
#[derive(Default)]
pub struct TokenStore {
    tokens: HashMap<String, Token>,
}

impl TokenStore {
    pub fn insert(&mut self, token: Token) {
        self.tokens.insert(token.id.clone(), token);
    }

    pub fn revoke(&mut self, id: &str) -> bool {
        self.tokens.remove(id).is_some()
    }

    pub fn revoke_session(&mut self, session_id: &str) {
        self.tokens.retain(|_, t| t.session_id != session_id);
    }

    /// 校验令牌有效性并返回引用。
    pub fn require(&self, id: &str) -> HostResult<&Token> {
        let token = self.tokens.get(id).ok_or(HostError::TokenInvalid)?;
        if !token.valid_now() {
            return Err(HostError::TokenInvalid);
        }
        Ok(token)
    }

    pub fn list_session(&self, session_id: &str) -> Vec<Token> {
        let mut v: Vec<Token> = self
            .tokens
            .values()
            .filter(|t| t.session_id == session_id && t.valid_now())
            .cloned()
            .collect();
        v.sort_by_key(|t| t.issued_at);
        v
    }
}

// ---------- 路径与资源约束检查 ----------

/// 规范化路径用于比较：Windows 下转为小写 + 去掉 \\?\ 前缀。
pub fn normalize_for_compare(p: &Path) -> String {
    let s = p.to_string_lossy().to_string();
    let s = s.strip_prefix(r"\\?\").unwrap_or(&s).to_string();
    let s = s.replace('/', "\\");
    let s = s.trim_end_matches('\\').to_string();
    if cfg!(windows) {
        s.to_lowercase()
    } else {
        s
    }
}

/// 判断 child 是否位于 root 之内（含 root 本身）。
pub fn path_within(root: &Path, child: &Path) -> bool {
    let r = normalize_for_compare(root);
    let c = normalize_for_compare(child);
    c == r || c.starts_with(&format!("{r}\\"))
}

/// 在 root 约束下解析路径（允许目标不存在，用于写操作）。
/// 相对路径基于 root 拼接；随后对最近的已存在祖先做 canonicalize，防止符号链接逃逸。
pub fn resolve_in_root_allow_missing(root: &Path, requested: &str) -> HostResult<PathBuf> {
    let root_canon = root
        .canonicalize()
        .map_err(|e| HostError::NotFound(format!("根目录不可访问: {root:?} ({e})")))?;
    let req = Path::new(requested);
    let joined = if req.is_absolute() {
        req.to_path_buf()
    } else {
        root_canon.join(req)
    };

    // 找到最近的已存在祖先并 canonicalize，随后把剩余部分拼回
    let mut existing = joined.clone();
    let mut tail: Vec<std::ffi::OsString> = Vec::new();
    loop {
        if existing.exists() {
            break;
        }
        match (existing.file_name(), existing.parent()) {
            (Some(name), Some(parent)) => {
                tail.push(name.to_os_string());
                existing = parent.to_path_buf();
            }
            _ => return Err(HostError::PathOutOfScope(requested.to_string())),
        }
    }
    let mut real = existing
        .canonicalize()
        .map_err(|e| HostError::PathOutOfScope(format!("{requested} ({e})")))?;
    for seg in tail.iter().rev() {
        real.push(seg);
    }

    if !path_within(&root_canon, &real) {
        return Err(HostError::PathOutOfScope(format!(
            "{requested} 逃逸出授权根目录 {root:?}"
        )));
    }
    Ok(real)
}

/// 在 root 约束下解析已存在的路径（读操作）。
pub fn resolve_in_root(root: &Path, requested: &str) -> HostResult<PathBuf> {
    let p = resolve_in_root_allow_missing(root, requested)?;
    if !p.exists() {
        return Err(HostError::NotFound(requested.to_string()));
    }
    Ok(p)
}

/// 在令牌的作用域集合中查找满足给定谓词的令牌。
fn any_scope<F: Fn(&Scope) -> bool>(token: &Token, pred: F) -> bool {
    token.scopes.iter().any(pred)
}

impl Token {
    /// 校验：读取位于 root 下的路径。
    pub fn require_read_path(&self, path: &Path) -> HostResult<()> {
        if any_scope(self, |s| match s {
            Scope::ProjectRead { root } => path_within(Path::new(root), path),
            Scope::WorktreeWrite { root } => path_within(Path::new(root), path),
            _ => false,
        }) {
            Ok(())
        } else {
            Err(HostError::PathOutOfScope(format!(
                "读取 {:?} 无对应 project.read 作用域",
                path
            )))
        }
    }

    /// 校验：写入 worktree 内的路径。
    pub fn require_worktree_write_path(&self, path: &Path) -> HostResult<()> {
        if any_scope(self, |s| match s {
            Scope::WorktreeWrite { root } => path_within(Path::new(root), path),
            _ => false,
        }) {
            Ok(())
        } else {
            Err(HostError::ScopeDenied(format!(
                "写入 {:?} 需要 worktree.write 作用域",
                path
            )))
        }
    }

    /// 校验：在允许的根目录内、用允许的命令启动进程。
    pub fn require_spawn(&self, cwd: &Path, cmd: &str, args: &[String], node_bin: &str) -> HostResult<()> {
        let base = Path::new(cmd)
            .file_stem()
            .map(|s| s.to_string_lossy().to_lowercase())
            .unwrap_or_default();
        // 开发服务器启动器：Node 与 Python 生态（gate 仅用它启动项目声明的目标进程）
        const LAUNCHERS: &[&str] = &[
            "node", "npm", "npx", "python", "python3", "py", "uvicorn", "gunicorn", "hypercorn",
            "flask", "fastapi", "uv",
        ];
        if base == "docker" {
            // docker 可以挂载宿主目录、暴露端口，必须逐参数白名单校验（见 validate_docker_*）
            validate_docker_invocation(cwd, args)?;
        } else if !(LAUNCHERS.contains(&base.as_str()) || cmd == node_bin) {
            return Err(HostError::ScopeDenied(format!(
                "命令 `{cmd}` 不在允许列表（node/npm/npx、Python 启动器或受限的 docker run/rm）内"
            )));
        }
        if any_scope(self, |s| match s {
            Scope::ProcSpawn { roots } => roots.iter().any(|r| path_within(Path::new(r), cwd)),
            _ => false,
        }) {
            Ok(())
        } else {
            Err(HostError::ScopeDenied(format!(
                "在 {:?} 启动进程需要 proc.spawn 作用域",
                cwd
            )))
        }
    }

    /// 校验：允许对本机回环地址发起探测。
    pub fn require_net(&self, host: &str) -> HostResult<()> {
        let host_ok = matches!(host, "127.0.0.1" | "localhost" | "::1" | "[::1]");
        if !host_ok {
            return Err(HostError::ScopeDenied(format!(
                "net.probe 仅允许回环地址，拒绝: {host}"
            )));
        }
        if any_scope(self, |s| matches!(s, Scope::NetProbe {})) {
            Ok(())
        } else {
            Err(HostError::ScopeDenied("需要 net.probe 作用域".into()))
        }
    }

    /// 校验：允许对用户显式声明的主机发起 HTTPS 探测（主机名大小写不敏感精确匹配）。
    pub fn require_egress(&self, host: &str) -> HostResult<()> {
        let host_lc = host.to_lowercase();
        if any_scope(self, |s| match s {
            Scope::NetEgress { host: h } => h.to_lowercase() == host_lc,
            _ => false,
        }) {
            Ok(())
        } else {
            Err(HostError::ScopeDenied(format!(
                "向 {host} 发起 HTTPS 探测需要 net.egress @ {host} 授权（仅可由用户批准，或由 gate 在 guardbuild.json 中预声明 net.egress:{host}）"
            )))
        }
    }

    /// 校验：写回工作区，必须与特定补丁哈希绑定。
    pub fn require_workspace_write(&self, root: &Path, patch_hash: &str) -> HostResult<()> {
        if any_scope(self, |s| match s {
            Scope::WorkspaceWrite { root: r, patch_hash: h } => {
                path_within(Path::new(r), root) && h == patch_hash
            }
            _ => false,
        }) {
            Ok(())
        } else {
            Err(HostError::ScopeDenied(
                "将补丁写回工作区需要与补丁哈希绑定的 workspace.write 授权（仅可由用户在 UI 批准）".into(),
            ))
        }
    }

    /// 校验：回滚，必须与特定备份绑定。
    pub fn require_workspace_rollback(&self, backup_id: &str) -> HostResult<()> {
        if any_scope(self, |s| match s {
            Scope::WorkspaceRollback { backup_id: b, .. } => b == backup_id,
            _ => false,
        }) {
            Ok(())
        } else {
            Err(HostError::ScopeDenied(
                "回滚需要与备份绑定的 workspace.rollback 授权（仅可由用户在 UI 触发）".into(),
            ))
        }
    }
}

// ---------- docker 参数白名单 ----------
//
// 容器隔离让目标跑在 docker 里，但 docker CLI 本身能力极强（挂载任意宿主目录、
// --privileged、host 网络等）。Host 不能只校验可执行名，必须逐参数收紧到
// sidecar 实际会生成的那一种调用形状。

fn docker_denied(reason: impl Into<String>) -> HostError {
    HostError::ScopeDenied(format!("docker 调用被拒绝：{}", reason.into()))
}

fn is_guardbuild_container_name(s: &str) -> bool {
    s.len() > "guardbuild-".len()
        && s.len() <= 80
        && s.starts_with("guardbuild-")
        && s
            .chars()
            .all(|c| c.is_ascii_alphanumeric() || matches!(c, '-' | '_' | '.'))
}

fn is_safe_image_ref(s: &str) -> bool {
    !s.is_empty()
        && s.len() <= 200
        && !s.starts_with('-')
        && s
            .chars()
            .all(|c| c.is_ascii_alphanumeric() || matches!(c, '_' | '.' | '/' | ':' | '@' | '-'))
}

/// 容器内绝对路径：不允许 .、..、空段与尾部斜杠（Docker 的 --mount 语义也要求绝对路径）。
fn is_safe_container_path(p: &str) -> bool {
    if !p.starts_with('/') || p == "/" || p.len() > 200 || p.contains('\0') {
        return false;
    }
    p[1..].split('/').all(|seg| !seg.is_empty() && seg != "." && seg != "..")
}

fn is_safe_env_key(k: &str) -> bool {
    !k.is_empty()
        && k.len() <= 100
        && k.chars().next().map(|c| c.is_ascii_alphabetic() || c == '_').unwrap_or(false)
        && k.chars().all(|c| c.is_ascii_alphanumeric() || c == '_')
}

fn parse_publish_spec(v: &str) -> Option<(u16, u16)> {
    let mut parts = v.split(':');
    let ip = parts.next()?;
    let host = parts.next()?.parse::<u16>().ok()?;
    let container = parts.next()?.parse::<u16>().ok()?;
    if parts.next().is_some() || ip != "127.0.0.1" || host == 0 || container == 0 {
        return None;
    }
    Some((host, container))
}

/// `-v <src>:<dst>[:ro|rw]`：src 必须是本次 spawn 的 cwd（防止挂载任意宿主目录）。
fn parse_volume_spec(cwd: &Path, spec: &str) -> HostResult<String> {
    let (rest, _mode) = match spec.rsplit_once(':') {
        Some((r, m)) if m == "ro" || m == "rw" => (r, Some(m)),
        _ => (spec, None),
    };
    // Windows 盘符本身带冒号，用「最后一个冒号」切分 source/target
    let (src, target) = rest
        .rsplit_once(':')
        .ok_or_else(|| docker_denied(format!("-v 需要 <宿主目录>:<容器目录>，收到 `{spec}`")))?;
    if !is_safe_container_path(target) {
        return Err(docker_denied(format!("-v 容器目录非法：`{target}`")));
    }
    let src_path = Path::new(src)
        .canonicalize()
        .map_err(|e| docker_denied(format!("-v 宿主目录不可访问：`{src}` ({e})")))?;
    if normalize_for_compare(&src_path) != normalize_for_compare(cwd) {
        return Err(docker_denied(format!(
            "-v 宿主目录必须是当前目标目录 {:?}，拒绝 `{src}`",
            cwd
        )));
    }
    Ok(target.to_string())
}

fn validate_docker_remove(sub: &str, rest: &[String]) -> HostResult<()> {
    let mut names = 0usize;
    for a in rest {
        if a == "--force" || (sub == "rm" && a == "-f") {
            continue;
        }
        if a.starts_with('-') {
            return Err(docker_denied(format!("`docker {sub}` 不允许参数 `{a}`")));
        }
        if !is_guardbuild_container_name(a) {
            return Err(docker_denied(format!(
                "`docker {sub}` 只能操作 guardbuild-* 容器，收到 `{a}`"
            )));
        }
        names += 1;
        if names > 8 {
            return Err(docker_denied("一次最多操作 8 个容器"));
        }
    }
    if names == 0 {
        return Err(docker_denied(format!("`docker {sub}` 缺少容器名")));
    }
    Ok(())
}

fn validate_docker_run(cwd: &Path, args: &[String]) -> HostResult<()> {
    let mut name: Option<String> = None;
    let mut publish: Option<(u16, u16)> = None;
    let mut mount_target: Option<String> = None;
    let mut workdir: Option<String> = None;
    let mut env_count = 0usize;
    let mut image: Option<String> = None;

    let mut i = 0usize;
    while i < args.len() {
        let a = args[i].as_str();
        if a == "--" {
            return Err(docker_denied("不接受 `--` 分隔符"));
        }
        if !a.starts_with('-') {
            image = Some(a.to_string());
            break;
        }
        match a {
            "--rm" | "--init" => {
                i += 1;
            }
            "--name" | "-p" | "--publish" | "-v" | "--volume" | "-w" | "--workdir" | "-e" | "--env" => {
                let v = args
                    .get(i + 1)
                    .ok_or_else(|| docker_denied(format!("`{a}` 缺少参数")))?;
                match a {
                    "--name" => {
                        if name.is_some() {
                            return Err(docker_denied("--name 只能出现一次"));
                        }
                        if !is_guardbuild_container_name(v) {
                            return Err(docker_denied(format!("容器名必须形如 guardbuild-*，收到 `{v}`")));
                        }
                        name = Some(v.clone());
                    }
                    "-p" | "--publish" => {
                        if publish.is_some() {
                            return Err(docker_denied("端口映射只能声明一次"));
                        }
                        publish = Some(parse_publish_spec(v).ok_or_else(|| {
                            docker_denied(format!(
                                "端口映射必须是 127.0.0.1:<宿主端口>:<容器端口>，收到 `{v}`"
                            ))
                        })?);
                    }
                    "-v" | "--volume" => {
                        if mount_target.is_some() {
                            return Err(docker_denied("只允许一个项目目录挂载"));
                        }
                        mount_target = Some(parse_volume_spec(cwd, v)?);
                    }
                    "-w" | "--workdir" => {
                        if workdir.is_some() {
                            return Err(docker_denied("-w 只能出现一次"));
                        }
                        if !is_safe_container_path(v) {
                            return Err(docker_denied(format!("-w 容器目录非法：`{v}`")));
                        }
                        workdir = Some(v.clone());
                    }
                    "-e" | "--env" => {
                        let (k, val) = v
                            .split_once('=')
                            .ok_or_else(|| docker_denied(format!("-e 需要 KEY=VALUE，收到 `{v}`")))?;
                        if !is_safe_env_key(k) {
                            return Err(docker_denied(format!("-e 变量名非法：`{k}`")));
                        }
                        if val.len() > 4096 || val.contains('\0') {
                            return Err(docker_denied(format!("-e {k} 的值过长或含非法字符")));
                        }
                        env_count += 1;
                        if env_count > 32 {
                            return Err(docker_denied("环境变量最多 32 个"));
                        }
                    }
                    _ => unreachable!(),
                }
                i += 2;
            }
            _ if a.starts_with("--name=") => {
                let v = &a["--name=".len()..];
                if name.is_some() || !is_guardbuild_container_name(v) {
                    return Err(docker_denied(format!("容器名必须形如 guardbuild-*，收到 `{v}`")));
                }
                name = Some(v.to_string());
                i += 1;
            }
            _ if a.starts_with("--publish=") => {
                let v = &a["--publish=".len()..];
                if publish.is_some() {
                    return Err(docker_denied("端口映射只能声明一次"));
                }
                publish = Some(parse_publish_spec(v).ok_or_else(|| {
                    docker_denied(format!("端口映射必须是 127.0.0.1:<宿主端口>:<容器端口>，收到 `{v}`"))
                })?);
                i += 1;
            }
            _ if a.starts_with("--volume=") => {
                if mount_target.is_some() {
                    return Err(docker_denied("只允许一个项目目录挂载"));
                }
                mount_target = Some(parse_volume_spec(cwd, &a["--volume=".len()..])?);
                i += 1;
            }
            _ if a.starts_with("--workdir=") => {
                if workdir.is_some() {
                    return Err(docker_denied("-w 只能出现一次"));
                }
                let v = &a["--workdir=".len()..];
                if !is_safe_container_path(v) {
                    return Err(docker_denied(format!("-w 容器目录非法：`{v}`")));
                }
                workdir = Some(v.to_string());
                i += 1;
            }
            _ if a.starts_with("--env=") => {
                let v = &a["--env=".len()..];
                let (k, val) = v
                    .split_once('=')
                    .ok_or_else(|| docker_denied(format!("-e 需要 KEY=VALUE，收到 `{v}`")))?;
                if !is_safe_env_key(k) || val.len() > 4096 || val.contains('\0') {
                    return Err(docker_denied(format!("-e 参数非法：`{v}`")));
                }
                env_count += 1;
                if env_count > 32 {
                    return Err(docker_denied("环境变量最多 32 个"));
                }
                i += 1;
            }
            _ => {
                return Err(docker_denied(format!(
                    "不允许的 docker run 参数 `{a}`（容器隔离仅支持 --rm/--init/--name/-p/-v/-w/-e）"
                )))
            }
        }
    }

    let image = image.ok_or_else(|| docker_denied("缺少镜像名"))?;
    if !is_safe_image_ref(&image) {
        return Err(docker_denied(format!("镜像名非法：`{image}`")));
    }
    let name = name.ok_or_else(|| docker_denied("缺少 --name guardbuild-*（用于清理容器）"))?;
    let (host_port, container_port) =
        publish.ok_or_else(|| docker_denied("缺少 127.0.0.1:<宿主端口>:<容器端口> 映射"))?;
    let target = mount_target.ok_or_else(|| docker_denied("缺少项目目录挂载（-v <cwd>:<容器目录>）"))?;
    let wd = workdir.ok_or_else(|| docker_denied("缺少容器工作目录（-w）"))?;
    if wd != target {
        return Err(docker_denied(format!(
            "-w `{wd}` 必须与挂载目标 `{target}` 一致"
        )));
    }
    let _ = (host_port, container_port, name);
    if args.len() > 96 {
        return Err(docker_denied("参数过多"));
    }
    Ok(())
}

/// 校验 docker 调用形状（仅 run/rm/stop/version，且 run 必须挂载当前项目目录、
/// 只映射回环端口、不启用 privileged/host 网络等危险能力）。
pub fn validate_docker_invocation(cwd: &Path, args: &[String]) -> HostResult<()> {
    let sub = args.first().map(String::as_str).unwrap_or("");
    match sub {
        "run" => validate_docker_run(cwd, &args[1..]),
        "rm" | "stop" => validate_docker_remove(sub, &args[1..]),
        "version" if args.len() == 1 => Ok(()),
        _ => Err(docker_denied(format!(
            "仅允许 docker run/rm/stop/version，收到 `{sub}`"
        ))),
    }
}

/// 事件/进程列表中的 docker 参数脱敏：`-e KEY=VALUE` 的 VALUE 可能是契约里的凭据。
pub fn redact_docker_env_args(cmd: &str, args: &[String]) -> Vec<String> {
    let is_docker = Path::new(cmd)
        .file_stem()
        .map(|s| s.to_string_lossy().eq_ignore_ascii_case("docker"))
        .unwrap_or(false);
    if !is_docker {
        return args.to_vec();
    }
    let mask = |kv: &str| match kv.split_once('=') {
        Some((k, _)) => format!("{k}=***"),
        None => "***".to_string(),
    };
    let mut out = Vec::with_capacity(args.len());
    let mut next_is_env = false;
    for a in args {
        if next_is_env {
            out.push(mask(a));
            next_is_env = false;
        } else if a == "-e" || a == "--env" {
            out.push(a.clone());
            next_is_env = true;
        } else if let Some(v) = a.strip_prefix("--env=") {
            out.push(format!("--env={}", mask(v)));
        } else {
            out.push(a.clone());
        }
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn path_within_works() {
        let root = if cfg!(windows) { Path::new(r"D:\proj") } else { Path::new("/proj") };
        let inside = if cfg!(windows) { Path::new(r"D:\proj\src\a.js") } else { Path::new("/proj/src/a.js") };
        let outside = if cfg!(windows) { Path::new(r"D:\other\a.js") } else { Path::new("/other/a.js") };
        assert!(path_within(root, inside));
        assert!(path_within(root, root));
        assert!(!path_within(root, outside));
    }

    #[test]
    fn workspace_write_requires_matching_hash() {
        let token = Token {
            id: "t1".into(),
            session_id: "s1".into(),
            scopes: vec![Scope::WorkspaceWrite {
                root: if cfg!(windows) { r"D:\proj".into() } else { "/proj".into() },
                patch_hash: "abc123".into(),
            }],
            issued_at: now_ms(),
            expires_at: now_ms() + 1000,
            via: "user".into(),
        };
        let root = if cfg!(windows) { Path::new(r"D:\proj") } else { Path::new("/proj") };
        assert!(token.require_workspace_write(root, "abc123").is_ok());
        assert!(token.require_workspace_write(root, "other").is_err());
    }

    #[test]
    fn sidecar_cannot_request_privileged_scopes() {
        let w = Scope::WorkspaceWrite { root: "x".into(), patch_hash: "h".into() };
        let r = Scope::WorkspaceRollback { root: "x".into(), backup_id: "b".into() };
        assert!(!w.requestable_by_sidecar());
        assert!(!r.requestable_by_sidecar());
        assert!(Scope::NetProbe {}.requestable_by_sidecar());
        assert!(Scope::NetEgress { host: "db.example.com".into() }.requestable_by_sidecar());
    }

    #[test]
    fn egress_host_must_match_declared_host() {
        let token = Token {
            id: "t2".into(),
            session_id: "s1".into(),
            scopes: vec![Scope::NetEgress { host: "abc123.supabase.co".into() }],
            issued_at: now_ms(),
            expires_at: now_ms() + 1000,
            via: "user".into(),
        };
        assert!(token.require_egress("abc123.supabase.co").is_ok());
        assert!(token.require_egress("ABC123.Supabase.CO").is_ok()); // 大小写不敏感
        assert!(token.require_egress("evil.example.com").is_err());
        assert!(token.require_egress("supabase.co").is_err());
    }

    #[test]
    fn normalize_egress_host_rejects_non_host_shapes() {
        assert_eq!(normalize_egress_host(" ABC.supabase.co "), Some("abc.supabase.co".into()));
        assert_eq!(normalize_egress_host("https://abc.supabase.co"), None);
        assert_eq!(normalize_egress_host("abc.supabase.co:443"), None);
        assert_eq!(normalize_egress_host("localhost"), None);
        assert_eq!(normalize_egress_host(""), None);
        assert_eq!(normalize_egress_host("a..b.com"), None);
    }

    #[test]
    fn expired_token_rejected() {
        let mut store = TokenStore::default();
        store.insert(Token {
            id: "t".into(),
            session_id: "s".into(),
            scopes: vec![],
            issued_at: 0,
            expires_at: now_ms() - 10,
            via: "test".into(),
        });
        assert!(store.require("t").is_err());
    }

    fn docker_cwd() -> PathBuf {
        std::env::temp_dir().canonicalize().unwrap()
    }

    fn docker_args(v: &[&str]) -> Vec<String> {
        v.iter().map(|s| s.to_string()).collect()
    }

    fn valid_run_args() -> Vec<String> {
        let mount = format!("{}:/app", docker_cwd().to_string_lossy());
        docker_args(&[
            "run",
            "--rm",
            "--init",
            "--name",
            "guardbuild-s1-target-1",
            "-p",
            "127.0.0.1:48123:3000",
            "-v",
            &mount,
            "-w",
            "/app",
            "-e",
            "PORT=3000",
            "-e",
            "NODE_ENV=test",
            "node:20-alpine",
            "node",
            "server.js",
        ])
    }

    #[test]
    fn docker_run_accepts_sidecar_shape() {
        assert!(validate_docker_invocation(&docker_cwd(), &valid_run_args()).is_ok());
    }

    #[test]
    fn docker_run_rejects_dangerous_or_malformed_args() {
        let cwd = docker_cwd();
        let cases: Vec<Vec<String>> = vec![
            docker_args(&["run", "--privileged", "alpine", "sh"]),
            docker_args(&["run", "--network", "host", "alpine", "sh"]),
            docker_args(&["run", "-d", "alpine", "sh"]),
            docker_args(&["run", "--name", "other", "alpine", "sh"]),
            docker_args(&["run", "-p", "0.0.0.0:8080:80", "alpine", "sh"]),
            docker_args(&["run", "-p", "127.0.0.1:0:80", "alpine", "sh"]),
            docker_args(&["run", "-v", "/:/app", "alpine", "sh"]),
            docker_args(&["run", "--volume", "/etc:/app", "alpine", "sh"]),
            docker_args(&["run", "-e", "BAD-KEY=1", "alpine", "sh"]),
            docker_args(&["create", "alpine"]),
            docker_args(&["pull", "alpine"]),
            docker_args(&[]),
        ];
        for args in cases {
            assert!(
                validate_docker_invocation(&cwd, &args).is_err(),
                "应拒绝: {args:?}"
            );
        }
    }

    #[test]
    fn docker_run_requires_mount_pointing_at_cwd() {
        let cwd = docker_cwd();
        let outside = if cfg!(windows) { Path::new(r"D:\") } else { Path::new("/") };
        let mount = format!("{}:/app", outside.to_string_lossy());
        let args = docker_args(&[
            "run",
            "--name",
            "guardbuild-s1-target-1",
            "-p",
            "127.0.0.1:48123:3000",
            "-v",
            &mount,
            "-w",
            "/app",
            "alpine",
            "sh",
        ]);
        assert!(validate_docker_invocation(&cwd, &args).is_err());
    }

    #[test]
    fn docker_remove_only_touches_guardbuild_containers() {
        let cwd = docker_cwd();
        assert!(validate_docker_invocation(&cwd, &docker_args(&["rm", "-f", "guardbuild-abc-1"])).is_ok());
        assert!(validate_docker_invocation(&cwd, &docker_args(&["stop", "guardbuild-abc-1"])).is_ok());
        assert!(validate_docker_invocation(&cwd, &docker_args(&["rm", "-f", "mysql"])).is_err());
        assert!(validate_docker_invocation(&cwd, &docker_args(&["rm", "-f"])).is_err());
        assert!(validate_docker_invocation(&cwd, &docker_args(&["rm", "-v", "x"])).is_err());
    }

    #[test]
    fn docker_env_values_are_redacted_in_logs() {
        let args = docker_args(&["run", "-e", "API_KEY=secret", "--env", "PORT=3000", "--env=TOKEN=abc", "img"]);
        let out = redact_docker_env_args("docker", &args);
        assert!(out.iter().all(|a| !a.contains("secret") && !a.contains("abc")));
        assert!(out.contains(&"API_KEY=***".to_string()));
        assert!(out.contains(&"--env=TOKEN=***".to_string()));
        // 非 docker 命令原样返回
        let node = docker_args(&["-e", "X=1"]);
        assert_eq!(redact_docker_env_args("node", &node), node);
    }
}
