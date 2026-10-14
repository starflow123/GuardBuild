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
            Scope::WorkspaceWrite { root, patch_hash } => {
                format!("workspace.write @ {root} (patch {})", &patch_hash[..8.min(patch_hash.len())])
            }
            Scope::WorkspaceRollback { root, backup_id } => {
                format!("workspace.rollback @ {root} (backup {backup_id})")
            }
        }
    }
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
    pub fn require_spawn(&self, cwd: &Path, cmd: &str, node_bin: &str) -> HostResult<()> {
        let base = Path::new(cmd)
            .file_stem()
            .map(|s| s.to_string_lossy().to_lowercase())
            .unwrap_or_default();
        let allowed_cmd = base == "node" || base == "npm" || cmd == node_bin;
        if !allowed_cmd {
            return Err(HostError::ScopeDenied(format!(
                "命令 `{cmd}` 不在允许列表（node/npm）内"
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
}
