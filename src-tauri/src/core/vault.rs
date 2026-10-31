use std::collections::HashMap;

use serde::{Deserialize, Serialize};

/// 凭证保险库：托管探测过程中获取的身份凭证（如登录会话 Token）。
///
/// 关键设计：凭证值**永不离开 Host**。Sidecar（编排/决策层）只能通过
/// `identityRef` 引用身份，由 Host 在发起 HTTP 请求时注入凭证头；
/// 任何流出 Host 的文本都会经过脱敏引擎，把保险库内的秘密替换为掩码。
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Credential {
    /// 注入的 HTTP 头名称，如 "Authorization"
    pub header: String,
    /// 头值，如 "Bearer abc123"
    pub value: String,
    /// 获取来源（用于审计）
    pub source: String,
}

#[derive(Default)]
pub struct Vault {
    entries: HashMap<String, Credential>,
    /// 只用于脱敏的秘密（引擎自生成的测试账号口令等）。不会作为请求头注入任何请求，
    /// 值也永不出 Host；任何流经 Host 的文本命中它都会被掩码。
    protected: HashMap<String, String>,
}

impl Vault {
    pub fn store(&mut self, identity: &str, header: &str, value: &str, source: &str) {
        self.entries.insert(
            identity.to_string(),
            Credential {
                header: header.to_string(),
                value: value.to_string(),
                source: source.to_string(),
            },
        );
    }

    pub fn get(&self, identity: &str) -> Option<&Credential> {
        self.entries.get(identity)
    }

    pub fn remove(&mut self, identity: &str) -> bool {
        self.entries.remove(identity).is_some()
    }

    pub fn names(&self) -> Vec<String> {
        let mut v: Vec<String> = self.entries.keys().cloned().collect();
        v.sort();
        v
    }

    pub fn clear(&mut self) {
        self.entries.clear();
        self.protected.clear();
    }

    /// 登记一个只用于脱敏的秘密（不是请求头凭证）。重复登记同一标签会覆盖旧值。
    pub fn protect(&mut self, label: &str, value: &str) {
        self.protected.insert(label.to_string(), value.to_string());
    }

    /// 返回全部秘密值（用于全局脱敏）。仅当长度 >= 6 时返回，避免误伤短字符串。
    pub fn secret_values(&self) -> Vec<(String, String)> {
        let mut out: Vec<(String, String)> = self
            .entries
            .iter()
            .filter(|(_, c)| c.value.len() >= 6)
            .map(|(k, c)| (k.clone(), c.value.clone()))
            .collect();
        for (k, v) in &self.protected {
            if v.len() >= 6 {
                out.push((k.clone(), v.clone()));
            }
        }
        out
    }
}

#[cfg(test)]
mod tests {
    use super::Vault;

    #[test]
    fn protected_secret_is_redacted_but_not_injectable() {
        let mut vault = Vault::default();
        vault.protect("password:alice", "Gb-rotating-horse-77");
        // 参与全局脱敏
        let secrets = vault.secret_values();
        assert!(secrets.iter().any(|(k, v)| k == "password:alice" && v == "Gb-rotating-horse-77"));
        // 但不是可用的请求头凭证，也不会出现在身份列表里
        assert!(vault.get("alice").is_none());
        assert!(vault.names().is_empty());
        // 过短的秘密不参与脱敏（避免误伤常规文本）
        vault.protect("password:short", "abc");
        assert!(!vault.secret_values().iter().any(|(k, _)| k == "password:short"));
    }

    #[test]
    fn clear_drops_protected_secrets_too() {
        let mut vault = Vault::default();
        vault.store("alice", "Authorization", "Bearer t0ken-value", "http://127.0.0.1");
        vault.protect("password:alice", "Gb-rotating-horse-77");
        vault.clear();
        assert!(vault.secret_values().is_empty());
    }
}
