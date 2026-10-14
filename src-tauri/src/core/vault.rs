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
    }

    /// 返回全部秘密值（用于全局脱敏）。仅当长度 >= 6 时返回，避免误伤短字符串。
    pub fn secret_values(&self) -> Vec<(String, String)> {
        self.entries
            .iter()
            .filter(|(_, c)| c.value.len() >= 6)
            .map(|(k, c)| (k.clone(), c.value.clone()))
            .collect()
    }
}
