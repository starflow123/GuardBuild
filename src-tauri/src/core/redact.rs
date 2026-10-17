use regex::Regex;
use serde::{Deserialize, Serialize};

use super::vault::Vault;

/// 脱敏报告：说明命中了哪些规则、替换了多少处。
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RedactionReport {
    pub pattern: String,
    pub count: usize,
}

pub const MASK: &str = "***REDACTED***";

/// 类型注解形态（SDL / TS / zod 等）：`password: String!`、`token: string`、`secret: string[]`。
/// 这类“值”是类型而不是秘密；脱敏会破坏源码语义（GraphQL SDL 会因此丢字段/丢参数）。
/// 只对**裸值**分支生效——引号包裹的 `"string"` 仍按秘密处理。
fn looks_like_type_annotation(value: &str) -> bool {
    let mut v = value.trim();
    loop {
        let trimmed = v
            .trim_end_matches(['!', '?'])
            .trim_end_matches("[]")
            .trim_end();
        if trimmed == v {
            break;
        }
        v = trimmed;
    }
    matches!(
        v.to_ascii_lowercase().as_str(),
        "string"
            | "number"
            | "boolean"
            | "bigint"
            | "symbol"
            | "unknown"
            | "any"
            | "object"
            | "void"
            | "null"
            | "undefined"
            | "date"
            | "buffer"
            | "int"
            | "float"
            | "id"
            | "bool"
            | "uuid"
            | "bytes"
            | "json"
    )
}

/// 上下文脱敏引擎。
///
/// 所有从 Host 流向 Sidecar（决策层）或 UI 展示的文本都要经过它：
/// 1. 先替换凭证保险库中的真实秘密值（最高优先级）；
/// 2. 再按通用规则匹配常见敏感模式（key=value、Bearer、JWT、常见 Key 前缀等）。
pub struct Redactor {
    rules: Vec<(Regex, &'static str)>,
}

impl Default for Redactor {
    fn default() -> Self {
        Self::new()
    }
}

impl Redactor {
    pub fn new() -> Self {
        let specs: Vec<(&str, &'static str)> = vec![
            (
                // key[:=]value 形式；值可能是 JSON 引号形式或裸值。
                // 键允许 DATABASE_PASSWORD 这类「词_词」复合前缀。
                // 组：1=键名 2=引号包裹的值 3=裸值
                r#"(?i)["']?\b((?:[A-Za-z0-9]+[_-])*(?:api[_-]?key|apikey|secret[_-]?key|client[_-]?secret|access[_-]?key|private[_-]?key|secret|token|password|passwd|pwd|credential))\b["']?\s*[:=]\s*(?:["']([A-Za-z0-9\-_./+@#$%^&*! ]{6,})["']|([A-Za-z0-9\-_./+@#$%^&*!]{6,}))"#,
                "secret_assignment",
            ),
            (
                r#"(?i)\bauthorization\b\s*[:=]\s*(bearer|basic|token)\s+[A-Za-z0-9\-._~+/=]{8,}"#,
                "authorization_header",
            ),
            (
                r#"(?i)\bbearer\s+[A-Za-z0-9\-._~+/=]{16,}"#,
                "bearer_token",
            ),
            (
                r"\beyJ[A-Za-z0-9_\-]{8,}\.[A-Za-z0-9_\-]{8,}\.[A-Za-z0-9_\-]{6,}\b",
                "jwt",
            ),
            (
                r"\b(sk|pk|rk|ghp|gho|glpat|xoxb|xoxp|AKIA)[-_][A-Za-z0-9\-_]{10,}\b",
                "api_key_prefix",
            ),
            (
                r#"(?i)(session[_-]?secret|jwt[_-]?secret|db[_-]?password|database[_-]?url)\s*[:=]\s*["']?[^\s"']{4,}["']?"#,
                "infra_secret",
            ),
        ];
        let rules = specs
            .into_iter()
            .filter_map(|(p, name)| Regex::new(p).ok().map(|r| (r, name)))
            .collect();
        Redactor { rules }
    }

    /// 对文本脱敏，返回 (脱敏后文本, 报告列表)。
    pub fn redact(&self, text: &str, vault: &Vault) -> (String, Vec<RedactionReport>) {
        let mut out = text.to_string();
        let mut reports: Vec<RedactionReport> = Vec::new();

        // 1) 保险库中的真实秘密值：整值替换
        for (name, value) in vault.secret_values() {
            if out.contains(&value) {
                let count = out.matches(&value).count();
                let masked = format!("***vault:{name}***");
                out = out.replace(&value, &masked);
                reports.push(RedactionReport {
                    pattern: format!("vault:{name}"),
                    count,
                });
            }
        }

        // 2) 通用规则
        for (re, name) in &self.rules {
            let mut count = 0usize;
            out = re
                .replace_all(&out, |caps: &regex::Captures| {
                    if *name != "secret_assignment" {
                        count += 1;
                        return MASK.to_string();
                    }
                    // 类型注解不是秘密：保留原文，避免把源码/SDL 改写成语义不符的文本
                    if let Some(bare) = caps.get(3) {
                        if looks_like_type_annotation(bare.as_str()) {
                            return caps
                                .get(0)
                                .map(|m| m.as_str().to_string())
                                .unwrap_or_default();
                        }
                    }
                    count += 1;
                    // 保留「键 → 掩码」结构；JSON 引号形式保持响应体为合法 JSON
                    let whole = caps.get(0).map(|m| m.as_str()).unwrap_or("");
                    let json_like = whole.contains("\":")
                        || whole.contains("':")
                        || whole.starts_with('"')
                        || whole.starts_with('\'');
                    if json_like {
                        format!("\"{}\": \"{}\"", &caps[1], MASK)
                    } else {
                        format!("{}={}", &caps[1], MASK)
                    }
                })
                .to_string();
            if count > 0 {
                reports.push(RedactionReport {
                    pattern: name.to_string(),
                    count,
                });
            }
        }

        (out, reports)
    }

    /// 快捷方法：仅返回脱敏后的文本。
    pub fn redact_text(&self, text: &str, vault: &Vault) -> String {
        self.redact(text, vault).0
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn redacts_env_style_secrets() {
        let r = Redactor::new();
        let v = Vault::default();
        let (out, reports) = r.redact("DATABASE_PASSWORD=supersecret123\nPORT=3000", &v);
        assert!(!out.contains("supersecret123"));
        assert!(out.contains("PORT=3000"));
        assert!(!reports.is_empty());
    }

    #[test]
    fn redacts_bearer_and_jwt() {
        let r = Redactor::new();
        let v = Vault::default();
        let (out, _) = r.redact(
            "Authorization: Bearer abcDEF1234567890xyz\ntoken=eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiIxMjM0NTY3ODkwIn0.abcdef",
            &v,
        );
        assert!(!out.contains("abcDEF1234567890xyz"));
        assert!(!out.contains("eyJhbGciOiJIUzI1NiJ9"));
    }

    #[test]
    fn keeps_json_valid_after_redaction() {
        let r = Redactor::new();
        let v = Vault::default();
        let (out, _) = r.redact(
            r#"{"token":"sess_9f8a7b6c5d4e","user":{"id":"u_1001","name":"alice"}}"#,
            &v,
        );
        let parsed: serde_json::Value =
            serde_json::from_str(&out).expect("脱敏后的 JSON 必须仍然合法");
        assert_eq!(parsed["user"]["id"], "u_1001");
        assert!(parsed["token"].as_str().unwrap().contains("REDACTED"));
    }

    #[test]
    fn keeps_type_annotations_intact() {
        let r = Redactor::new();
        let v = Vault::default();
        // GraphQL SDL：类型声明被改写会让静态分析丢掉 password 参数与 token 字段
        let sdl = "login(email: String!, password: String!): AuthPayload!\ntype AuthPayload { token: String! user: User! }";
        let (out, reports) = r.redact(sdl, &v);
        assert_eq!(out, sdl);
        assert!(reports.is_empty());
        // TS 类型注解同理
        let ts = "password: string;\ntoken?: string;\nsecret: string[];";
        let (out_ts, _) = r.redact(ts, &v);
        assert_eq!(out_ts, ts);
    }

    #[test]
    fn still_redacts_bare_secret_values() {
        let r = Redactor::new();
        let v = Vault::default();
        let (out, reports) = r.redact("password=hunter2secret\ntoken: sess_9f8a7b6c5d", &v);
        assert!(!out.contains("hunter2secret"));
        assert!(!out.contains("sess_9f8a7b6c5d"));
        assert_eq!(reports.iter().map(|x| x.count).sum::<usize>(), 2);
        // 引号包裹的 "string" 仍按秘密处理（只有裸类型注解被豁免）
        let (quoted, _) = r.redact(r#"password: "string""#, &v);
        assert!(quoted.contains(MASK));
    }

    #[test]
    fn redacts_vault_values_anywhere() {
        let r = Redactor::new();
        let mut v = Vault::default();
        v.store("alice", "Authorization", "Bearer sess_alice_9f8a7b6c5d4e", "login");
        let (out, reports) = r.redact(r#"{"msg":"welcome","sess":"Bearer sess_alice_9f8a7b6c5d4e"}"#, &v);
        assert!(!out.contains("sess_alice_9f8a7b6c5d4e"));
        assert!(out.contains("***vault:alice***"));
        assert!(reports.iter().any(|x| x.pattern == "vault:alice"));
    }
}
