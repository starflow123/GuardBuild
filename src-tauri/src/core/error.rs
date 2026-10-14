use serde_json::json;

/// 统一错误类型。每个变体映射到 JSON-RPC 错误码。
#[derive(Debug, Clone, thiserror::Error)]
pub enum HostError {
    #[error("请求参数无效: {0}")]
    InvalidParams(String),
    #[error("未知方法: {0}")]
    MethodNotFound(String),
    #[error("令牌无效或已过期")]
    TokenInvalid,
    #[error("作用域不足: {0}")]
    ScopeDenied(String),
    #[error("路径超出授权范围: {0}")]
    PathOutOfScope(String),
    #[error("用户拒绝了授权请求")]
    ConsentDenied,
    #[error("目标不存在: {0}")]
    NotFound(String),
    #[error("状态冲突: {0}")]
    Conflict(String),
    #[error("Git 操作失败: {0}")]
    Git(String),
    #[error("进程操作失败: {0}")]
    Proc(String),
    #[error("网络请求失败: {0}")]
    Network(String),
    #[error("IO 错误: {0}")]
    Io(String),
    #[error("内部错误: {0}")]
    Internal(String),
    #[error("协议错误: {0}")]
    Protocol(String),
}

impl HostError {
    pub fn code(&self) -> i32 {
        match self {
            HostError::InvalidParams(_) => -32602,
            HostError::MethodNotFound(_) => -32601,
            HostError::TokenInvalid => 1001,
            HostError::ScopeDenied(_) => 1002,
            HostError::PathOutOfScope(_) => 1003,
            HostError::ConsentDenied => 1004,
            HostError::NotFound(_) => 1005,
            HostError::Conflict(_) => 1007,
            HostError::Git(_) => 1008,
            HostError::Proc(_) => 1009,
            HostError::Network(_) => 1010,
            HostError::Io(_) => 1011,
            HostError::Internal(_) => 1012,
            HostError::Protocol(_) => 1013,
        }
    }

    pub fn data(&self) -> serde_json::Value {
        json!({ "code_name": self.name() })
    }

    pub fn name(&self) -> &'static str {
        match self {
            HostError::InvalidParams(_) => "invalid_params",
            HostError::MethodNotFound(_) => "method_not_found",
            HostError::TokenInvalid => "token_invalid",
            HostError::ScopeDenied(_) => "scope_denied",
            HostError::PathOutOfScope(_) => "path_out_of_scope",
            HostError::ConsentDenied => "consent_denied",
            HostError::NotFound(_) => "not_found",
            HostError::Conflict(_) => "conflict",
            HostError::Git(_) => "git_error",
            HostError::Proc(_) => "proc_error",
            HostError::Network(_) => "network_error",
            HostError::Io(_) => "io_error",
            HostError::Internal(_) => "internal",
            HostError::Protocol(_) => "protocol",
        }
    }
}

impl From<std::io::Error> for HostError {
    fn from(e: std::io::Error) -> Self {
        HostError::Io(e.to_string())
    }
}

impl From<serde_json::Error> for HostError {
    fn from(e: serde_json::Error) -> Self {
        HostError::InvalidParams(format!("JSON 解析失败: {e}"))
    }
}

pub type HostResult<T> = Result<T, HostError>;
