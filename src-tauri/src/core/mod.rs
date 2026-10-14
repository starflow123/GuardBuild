//! GuardBuild Host 核心：与 UI 框架无关的能力宿主。
//!
//! 职责划分：
//! - Host（Rust）：托管文件、进程、网络、Git 等系统能力；签发作用域令牌；脱敏上下文；持有凭证保险库。
//! - Sidecar（Node.js）：任务编排与决策（本项目中为规则规划器，可替换为模型）。
//! - 二者通过按行分隔的 JSON-RPC 2.0 通信（stdin/stdout），Host 是权限的唯一执行点。

pub mod error;
pub mod fsops;
pub mod gitops;
pub mod host;
pub mod httpclient;
pub mod procops;
pub mod redact;
pub mod rpc;
pub mod token;
pub mod vault;

pub use error::HostError;
pub use host::{Host, HostConfig, UiSink};
