use std::collections::HashMap;
use std::io::{BufRead, BufReader, Write};
use std::process::{ChildStdin, ChildStdout};
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::sync::mpsc::{self, Sender};
use std::sync::{Arc, Mutex};
use std::thread;
use std::time::Duration;

use serde_json::{json, Value};

use super::error::{HostError, HostResult};

pub const HOST_REQUEST_ID_BASE: u64 = 10_000_000;

#[derive(Debug, Clone)]
pub struct RpcError {
    pub code: i32,
    pub message: String,
    pub data: Option<Value>,
}

impl RpcError {
    pub fn from_host_error(e: &HostError) -> Self {
        RpcError {
            code: e.code(),
            message: e.to_string(),
            data: Some(e.data()),
        }
    }
}

impl From<HostError> for RpcError {
    fn from(e: HostError) -> Self {
        RpcError::from_host_error(&e)
    }
}

pub type RpcResult = Result<Value, RpcError>;
type RequestHandler = Arc<dyn Fn(Value) -> RpcResult + Send + Sync>;
type NotifyHandler = Arc<dyn Fn(Value) + Send + Sync>;

/// 与 Sidecar 子进程的 JSON-RPC 2.0 双向连接（按行分隔 NDJSON）。
///
/// - Sidecar → Host：能力调用（Host 注册 request handlers）
/// - Host → Sidecar：编排指令（Host 通过 send_request 发起）
pub struct RpcConnection {
    writer: Mutex<ChildStdin>,
    next_id: AtomicU64,
    pending: Mutex<HashMap<u64, Sender<Result<Value, RpcError>>>>,
    request_handlers: Mutex<HashMap<String, RequestHandler>>,
    notify_handlers: Mutex<HashMap<String, NotifyHandler>>,
    closed: AtomicBool,
}

impl RpcConnection {
    pub fn new(stdin: ChildStdin, stdout: ChildStdout) -> Arc<Self> {
        let conn = Arc::new(RpcConnection {
            writer: Mutex::new(stdin),
            next_id: AtomicU64::new(HOST_REQUEST_ID_BASE),
            pending: Mutex::new(HashMap::new()),
            request_handlers: Mutex::new(HashMap::new()),
            notify_handlers: Mutex::new(HashMap::new()),
            closed: AtomicBool::new(false),
        });
        Self::start_reader(conn.clone(), stdout);
        conn
    }

    pub fn is_closed(&self) -> bool {
        self.closed.load(Ordering::SeqCst)
    }

    pub fn on_request<F>(&self, method: &str, f: F)
    where
        F: Fn(Value) -> RpcResult + Send + Sync + 'static,
    {
        self.request_handlers
            .lock()
            .unwrap()
            .insert(method.to_string(), Arc::new(f));
    }

    pub fn on_notification<F>(&self, method: &str, f: F)
    where
        F: Fn(Value) + Send + Sync + 'static,
    {
        self.notify_handlers
            .lock()
            .unwrap()
            .insert(method.to_string(), Arc::new(f));
    }

    fn start_reader(conn: Arc<RpcConnection>, stdout: ChildStdout) {
        thread::spawn(move || {
            let reader = BufReader::new(stdout);
            for line in reader.lines() {
                let line = match line {
                    Ok(l) => l,
                    Err(_) => break,
                };
                if line.trim().is_empty() {
                    continue;
                }
                let value: Value = match serde_json::from_str(&line) {
                    Ok(v) => v,
                    Err(e) => {
                        eprintln!("[rpc] 非法 JSON 行: {e}");
                        continue;
                    }
                };
                Self::handle_message(conn.clone(), value);
            }
            conn.closed.store(true, Ordering::SeqCst);
            // 连接关闭：唤醒所有等待者
            let mut pending = conn.pending.lock().unwrap();
            for (_, tx) in pending.drain() {
                let _ = tx.send(Err(RpcError {
                    code: 1014,
                    message: "sidecar 连接已关闭".into(),
                    data: None,
                }));
            }
            eprintln!("[rpc] sidecar 连接关闭");
        });
    }

    fn handle_message(conn: Arc<RpcConnection>, msg: Value) {
        let obj = match msg.as_object() {
            Some(o) => o,
            None => return,
        };
        let id = obj.get("id").cloned();
        let method = obj.get("method").and_then(|m| m.as_str()).map(|s| s.to_string());

        match (method, id) {
            // 响应（Host 发起请求的返回）
            (None, Some(id_value)) => {
                let id_num = id_value.as_u64();
                let pending_tx = id_num.and_then(|n| conn.pending.lock().unwrap().remove(&n));
                if let Some(tx) = pending_tx {
                    if let Some(err) = obj.get("error") {
                        let e = RpcError {
                            code: err.get("code").and_then(|c| c.as_i64()).unwrap_or(-32000) as i32,
                            message: err
                                .get("message")
                                .and_then(|m| m.as_str())
                                .unwrap_or("unknown")
                                .to_string(),
                            data: err.get("data").cloned(),
                        };
                        let _ = tx.send(Err(e));
                    } else {
                        let _ = tx.send(Ok(obj.get("result").cloned().unwrap_or(Value::Null)));
                    }
                }
            }
            // 请求（需要响应）
            (Some(method), Some(id_value)) => {
                let params = obj.get("params").cloned().unwrap_or(json!({}));
                let handler = conn.request_handlers.lock().unwrap().get(&method).cloned();
                let conn2 = conn.clone();
                thread::spawn(move || {
                    let result: RpcResult = match handler {
                        Some(h) => h(params),
                        None => Err(RpcError::from_host_error(&HostError::MethodNotFound(method.clone()))),
                    };
                    let response = match result {
                        Ok(v) => json!({ "jsonrpc": "2.0", "id": id_value, "result": v }),
                        Err(e) => json!({
                            "jsonrpc": "2.0",
                            "id": id_value,
                            "error": { "code": e.code, "message": e.message, "data": e.data }
                        }),
                    };
                    let _ = conn2.write_line(&response);
                });
            }
            // 通知（无需响应）
            (Some(method), None) => {
                let params = obj.get("params").cloned().unwrap_or(json!({}));
                let handler = conn.notify_handlers.lock().unwrap().get(&method).cloned();
                if let Some(h) = handler {
                    thread::spawn(move || h(params));
                }
            }
            (None, None) => {}
        }
    }

    fn write_line(&self, v: &Value) -> HostResult<()> {
        let mut line = serde_json::to_string(v).map_err(HostError::from)?;
        line.push('\n');
        let mut w = self.writer.lock().unwrap();
        w.write_all(line.as_bytes()).map_err(HostError::from)?;
        w.flush().map_err(HostError::from)?;
        Ok(())
    }

    /// 向 Sidecar 发起请求并等待响应。
    pub fn call(&self, method: &str, params: Value, timeout: Duration) -> HostResult<Value> {
        if self.is_closed() {
            return Err(HostError::Protocol("sidecar 未连接".into()));
        }
        let id = self.next_id.fetch_add(1, Ordering::SeqCst);
        let (tx, rx) = mpsc::channel::<Result<Value, RpcError>>();
        self.pending.lock().unwrap().insert(id, tx);
        let msg = json!({ "jsonrpc": "2.0", "id": id, "method": method, "params": params });
        self.write_line(&msg)?;
        match rx.recv_timeout(timeout) {
            Ok(Ok(v)) => Ok(v),
            Ok(Err(e)) => Err(HostError::Internal(format!("[{}] {}", e.code, e.message))),
            Err(_) => {
                self.pending.lock().unwrap().remove(&id);
                Err(HostError::Protocol(format!("调用 {method} 超时")))
            }
        }
    }

    pub fn notify(&self, method: &str, params: Value) -> HostResult<()> {
        if self.is_closed() {
            return Err(HostError::Protocol("sidecar 未连接".into()));
        }
        let msg = json!({ "jsonrpc": "2.0", "method": method, "params": params });
        self.write_line(&msg)
    }
}
