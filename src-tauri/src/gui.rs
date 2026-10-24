use std::path::PathBuf;
use std::sync::Arc;

use serde_json::{json, Value};
use tauri::{AppHandle, Emitter, Manager};

use crate::core::host::{Host, HostConfig, UiSink, PROTOCOL_VERSION};

pub struct GuiSink {
    app: AppHandle,
}

impl UiSink for GuiSink {
    fn emit_state(&self, v: &Value) {
        let _ = self.app.emit("guard://state", v);
    }
    fn emit_event(&self, v: &Value) {
        let _ = self.app.emit("guard://event", v);
    }
    fn emit_consent(&self, v: &Value) {
        let _ = self.app.emit("guard://consent", v);
    }
    fn emit_log(&self, v: &Value) {
        let _ = self.app.emit("guard://log", v);
    }
}

pub struct AppState {
    pub host: Arc<Host>,
}

fn resolve_sidecar_path() -> PathBuf {
    let cwd = std::env::current_dir().unwrap_or_else(|_| PathBuf::from("."));
    crate::core::runtime::resolve_sidecar_path(
        std::env::var("GUARDBUILD_SIDECAR").ok().map(PathBuf::from),
        crate::core::runtime::current_exe_dir().as_deref(),
        &cwd,
    )
}

pub fn resolve_data_dir() -> PathBuf {
    if let Ok(p) = std::env::var("GUARDBUILD_DATA_DIR") {
        return PathBuf::from(p);
    }
    let exe_dir = std::env::current_exe()
        .ok()
        .and_then(|p| p.parent().map(|d| d.to_path_buf()))
        .unwrap_or_else(|| PathBuf::from("."));
    exe_dir.join("guardbuild-data")
}

pub fn build_host() -> Arc<Host> {
    let cfg = HostConfig {
        data_dir: resolve_data_dir(),
        sidecar_path: resolve_sidecar_path(),
        node_bin: crate::core::runtime::resolve_node_bin(
            std::env::var("GUARDBUILD_NODE").ok(),
            crate::core::runtime::current_exe_dir().as_deref(),
        ),
        auto_consent: std::env::var("GUARDBUILD_AUTO_CONSENT").map(|v| v == "1").unwrap_or(false),
        headless: false,
        app_version: env!("CARGO_PKG_VERSION").to_string(),
        gate: false,
        granted_scopes: Vec::new(),
        report_dir: None,
    };
    Host::new(cfg)
}

#[tauri::command]
pub fn get_state(state: tauri::State<'_, AppState>) -> Value {
    state.host.merged_view()
}

#[tauri::command]
pub fn get_events(limit: Option<usize>, state: tauri::State<'_, AppState>) -> Value {
    state.host.get_events(limit.unwrap_or(300))
}

#[tauri::command]
pub fn get_host_info(state: tauri::State<'_, AppState>) -> Value {
    json!({
        "protocolVersion": PROTOCOL_VERSION,
        "appVersion": env!("CARGO_PKG_VERSION"),
        "dataDir": state.host.data_dir().to_string_lossy(),
        "sidecarReady": state.host.sidecar_ready(),
        "node": "node",
    })
}

#[tauri::command]
pub async fn pick_project_dir() -> Option<String> {
    tauri::async_runtime::spawn_blocking(|| {
        rfd::FileDialog::new()
            .set_title("选择要诊断的目标项目目录")
            .pick_folder()
            .map(|p| p.to_string_lossy().to_string())
    })
    .await
    .ok()
    .flatten()
}

#[tauri::command]
pub async fn start_session(
    project_root: String,
    target_url: Option<String>,
    state: tauri::State<'_, AppState>,
) -> Result<Value, String> {
    let host = state.host.clone();
    tauri::async_runtime::spawn_blocking(move || {
        host.start_session(&project_root, target_url.as_deref())
    })
    .await
    .map_err(|e| e.to_string())?
    .map_err(|e| e.to_string())
}

#[tauri::command]
pub async fn resolve_consent(
    consent_id: String,
    approved: bool,
    state: tauri::State<'_, AppState>,
) -> Result<Value, String> {
    state
        .host
        .resolve_consent(&consent_id, approved)
        .map_err(|e| e.to_string())
}

#[tauri::command]
pub async fn approve_patch(
    patch_hash: Option<String>,
    state: tauri::State<'_, AppState>,
) -> Result<Value, String> {
    let host = state.host.clone();
    let hash = patch_hash.unwrap_or_default();
    tauri::async_runtime::spawn_blocking(move || host.approve_patch(&hash))
        .await
        .map_err(|e| e.to_string())?
        .map_err(|e| e.to_string())
}

#[tauri::command]
pub async fn approve_writeback(
    patch_hash: String,
    state: tauri::State<'_, AppState>,
) -> Result<Value, String> {
    let host = state.host.clone();
    tauri::async_runtime::spawn_blocking(move || host.approve_writeback(&patch_hash))
        .await
        .map_err(|e| e.to_string())?
        .map_err(|e| e.to_string())
}

#[tauri::command]
pub async fn request_rollback(state: tauri::State<'_, AppState>) -> Result<Value, String> {
    let host = state.host.clone();
    tauri::async_runtime::spawn_blocking(move || host.request_rollback())
        .await
        .map_err(|e| e.to_string())?
        .map_err(|e| e.to_string())
}

#[tauri::command]
pub async fn cancel_session(state: tauri::State<'_, AppState>) -> Result<Value, String> {
    state.host.cancel_session().map_err(|e| e.to_string())
}

pub fn run() {
    let host = build_host();
    let host_for_setup = host.clone();
    if let Err(e) = host.start() {
        host.log("error", &format!("Sidecar 启动失败: {e}"));
    }

    let app = tauri::Builder::default()
        .manage(AppState { host: host.clone() })
        .invoke_handler(tauri::generate_handler![
            get_state,
            get_events,
            get_host_info,
            pick_project_dir,
            start_session,
            resolve_consent,
            approve_patch,
            approve_writeback,
            request_rollback,
            cancel_session,
        ])
        .setup(move |app| {
            let sink = Arc::new(GuiSink {
                app: app.handle().clone(),
            });
            host_for_setup.set_ui_sink(sink);
            // 推送一次初始状态
            let state = app.state::<AppState>();
            let _ = app.emit("guard://state", state.host.merged_view());
            Ok(())
        })
        .build(tauri::generate_context!())
        .expect("Tauri 初始化失败");

    app.run(move |_app_handle, event| {
        if let tauri::RunEvent::Exit = event {
            host.shutdown();
        }
    });
}
