//! GuardBuild 无头宿主：端到端自动化验收 + CI gate（无 GUI）。
//!
//! 命令行参数：
//!   --project <dir>   以该目录为目标自动启动会话（等价 GUARDBUILD_E2E_PROJECT）
//!   --gate            CI gate 模式：按 guardbuild.json.scopes 预声明授权（via=policy）、
//!                     自动批准补丁、结构性禁止写回；到终态输出 GB_GATE 并按约定退出码结束：
//!                       0 = 未发现可利用漏洞（no_candidates / attack_not_reproducible）
//!                       1 = 漏洞证据成立（writeback_pending 附已验证补丁；verify_failed 附证据；
//!                           vulnerable_unfixed 表示攻击已复现但无可自动修复候选）
//!                       2 = 执行失败（环境/契约/内部错误/超时）
//!   --report <dir>    报告输出目录（report.emit 的落盘位置）
//!
//! 环境变量（自动化兼容）：GUARDBUILD_DATA_DIR / GUARDBUILD_SIDECAR / GUARDBUILD_NODE /
//!   GUARDBUILD_AUTO_CONSENT / GUARDBUILD_E2E_PROJECT / GUARDBUILD_GATE_TIMEOUT_MS
//!
//! stdin 命令：start / patch_approve / writeback_approve / rollback / cancel / consent / quit
//! stdout 输出：GB_STATE / GB_EVENT / GB_LOG / GB_CONSENT / GB_RESULT / GB_GATE 前缀的 NDJSON。

use std::io::BufRead;
use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::time::{Duration, Instant};

use serde_json::{json, Value};

use guardbuild_lib::core::host::{Host, HostConfig, GATE_DEFAULT_SCOPES};

struct Args {
    project: Option<String>,
    url: Option<String>,
    gate: bool,
    report_dir: Option<PathBuf>,
}

fn parse_args() -> Args {
    let mut args = Args { project: None, url: None, gate: false, report_dir: None };
    let mut it = std::env::args().skip(1);
    while let Some(a) = it.next() {
        match a.as_str() {
            "--gate" => args.gate = true,
            "--project" => args.project = it.next(),
            "--url" => args.url = it.next(),
            "--report" => args.report_dir = it.next().map(PathBuf::from),
            other => eprintln!("[gate] 忽略未知参数: {other}"),
        }
    }
    if args.project.is_none() {
        args.project = std::env::var("GUARDBUILD_E2E_PROJECT").ok();
    }
    args
}

/// 读取 `<project>/guardbuild.json` 的 scopes 作为 gate 预声明授权；缺失/非法回落缺省四作用域。
fn read_gate_scopes(project: &str) -> Vec<String> {
    let defaults = || GATE_DEFAULT_SCOPES.iter().map(|s| s.to_string()).collect::<Vec<_>>();
    let raw = match std::fs::read_to_string(Path::new(project).join("guardbuild.json")) {
        Ok(s) => s,
        Err(_) => return defaults(),
    };
    let parsed: Value = match serde_json::from_str(&raw) {
        Ok(v) => v,
        Err(e) => {
            eprintln!("[gate] guardbuild.json 解析失败（{e}），使用缺省作用域");
            return defaults();
        }
    };
    match parsed.get("scopes").and_then(|s| s.as_array()) {
        Some(arr) => {
            let scopes: Vec<String> = arr
                .iter()
                .filter_map(|v| v.as_str())
                .map(|s| s.to_string())
                .collect();
            if scopes.is_empty() {
                defaults()
            } else {
                scopes
            }
        }
        None => defaults(),
    }
}

fn gate_timeout_ms() -> u64 {
    std::env::var("GUARDBUILD_GATE_TIMEOUT_MS")
        .ok()
        .and_then(|v| v.parse().ok())
        .unwrap_or(15 * 60 * 1000)
}

/// gate 终态观察器：轮询合并视图，到达可裁决状态后输出 GB_GATE 并以约定退出码结束进程。
fn spawn_gate_watcher(host: Arc<Host>) {
    std::thread::spawn(move || {
        let started = Instant::now();
        let timeout = Duration::from_millis(gate_timeout_ms());
        let mut patch_approved = false;
        loop {
            std::thread::sleep(Duration::from_millis(300));
            if started.elapsed() > timeout {
                finish_gate(&host, 2, json!({ "verdict": "timeout", "state": "running" }));
            }
            let view = host.merged_view();
            let state = view.get("state").and_then(|s| s.as_str()).unwrap_or("");
            let session_id = view
                .get("sessionId")
                .and_then(|s| s.as_str())
                .unwrap_or("")
                .to_string();
            let patch_hash = view
                .get("patch")
                .and_then(|p| p.get("hash"))
                .and_then(|h| h.as_str())
                .map(|s| s.to_string());
            let acceptance = view.get("acceptance").cloned().filter(|v| !v.is_null());
            let findings = view
                .get("findings")
                .and_then(|f| f.as_array())
                .map(|a| a.len())
                .unwrap_or(0);
            let base = |verdict: &str| {
                json!({
                    "verdict": verdict,
                    "state": state,
                    "sessionId": session_id,
                    "patchHash": patch_hash,
                    "findings": findings,
                    "acceptance": acceptance,
                })
            };

            match state {
                "patch_review" => {
                    if !patch_approved {
                        patch_approved = true;
                        if let Err(e) = host.approve_patch("") {
                            eprintln!("[gate] 自动批准补丁未生效（状态可能已前进）: {e}");
                        }
                    }
                }
                "writeback_pending" => {
                    let mut p = base("vulnerable");
                    p["patchStatus"] = json!("verified");
                    finish_gate(&host, 1, p);
                }
                "verify_failed" => {
                    let mut p = base("vulnerable");
                    p["patchStatus"] = json!("verify_failed");
                    finish_gate(&host, 1, p);
                }
                "error" => {
                    let code = view
                        .get("error")
                        .and_then(|e| e.get("code"))
                        .and_then(|c| c.as_str())
                        .unwrap_or("internal");
                    let (exit_code, verdict) = match code {
                        "no_candidates" => (0, "no_candidates"),
                        "attack_not_reproducible" => (0, "not_reproducible"),
                        "no_patchable_candidates" => (1, "vulnerable_unfixed"),
                        _ => (2, "failed"),
                    };
                    let mut p = base(verdict);
                    p["error"] = view.get("error").cloned().unwrap_or(Value::Null);
                    finish_gate(&host, exit_code, p);
                }
                "completed" => {
                    // 纯黑盒终态：结果在 view.blackbox 中（不生成补丁）
                    let bb = view.get("blackbox");
                    let outcome = bb
                        .and_then(|b| b.get("outcome"))
                        .and_then(|o| o.as_str())
                        .unwrap_or("no_findings");
                    let exit_code = bb
                        .and_then(|b| b.get("exitCode"))
                        .and_then(|e| e.as_i64())
                        .unwrap_or(0) as i32;
                    let verdict = match outcome {
                        "vulnerable_unfixed" => "vulnerable_unfixed",
                        _ => "no_findings",
                    };
                    let mut p = base(verdict);
                    if let Some(b) = bb {
                        p["blackbox"] = json!({
                            "url": b.get("url").cloned().unwrap_or(Value::Null),
                            "routeCount": b.get("routeCount").cloned().unwrap_or(Value::Null),
                            "findingCount": b.get("findings").and_then(|f| f.as_array()).map(|a| a.len()).unwrap_or(0),
                            "openapiFound": b.get("openapiFound").cloned().unwrap_or(Value::Null),
                            "login": b.get("login").cloned().unwrap_or(Value::Null),
                        });
                    }
                    finish_gate(&host, exit_code, p);
                }
                "aborted" => finish_gate(&host, 2, base("aborted")),
                "applied" => {
                    let mut p = base("vulnerable");
                    p["patchStatus"] = json!("applied");
                    finish_gate(&host, 1, p);
                }
                _ => {}
            }
        }
    });
}

fn finish_gate(host: &Arc<Host>, exit_code: i32, mut payload: Value) -> ! {
    host.shutdown();
    if let Some(obj) = payload.as_object_mut() {
        obj.insert("exitCode".into(), json!(exit_code));
    }
    println!("GB_GATE {}", serde_json::to_string(&payload).unwrap_or_default());
    use std::io::Write;
    let _ = std::io::stdout().flush();
    std::process::exit(exit_code);
}

fn main() {
    let mut args = parse_args();

    let data_dir = std::env::var("GUARDBUILD_DATA_DIR")
        .map(PathBuf::from)
        .unwrap_or_else(|_| std::env::temp_dir().join("guardbuild-headless-data"));
    let sidecar_path = std::env::var("GUARDBUILD_SIDECAR")
        .map(PathBuf::from)
        .unwrap_or_else(|_| PathBuf::from("sidecar/main.mjs"));
    // host 以 sidecar 所在目录作为子进程 cwd，相对路径会在此基础上被二次拼接
    let sidecar_path = if sidecar_path.is_relative() {
        std::env::current_dir()
            .map(|d| d.join(&sidecar_path))
            .unwrap_or(sidecar_path)
    } else {
        sidecar_path
    };
    let node_bin = std::env::var("GUARDBUILD_NODE").unwrap_or_else(|_| "node".to_string());
    let auto_consent = !args.gate
        && std::env::var("GUARDBUILD_AUTO_CONSENT")
            .map(|v| v != "0")
            .unwrap_or(true);

    // 纯黑盒 --url 模式不需要本地项目：缺省以当前目录作为会话根（仅用于 report/作用域，不做源码分析）
    if args.url.is_some() && args.project.is_none() {
        args.project = std::env::current_dir().ok().map(|p| p.to_string_lossy().to_string());
    }

    if args.gate && args.project.is_none() {
        println!("GB_ERROR {}", json!({ "stage": "gate", "error": "--gate 需要 --project <dir>（或 GUARDBUILD_E2E_PROJECT/--url）" }));
        std::process::exit(2);
    }

    let granted_scopes = if args.gate {
        let scopes = read_gate_scopes(args.project.as_deref().unwrap_or(""));
        eprintln!("[gate] 预声明作用域: {}", scopes.join(", "));
        if let Some(r) = &args.report_dir {
            eprintln!("[gate] 报告目录: {}", r.display());
        }
        scopes
    } else {
        Vec::new()
    };

    let cfg = HostConfig {
        data_dir,
        sidecar_path,
        node_bin,
        auto_consent,
        headless: true,
        app_version: env!("CARGO_PKG_VERSION").to_string(),
        gate: args.gate,
        granted_scopes,
        report_dir: args.report_dir.clone(),
    };
    let host: Arc<Host> = Host::new(cfg);

    if let Err(e) = host.start() {
        println!("GB_ERROR {}", json!({ "stage": "start", "error": e.to_string() }));
        std::process::exit(2);
    }
    println!("GB_READY {}", json!({ "protocolVersion": "guardbuild.rpc/1", "gate": args.gate }));

    if args.gate {
        spawn_gate_watcher(host.clone());
    }

    if let Some(p) = args.project.clone() {
        let h = host.clone();
        let blackbox = args.url.clone();
        std::thread::spawn(move || {
            for _ in 0..300 {
                if h.sidecar_ready() {
                    break;
                }
                std::thread::sleep(Duration::from_millis(100));
            }
            match h.start_session(&p, blackbox.as_deref()) {
                Ok(v) => println!("GB_RESULT {}", json!({ "cmd": "autostart", "ok": true, "data": v })),
                Err(e) => println!("GB_RESULT {}", json!({ "cmd": "autostart", "ok": false, "error": e.to_string() })),
            }
        });
    }

    let stdin = std::io::stdin();
    for line in stdin.lock().lines() {
        let line = match line {
            Ok(l) => l,
            Err(_) => break,
        };
        let trimmed = line.trim();
        if trimmed.is_empty() {
            continue;
        }
        let msg: Value = match serde_json::from_str(trimmed) {
            Ok(v) => v,
            Err(e) => {
                println!("GB_RESULT {}", json!({ "cmd": "?", "ok": false, "error": format!("非法 JSON: {e}") }));
                continue;
            }
        };
        let cmd = msg.get("cmd").and_then(|c| c.as_str()).unwrap_or("").to_string();
        let result: Result<Value, String> = match cmd.as_str() {
            "start" => {
                let project = msg.get("project").and_then(|p| p.as_str()).unwrap_or("").to_string();
                let target = msg
                    .get("targetUrl")
                    .or_else(|| msg.get("blackboxUrl"))
                    .and_then(|u| u.as_str())
                    .map(|s| s.to_string());
                host.start_session(&project, target.as_deref()).map_err(|e| e.to_string())
            }
            "patch_approve" => {
                let hash = msg.get("patchHash").and_then(|h| h.as_str()).unwrap_or("").to_string();
                host.approve_patch(&hash).map_err(|e| e.to_string())
            }
            "writeback_approve" => {
                let hash = msg
                    .get("patchHash")
                    .and_then(|h| h.as_str())
                    .map(|s| s.to_string())
                    .unwrap_or_else(|| {
                        host.merged_view()
                            .get("patch")
                            .and_then(|p| p.get("hash"))
                            .and_then(|h| h.as_str())
                            .unwrap_or("")
                            .to_string()
                    });
                host.approve_writeback(&hash).map_err(|e| e.to_string())
            }
            "rollback" => host.request_rollback().map_err(|e| e.to_string()),
            "cancel" => host.cancel_session().map_err(|e| e.to_string()),
            "consent" => {
                let id = msg.get("id").and_then(|i| i.as_str()).unwrap_or("").to_string();
                let approve = msg.get("approve").and_then(|a| a.as_bool()).unwrap_or(false);
                host.resolve_consent(&id, approve).map_err(|e| e.to_string())
            }
            "quit" => {
                host.shutdown();
                println!("GB_RESULT {}", json!({ "cmd": "quit", "ok": true }));
                std::process::exit(0);
            }
            other => Err(format!("未知命令: {other}")),
        };
        match result {
            Ok(v) => println!("GB_RESULT {}", json!({ "cmd": cmd, "ok": true, "data": v })),
            Err(e) => println!("GB_RESULT {}", json!({ "cmd": cmd, "ok": false, "error": e })),
        }
    }

    if args.gate {
        // gate 模式：stdin 不可用（CI 常态）时不退出，等待 watcher 裁决
        loop {
            std::thread::sleep(Duration::from_secs(3600));
        }
    }
    host.shutdown();
}
