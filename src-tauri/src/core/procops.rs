use std::collections::{HashMap, VecDeque};
use std::io::{BufRead, BufReader};
use std::path::{Path, PathBuf};
use std::process::{Child, Command, Stdio};
use std::sync::atomic::{AtomicBool, AtomicI64, Ordering};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use serde::{Deserialize, Serialize};

use super::error::{HostError, HostResult};

pub const MAX_RING_LINES: usize = 1000;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ProcLogLine {
    pub stream: String, // stdout | stderr
    pub line: String,
    pub ts: i64,
    /// 该行是否有内容被脱敏
    pub redacted: bool,
}

#[derive(Default)]
pub struct RingBuffer {
    pub lines: VecDeque<ProcLogLine>,
}

impl RingBuffer {
    pub fn push(&mut self, line: ProcLogLine) {
        if self.lines.len() >= MAX_RING_LINES {
            self.lines.pop_front();
        }
        self.lines.push_back(line);
    }
    pub fn tail(&self, n: usize) -> Vec<ProcLogLine> {
        let skip = self.lines.len().saturating_sub(n);
        self.lines.iter().skip(skip).cloned().collect()
    }
}

pub struct ProcRecord {
    pub pid: u32,
    pub session_id: String,
    pub role: String,
    pub cmd: String,
    pub args: Vec<String>,
    pub cwd: PathBuf,
    pub started_at: i64,
    pub exited: AtomicBool,
    pub exit_code: AtomicI64,
    pub out: Arc<Mutex<RingBuffer>>,
    child: Arc<Mutex<Child>>,
}

impl ProcRecord {
    pub fn is_exited(&self) -> bool {
        self.exited.load(Ordering::SeqCst)
    }

    pub fn logs_tail(&self, n: usize) -> Vec<ProcLogLine> {
        self.out.lock().unwrap().tail(n)
    }

    pub fn kill(&self) {
        let mut child = self.child.lock().unwrap();
        let _ = child.kill();
        let _ = child.wait();
    }
}

/// 进程表：托管所有由 Host 启动的子进程。
#[derive(Default)]
pub struct ProcTable {
    procs: HashMap<u32, Arc<ProcRecord>>,
}

impl ProcTable {
    pub fn get(&self, pid: u32) -> Option<Arc<ProcRecord>> {
        self.procs.get(&pid).cloned()
    }

    pub fn list(&self, session_id: Option<&str>) -> Vec<Arc<ProcRecord>> {
        let mut v: Vec<Arc<ProcRecord>> = self
            .procs
            .values()
            .filter(|p| session_id.map(|s| p.session_id == s).unwrap_or(true))
            .cloned()
            .collect();
        v.sort_by_key(|p| p.started_at);
        v
    }

    pub fn remove(&mut self, pid: u32) {
        self.procs.remove(&pid);
    }

    pub fn kill_session(&mut self, session_id: &str) -> usize {
        let mut n = 0;
        for p in self.procs.values() {
            if p.session_id == session_id {
                p.kill();
                n += 1;
            }
        }
        self.procs.retain(|_, p| p.session_id != session_id);
        n
    }

    pub fn kill_all(&mut self) {
        for p in self.procs.values() {
            p.kill();
        }
        self.procs.clear();
    }
}

/// 构造子进程环境：白名单制。默认**不继承**父进程环境，
/// 避免把开发机上的 API Key / 密钥无意中暴露给被测进程。
pub fn sanitized_env(extra: &[(String, String)]) -> Vec<(String, String)> {
    let keep = [
        "PATH",
        "PATHEXT",
        "SystemRoot",
        "windir",
        "SystemDrive",
        "ComSpec",
        "TEMP",
        "TMP",
        "USERPROFILE",
        "HOME",
        "APPDATA",
        "LOCALAPPDATA",
        "NUMBER_OF_PROCESSORS",
        "OS",
        "LANG",
        "LC_ALL",
        "TZ",
    ];
    let mut env: Vec<(String, String)> = Vec::new();
    for k in keep {
        if let Ok(v) = std::env::var(k) {
            env.push((k.to_string(), v));
        }
    }
    for (k, v) in extra {
        env.retain(|(ek, _)| !ek.eq_ignore_ascii_case(k));
        env.push((k.clone(), v.clone()));
    }
    env
}

#[cfg(windows)]
fn apply_no_window(cmd: &mut Command) {
    use std::os::windows::process::CommandExt;
    const CREATE_NO_WINDOW: u32 = 0x0800_0000;
    cmd.creation_flags(CREATE_NO_WINDOW);
}

#[cfg(not(windows))]
fn apply_no_window(_cmd: &mut Command) {}

/// 启动进程并挂接日志泵。返回进程记录。
pub fn spawn(
    table: &mut ProcTable,
    session_id: &str,
    role: &str,
    program: &str,
    args: &[String],
    cwd: &Path,
    env: &[(String, String)],
    resolve_log: Arc<dyn Fn(&str) -> Option<ProcLogLine> + Send + Sync>,
) -> HostResult<Arc<ProcRecord>> {
    let mut cmd = Command::new(program);
    cmd.args(args)
        .current_dir(cwd)
        .stdin(Stdio::null())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .env_clear();
    for (k, v) in sanitized_env(env) {
        cmd.env(k, v);
    }
    apply_no_window(&mut cmd);

    let mut child = cmd
        .spawn()
        .map_err(|e| HostError::Proc(format!("启动 `{program}` 失败: {e}")))?;
    let pid = child.id() as u32;

    let out = Arc::new(Mutex::new(RingBuffer::default()));
    let stdout = child.stdout.take();
    let stderr = child.stderr.take();

    let pump = |stream: &'static str,
                reader: Option<Box<dyn std::io::Read + Send>>,
                out: Arc<Mutex<RingBuffer>>,
                resolve_log: Arc<dyn Fn(&str) -> Option<ProcLogLine> + Send + Sync>| {
        if let Some(r) = reader {
            std::thread::spawn(move || {
                let br = BufReader::new(r);
                for line in br.lines() {
                    match line {
                        Ok(l) => {
                            let entry = resolve_log(&l).unwrap_or(ProcLogLine {
                                stream: stream.to_string(),
                                line: l,
                                ts: crate::core::token::now_ms(),
                                redacted: false,
                            });
                            out.lock().unwrap().push(entry);
                        }
                        Err(_) => break,
                    }
                }
            });
        }
    };

    pump(
        "stdout",
        stdout.map(|s| Box::new(s) as Box<dyn std::io::Read + Send>),
        out.clone(),
        resolve_log.clone(),
    );
    pump(
        "stderr",
        stderr.map(|s| Box::new(s) as Box<dyn std::io::Read + Send>),
        out.clone(),
        resolve_log,
    );

    let record = Arc::new(ProcRecord {
        pid,
        session_id: session_id.to_string(),
        role: role.to_string(),
        cmd: program.to_string(),
        args: args.to_vec(),
        cwd: cwd.to_path_buf(),
        started_at: crate::core::token::now_ms(),
        exited: AtomicBool::new(false),
        exit_code: AtomicI64::new(-9999),
        out,
        child: Arc::new(Mutex::new(child)),
    });

    // 监视退出
    {
        let rec = record.clone();
        std::thread::spawn(move || loop {
            {
                let mut child = rec.child.lock().unwrap();
                match child.try_wait() {
                    Ok(Some(status)) => {
                        rec.exited.store(true, Ordering::SeqCst);
                        rec.exit_code
                            .store(status.code().unwrap_or(-1) as i64, Ordering::SeqCst);
                        break;
                    }
                    Ok(None) => {}
                    Err(_) => break,
                }
            }
            std::thread::sleep(Duration::from_millis(200));
        });
    }

    table.procs.insert(pid, record.clone());
    Ok(record)
}

/// 等待进程日志中出现指定模式（子串或正则），返回匹配的完整行。
pub fn wait_for_output(
    table: &ProcTable,
    pid: u32,
    pattern: &str,
    timeout_ms: u64,
) -> HostResult<Option<String>> {
    let rec = table
        .get(pid)
        .ok_or_else(|| HostError::NotFound(format!("进程 {pid} 不存在")))?;
    let re = regex::Regex::new(pattern).ok();
    let deadline = Instant::now() + Duration::from_millis(timeout_ms);
    loop {
        {
            let rb = rec.out.lock().unwrap();
            for l in rb.lines.iter() {
                let matched = match &re {
                    Some(re) => re.is_match(&l.line),
                    None => l.line.contains(pattern),
                };
                if matched {
                    return Ok(Some(l.line.clone()));
                }
            }
        }
        if rec.is_exited() {
            return Ok(None);
        }
        if Instant::now() >= deadline {
            return Ok(None);
        }
        std::thread::sleep(Duration::from_millis(60));
    }
}
