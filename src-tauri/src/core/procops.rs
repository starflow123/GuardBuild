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
        // Host 托管的 docker run 与该容器同生命周期：先删容器，再回收 CLI，
        // 避免 UI 终止目标 / 阶段切换 / 宿主退出时留下仍在运行的容器。
        if let Some(name) = docker_container_name(&self.cmd, &self.args) {
            remove_docker_container(&name);
        }
        // npm/.cmd 启动器会经 cmd.exe 再派生孙进程；仅 kill 直接子进程会把
        // node server.js 留成孤儿（持有工作区句柄，导致 E2E 清理 EBUSY）。
        #[cfg(windows)]
        {
            use std::os::windows::process::CommandExt;
            use std::process::{Command, Stdio};
            const CREATE_NO_WINDOW: u32 = 0x0800_0000;
            let _ = Command::new("taskkill")
                .args(["/PID", &self.pid.to_string(), "/T", "/F"])
                .creation_flags(CREATE_NO_WINDOW)
                .stdin(Stdio::null())
                .stdout(Stdio::null())
                .stderr(Stdio::null())
                .status();
        }
        let mut child = self.child.lock().unwrap();
        let _ = child.kill();
        let _ = child.wait();
    }
}

/// 从 `docker run` 参数中提取容器名（仅接受 guardbuild-* 前缀，防御性双重校验）。
pub fn docker_container_name(program: &str, args: &[String]) -> Option<String> {
    let base = Path::new(program)
        .file_stem()?
        .to_string_lossy()
        .to_lowercase();
    if base != "docker" || args.first().map(String::as_str) != Some("run") {
        return None;
    }
    let mut it = args.iter().skip(1);
    while let Some(a) = it.next() {
        if a == "--name" {
            return it.next().filter(|n| n.starts_with("guardbuild-")).cloned();
        }
        if let Some(n) = a.strip_prefix("--name=") {
            return n.starts_with("guardbuild-").then(|| n.to_string());
        }
        // 跳过带值参数，避免把它们的值误判为 --name
        if matches!(
            a.as_str(),
            "-e" | "--env" | "-p" | "--publish" | "-v" | "--volume" | "-w" | "--workdir"
        ) {
            it.next();
        }
    }
    None
}

fn remove_docker_container(name: &str) {
    let mut cmd = Command::new("docker");
    cmd.args(["rm", "-f", name])
        .stdin(Stdio::null())
        .stdout(Stdio::null())
        .stderr(Stdio::null());
    #[cfg(windows)]
    {
        use std::os::windows::process::CommandExt;
        const CREATE_NO_WINDOW: u32 = 0x0800_0000;
        cmd.creation_flags(CREATE_NO_WINDOW);
    }
    let _ = cmd.status();
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

fn env_value(env: &[(String, String)], key: &str) -> Option<String> {
    env.iter()
        .find(|(k, _)| k.eq_ignore_ascii_case(key))
        .map(|(_, v)| v.clone())
        .or_else(|| std::env::var(key).ok())
}

/// Windows 下沿 PATH + PATHEXT 解析可执行文件（npm → npm.cmd）。
/// 返回 (真实路径, 是否需要经 cmd.exe 包装)。非 Windows 原样返回。
#[cfg(windows)]
pub fn resolve_program(program: &str, env: &[(String, String)]) -> (PathBuf, bool) {
    let exts: Vec<String> = env_value(env, "PATHEXT")
        .unwrap_or_else(|| ".COM;.EXE;.BAT;.CMD".to_string())
        .split(';')
        .filter(|s| !s.trim().is_empty())
        .map(|s| s.trim().to_string())
        .collect();
    let lower = program.to_lowercase();
    let has_sep = program.contains('/') || program.contains('\\');
    let ends_exec = exts.iter().any(|e| lower.ends_with(&e.to_lowercase()));

    let via_cmd = |p: &Path| {
        p.extension()
            .map(|e| {
                let e = e.to_string_lossy().to_lowercase();
                e == "cmd" || e == "bat"
            })
            .unwrap_or(false)
    };

    if has_sep || ends_exec {
        let p = PathBuf::from(program);
        if p.is_file() {
            let wrap = via_cmd(&p);
            return (p, wrap);
        }
        if !ends_exec {
            for e in &exts {
                let cand = PathBuf::from(format!("{program}{e}"));
                if cand.is_file() {
                    let wrap = via_cmd(&cand);
                    return (cand, wrap);
                }
            }
        }
        return (PathBuf::from(program), false);
    }

    let path_var = env_value(env, "PATH").unwrap_or_default();
    for dir in std::env::split_paths(&path_var) {
        for e in &exts {
            let cand = dir.join(format!("{program}{e}"));
            if cand.is_file() {
                let wrap = via_cmd(&cand);
                return (cand, wrap);
            }
        }
    }
    (PathBuf::from(program), false)
}

#[cfg(not(windows))]
pub fn resolve_program(program: &str, _env: &[(String, String)]) -> (PathBuf, bool) {
    (PathBuf::from(program), false)
}

/// MSVC 风格参数引用（引号/反斜杠转义），用于拼进 cmd.exe 的命令行。
#[cfg(windows)]
fn quote_cmd_arg(s: &str) -> String {
    let needs = s.is_empty() || s.chars().any(|c| c.is_whitespace() || "\"&|<>^()".contains(c));
    if !needs {
        return s.to_string();
    }
    let mut out = String::with_capacity(s.len() + 2);
    out.push('"');
    let mut backslashes = 0usize;
    for ch in s.chars() {
        match ch {
            '\\' => {
                backslashes += 1;
                out.push('\\');
            }
            '"' => {
                for _ in 0..backslashes {
                    out.push('\\');
                }
                out.push('\\');
                out.push('"');
                backslashes = 0;
            }
            c => {
                backslashes = 0;
                out.push(c);
            }
        }
    }
    for _ in 0..backslashes {
        out.push('\\');
    }
    out.push('"');
    out
}

/// 构造命令：.cmd/.bat 需经 `cmd.exe /d /s /c` 执行。
/// 外层再包一对引号，配合 /s 的「剥首尾引号」规则保证带空格路径正确。
fn build_command(program: &Path, args: &[String], via_cmd: bool) -> Command {
    #[cfg(windows)]
    if via_cmd {
        use std::os::windows::process::CommandExt;
        let mut tail = quote_cmd_arg(&program.to_string_lossy());
        for a in args {
            tail.push(' ');
            tail.push_str(&quote_cmd_arg(a));
        }
        let mut c = Command::new("cmd.exe");
        c.raw_arg("/d")
            .raw_arg("/s")
            .raw_arg("/c")
            .raw_arg(format!("\"{tail}\""));
        return c;
    }
    let _ = via_cmd;
    let mut c = Command::new(program);
    c.args(args);
    c
}

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
    let (exe, via_cmd) = resolve_program(program, env);
    let mut cmd = build_command(&exe, args, via_cmd);
    cmd.current_dir(cwd)
        .stdin(Stdio::null())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .env_clear();
    for (k, v) in sanitized_env(env) {
        cmd.env(k, v);
    }
    apply_no_window(&mut cmd);

    let mut child = cmd.spawn().map_err(|e| {
        HostError::Proc(format!(
            "启动 `{program}` 失败（解析为 {}）: {e}",
            exe.to_string_lossy()
        ))
    })?;
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
                        rec.exit_code
                            .store(status.code().unwrap_or(-1) as i64, Ordering::SeqCst);
                        rec.exited.store(true, Ordering::SeqCst);
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

/// 等待进程退出，返回退出码；超时返回 None。不持有进程表锁。
pub fn wait_exit(rec: &ProcRecord, timeout_ms: u64) -> Option<i64> {
    let deadline = Instant::now() + Duration::from_millis(timeout_ms);
    loop {
        if rec.is_exited() {
            return Some(rec.exit_code.load(Ordering::SeqCst));
        }
        if Instant::now() >= deadline {
            return None;
        }
        std::thread::sleep(Duration::from_millis(80));
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn args(v: &[&str]) -> Vec<String> {
        v.iter().map(|s| s.to_string()).collect()
    }

    #[test]
    fn docker_container_name_extracts_only_guardbuild_run_names() {
        let a = args(&[
            "run", "--rm", "--name", "guardbuild-s1-target-1", "-e", "PORT=3000", "-p",
            "127.0.0.1:1:3000", "-v", "D:/p:/app", "alpine", "sh",
        ]);
        assert_eq!(docker_container_name("docker", &a).as_deref(), Some("guardbuild-s1-target-1"));
        let b = args(&["run", "--name=guardbuild-x-2", "alpine"]);
        assert_eq!(docker_container_name(r"C:\bin\docker.exe", &b).as_deref(), Some("guardbuild-x-2"));
        assert_eq!(docker_container_name("docker", &args(&["rm", "-f", "guardbuild-x-2"])), None);
        assert_eq!(docker_container_name("docker", &args(&["run", "--name", "other", "alpine"])), None);
        assert_eq!(docker_container_name("node", &a), None);
    }
}
