use std::path::{Path, PathBuf};
use std::process::Command;

use serde::{Deserialize, Serialize};

use super::error::{HostError, HostResult};
use super::fsops;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct FileChange {
    pub path: String,
    pub insertions: usize,
    pub deletions: usize,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DiffCapture {
    pub diff: String,
    pub files: Vec<FileChange>,
    pub patch_hash: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BackupEntry {
    pub path: String,
    pub backup_path: String,
    pub sha_before: String,
    pub sha_after: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BackupManifest {
    pub backup_id: String,
    pub session_id: String,
    pub root: String,
    pub created_at: i64,
    pub patch_hash: String,
    pub files: Vec<BackupEntry>,
}

#[cfg(windows)]
fn apply_no_window(cmd: &mut Command) {
    use std::os::windows::process::CommandExt;
    const CREATE_NO_WINDOW: u32 = 0x0800_0000;
    cmd.creation_flags(CREATE_NO_WINDOW);
}

#[cfg(not(windows))]
fn apply_no_window(_cmd: &mut Command) {}

/// Windows 默认 260 字符路径上限会让真实前端仓库（嵌套组件目录）检出失败：
/// `error: unable to create file …: Filename too long`。这里按命令注入 core.longpaths，
/// 只影响 GuardBuild 自己起的 git 进程，不改用户全局配置。
#[cfg(windows)]
const LONG_PATHS_ARGS: [&str; 2] = ["-c", "core.longpaths=true"];

#[cfg(not(windows))]
const LONG_PATHS_ARGS: [&str; 0] = [];

fn run_git(dir: &Path, args: &[&str]) -> HostResult<(bool, String, String)> {
    let mut cmd = Command::new("git");
    cmd.args(LONG_PATHS_ARGS).arg("-C").arg(dir).args(args);
    apply_no_window(&mut cmd);
    let out = cmd
        .output()
        .map_err(|e| HostError::Git(format!("无法执行 git: {e}")))?;
    Ok((
        out.status.success(),
        String::from_utf8_lossy(&out.stdout).to_string(),
        String::from_utf8_lossy(&out.stderr).to_string(),
    ))
}

/// 长路径失败的原文要翻译成人话：否则用户看到 `Filename too long` 只会以为磁盘坏了。
pub fn annotate_git_error(context: &str, stderr: &str) -> String {
    const LONG_PATH_MARKS: [&str; 3] = ["Filename too long", "unable to create file", "Could not reset index file"];
    let text = stderr.trim();
    if LONG_PATH_MARKS.iter().any(|m| text.contains(m)) {
        return format!(
            "{context}: {text}（疑似 Windows 长路径：GuardBuild 已按命令启用 core.longpaths=true，若仍失败请把会话数据目录设到更短的路径，如 D:/gbdata，或安装 Git for Windows ≥ 2.37）"
        );
    }
    format!("{context}: {text}")
}

pub fn is_git_repo(dir: &Path) -> bool {
    match run_git(dir, &["rev-parse", "--is-inside-work-tree"]) {
        Ok((ok, stdout, _)) => ok && stdout.trim() == "true",
        Err(_) => false,
    }
}

pub fn head_exists(dir: &Path) -> bool {
    matches!(run_git(dir, &["rev-parse", "--verify", "HEAD"]), Ok((true, _, _)))
}

pub fn status_porcelain(dir: &Path) -> HostResult<Vec<(String, String)>> {
    let (ok, stdout, stderr) = run_git(dir, &["status", "--porcelain=v1"])?;
    if !ok {
        return Err(HostError::Git(format!("git status 失败: {stderr}")));
    }
    Ok(stdout
        .lines()
        .filter(|l| l.len() > 3)
        .map(|l| (l[..2].trim().to_string(), l[3..].to_string()))
        .collect())
}

/// 在隔离目录创建 worktree（从 HEAD 检出，detached），不触碰原工作区与未提交改动。
pub fn worktree_add(root: &Path, target_dir: &Path) -> HostResult<()> {
    if !is_git_repo(root) {
        return Err(HostError::Git(
            "目标目录不是 Git 仓库；请在目标项目中执行 `git init && git add -A && git commit` 后重试".into(),
        ));
    }
    if !head_exists(root) {
        return Err(HostError::Git(
            "Git 仓库尚无提交（HEAD 不存在）；请先提交一次基线后再运行修复".into(),
        ));
    }
    if let Some(parent) = target_dir.parent() {
        std::fs::create_dir_all(parent).map_err(HostError::from)?;
    }
    let dir_str = target_dir.to_string_lossy().to_string();
    let (ok, _stdout, stderr) = run_git(root, &["worktree", "add", "--detach", &dir_str, "HEAD"])?;
    if !ok {
        // 目录可能已存在残留，先 prune 再重试一次
        let _ = run_git(root, &["worktree", "prune"]);
        let (ok2, _, stderr2) = run_git(root, &["worktree", "add", "--detach", &dir_str, "HEAD"])?;
        if !ok2 {
            return Err(HostError::Git(annotate_git_error(
                "git worktree add 失败",
                &format!("{stderr} / {stderr2}"),
            )));
        }
    }
    Ok(())
}

#[cfg(windows)]
fn is_link_meta(md: &std::fs::Metadata) -> bool {
    use std::os::windows::fs::MetadataExt;
    const FILE_ATTRIBUTE_REPARSE_POINT: u32 = 0x400;
    md.file_attributes() & FILE_ATTRIBUTE_REPARSE_POINT != 0
}

#[cfg(not(windows))]
fn is_link_meta(md: &std::fs::Metadata) -> bool {
    md.file_type().is_symlink()
}

fn remove_link(path: &Path, md: &std::fs::Metadata) -> std::io::Result<()> {
    #[cfg(windows)]
    {
        // junction 表现为目录重解析点；目录符号链接则两种删除方式都可能适用
        if md.is_dir() {
            std::fs::remove_dir(path).or_else(|_| std::fs::remove_file(path))
        } else {
            std::fs::remove_file(path).or_else(|_| std::fs::remove_dir(path))
        }
    }
    #[cfg(not(windows))]
    {
        let _ = md;
        std::fs::remove_file(path)
    }
}

/// 摘除目录树中的链接/junction 本身（绝不跟随目标）。
/// `git worktree remove --force` 会穿透 Windows junction，先摘链接才能保住 node_modules 等外部目录。
pub fn scrub_links(dir: &Path) -> HostResult<usize> {
    let mut removed = 0usize;
    let mut visited = 0usize;
    let mut stack = vec![dir.to_path_buf()];
    while let Some(cur) = stack.pop() {
        let entries = match std::fs::read_dir(&cur) {
            Ok(e) => e,
            Err(_) => continue,
        };
        for ent in entries.flatten() {
            visited += 1;
            if visited > 200_000 {
                return Ok(removed);
            }
            let path = ent.path();
            let Ok(md) = std::fs::symlink_metadata(&path) else {
                continue;
            };
            if is_link_meta(&md) {
                remove_link(&path, &md)
                    .map_err(|e| HostError::Io(format!("移除链接失败 {:?}: {e}", path)))?;
                removed += 1;
            } else if md.is_dir() {
                stack.push(path);
            }
        }
    }
    Ok(removed)
}

/// 删除隔离 worktree（幂等）。先停实例再调用；目录不存在时仅清理 git 注册。
pub fn worktree_remove(root: &Path, target_dir: &Path) -> HostResult<()> {
    if std::fs::symlink_metadata(target_dir).is_err() {
        let _ = run_git(root, &["worktree", "prune"]);
        return Ok(());
    }
    scrub_links(target_dir)?;
    let dir_str = target_dir.to_string_lossy().to_string();
    let (ok, _, stderr) = run_git(root, &["worktree", "remove", "--force", &dir_str])?;
    if !ok {
        // worktree 注册可能已丢失（上次清理中断）：清掉注册后直接删除本会话临时目录
        let _ = run_git(root, &["worktree", "prune"]);
        std::fs::remove_dir_all(target_dir).map_err(|e| {
            HostError::Git(format!("git worktree remove 失败: {stderr}；目录清理失败: {e}"))
        })?;
    }
    Ok(())
}

/// 为编排层**明确申报**的新文件建立 intent-to-add 记录，使其进入 `git diff` 与补丁。
///
/// 为什么必须显式申报而不是 `git add -N .`：worktree 里目标进程运行时会落下临时文件、
/// 数据库文件、构建产物，全量登记会把它们混进「修复补丁」，让写回污染工作区。
/// 任一申报路径失败即报错——静默漏掉一个新建文件会让验收通过的说法不成立。
pub fn intent_to_add(dir: &Path, rels: &[String]) -> HostResult<Vec<String>> {
    let mut added = Vec::new();
    for rel in rels {
        let p = rel.replace('\\', "/");
        if p.is_empty() || p.contains("..") || p.starts_with('/') || Path::new(rel).is_absolute() {
            return Err(HostError::InvalidParams(format!(
                "intentAdd 只接受 worktree 内相对路径，收到 `{rel}`"
            )));
        }
        let abs = dir.join(&p);
        if !abs.exists() {
            return Err(HostError::NotFound(format!("新建文件不存在，无法登记进补丁: {p}")));
        }
        let (ok, _out, stderr) = run_git(dir, &["add", "--intent-to-add", "--", &p])?;
        if !ok {
            return Err(HostError::Git(format!(
                "git add --intent-to-add `{p}` 失败: {}",
                stderr.trim()
            )));
        }
        added.push(p);
    }
    Ok(added)
}

/// 捕获目录相对 HEAD 的完整 diff。未跟踪文件仅在 `intent_to_add` 显式登记后进入补丁。
pub fn diff_capture(dir: &Path) -> HostResult<DiffCapture> {
    let (ok, diff, stderr) = run_git(dir, &["diff", "--no-color", "--no-ext-diff"])?;
    if !ok {
        return Err(HostError::Git(format!("git diff 失败: {stderr}")));
    }
    let (ok2, numstat, stderr2) = run_git(dir, &["diff", "--numstat"])?;
    if !ok2 {
        return Err(HostError::Git(format!("git diff --numstat 失败: {stderr2}")));
    }
    let mut files = Vec::new();
    for line in numstat.lines() {
        let cols: Vec<&str> = line.split('\t').collect();
        if cols.len() == 3 {
            files.push(FileChange {
                insertions: cols[0].parse().unwrap_or(0),
                deletions: cols[1].parse().unwrap_or(0),
                path: cols[2].to_string(),
            });
        }
    }
    let patch_hash = fsops::sha256_hex(diff.as_bytes());
    Ok(DiffCapture {
        diff,
        files,
        patch_hash,
    })
}

/// 将补丁应用到工作区：先 --check，再备份被修改文件，最后 apply。
/// 返回 (backup_manifest, 应用的文件列表)。
pub fn writeback_patch(
    root: &Path,
    patch: &str,
    patch_hash: &str,
    session_id: &str,
    backup_root: &Path,
) -> HostResult<BackupManifest> {
    if patch.trim().is_empty() {
        return Err(HostError::Git("补丁为空".into()));
    }
    // 1) 预检
    let tmp_patch = backup_root.join(format!("apply-{}.patch", &patch_hash[..12]));
    std::fs::create_dir_all(backup_root).map_err(HostError::from)?;
    std::fs::write(&tmp_patch, patch).map_err(HostError::from)?;
    let tmp_str = tmp_patch.to_string_lossy().to_string();
    let (ok, _, stderr) = run_git(root, &["apply", "--check", "--whitespace=nowarn", &tmp_str])?;
    if !ok {
        return Err(HostError::Conflict(format!(
            "补丁无法干净地应用到工作区（可能文件已被修改）: {stderr}"
        )));
    }

    // 2) 解析文件列表并备份
    let files = parse_patch_files(patch);
    if files.is_empty() {
        return Err(HostError::Git("补丁不包含任何文件变更".into()));
    }
    let backup_id = format!(
        "bk_{}",
        &fsops::sha256_hex(format!("{session_id}:{patch_hash}:{}", crate::core::token::now_ms()).as_bytes())[..16]
    );
    let backup_dir = backup_root.join(&backup_id).join("files");
    let mut entries: Vec<BackupEntry> = Vec::new();
    for rel in &files {
        let abs = root.join(rel);
        let sha_before = if abs.exists() {
            fsops::sha256_file(&abs)?
        } else {
            String::from("")
        };
        let backup_path = backup_dir.join(rel);
        if abs.exists() {
            fsops::copy_file(&abs, &backup_path)?;
        }
        entries.push(BackupEntry {
            path: rel.clone(),
            backup_path: backup_path.to_string_lossy().to_string(),
            sha_before,
            sha_after: String::new(),
        });
    }

    // 3) 应用
    let (ok2, _out, stderr2) = run_git(root, &["apply", "--whitespace=nowarn", &tmp_str])?;
    if !ok2 {
        return Err(HostError::Git(annotate_git_error("git apply 失败", &stderr2)));
    }
    let _ = std::fs::remove_file(&tmp_patch);

    // 4) 记录应用后哈希，写 manifest
    for e in entries.iter_mut() {
        let abs = root.join(&e.path);
        e.sha_after = if abs.exists() {
            fsops::sha256_file(&abs)?
        } else {
            String::new()
        };
    }
    let manifest = BackupManifest {
        backup_id: backup_id.clone(),
        session_id: session_id.to_string(),
        root: root.to_string_lossy().to_string(),
        created_at: crate::core::token::now_ms(),
        patch_hash: patch_hash.to_string(),
        files: entries,
    };
    let manifest_path = backup_root.join(&backup_id).join("manifest.json");
    std::fs::create_dir_all(manifest_path.parent().unwrap()).map_err(HostError::from)?;
    std::fs::write(
        &manifest_path,
        serde_json::to_string_pretty(&manifest).map_err(HostError::from)?,
    )
    .map_err(HostError::from)?;
    Ok(manifest)
}

pub fn load_manifest(backup_root: &Path, backup_id: &str) -> HostResult<BackupManifest> {
    let p = backup_root.join(backup_id).join("manifest.json");
    let text = std::fs::read_to_string(&p)
        .map_err(|e| HostError::NotFound(format!("备份清单不存在: {:?} ({e})", p)))?;
    serde_json::from_str(&text).map_err(HostError::from)
}

/// 回滚：恢复备份文件。返回 (已恢复文件, 有冲突的文件)。
/// 冲突 = 当前文件哈希与「写回后记录」不一致（说明用户在写回后手动改过）。
pub fn rollback(backup_root: &Path, backup_id: &str) -> HostResult<(Vec<String>, Vec<String>)> {
    let manifest = load_manifest(backup_root, backup_id)?;
    let root = PathBuf::from(&manifest.root);
    let mut restored = Vec::new();
    let mut conflicts = Vec::new();
    for e in &manifest.files {
        let abs = root.join(&e.path);
        let current_sha = if abs.exists() {
            fsops::sha256_file(&abs).unwrap_or_default()
        } else {
            String::new()
        };
        if !e.sha_after.is_empty() && current_sha != e.sha_after && !current_sha.is_empty() {
            conflicts.push(e.path.clone());
        }
        let backup = PathBuf::from(&e.backup_path);
        if backup.exists() {
            fsops::copy_file(&backup, &abs)?;
            restored.push(e.path.clone());
        } else if e.sha_before.is_empty() {
            // 原文件本来不存在 → 删除新增文件
            let _ = std::fs::remove_file(&abs);
            restored.push(e.path.clone());
        }
    }
    Ok((restored, conflicts))
}

/// 从 unified diff 中解析涉及的文件相对路径（跳过 /dev/null）。
fn parse_patch_files(patch: &str) -> Vec<String> {
    let mut files = Vec::new();
    for line in patch.lines() {
        if let Some(rest) = line.strip_prefix("+++ b/") {
            let p = rest.trim().to_string();
            if p != "/dev/null" && !p.is_empty() && !files.contains(&p) {
                files.push(p);
            }
        }
    }
    files
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn long_path_git_failure_is_translated() {
        // 取自 juice-shop 白盒实测原文（2026-10-30，dogfood/reports/kb-20261030/juice）
        let stderr = "Preparing worktree (detached HEAD dc40466)\nerror: unable to create file frontend/src/app/score-board/components/filter-settings/components/score-board-additional-settings-dialog/score-board-additional-settings-dialog.component.scss: Filename too long\nfatal: Could not reset index file to revision 'HEAD'.";
        let msg = annotate_git_error("git worktree add 失败", stderr);
        assert!(msg.contains("git worktree add 失败"), "保留原始上下文");
        assert!(msg.contains("core.longpaths"), "给出长路径处置建议");
        assert!(msg.contains("Filename too long"), "原文不能丢");
    }

    #[test]
    fn unrelated_git_failure_gets_no_longpath_hint() {
        let msg = annotate_git_error("git apply 失败", "error: patch failed: src/app.js:12");
        assert_eq!(msg, "git apply 失败: error: patch failed: src/app.js:12");
    }

    #[cfg(windows)]
    #[test]
    fn every_git_command_carries_longpaths_flag() {
        assert_eq!(LONG_PATHS_ARGS, ["-c", "core.longpaths=true"]);
    }

    #[cfg(not(windows))]
    #[test]
    fn longpaths_flag_is_windows_only() {
        assert!(LONG_PATHS_ARGS.is_empty());
    }

    fn git_init(dir: &Path) {
        let run = |args: &[&str]| {
            let mut c = Command::new("git");
            c.arg("-C").arg(dir).args(args);
            apply_no_window(&mut c);
            let out = c.output().unwrap();
            assert!(
                out.status.success(),
                "git {:?} failed: {}",
                args,
                String::from_utf8_lossy(&out.stderr)
            );
        };
        run(&["init", "-q"]);
        run(&["config", "user.email", "t@example.com"]);
        run(&["config", "user.name", "tester"]);
        run(&["config", "core.autocrlf", "false"]);
    }

    #[test]
    fn worktree_flow_keeps_workspace_untouched() {
        let base = std::env::temp_dir().join(format!("gb_git_test_{}", std::process::id()));
        let repo = base.join("repo");
        std::fs::create_dir_all(repo.join("src")).unwrap();
        git_init(&repo);
        let baseline = "const a = 1;\nconst b = 0;\nconst c = 3;\nconst d = 4;\nconst e = 5;\n";
        std::fs::write(repo.join("src/app.js"), baseline).unwrap();
        // 提交基线
        let run = |args: &[&str]| {
            let mut c = Command::new("git");
            c.arg("-C").arg(&repo).args(args);
            apply_no_window(&mut c);
            let out = c.output().unwrap();
            assert!(out.status.success(), "{}", String::from_utf8_lossy(&out.stderr));
        };
        run(&["add", "-A"]);
        run(&["commit", "-qm", "base"]);

        // 制造未提交改动（与补丁区域不重叠，必须被保留）
        std::fs::write(repo.join("src/app.js"), format!("{baseline}const local = true;\n")).unwrap();

        // 创建 worktree 并修改第 1 行
        let wt = base.join("wt");
        worktree_add(&repo, &wt).unwrap();
        assert!(wt.join("src/app.js").exists());
        std::fs::write(wt.join("src/app.js"), "const a = 1; const fixed = true;\nconst b = 0;\nconst c = 3;\nconst d = 4;\nconst e = 5;\n").unwrap();
        let cap = diff_capture(&wt).unwrap();
        assert!(cap.diff.contains("const fixed = true"));
        assert_eq!(cap.files.len(), 1);

        // 写回工作区：补丁生效，且本地未提交改动仍在
        let backups = base.join("backups");
        let manifest = writeback_patch(&repo, &cap.diff, &cap.patch_hash, "s_test", &backups).unwrap();
        assert_eq!(manifest.files.len(), 1);
        let content = std::fs::read_to_string(repo.join("src/app.js")).unwrap();
        assert!(content.contains("const fixed = true"), "补丁应已生效: {content}");
        assert!(content.contains("const local = true"), "本地未提交改动应被保留: {content}");

        // 回滚：恢复写回前状态（本地改动仍在、补丁消失）
        let (restored, conflicts) = rollback(&backups, &manifest.backup_id).unwrap();
        assert_eq!(restored.len(), 1);
        assert!(conflicts.is_empty());
        let content2 = std::fs::read_to_string(repo.join("src/app.js")).unwrap();
        assert!(content2.contains("const local = true"), "回滚后本地改动应在: {content2}");
        assert!(!content2.contains("const fixed = true"), "回滚后补丁应消失: {content2}");
        assert!(content2.starts_with("const a = 1;\n"), "第 1 行应恢复原样: {content2}");

        // 冲突保护：本地改动与补丁区域重叠时应拒绝写回
        std::fs::write(repo.join("src/app.js"), "const a = 999; // conflict\nconst b = 0;\nconst c = 3;\nconst d = 4;\nconst e = 5;\n").unwrap();
        let err = writeback_patch(&repo, &cap.diff, &cap.patch_hash, "s_test", &backups).unwrap_err();
        assert!(matches!(err, HostError::Conflict(_)), "应返回冲突错误，实际: {err:?}");
        let content3 = std::fs::read_to_string(repo.join("src/app.js")).unwrap();
        assert!(content3.contains("const a = 999"), "拒绝写回后本地文件不应被改动: {content3}");

        let _ = std::fs::remove_dir_all(&base);
    }

    /// 真实回归：juice-shop 白盒轮曾死在 worktree add
    /// （`error: unable to create file …component.scss: Filename too long`）。
    /// 只在 Windows 有意义——POSIX 下 260 字符不是限制。
    #[cfg(windows)]
    #[test]
    fn worktree_add_checks_out_windows_long_paths() {
        let base = std::env::temp_dir().join(format!("gb_git_lp_{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&base);
        let repo = base.join("repo");
        let seg = "score-board-additional-settings-dialog-component";
        let deep = (0..5)
            .map(|i| format!("{seg}-{i}"))
            .collect::<Vec<_>>()
            .join("/");
        let rel = format!("{deep}/{seg}.scss");
        let abs_len = repo.join(&rel).to_string_lossy().len();
        assert!(abs_len > 260, "测试路径必须真的超过 260 字符才能复现，实际 {abs_len}");

        std::fs::create_dir_all(repo.join(&deep)).unwrap();
        git_init(&repo);
        std::fs::write(repo.join(&rel), ".dialog { color: red; }\n").unwrap();
        // 夹具自身的 git 命令也走 run_git：长路径下裸 git 连目录都打不开
        for args in [&["add", "-A"][..], &["commit", "-qm", "base"][..]] {
            let (ok, _out, stderr) = run_git(&repo, args).unwrap();
            assert!(ok, "git {args:?} 失败: {stderr}");
        }

        let wt = base.join("wt");
        worktree_add(&repo, &wt).expect("按命令启用 core.longpaths 后，深路径应能检出");
        assert!(wt.join(&rel).exists(), "worktree 里应能看到长路径文件");

        let _ = std::fs::remove_dir_all(&base);
    }

    #[test]
    fn intent_to_add_puts_new_files_into_patch_and_rollback() {
        let base = std::env::temp_dir().join(format!("gb_git_new_{}", std::process::id()));
        let repo = base.join("repo");
        std::fs::create_dir_all(repo.join("src")).unwrap();
        git_init(&repo);
        std::fs::write(repo.join("src/app.js"), "const a = 1;\nconst b = 2;\n").unwrap();
        let run = |args: &[&str]| {
            let mut c = Command::new("git");
            c.arg("-C").arg(&repo).args(args);
            apply_no_window(&mut c);
            let out = c.output().unwrap();
            assert!(out.status.success(), "{}", String::from_utf8_lossy(&out.stderr));
        };
        run(&["add", "-A"]);
        run(&["commit", "-qm", "base"]);

        let wt = base.join("wt");
        worktree_add(&repo, &wt).unwrap();
        std::fs::write(wt.join("src/app.js"), "const a = 1; // guarded\nconst b = 2;\n").unwrap();
        std::fs::create_dir_all(wt.join("src/guards")).unwrap();
        std::fs::write(wt.join("src/guards/owner.js"), "export const guard = true;\n").unwrap();
        // 目标进程运行时落下的临时文件：未申报就不该进补丁
        std::fs::write(wt.join("runtime.db"), "junk\n").unwrap();

        let before = diff_capture(&wt).unwrap();
        assert!(!before.diff.contains("owner.js"), "未登记的新文件不应进补丁: {}", before.diff);

        let added = intent_to_add(&wt, &["src/guards/owner.js".to_string()]).unwrap();
        assert_eq!(added, vec!["src/guards/owner.js".to_string()]);
        let cap = diff_capture(&wt).unwrap();
        assert!(cap.diff.contains("new file mode"), "新文件应以新建形态进补丁:\n{}", cap.diff);
        assert_eq!(cap.files.len(), 2, "改动文件 + 新建文件: {:?}", cap.files);
        assert!(!cap.diff.contains("runtime.db"), "未申报的运行时产物不得进补丁");

        let backups = base.join("backups");
        let manifest = writeback_patch(&repo, &cap.diff, &cap.patch_hash, "s_new", &backups).unwrap();
        assert!(repo.join("src/guards/owner.js").exists(), "写回应创建新文件");
        assert_eq!(manifest.files.len(), 2);

        let (restored, conflicts) = rollback(&backups, &manifest.backup_id).unwrap();
        assert!(conflicts.is_empty());
        assert_eq!(restored.len(), 2);
        assert!(!repo.join("src/guards/owner.js").exists(), "回滚应删除原本不存在的新建文件");
        assert!(repo.join("src/app.js").exists(), "回滚不应删掉原有文件");

        // 拒绝：越界路径与不存在的文件
        assert!(intent_to_add(&wt, &["../escape.js".to_string()]).is_err());
        assert!(intent_to_add(&wt, &["src/missing.js".to_string()]).is_err());

        let _ = std::fs::remove_dir_all(&base);
    }

    #[test]
    fn worktree_remove_scrubs_links_without_following_target() {
        let base = std::env::temp_dir().join(format!("gb_git_rm_{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&base);
        let repo = base.join("repo");
        std::fs::create_dir_all(repo.join("src")).unwrap();
        git_init(&repo);
        std::fs::write(repo.join("src/app.js"), "const a = 1;\n").unwrap();
        let run = |args: &[&str]| {
            let mut c = Command::new("git");
            c.arg("-C").arg(&repo).args(args);
            apply_no_window(&mut c);
            let out = c.output().unwrap();
            assert!(out.status.success(), "{}", String::from_utf8_lossy(&out.stderr));
        };
        run(&["add", "-A"]);
        run(&["commit", "-qm", "base"]);

        let wt = base.join("wt");
        worktree_add(&repo, &wt).unwrap();
        // 模拟 patcher 的 node_modules 链接（Windows junction / Unix symlink）
        let deps = base.join("deps");
        std::fs::create_dir_all(deps.join("pkg")).unwrap();
        std::fs::write(deps.join("pkg/keep.txt"), "keep").unwrap();
        fsops::link_dir(&deps, &wt.join("node_modules")).unwrap();

        worktree_remove(&repo, &wt).unwrap();
        assert!(!wt.exists(), "worktree 目录应被删除");
        assert!(
            deps.join("pkg/keep.txt").exists(),
            "链接目标（node_modules）必须保留"
        );
        assert!(repo.join("src/app.js").exists(), "原工作区不应受影响");

        // 幂等：二次清理不报错
        worktree_remove(&repo, &wt).unwrap();

        let _ = std::fs::remove_dir_all(&base);
    }
}
