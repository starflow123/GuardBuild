use std::fs;
use std::path::{Path, PathBuf};

use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

use super::error::{HostError, HostResult};

pub const MAX_READ_BYTES: u64 = 1024 * 1024; // 1 MiB
pub const MAX_LIST_ENTRIES: usize = 4000;

/// 依赖/虚拟环境/缓存目录：不属于项目源码，且虚拟环境常含数千文件，
/// 若不跳过会挤占 MAX_LIST_ENTRIES 配额，导致真正的源码目录（如 app/api）未被列举。
const SKIP_DIRS: &[&str] = &[
    "node_modules",
    ".git",
    ".venv",
    "venv",
    "site-packages",
    "__pycache__",
    ".tox",
    ".nox",
    ".pytest_cache",
    ".mypy_cache",
    ".ruff_cache",
];

fn skip_dir(name: &str) -> bool {
    SKIP_DIRS.iter().any(|s| s.eq_ignore_ascii_case(name))
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DirEntryInfo {
    pub name: String,
    pub path: String,
    pub kind: String, // file | dir | symlink | other
    pub size: u64,
}

pub fn sha256_hex(bytes: &[u8]) -> String {
    let mut h = Sha256::new();
    h.update(bytes);
    hex::encode(h.finalize())
}

pub fn sha256_file(path: &Path) -> HostResult<String> {
    let bytes = fs::read(path).map_err(|e| HostError::Io(format!("{:?}: {e}", path)))?;
    Ok(sha256_hex(&bytes))
}

fn entry_kind(md: &fs::Metadata) -> &'static str {
    let ft = md.file_type();
    if ft.is_dir() {
        "dir"
    } else if ft.is_file() {
        "file"
    } else if ft.is_symlink() {
        "symlink"
    } else {
        "other"
    }
}

/// 列出目录（限制深度与条目数量，避免把 node_modules 整个灌进上下文）。
pub fn list_dir(dir: &Path, depth: usize) -> HostResult<Vec<DirEntryInfo>> {
    let mut out: Vec<DirEntryInfo> = Vec::new();
    if depth == 0 {
        return Ok(out);
    }
    let rd = fs::read_dir(dir).map_err(|e| HostError::Io(format!("{:?}: {e}", dir)))?;
    let mut items: Vec<PathBuf> = Vec::new();
    for e in rd.flatten() {
        items.push(e.path());
    }
    items.sort();
    for p in items {
        let name = p.file_name().map(|s| s.to_string_lossy().to_string()).unwrap_or_default();
        let md = match fs::symlink_metadata(&p) {
            Ok(m) => m,
            Err(_) => continue,
        };
        let kind = entry_kind(&md);
        out.push(DirEntryInfo {
            name: name.clone(),
            path: p.to_string_lossy().to_string(),
            kind: kind.to_string(),
            size: if kind == "file" { md.len() } else { 0 },
        });
        if out.len() >= MAX_LIST_ENTRIES {
            break;
        }
        if kind == "dir" && !skip_dir(&name) && depth > 1 {
            let mut sub = list_dir(&p, depth - 1)?;
            if out.len() + sub.len() > MAX_LIST_ENTRIES {
                sub.truncate(MAX_LIST_ENTRIES.saturating_sub(out.len()));
            }
            out.extend(sub);
            if out.len() >= MAX_LIST_ENTRIES {
                break;
            }
        }
    }
    Ok(out)
}

/// 读取文本文件。二进制文件（前 8KB 含 NUL）会被拒绝。
pub fn read_text(path: &Path) -> HostResult<(String, String, u64)> {
    let md = fs::metadata(path).map_err(|e| HostError::NotFound(format!("{:?}: {e}", path)))?;
    if md.len() > MAX_READ_BYTES {
        return Err(HostError::InvalidParams(format!(
            "文件过大（{} 字节 > 上限 {} 字节）: {:?}",
            md.len(),
            MAX_READ_BYTES,
            path
        )));
    }
    let bytes = fs::read(path).map_err(|e| HostError::Io(format!("{:?}: {e}", path)))?;
    if bytes.iter().take(8192).any(|b| *b == 0) {
        return Err(HostError::InvalidParams(format!("二进制文件不可作为文本读取: {:?}", path)));
    }
    let sha = sha256_hex(&bytes);
    let content = String::from_utf8_lossy(&bytes).to_string();
    Ok((content, sha, md.len()))
}

/// 写入文本文件（父目录自动创建），返回 sha256。
pub fn write_text(path: &Path, content: &str) -> HostResult<String> {
    if let Some(parent) = path.parent() {
        fs::create_dir_all(parent).map_err(|e| HostError::Io(format!("{:?}: {e}", parent)))?;
    }
    fs::write(path, content.as_bytes()).map_err(|e| HostError::Io(format!("{:?}: {e}", path)))?;
    Ok(sha256_hex(content.as_bytes()))
}

pub fn stat(path: &Path) -> HostResult<DirEntryInfo> {
    let md = fs::metadata(path).map_err(|e| HostError::NotFound(format!("{:?}: {e}", path)))?;
    let name = path.file_name().map(|s| s.to_string_lossy().to_string()).unwrap_or_default();
    Ok(DirEntryInfo {
        name,
        path: path.to_string_lossy().to_string(),
        kind: entry_kind(&md).to_string(),
        size: md.len(),
    })
}

/// 复制文件到备份位置。
pub fn copy_file(src: &Path, dst: &Path) -> HostResult<()> {
    if let Some(parent) = dst.parent() {
        fs::create_dir_all(parent).map_err(|e| HostError::Io(format!("{:?}: {e}", parent)))?;
    }
    fs::copy(src, dst).map_err(|e| HostError::Io(format!("{:?} -> {:?}: {e}", src, dst)))?;
    Ok(())
}

/// 创建目录链接：Windows 用 junction（mklink /J，无需管理员），Unix 用 symlink。
/// 用于把 node_modules 等重目录链接进 worktree，避免全量拷贝。
pub fn link_dir(src: &Path, dst: &Path) -> HostResult<()> {
    if dst.exists() {
        return Err(HostError::Conflict(format!("链接目标已存在: {:?}", dst)));
    }
    if !src.is_dir() {
        return Err(HostError::NotFound(format!("链接源目录不存在: {:?}", src)));
    }
    if let Some(parent) = dst.parent() {
        fs::create_dir_all(parent).map_err(|e| HostError::Io(format!("{:?}: {e}", parent)))?;
    }
    #[cfg(windows)]
    {
        let out = std::process::Command::new("cmd")
            .args(["/C", "mklink", "/J"])
            .arg(dst)
            .arg(src)
            .output()
            .map_err(|e| HostError::Io(format!("mklink 调用失败: {e}")))?;
        if !out.status.success() {
            return Err(HostError::Io(format!(
                "mklink /J {:?} -> {:?} 失败: {}",
                dst,
                src,
                String::from_utf8_lossy(&out.stderr).trim()
            )));
        }
        Ok(())
    }
    #[cfg(not(windows))]
    {
        std::os::unix::fs::symlink(src, dst)
            .map_err(|e| HostError::Io(format!("{:?} -> {:?}: {e}", src, dst)))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn temp_proj(tag: &str) -> PathBuf {
        let dir = std::env::temp_dir().join(format!(
            "guardbuild-fsops-{tag}-{}",
            uuid::Uuid::new_v4()
        ));
        fs::create_dir_all(&dir).unwrap();
        dir
    }

    #[test]
    fn list_dir_skips_virtualenv_and_cache_dirs() {
        let root = temp_proj("skip");
        fs::create_dir_all(root.join("app/api/v1")).unwrap();
        fs::write(root.join("app/api/v1/articles.py"), "x").unwrap();
        fs::create_dir_all(root.join(".venv/Lib/site-packages/fastapi")).unwrap();
        fs::write(root.join(".venv/Lib/site-packages/fastapi/routing.py"), "x").unwrap();
        fs::create_dir_all(root.join("__pycache__")).unwrap();
        fs::write(root.join("__pycache__/main.py"), "x").unwrap();

        let entries = list_dir(&root, 6).unwrap();
        let paths: Vec<String> = entries.iter().map(|e| e.path.clone()).collect();
        assert!(
            paths.iter().any(|p| p.ends_with("articles.py")),
            "真实源码应被列举: {paths:?}"
        );
        assert!(
            !paths.iter().any(|p| p.contains("site-packages") || p.contains("routing.py")),
            "虚拟环境内容不应被列举: {paths:?}"
        );
        assert!(
            !paths.iter().any(|p| p.ends_with("__pycache__/main.py") || p.ends_with("__pycache__\\main.py")),
            "缓存目录内容不应被列举: {paths:?}"
        );
        let _ = fs::remove_dir_all(&root);
    }

    #[test]
    fn list_dir_keeps_source_dir_named_app_and_src() {
        let root = temp_proj("keep");
        fs::create_dir_all(root.join("src/routes")).unwrap();
        fs::write(root.join("src/routes/orders.ts"), "x").unwrap();
        let entries = list_dir(&root, 6).unwrap();
        assert!(entries.iter().any(|e| e.path.ends_with("orders.ts")));
        let _ = fs::remove_dir_all(&root);
    }
}
