use std::fs;
use std::path::{Path, PathBuf};

use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

use super::error::{HostError, HostResult};

pub const MAX_READ_BYTES: u64 = 1024 * 1024; // 1 MiB
pub const MAX_LIST_ENTRIES: usize = 4000;

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
        if kind == "dir" && name != "node_modules" && name != ".git" && depth > 1 {
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
