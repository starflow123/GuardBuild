//! 运行时布局解析：优先使用随包 node 与安装目录内的 sidecar，缺失时回落开发布局 / PATH。
//!
//! 安装包把 `runtime/node(.exe)`、`sidecar/`、`shared/` 放在 exe 同级（或以 `resources/` 包装）；
//! 开发态则从 `src-tauri/target/{debug,release}` 回溯到仓库根。解析顺序固定，便于单测锁住。

use std::path::{Path, PathBuf};

pub fn node_file_name() -> &'static str {
    if cfg!(windows) {
        "node.exe"
    } else {
        "node"
    }
}

/// 随包 node 的候选位置（按优先级）
pub fn node_candidates(exe_dir: &Path) -> Vec<PathBuf> {
    let name = node_file_name();
    vec![
        exe_dir.join("runtime").join(name),
        exe_dir.join("resources").join("runtime").join(name),
        exe_dir.join("..").join("runtime").join(name),
        // 开发态：src-tauri/target/{debug,release} → src-tauri/runtime
        exe_dir.join("..").join("..").join("runtime").join(name),
    ]
}

/// `GUARDBUILD_NODE` 显式覆盖 > 随包 node > PATH 中的 `node`
pub fn resolve_node_bin(explicit: Option<String>, exe_dir: Option<&Path>) -> String {
    if let Some(v) = explicit {
        let v = v.trim();
        if !v.is_empty() {
            return v.to_string();
        }
    }
    if let Some(dir) = exe_dir {
        for c in node_candidates(dir) {
            if c.is_file() {
                return c.to_string_lossy().to_string();
            }
        }
    }
    "node".to_string()
}

/// sidecar 入口候选位置（按优先级）
pub fn sidecar_candidates(exe_dir: &Path, cwd: &Path) -> Vec<PathBuf> {
    vec![
        // 安装布局：exe 同级（Tauri 在 Windows 上把 resources 放在 exe 目录）
        exe_dir.join("sidecar").join("main.mjs"),
        exe_dir.join("resources").join("sidecar").join("main.mjs"),
        exe_dir.join("..").join("resources").join("sidecar").join("main.mjs"),
        // 开发布局：target/{debug,release} → 仓库根/sidecar
        exe_dir.join("..").join("..").join("..").join("sidecar").join("main.mjs"),
        // 从仓库根 / 相邻目录运行
        cwd.join("sidecar").join("main.mjs"),
        cwd.join("..").join("sidecar").join("main.mjs"),
    ]
}

/// `GUARDBUILD_SIDECAR` 显式覆盖 > 安装布局 > 开发布局 > 当前目录相对路径
pub fn resolve_sidecar_path(
    explicit: Option<PathBuf>,
    exe_dir: Option<&Path>,
    cwd: &Path,
) -> PathBuf {
    if let Some(p) = explicit {
        return p;
    }
    if let Some(dir) = exe_dir {
        for c in sidecar_candidates(dir, cwd) {
            if c.is_file() {
                return c;
            }
        }
    } else {
        for c in sidecar_candidates(cwd, cwd) {
            if c.is_file() {
                return c;
            }
        }
    }
    PathBuf::from("sidecar/main.mjs")
}

pub fn current_exe_dir() -> Option<PathBuf> {
    std::env::current_exe()
        .ok()
        .and_then(|p| p.parent().map(|d| d.to_path_buf()))
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::fs;

    fn scratch(tag: &str) -> PathBuf {
        let dir = std::env::temp_dir().join(format!(
            "guardbuild-runtime-{}-{}-{:?}",
            std::process::id(),
            tag,
            std::thread::current().id()
        ));
        let _ = fs::remove_dir_all(&dir);
        fs::create_dir_all(&dir).unwrap();
        dir
    }

    fn touch(p: &Path) {
        fs::create_dir_all(p.parent().unwrap()).unwrap();
        fs::write(p, b"stub").unwrap();
    }

    #[test]
    fn bundled_node_wins_over_path_fallback() {
        let dir = scratch("node");
        touch(&dir.join("runtime").join(node_file_name()));
        let got = resolve_node_bin(None, Some(&dir));
        assert_eq!(got, dir.join("runtime").join(node_file_name()).to_string_lossy());
        let _ = fs::remove_dir_all(&dir);
    }

    #[test]
    fn node_precedence_is_runtime_then_resources() {
        let dir = scratch("precedence");
        touch(&dir.join("resources").join("runtime").join(node_file_name()));
        let resources = resolve_node_bin(None, Some(&dir));
        assert!(resources.contains("resources"));
        touch(&dir.join("runtime").join(node_file_name()));
        let direct = PathBuf::from(resolve_node_bin(None, Some(&dir)));
        assert_eq!(direct, dir.join("runtime").join(node_file_name()));
        assert!(!direct.to_string_lossy().contains("resources"));
        let _ = fs::remove_dir_all(&dir);
    }

    #[test]
    fn explicit_node_override_wins() {
        let dir = scratch("override");
        touch(&dir.join("runtime").join(node_file_name()));
        let got = resolve_node_bin(Some("D:/custom/node.exe".into()), Some(&dir));
        assert_eq!(got, "D:/custom/node.exe");
        let _ = fs::remove_dir_all(&dir);
    }

    #[test]
    fn empty_override_falls_through_to_bundled() {
        let dir = scratch("empty");
        touch(&dir.join("runtime").join(node_file_name()));
        let got = resolve_node_bin(Some("   ".into()), Some(&dir));
        assert_eq!(got, dir.join("runtime").join(node_file_name()).to_string_lossy());
        let _ = fs::remove_dir_all(&dir);
    }

    #[test]
    fn node_falls_back_to_path_marker() {
        let dir = scratch("fallback");
        assert_eq!(resolve_node_bin(None, Some(&dir)), "node");
        let _ = fs::remove_dir_all(&dir);
    }

    #[test]
    fn installed_sidecar_wins_over_cwd() {
        let dir = scratch("sidecar");
        let cwd = dir.join("work");
        fs::create_dir_all(&cwd).unwrap();
        let installed = dir.join("sidecar").join("main.mjs");
        touch(&installed);
        touch(&cwd.join("sidecar").join("main.mjs"));
        let got = resolve_sidecar_path(None, Some(&dir), &cwd);
        assert_eq!(got, installed);
        let _ = fs::remove_dir_all(&dir);
    }

    #[test]
    fn sidecar_uses_dev_layout_when_installed_missing() {
        let root = scratch("devlayout");
        let exe_dir = root.join("src-tauri").join("target").join("release");
        fs::create_dir_all(&exe_dir).unwrap();
        let dev = root.join("sidecar").join("main.mjs");
        touch(&dev);
        let got = resolve_sidecar_path(None, Some(&exe_dir), &root);
        assert_eq!(got.canonicalize().unwrap(), dev.canonicalize().unwrap());
        let _ = fs::remove_dir_all(&root);
    }

    #[test]
    fn sidecar_explicit_override_wins() {
        let dir = scratch("explicit");
        let explicit = dir.join("custom").join("main.mjs");
        let got = resolve_sidecar_path(Some(explicit.clone()), Some(&dir), &dir);
        assert_eq!(got, explicit);
        let _ = fs::remove_dir_all(&dir);
    }
}
