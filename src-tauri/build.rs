fn main() {
    // 仅 GUI 构建需要 tauri-build（生成 context/资源）；无头构建跳过，
    // 保证 --no-default-features 下不引入 Tauri 构建链。
    if std::env::var_os("CARGO_FEATURE_GUI").is_some() {
        tauri_build::build()
    }
}
