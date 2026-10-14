#![cfg_attr(not(debug_assertions), windows_subsystem = "windows")]

#[cfg(feature = "gui")]
fn main() {
    guardbuild_lib::gui::run();
}

#[cfg(not(feature = "gui"))]
fn main() {
    eprintln!("guardbuild GUI 未编译（缺少 `gui` feature）。请使用 `cargo build --features gui`，或使用 guardbuild-headless。");
    std::process::exit(1);
}
