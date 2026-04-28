#![cfg_attr(not(debug_assertions), windows_subsystem = "windows")]

mod engine_bridge;

fn main() {
    tauri::Builder::default()
        .invoke_handler(tauri::generate_handler![engine_bridge::run_engine_bridge_command])
        .run(tauri::generate_context!())
        .expect("failed to run Aegis EV desktop shell");
}
