// Hide the console window on Windows in release.
#![cfg_attr(not(debug_assertions), windows_subsystem = "windows")]

fn main() {
    easylock_gui_lib::run();
}
