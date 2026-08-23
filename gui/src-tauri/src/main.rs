// Prevent a console window from opening in release builds.
#![cfg_attr(not(debug_assertions), windows_subsystem = "windows")]

fn main() {
    claude_aegis_gui_lib::run()
}
