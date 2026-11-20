#![cfg_attr(not(debug_assertions), windows_subsystem = "windows")]

fn main() {
    security_agent_desktop_mac::run();
}
