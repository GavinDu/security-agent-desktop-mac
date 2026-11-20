use crate::{
    navigation,
    vpn::config::{self, Peer},
};
use std::net::Ipv4Addr;
use tauri::WebviewWindow;

/// Preview only: peer enrollment must be done by a privileged daemon with
/// local operator confirmation; private keys never cross this IPC.
#[tauri::command]
pub fn preview_wireguard_peer(
    window: WebviewWindow,
    public_key: String,
    tunnel_ip: String,
) -> Result<String, String> {
    navigation::ensure_privileged_webview(&window)?;
    let address: Ipv4Addr = tunnel_ip.parse().map_err(|_| "Invalid peer IPv4 address")?;
    config::render_peer(&Peer {
        public_key,
        preshared_key: None,
        tunnel_ip: address,
    })
}
