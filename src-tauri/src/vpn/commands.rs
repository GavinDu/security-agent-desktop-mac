use std::net::Ipv4Addr;
use crate::vpn::config::{self, Peer};

/// Preview only: peer enrollment must be done by a privileged daemon with
/// local operator confirmation; private keys never cross this IPC.
#[tauri::command]
pub fn preview_wireguard_peer(public_key: String, tunnel_ip: String) -> Result<String, String> {
    let address: Ipv4Addr = tunnel_ip.parse().map_err(|_| "Invalid peer IPv4 address")?;
    config::render_peer(&Peer { public_key, preshared_key: None, tunnel_ip: address })
}
