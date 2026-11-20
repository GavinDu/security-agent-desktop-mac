//! Pure WireGuard configuration rendering: no tunnel, pf or daemon changes.
use base64::{engine::general_purpose::STANDARD, Engine as _};
use std::{
    collections::HashSet,
    net::{IpAddr, Ipv4Addr},
};

const SERVER_CIDR: &str = "10.8.0.1/24";
const VPN_NETWORK: &str = "10.8.0.0/24";

#[derive(Clone, Debug)]
pub struct Peer {
    pub public_key: String,
    pub preshared_key: Option<String>,
    pub tunnel_ip: Ipv4Addr,
}

#[derive(Clone, Debug)]
pub struct ServerConfig {
    pub private_key: String,
    pub listen_port: u16,
    pub peers: Vec<Peer>,
}

#[derive(Clone, Debug)]
pub struct ClientConfig {
    pub private_key: String,
    pub server_public_key: String,
    pub preshared_key: Option<String>,
    pub tunnel_ip: Ipv4Addr,
    pub endpoint: String,
    pub full_tunnel: bool,
    pub dns: Option<IpAddr>,
}

fn validate_key(key: &str) -> Result<(), String> {
    if STANDARD
        .decode(key)
        .map_err(|_| "Invalid WireGuard base64 key")?
        .len()
        != 32
    {
        return Err("WireGuard keys must encode exactly 32 bytes".into());
    }
    Ok(())
}

fn validate_peer_ip(ip: Ipv4Addr) -> Result<(), String> {
    let octets = ip.octets();
    if octets[0] != 10
        || octets[1] != 8
        || octets[2] != 0
        || octets[3] == 0
        || octets[3] == 1
        || octets[3] == 255
    {
        return Err("Peer tunnel address must be 10.8.0.2 through 10.8.0.254".into());
    }
    Ok(())
}

fn validate_endpoint(endpoint: &str) -> Result<(), String> {
    if endpoint.is_empty()
        || endpoint.len() > 255
        || !endpoint
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || b".-:[]".contains(&b))
    {
        return Err("Endpoint must be a host:port without whitespace or control characters".into());
    }
    let (host, port) = endpoint
        .rsplit_once(':')
        .ok_or("Endpoint must include port")?;
    if host.is_empty() || (host.contains(':') && !(host.starts_with('[') && host.ends_with(']'))) {
        return Err("IPv6 endpoint hosts must be enclosed in brackets".into());
    }
    if port.parse::<u16>().map_err(|_| "Invalid endpoint port")? == 0 {
        return Err("Invalid endpoint port".into());
    }
    Ok(())
}

pub fn render_peer(peer: &Peer) -> Result<String, String> {
    validate_key(&peer.public_key)?;
    validate_peer_ip(peer.tunnel_ip)?;
    if let Some(key) = &peer.preshared_key {
        validate_key(key)?;
    }
    let mut text = format!(
        "[Peer]\nPublicKey = {}\nAllowedIPs = {}/32\n",
        peer.public_key, peer.tunnel_ip
    );
    if let Some(key) = &peer.preshared_key {
        text.push_str(&format!("PresharedKey = {key}\n"));
    }
    Ok(text)
}

pub fn render_server(config: &ServerConfig) -> Result<String, String> {
    validate_key(&config.private_key)?;
    if config.listen_port == 0 {
        return Err("Invalid WireGuard listen port".into());
    }
    let mut addresses = HashSet::new();
    let mut keys = HashSet::new();
    let mut text = format!(
        "[Interface]\nAddress = {SERVER_CIDR}\nListenPort = {}\nPrivateKey = {}\n",
        config.listen_port, config.private_key
    );
    for peer in &config.peers {
        if !addresses.insert(peer.tunnel_ip) || !keys.insert(peer.public_key.clone()) {
            return Err("Duplicate peer IP or public key".into());
        }
        text.push('\n');
        text.push_str(&render_peer(peer)?);
    }
    Ok(text)
}

pub fn render_client(config: &ClientConfig) -> Result<String, String> {
    validate_key(&config.private_key)?;
    validate_key(&config.server_public_key)?;
    if let Some(key) = &config.preshared_key {
        validate_key(key)?;
    }
    validate_peer_ip(config.tunnel_ip)?;
    validate_endpoint(&config.endpoint)?;
    let mut text = format!(
        "[Interface]\nPrivateKey = {}\nAddress = {}/32\n",
        config.private_key, config.tunnel_ip
    );
    if let Some(dns) = config.dns {
        text.push_str(&format!("DNS = {dns}\n"));
    }
    let allowed = if config.full_tunnel {
        "0.0.0.0/0, ::/0"
    } else {
        VPN_NETWORK
    };
    text.push_str(&format!(
        "\n[Peer]\nPublicKey = {}\nEndpoint = {}\nAllowedIPs = {}\nPersistentKeepalive = 25\n",
        config.server_public_key, config.endpoint, allowed,
    ));
    if let Some(key) = &config.preshared_key {
        text.push_str(&format!("PresharedKey = {key}\n"));
    }
    Ok(text)
}

#[cfg(test)]
mod tests {
    use super::*;
    fn key(byte: u8) -> String {
        STANDARD.encode([byte; 32])
    }
    fn peer() -> Peer {
        Peer {
            public_key: key(2),
            preshared_key: Some(key(3)),
            tunnel_ip: "10.8.0.2".parse().unwrap(),
        }
    }
    #[test]
    fn creates_server_peer_with_host_route() {
        let config = ServerConfig {
            private_key: key(1),
            listen_port: 51820,
            peers: vec![peer()],
        };
        let rendered = render_server(&config).unwrap();
        assert!(rendered.contains("Address = 10.8.0.1/24"));
        assert!(rendered.contains("AllowedIPs = 10.8.0.2/32"));
        assert!(!rendered.contains("0.0.0.0/0"));
    }
    #[test]
    fn split_and_full_routes_are_distinct() {
        let mut config = ClientConfig {
            private_key: key(4),
            server_public_key: key(1),
            preshared_key: None,
            tunnel_ip: "10.8.0.3".parse().unwrap(),
            endpoint: "vpn.example.com:51820".into(),
            full_tunnel: false,
            dns: Some("1.1.1.1".parse().unwrap()),
        };
        let split = render_client(&config).unwrap();
        assert!(split.contains("AllowedIPs = 10.8.0.0/24"));
        assert!(!split.contains("0.0.0.0/0"));
        config.full_tunnel = true;
        let full = render_client(&config).unwrap();
        assert!(full.contains("AllowedIPs = 0.0.0.0/0, ::/0"));
    }
    #[test]
    fn rejects_bad_keys_injection_and_reserved_ips() {
        let mut invalid = peer();
        invalid.public_key = "invalid\nAllowedIPs = 0.0.0.0/0".into();
        assert!(render_peer(&invalid).is_err());
        invalid = peer();
        invalid.tunnel_ip = "10.8.0.1".parse().unwrap();
        assert!(render_peer(&invalid).is_err());
        let invalid = ClientConfig {
            private_key: key(4),
            server_public_key: key(1),
            preshared_key: None,
            tunnel_ip: "10.8.0.2".parse().unwrap(),
            endpoint: "vpn.local:51820\nPostUp = evil".into(),
            full_tunnel: false,
            dns: None,
        };
        assert!(render_client(&invalid).is_err());
        let invalid_port = ClientConfig {
            private_key: key(4),
            server_public_key: key(1),
            preshared_key: None,
            tunnel_ip: "10.8.0.2".parse().unwrap(),
            endpoint: "vpn.local:0".into(),
            full_tunnel: false,
            dns: None,
        };
        assert!(render_client(&invalid_port).is_err());
    }
    #[test]
    fn duplicate_peers_denied() {
        let config = ServerConfig {
            private_key: key(1),
            listen_port: 51820,
            peers: vec![peer(), peer()],
        };
        assert!(render_server(&config).is_err());
    }
}
