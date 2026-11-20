# Architecture and roadmap

## Control plane

~~~text
Mac Tauri WebView -> Tauri IPC -> ToolRegistry -> approvals -> tools
                     |                ^
                     v                |
                   AgentState --------+
                     ^
iPhone (future) -> WireGuard utun -> axum 10.8.0.1:8080
~~~

The HTTP listener runs as a normal user inside Tauri. Only a future
dedicated launchd service will own privileged network configuration.
Every HTTP tool request is checked against the TCP peer socket IP and
a Keychain-backed bearer token. X-Forwarded-For is intentionally ignored.

The remote phone needs both an authorized WireGuard peer and an API
token obtained from a later secure local pairing ceremony. A WireGuard
peer public key alone does not grant tool authorization. API clients
cannot change file roots, approval policies, or secrets remotely.

## Project phases

| Phase | Goal | Current |
| --- | --- | --- |
| 0 | Tauri shell, tray, WebView, DMG | Scaffold committed, CI pending |
| 1 | Local Axum, file/shell tools, approvals, Keychain | Deterministic tool dispatch; no model or MCP yet |
| 2 | WireGuard daemon, per-phone peers, QR pairing | Pure config renderer only |
| 3 | launchd + privileged network service | Not implemented |
| 4 | Quick-ask, schedules, per-account settings | Not implemented |
| 5 | pf firewall, NAT, rotation, signing, updater | Not implemented |

## Release security gates

1. Use one peer per phone, a /32 server AllowedIPs entry, a per-peer
   preshared key when available, and an operator-controlled revoke UI.
2. Never expose the Axum listener on en0 or the wildcard address.
3. Keep root-owned launchd networking separate from the Tauri user
   process; modern ServiceManagement APIs are preferable for helpers.
4. Own a discrete pf anchor, apply/revert rules atomically, and test
   routing changes with uplink switching, reboot, and power loss.
5. Verify DNS, NAT, IPv6 fail-closed policy and full-tunnel Safari on
   cellular as distinct tests from agent API reachability.
6. Add an rmcp catalog and account-scoped credential store before
   claiming MCP support.
7. Define a model inference adapter and conversation orchestration
   explicitly before describing HTTP /chat as autonomous inference.

## Upstream reference and license

[Proton Lumo Desktop](https://github.com/ProtonLumo/lumo-desktop) is
GPL-3.0-only. This code follows a *similar architecture pattern* without
copying source files or embedding the Proton application. Any future
import of upstream code must be evaluated for GPL and notice obligations.
