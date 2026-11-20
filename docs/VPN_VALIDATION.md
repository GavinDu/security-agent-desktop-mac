# VPN integration acceptance plan (not yet executed)

The first implementation only renders configuration text. This
checklist becomes executable after a launchd-managed wireguard-go daemon
and verified macOS pf ownership have been implemented. Do not enable
global forwarding or pf on a production Mac until reversibility is
confirmed.

1. Start a privileged WireGuard service; verify a macOS **utun**
   interface owns 10.8.0.1/24 and UDP 51820 is listening. Note that
   wg0 is Linux naming; macOS uses utun interfaces.
2. Enroll a phone's unique public key with /32 AllowedIPs and a
   corresponding phone private key kept in iOS Keychain. Test a
   handshake using **cellular**, not same-LAN Wi-Fi.
3. Verify the tunnel reaches GET http://10.8.0.1:8080/health and
   authenticated POST /tools, with a desktop approval shown for bash.
4. Scan port 8080 from a second LAN machine without a tunnel. It must
   not be reachable. An otherwise eligible tunnel source without a
   bearer token must receive 401.
5. In split mode (AllowedIPs 10.8.0.0/24), Safari should continue to
   browse using normal cellular service if the Mac VPN stops.
6. In full mode (AllowedIPs 0.0.0.0/0, ::/0), test IPv4 forwarding,
   scoped pf NAT on the actual outbound interface, DNS resolution,
   and Safari public internet access. Confirm IPv6 cannot bypass the
   tunnel; without IPv6 forwarding, enforce a fail-closed policy.
7. Restart the Mac, change uplink interface, revoke a phone, then stop
   the daemon. Confirm reboot reconnect, revoke enforcement and no
   orphaned NAT, DNS, or forwarding configuration.

**Classic failure to detect**: the local agent at 10.8.0.1:8080 is
reachable while Safari fails in full mode because forwarding, pf NAT
or DNS is missing. Keep the tests separate.
