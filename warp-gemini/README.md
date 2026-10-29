# Gemini WARP Local Proxy for VPS Nodes

Install/reapply Cloudflare WARP **without replacing the server's default route**. Designed for Ubuntu/Debian servers running Xray, Marzban Node or other VPN services. The WARP client runs as an isolated **SOCKS5** proxy at 127.0.0.1:40000. Installation does **not** edit Docker, Xray, Marzban, GRE, UFW, iptables or existing forwarding rules.

## Permanent install / update command

This URL and command stay the same for future releases:

```bash
curl -fsSL https://raw.githubusercontent.com/smorad3363/assistant-vps/master/warp-gemini/install.sh | sudo bash
```

**By running this installer, you accept Cloudflare WARP's terms of service.** Review the upstream terms before using on additional servers.

For an existing registered WARP client, the installer preserves its registration and refuses to replace a non-proxy mode or change an already configured proxy port. Repeated installation is idempotent. If 40000 is unavailable, set `WARP_PORT` through the environment (for example, for a script saved locally use `sudo env WARP_PORT=40001 bash install.sh`). Supported distributions depend on Cloudflare's official apt repository availability for their codename.

## Test WARP without touching regular user traffic

```bash
warp-cli status
curl -fsS --socks5-hostname 127.0.0.1:40000 https://www.cloudflare.com/cdn-cgi/trace | grep -E '^(ip|loc|warp)='
curl -fsS https://www.cloudflare.com/cdn-cgi/trace | grep -E '^(ip|loc|warp)='
```

The SOCKS request should return `warp=on`; the direct request should return `warp=off`. A healthy WARP connection is **not** proof that authenticated Gemini chat works in your account or country; test real chat separately.

To get read-only Xray/RAM diagnostics, use:

```bash
curl -fsSL https://raw.githubusercontent.com/smorad3363/assistant-vps/master/warp-gemini/install.sh | sudo bash -s -- diagnose
```

## Optional Xray/Marzban routing (not automatically installed)

A Marzban node receives its Xray configuration from its master. To make **connected VPN clients** use WARP for Gemini, configure the following SOCKS5 outbound **in the authoritative Xray configuration**, then add the routing rule **ahead of broad catch-all rules**. The installer deliberately does not modify live Xray, because the panel could overwrite local edits or cause disconnections.

Outbound object to add to the `outbounds` list:

```json
{
  "tag": "warp-gemini",
  "protocol": "socks",
  "settings": {
    "servers": [
      {"address": "127.0.0.1", "port": 40000}
    ]
  }
}
```

Routing rule to add to `routing.rules`:

```json
{
  "type": "field",
  "domain": [
    "full:gemini.google.com",
    "domain:generativelanguage.googleapis.com",
    "domain:aisandbox-pa.googleapis.com",
    "domain:alkalimakersuite-pa.clients6.google.com"
  ],
  "outboundTag": "warp-gemini"
}
```

These domains are a starting point, not a guaranteed complete list of endpoints for every Gemini product version. DNS/sniffing must make domain matching possible; check actual application behavior and expand only on evidence. Xray SOCKS outbound runs on **the host running Xray** (same host network namespace as `warp-svc`), not automatically on every other Marzban node. On multi-node deployments, install and validate WARP separately on each node you want to route through it. Some long-lived requests, streaming or UDP/QUIC may be unsuitable for WARP proxy mode. Do not route all Google or all VPN traffic to WARP by default.

## Reliability and troubleshooting

* The Cloudflare WARP service is managed by `warp-svc` and its own systemd unit.
* This installer does not update or restart Xray. It does not fix memory growth, old Xray versions or excessive connection counts.
* If Xray memory is growing rapidly, investigate simultaneous connections, socket states, out-of-memory kills and Xray version **before** introducing more routing.
* WARP is **not** a country selector and may not resolve Gemini's country/account restrictions.
* Use `sudo warp-cli disconnect` to stop WARP without modifying the VPN's regular internet route.
* Direct/Proxy routing can be checked with `ip -4 route get 1.1.1.1` and the Cloudflare trace endpoint.

Official references: https://developers.cloudflare.com/warp-client/get-started/linux/ and https://developers.cloudflare.com/warp-client/warp-modes/


## Interactive node manager

After running the permanent installer, run:

```bash
sudo warp-menu
```

The menu supports:
1. List domain rules and current saved settings.
2. Add one or multiple domains (comma-separated, defaults to `domain:example.com`; `full:example.com` matches only the exact hostname).
3. Remove individual domains by number or name.
4. Toggle WARP routing in Xray (changes take effect at Apply).
5. Compare the host's direct IPv4 with WARP's current exit IP, country, and connection health.
6. Disconnect/reconnect **only the WARP tunnel** and compare exit IP before/after. A different IP or country cannot be guaranteed.
7. Compare Gemini and AI Studio HTTP reachability over direct and WARP paths.
8. Install a non-invasive per-node Xray executable overlay in an additional Compose override file, without restarting.
9. Apply saved rules by recreating the Marzban Node container. **This temporarily disconnects ALL clients on that node and requires the Marzban master to reconnect.** A typed `APPLY` confirmation is required.
10. Run diagnostics.
11. Inspect **live Xray rules** and compare them with the saved domain list, without showing user/secret configuration.

CLI equivalents for scripts:

```bash
sudo warp-menu status
sudo warp-menu domains
sudo warp-menu live
sudo warp-menu test
sudo warp-menu diagnose
```

On the tested deployment, the host uses `/opt/master/docker-compose.yml` for the `marzban-node` service. The integration adds `/opt/master/docker-compose.override.yml` and mounts a dedicated Xray executable wrapper. It does **not** modify Marzban core source code or the original Compose file. Per-node rules live in `/var/lib/master/warp-gemini.json`, an already mounted host directory. This implementation requires the Node container to share the host network namespace so SOCKS5 at `127.0.0.1:40000` is reachable.

The executable wrapper applies the local domains and WARP SOCKS5 outbound each time Marzban sends a new Xray configuration. It preserves the Marzban API route ahead of domain rules. It passes configuration through an anonymous memory file descriptor instead of persisting the combined configuration on disk. The real Xray binary is unchanged. The wrapper uses an **absolute interpreter path** because Marzban Node launches Xray with a restricted environment.

**Safety notes:** Other Marzban Node installations may use a different Compose path or service name. The manager intentionally refuses unknown layouts or conflicts with an existing Compose override. Use a maintenance window for Apply on high-traffic nodes. Test authenticated Gemini chats separately; HTTP 200 and `warp=on` do not ensure account eligibility.

### Rollback per-node Xray routing without uninstalling WARP

Only if your Compose override belongs to this manager and you intend to remove its routing integration:

```bash
sudo mv /opt/master/docker-compose.override.yml /opt/master/docker-compose.override.yml.disabled
cd /opt/master
sudo docker compose up -d --no-deps --force-recreate marzban-node
```

This requires the master to reconnect and interrupts active user connections. The WARP local proxy and saved rules remain available for future reactivation.


## Optional forced IPv4 egress for Gemini

The Cloudflare WARP SOCKS5 server may choose an IPv6 egress address when it receives a **domain name**. Disabling IPv6 on the Ubuntu host does not change the egress family selected by WARP.

The local node's Xray 25.3.6 accepts `targetStrategy=UseIPv4` on a SOCKS outbound but in live testing that setting alone still resulted in IPv6 egress. The proven route is:

```text
Gemini domain -> Xray Freedom (ForceIPv4) -> Xray SOCKS5 -> Cloudflare WARP -> destination
```

To control this, run `sudo warp-menu` and use **12** to toggle forced IPv4 egress. Use **13** to enable domain Sniffing for an existing Trojan inbound on port 2053. Use **9** to apply saved changes; **this recreates the node and temporarily disconnects all its clients**. Option 11 shows the live effective settings after reconnection.

You can compare WARP egress families **without Xray changes**:

```bash
# SOCKS server resolves the hostname; IPv6 egress is possible.
curl -fsS --socks5-hostname 127.0.0.1:40000 https://www.cloudflare.com/cdn-cgi/trace | grep -E '^(ip|loc|warp)='

# Local DNS resolves an IPv4 destination before SOCKS.
curl -4 -fsS --socks5 127.0.0.1:40000 https://www.cloudflare.com/cdn-cgi/trace | grep -E '^(ip|loc|warp)='
```

The two IPs may vary with Cloudflare's routing. The system's default route and other client traffic remain unchanged. Google's country and abuse checks can still block Gemini even with an IPv4 egress; live authenticated chat must be tested.

## Isolated WGCF + WireProxy (real WireGuard tunnel, secondary SOCKS5)

**Important:** Official Cloudflare WARP's **Local Proxy** supports MASQUE only. Attempting to run `warp-cli tunnel protocol set WireGuard` while keeping Local Proxy mode fails with `Proxy mode only supports MASQUE`. This limitation is confirmed by Cloudflare and was reproduced on Ubuntu 26.04. Do not use the old `warp-protocol wireguard` approach.

The supported alternative in this repo is an **independent, unofficial WGCF registration** with userspace WireProxy. It is isolated from the official Cloudflare MASQUE SOCKS5 service:

| Backend | Local bind | Transport | Default route |
| --- | --- | --- | --- |
| Cloudflare official WARP proxy | 127.0.0.1:40000 | MASQUE | Unchanged |
| WGCF + WireProxy | 127.0.0.1:40001 | WireGuard | Unchanged |

Run the permanent one-line installer to install or update the menu and helpers. In `sudo warp-menu`:

- **14**: install the isolated WGCF + WireProxy backend; keeps credentials and configuration on subsequent runs.
- **15**: select Gemini backend port 40000 (official MASQUE) or 40001 (WGCF WireGuard). The selection is saved but does **not** affect active Xray until applied.
- **16**: check WGCF service, exit IP, location and health.
- **9**: apply the changed backend, which recreates Marzban Node and **briefly disconnects all clients**, then requires master reconnection.
- **11**: verify the backend port in the **live Xray configuration**.

WGCF setup is also available via the permanent GitHub file: `sudo wgcf-wireproxy-install install`, and `sudo wgcf-wireproxy-install status`. This installer uses pinned release artifacts **wgcf 2.3.0** and **wireproxy 1.1.3**, verified with SHA-256 release digests. It preserves existing WGCF account keys and verifies `warp=on`. Those keys are private and stored at `/opt/warp-gemini/wgcf-isolated`. A separate `warp-gemini-wgcf-proxy.service` enables it across reboots. It does not edit Xray or other services.

**Important limitation:** On the tested node both independent methods returned the same Cloudflare IPv4 exit, `104.28.193.116`. A different WireGuard transport does not guarantee a different exit IP, an allowed country or Gemini account eligibility. Only a genuine authenticated chat confirms that Gemini works.

Rollback to official MASQUE is available via menu option 15 (select 40000), then apply with option 9. Never use the old global WGCF route-changing installer on the production Marzban/GRE node.

## Optional single-egress Google session test on Trojan 2053

If Gemini displays Google's unusual-traffic page, the existing five Gemini-specific domain rules may route `gemini.google.com` via WARP while related `accounts.google.com` and `www.google.com` use the direct server IP. This is a **possible** source of inconsistent sessions, not proven to be the cause of Google's rate limit.

This project offers a controlled **A/B test limited to the Trojan inbound on port 2053**, leaving port 2096 and other inbounds on their existing routes. Menu **option 17** toggles the experiment; **option 9** applies it and temporarily disconnects all Marzban Node clients while the container is recreated. The tested domain groups on only 2053 are:

- `domain:google.com`
- `domain:googleapis.com`
- `domain:googleusercontent.com`
- `domain:gstatic.com`

The more narrowly targeted original Gemini routing rules remain for the other inbounds. Menu option 11 verifies the live 2053 rule after the master reconnects and starts Xray. **To roll back**, toggle option 17 OFF and apply with option 9. The feature is disabled by default on fresh installs, since redirecting Google search and login traffic for a whole inbound can impact other users.

A matching route does not mean a verified authenticated Gemini chat; the user must try actually sending a chat message. If Google still complains about unusual traffic, **do not keep rotating or stacking WARP IPs**: investigate automated requests from clients, complete any available CAPTCHA, allow rate-limits to expire and consider a clean dedicated egress with appropriate provider policy. See Google's guidance at https://support.google.com/websearch/answer/86640

## Gemini network health monitor (October 2026)

The permanent installer now also installs a **read-only** server-side health monitor. It does not restart WARP, rotate identities, change Gemini routing, recreate the Marzban Node, or edit the firewall.

The `warp-gemini-health.timer` runs about every 20 minutes. It compares the server's direct IPv4, the official WARP SOCKS5 port 40000, and the isolated WGCF/WireProxy SOCKS5 port 40001. It records IPv4 exit IP, Cloudflare country, `warp=on`, public Gemini HTTP status, a Google `/sorry/` redirect, explicit HTTP 403/429 and visible country/unusual-traffic phrases when present.

Run:

```bash
sudo warp-menu
# Option 18: check health now
# Option 19: view last health check

sudo warp-health check
sudo warp-health report
systemctl status warp-gemini-health.timer
```

Logs and state are limited to `/var/lib/warp-gemini/health.json`, `history.jsonl` (event/change-only, capped and rotated), and an optional `history.previous.jsonl`. No credentials, account data, or Gemini chat contents are captured.

**Critical distinction:** Anonymous `gemini.google.com/app` page availability does not prove that Gemini is available to a signed-in user; Google's country/account checks can fail after HTTP 200. Only a real signed-in chat test validates the user's experience. Do not run aggressive automatic WARP IP rotation based on these probes: the two available transports on the tested node both exit at the same Cloudflare IPv4 and indiscriminate switching can disrupt VPN clients or change their Google session IP.

On the tested node, the separate **Google full-route A/B test** is already enabled **only for Trojan port 2053**; port 2096 retains the narrower domain rules. Compare the two VPN profiles during actual signed-in Gemini testing. This A/B rule can be managed with menu option 17 (requires option 9 to apply; that briefly interrupts clients).
