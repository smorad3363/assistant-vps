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
