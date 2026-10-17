# GRE Tunnel Manager

**Development preview — NOT production ready.**

An independent project intended for Ubuntu 22.04/24.04 to manage several native IPv4 GRE tunnels and individual port mappings. The implementation follows GRE Tunnel Manager contract v1.0.0.

## Permanent installer / updater

The entry point is reserved at this **unchanging** path:

```bash
curl -fsSL https://raw.githubusercontent.com/smorad3363/assistant-vps/master/gre-tun/install.sh | sudo bash
```

At this first GitHub commit the full code has not been uploaded. The bootstrap exits safely without changing the host until the complete tested project tree is published here. Do **not** use as a replacement for existing network management.

When the release is ready, this same command will download the current release, validate it, preserve configuration and historic traffic data, and install/update it in place. Future releases must not change this URL.

## Intended interface

```text
GRE Tunnel Manager

1) Create tunnel
2) Manage tunnels and ports
3) Test connection
4) Uninstall

0) Exit
```

Features required before a production release: bidirectional GRE routing, 5445:5454 source/target port mapping, TCP/UDP/Both, per-port aggregate speed caps, rolling 1h/24h volume and average-speed figures, peer setup tokens, scoped rollback, service recovery, and ownership-safe uninstall.

## Status

- Roadmap and frozen contract package received and checked.
- Offline development snapshot created locally; 47 unit/contract tests passed.
- Full runnable files are **not yet committed to this GitHub folder**.
- Real GRE/NAT/QoS integration tests: NOT RUN.
- Production release: BLOCKED.

Keep all application messages and terminal output in English. Treat external addresses and fixtures as examples only.
