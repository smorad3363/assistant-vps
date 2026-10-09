# Port Manager V2 — Tunnel Edition (DEVELOPMENT)

> **NOT READY FOR PRODUCTION.** Current version: `2.0.0-dev.1`.
> Phase-1 bootstrap only. No tunnel, NAT, shaping or telemetry is implemented.
> It installs **disabled** systemd unit templates but never starts or enables them.

Port Manager V2 is a separate IPv4 NAT-forwarding application to be developed
alongside the original Port Manager V1. **NAT is not an encrypted VPN.**

### Version routing (master URLs become valid only after acceptance & merge)

Original V1 command (permanently unchanged):

```bash
curl -fsSL https://raw.githubusercontent.com/smorad3363/assistant-vps/master/portmanager-dashboard/install.sh | sudo bash
```

New V1 alias:

```bash
curl -fsSL https://raw.githubusercontent.com/smorad3363/assistant-vps/master/portmanager-v1/install.sh | sudo bash
```

V2 independent installer, reserved until release gates pass:

```bash
curl -fsSL https://raw.githubusercontent.com/smorad3363/assistant-vps/master/portmanager-v2/install.sh | sudo bash
```

On this development branch, the bootstrap may be tried **in an isolated VM
only**, using a pinned commit in `PORTMANAGER2_REF`. Never run on production.

### Safe current commands
- `portmanager2 --version`
- `portmanager2 help`
- `portmanager2 doctor --json` (read only; unsupported checks labeled)
- `portmanager2 status --json`
- `portmanager2 limits list --json` (reports unavailable)
- `portmanager2 uninstall --dry-run`
- `sudo portmanager2 uninstall --yes` (removes only verified V2 units
  and V2 launcher/release; retains V2 config/data)
- `sudo portmanager2 uninstall --purge` (interactive double confirmation)

All unfinished tunnel, traffic and bandwidth-changing commands return
`E_UNSUPPORTED` (exit 8) **without making network changes**.

See [implementation checkpoints](docs/PROGRESS.md) and
[architecture](docs/ARCHITECTURE.md). Stable release is gated on AT-001..040,
VM/netns TCP/UDP tests, SSH protection and V1 coexistence checks.
