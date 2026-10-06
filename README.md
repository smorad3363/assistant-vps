# GRE Link Tool

Persistent GRE setup, bidirectional iperf3 testing, editable tunnel settings, automatic self-update, and a systemd watchdog with automatic tunnel repair.

## Permanent install/update command

Use this same command every time:

```bash
curl -fsSL https://raw.githubusercontent.com/smorad3363/assistant-vps/master/gre-link-tool.sh -o /tmp/gre-link-tool.sh && sudo install -m 755 /tmp/gre-link-tool.sh /usr/local/bin/gre-link-tool && sudo gre-link-tool
```

After the first installation, you can normally run:

```bash
sudo gre-link-tool
```

Every normal run checks the GitHub raw script first. If it changed, the tool validates the downloaded Bash script, installs it to `/usr/local/bin/gre-link-tool`, and continues with the updated copy.

## Tunnel watchdog

The GRE setup installs and enables:

- `gre-link-tool.service` — persistent GRE tunnel.
- `gre-link-tool-watchdog.service` — health check and automatic repair.
- `gre-link-tool-watchdog.timer` — periodic checks.

Defaults:
- Check interval: 30 seconds.
- Automatic repair after: 3 consecutive failures.

## Edit mode

Menu option **5** edits and reapplies the saved configuration, including:

- Local and peer public IPv4 addresses.
- GRE interface name.
- Local tunnel CIDR and peer tunnel IP.
- GRE MTU.
- iperf3 test port and UDP target rate.
- Forwarding enable/disable, protocol, and port.
- Watchdog enable/disable, interval, and failure threshold.
