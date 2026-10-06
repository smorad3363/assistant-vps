# Port Manager Dashboard

Combined per-port bandwidth monitor/limiter + per-interface network dashboard.

## Features

- Per-port live bandwidth monitoring
- tc bandwidth limits
- INPUT / OUTPUT / FORWARD accounting
- NAT/conntrack-aware port accounting
- Per-interface RX/TX dashboard
- Refreshes every 1 second
- Rolling 1-minute average
- 60-second terminal graphs
- Saved network averages for 1h / 24h / 7d reports

## One-line install

```bash
curl -fsSL https://raw.githubusercontent.com/smorad3363/assistant-vps/master/portmanager-dashboard/install.sh | sudo bash
```

Then run:

```bash
portmanager
```

The installer validates the script with `bash -n` before installing it to `/usr/local/bin/portmanager`.
