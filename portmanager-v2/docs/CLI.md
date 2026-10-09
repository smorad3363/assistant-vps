# Port Manager V2 — 2.1.0-rc.3

## Install

```bash
curl -fsSL https://raw.githubusercontent.com/smorad3363/assistant-vps/master/portmanager-dashboard/install.sh | sudo bash
# Original V1 instead:
curl -fsSL https://raw.githubusercontent.com/smorad3363/assistant-vps/master/portmanager-dashboard/install.sh | sudo bash -s -- v1
```

## Network and tunnel management

```bash
sudo portmanager2
sudo portmanager2 doctor --json
sudo portmanager2 tunnel list --json
sudo portmanager2 tunnel create --name demo --listen-ip 192.0.2.11 --interface eth0 --protocol tcp,udp --mode ports --mapping 443:8443,2053:2053 --target-ip 198.51.100.10 --dry-run
sudo portmanager2 tunnel create --name demo --listen-ip 192.0.2.11 --interface eth0 --protocol tcp,udp --mode ports --mapping 443:8443,2053:2053 --target-ip 198.51.100.10
sudo portmanager2 tunnel check --json
sudo portmanager2 tunnel apply
sudo portmanager2 tunnel delete <uuid> --yes
```

All-except requires `--ack-all-ports` and dedicated exclusions for SSH/admin
ports, and produces a unique 120-second rollback confirmation token.

## Per-port 10-minute live graph

```bash
sudo portmanager2 graph --refresh 5 --window 10m
sudo portmanager2 graph --refresh 10 --all-ports
sudo portmanager2 graph --refresh 5 --once --json
sudo portmanager2 live --interval 5
sudo portmanager2 report --window 1h --json
```

## Timed upload/download port limits

Use menu option **05** or create a JSON schedule with fields listed in
[ADR-0003](ADR-0003-SCHEDULED-LIMITS.md).

```bash
sudo portmanager2 limits list --json
sudo portmanager2 limits schedule-preview --file /tmp/my-schedule.json --json
sudo portmanager2 limits schedule-install --file /tmp/my-schedule.json --json
sudo portmanager2 limits schedule-list --json
sudo portmanager2 limits schedule-apply
```

The installer automatically activates V2 systemd sample timer on a successful
schedule installation. A **V1 installation** or foreign clsact/filters causes
an explicit ownership conflict and no rate write. Policing may DROP packets.

## Lifecycle and rollback

```bash
sudo portmanager2 backup create
sudo portmanager2 backup list
sudo portmanager2 confirm <pending-uuid>
sudo portmanager2 rollback-pending <pending-uuid>
sudo portmanager2 uninstall --dry-run
sudo portmanager2 uninstall --yes
sudo portmanager2 uninstall --purge   # requires interactive second confirmation
```

Never use broad `iptables -F` or `tc qdisc del ... root` to repair V2.
