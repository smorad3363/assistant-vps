# Port Manager V2 command reference — 2.0.0-dev.1

The authoritative user story is
[PM2-SPEC-001](PM2-SPEC-001.fa.md). CLI commands work only on an isolated
test VM while V2 is in development. A plain `portmanager2` opens the
interactive text menu on a TTY.

## Read-only

```bash
portmanager2 --version
portmanager2 help
portmanager2 doctor --json
portmanager2 status --json
portmanager2 tunnel list --json
portmanager2 tunnel show <uuid> --json
portmanager2 tunnel check --json
portmanager2 limits list --json
portmanager2 report --window 1h --json
portmanager2 report --window 24h --json
portmanager2 report --window 7d --json
portmanager2 logs --lines 100
portmanager2 live --interval 1
portmanager2 backup list
portmanager2 uninstall --dry-run
```

## Tunnel changes (root; network mutation unless `--dry-run`)

```bash
sudo portmanager2 tunnel create --name demo --listen-ip 192.0.2.11 --interface eth0 --protocol tcp,udp --mode ports --mapping 443:8443,2053:2053 --target-ip 198.51.100.10 --dry-run
sudo portmanager2 tunnel create --name demo --listen-ip 192.0.2.11 --interface eth0 --protocol tcp,udp --mode ports --mapping 443:8443,2053:2053 --target-ip 198.51.100.10
sudo portmanager2 tunnel update <uuid> --name demo --listen-ip 192.0.2.11 --interface eth0 --protocol tcp,udp --mode ports --mapping 443:8443 --target-ip 198.51.100.10
sudo portmanager2 tunnel enable <uuid>
sudo portmanager2 tunnel disable <uuid>
sudo portmanager2 tunnel delete <uuid> --yes
sudo portmanager2 tunnel apply
```

`all-except` example (test VM only; port 22 **must** be excluded,
additional real SSH/service ports should be excluded):

```bash
sudo portmanager2 tunnel create --name wide --listen-ip 192.0.2.11 --interface eth0 --protocol tcp,udp --mode all-except --exclude 22,2222,443 --target-ip 198.51.100.10 --ack-all-ports
# Save pending_confirmation from the response and confirm ONLY after testing access:
sudo portmanager2 confirm <pending_confirmation-uuid>
# Or explicitly revert:
sudo portmanager2 rollback-pending <pending_confirmation-uuid>
```

Network-protected operations prearm a 120-second rollback watchdog.
Never enable a new all-except rule without independent console access.

## Lifecycle, traffic, backup and removal

```bash
sudo portmanager2 sample
sudo portmanager2 restore
sudo portmanager2 backup create
sudo portmanager2 backup restore <backup-id> --dry-run
sudo portmanager2 backup restore <backup-id>
sudo portmanager2 uninstall --yes
sudo portmanager2 uninstall --purge    # requires interactive extra confirmation
```

`PORTMANAGER2_ENABLE_SERVICES=1` opt-in at install activates only owned
`portmanager2-restore.service` and `portmanager2-sample.timer`.
`portmanager2` does not modify V1 `portmanager` or `PORTMANAGER_ACCT`.
Bandwidth shaping mutations intentionally return an error; 2.0 has no `tc`
root/ingress changes. JSON responses use `ok`, `code`, `message`,
`details`, `request_id`; see the spec for the error codes.

A refused `E_CONFLICT` / `E_ROLLBACK` must never be worked around with
global `iptables -F`. Preserve configuration/journal/iptables evidence and
investigate ownership on the isolated VM.
