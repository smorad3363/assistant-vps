# Port Manager — shared version selector

The original one-line URL now installs **22 by default**, and the same URL
with an explicit `v1` argument installs the frozen original Port Manager 21.

**V2 (default)**

```bash
curl -fsSL https://raw.githubusercontent.com/smorad3363/assistant-vps/master/portmanager-dashboard/install.sh | sudo bash
sudo portmanager2
```

**V1 (original release)**

```bash
curl -fsSL https://raw.githubusercontent.com/smorad3363/assistant-vps/master/portmanager-dashboard/install.sh | sudo bash -s -- v1
sudo portmanager
```

**Why not `sudo bash v1`?** Bash interprets `v1` as a filename and
ignores the piped installer. Use `sudo bash -s -- v1` to pass an argument
to a script read from standard input.

V1 is preserved verbatim in
`portmanager-v1/legacy-install.sh`. The original legacy payload
`portmanager-dashboard/portmanager.sh.gz.b64` is not modified.

V2 runs independently from V1, adds IPv4 TCP/UDP NAT tunneling, read-only
live per-port 10-minute moving-average graphs, own traffic reports,
120-second rollback guard and opt-in scheduled per-port tc policing.
The V2 `tc` module refuses to run with V1 installed or with a foreign
clsact; it never touches V1's root qdisc.

**Never deploy rate enforcement on a live VPS without independent console
access, snapshot and a test plan.** See `portmanager-v2/README.md` and
`portmanager-v2/docs/RELEASE-ROUTER.fa.md`.

## Uninstall Port Manager V2 (including owned data)

**First preview the exact removal without changes:**

```bash
curl -fsSL https://raw.githubusercontent.com/smorad3363/assistant-vps/master/portmanager-dashboard/install.sh | sudo bash -s -- uninstall --dry-run
```

**Then remove V2 with confirmation:**

```bash
curl -fsSL https://raw.githubusercontent.com/smorad3363/assistant-vps/master/portmanager-dashboard/install.sh | sudo bash -s -- uninstall
```

For deliberate noninteractive removal, append `--yes` instead. The dedicated implementation is [uninstall.sh](uninstall.sh).

This verifies ownership of the installed V2 release, configuration and data, systemd units, iptables chains, history-monitor counters and tc filters before removal. It clears V2-owned rules and services and permanently deletes V2 configuration, saved statistics, logs, and any integrity-verified archived V1 backup. It does **not** reset unrelated iptables rules, Docker, UFW, GRE, other services, or IPv4 forwarding. It does **not** remove or certify cleanup of any standalone V1 legacy firewall, tc, cron or other resources. An unknown ownership marker, changed firewall rule, foreign chain reference, active V1 executable or active V1 cron job aborts removal rather than guessing. Take a snapshot and use independent console access on production gateways; removing active managed forwarding rules can interrupt traffic.
