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

## Menu uninstall (data can survive reinstallation)

Run `sudo portmanager`, choose **[9]**, then choose:
- **Yes**: uninstall V2 and its owned system rules but keep the configuration,
  previous traffic reports and database; reinstall automatically reloads them.
- **No**: uninstall V2 and all its data; reinstall initializes from zero.

No second confirmation or typed phrases. The direct uninstall command asks
the same question:

```bash
curl -fsSL https://raw.githubusercontent.com/smorad3363/assistant-vps/master/portmanager-dashboard/install.sh | sudo bash -s -- uninstall
```

Add `--yes --keep-data` or `--yes --purge-data` to choose noninteractively.
`--dry-run` previews only. Unrelated iptables, tc, GRE, Docker, UFW or
standalone legacy V1 artifacts are not reset.

