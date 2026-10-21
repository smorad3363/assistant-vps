# GRE Tunnel Manager

**Release: 0.2.2-dev / NOT PRODUCTION READY.** Contract version: 1.0.0.

The Python standard-library CLI stores desired tunnel and port-forward definitions, exchanges bounded setup tokens, validates the local structure, and reads per-forward SQLite traffic histories. A native GRE / nftables engine has been prototyped but **live activation is restricted to an explicitly marked disposable lab**. The HTB/IFB shaping, independent 60-second rollback, and two-ended Ubuntu VM acceptance gates are not complete. Do not replace a working GRE deployment with this release.

## Permanent, unchanged installation AND update command

```bash
curl -fsSL https://raw.githubusercontent.com/smorad3363/assistant-vps/master/gre-tun/install.sh | sudo bash
```

The URL is permanent: the `master/gre-tun/install.sh` file remains the public entry point for both initial installation and all subsequent updates. This development installer verifies a complete SHA256 inventory, tests the downloaded source, checks path ownership and atomically swaps only the owned application source. Configuration and SQLite history are kept outside `/opt/gre-tun`. It installs official Ubuntu dependencies if missing. It does **not** enable any new GRE forwarding on installation. Run only on Ubuntu Server 22.04/24.04 with systemd.

After installation:

```bash
sudo gre-tun
sudo gre-tun --version
sudo gre-tun status --json
sudo gre-tun apply --check
sudo gre-tun stats P0001 --json
sudo systemctl status gre-tun.service --no-pager
```

`gre-tun apply` explicitly refuses live activation on ordinary hosts. The internal experimental reconciler requires *both* an explicit disposable-lab marker and an opt-in environment flag. This intentionally differs from a production-ready package. No production launch command is supplied in this development release.

## What is implemented

- Frozen menu strings and exactly four main actions; local peer configuration and secure-input parsing, e.g. `5445:5454`.
- Atomic, lock-protected desired-state JSON; tunnel/forward numeric IDs and non-reuse within the saved configuration.
- Editing, toggling, and deleting locally defined port mappings; export/import GRE setup tokens.
- Native GRE and nftables policy/NAT rule rendering, local capability/conflict preflight and fail-closed bandwidth rejection. Live backend is experimental and **not yet certified**.
- Named forward accounting counter reader, SQLite intervals, coverage-aware rolling 1h/24h rates; background **read-only accounting daemon**. Current two-second speeds and the supported complete traffic kernel path are NOT RUN.
- Stable installer with source inventory hashes, offline unit tests and no default network activation.

## Tests

```bash
bash RUN_CONTRACT_TESTS.sh
PYTHONPATH=src python3 -m unittest discover -s tests/unit -v
PYTHONPATH=src python3 -m unittest discover -s tests -v
sudo bash tests/integration/run.sh
sudo bash tests/integration/reboot-check.sh
```

The integration scripts refuse unmarked servers and return `77` as NOT RUN; they are not substitutes for two-ended live validation. See `TEST_RESULTS.md`, `IMPLEMENTATION_STATUS.md`, the original spec and tests for remaining acceptance cases.

## Connection tests before any tunnel exists (0.2.2-dev)

`3) Test connection` now works **without a saved tunnel or a role/setup configuration**. Its four choices
are (1) pre-tunnel readiness, (2) existing configured GRE tunnel test,
(3) receive a bounded GRE protocol-47 challenge, and (4) send the challenge.
The four *main* menu choices are unchanged. The readiness test checks
IPv4 route/source interface, public source address, ICMP reachability and
privileges without writing files or network settings. ICMP may be blocked;
**ICMP success does not prove GRE** and passive readiness never claims GRE PASS.

From the Iran host before configuring the tunnel:

```bash
sudo gre-tun test --peer 178.83.45.63
```

To test GRE protocol 47 in **both directions without creating a tunnel**,
open an SSH terminal on each machine. First run on the foreign host:

```bash
sudo gre-tun test --listen --peer IRAN_PUBLIC_IPV4
```

The listener prints a random 32-character token, and waits up to 120 seconds.
Immediately run on the Iran host (replacing TOKEN with the printed token):

```bash
sudo gre-tun test --probe --peer 178.83.45.63 --token TOKEN
```

A matching response reports `GRE path: PASS` on the sender; the listener
reports reception of the same challenge. A timeout reports `UNVERIFIED`,
never a false success. Neither mode creates a tunnel, address, route, firewall
rule, NAT rule, qdisc or persistent process. Each uses an in-memory raw IPv4
socket for a few seconds, requires root/CAP_NET_RAW, and sends a handful of
small experimental-protocol GRE packets. The receiver accepts requests only
from the specified peer and only with the exact random token. A firewall may
filter protocol 47; allowing a TCP/UDP *port* numbered 47 does not allow GRE.

This test is evidence of **GRE protocol-47 traversal**, not proof that keyed
GRE configuration, MTU, NAT, port forwarding or speed caps will work. Those
still require an active disposable lab and two-endpoint traffic tests.

If a tunnel is already saved, choice (2) checks the recorded owned interface
and bounded inner ICMP. `gre-tun test all` retains its prior semantics.
Passive `gre-tun test --peer IP` exits 7 if readiness is inconclusive, 6 on a
local route failure. Active GRE tests return 0 only for a matching authenticated
challenge, 7 when they cannot verify passage.

**This remains a development build: storing a tunnel does not activate it.**
