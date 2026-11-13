# GRE Manager 1.0 — web control plane

One installation on Iran provides three pages: **GRE**, **IPTables / direct
forwarding**, and **Settings**. There are no interactive Bash management menus.

```bash
curl -fsSL https://raw.githubusercontent.com/smorad3363/assistant-vps/master/gre.sh | sudo bash
```

The installer prints the HTTPS address and a randomly generated initial password.
Save the password: it is printed only on first installation. The default port is
8787. Initial TLS uses a self-signed certificate; Settings accepts a matching PEM
certificate chain and private key. Use Settings to change the panel port, login
name/password, protected ports, telemetry retention and automatic checks.

Supported initial targets: Linux with root, directly assigned IPv4, systemd, and
apt (Ubuntu 22.04/24.04, Debian) or dnf. GRE requires IP protocol 47 connectivity.
The web interface has no CDN, external fonts, analytics, or JavaScript framework
runtime dependencies. Application code is Python's standard library plus the
host's OpenSSH, Netfilter, iproute2 and OpenSSL commands.

## Connections

**GRE**: add a foreign server with its SSH host, port and root credentials (or an
unencrypted private key). A non-root account needs initial passwordless sudo.
SSH host keys are scanned, pinned to a dedicated known-hosts file and their
fingerprints displayed. The password is used only during bootstrap. Subsequent
operations use a generated Ed25519 key restricted to a forced management command.
The foreign helper has no listening web/API port. Its service restores all saved
peers at boot, including multiple Iran servers sharing the same foreign server.

Select the Iran listen IPv4, foreign GRE endpoint, protocols and ports. Local GRE
IPv4 and foreign service IPv4 may differ from those endpoints; both are editable
under connection details. A remote service IPv4 is supported through direct NAT
on the foreign side, including correct SNAT for its return path. No Xray config
is modified. Domain destinations are resolved when saved; their selected IPv4 is
displayed. Re-saving refreshes DNS, with the normal two-endpoint transaction.

**IPTables**: direct DNAT/SNAT is configured entirely on Iran. No outside SSH
installation is required. The destination service and its firewall must already
accept connections. Direct forwarding creates no encapsulation interface.

Ports accept `all`, lists (`443,1000,51821`) or ranges (`8000-8100`). A single
input port can use a different target port. Advanced per-port mappings such as
`8080:80,8443:443` work with lists or `all`. All-port mode excludes panel/SSH and
custom reserved ports. Explicitly selecting a management port is rejected.
The same input IP/protocol/port cannot belong to two enabled connections.
Exclude a port from an existing all-port connection before assigning it elsewhere.

## Automatic setup and speed limits

New automatic-MTU GRE connections test full-sized payloads, cap the result at
the configured ceiling and leave 20 bytes of headroom. Saved imported MTUs are
preserved. Manual MTU is available. IPv4 TCP MSS follows GRE MTU; reverse path
checking uses loose mode only on owned GRE devices. IPv6, default routes and VPN
applications are not changed.

Upload/download caps are aggregate **per direction per connection**, in decimal
Mbps; zero means unlimited. Optional per-port caps are applied in addition to the
connection cap. The first implementation uses scoped kernel byte-rate policing
with a brief initial burst allowance. It does not replace the host qdisc or run
a user-space traffic proxy. Excess traffic is dropped; UDP senders must tolerate the configured
cap. Rate limiting never applies to unrelated ports, SSH or panel traffic.

## Telemetry

Actual accepted-forward byte counters are collected every five seconds, separately
for original and reply directions. NAT counters are not used as a traffic ledger.
Totals are persisted in SQLite across application restarts and server reboots.
A hard power loss may omit the last unsampled interval. This is operational
telemetry, not an ISP billing meter. Dates and daily totals use Asia/Tehran.

Specific lists of up to 128 ports are automatically counted individually. Wide
ranges and `all` retain an aggregate counter; select individual monitored ports
in connection details for a breakdown. This avoids adding 65,535 firewall rules.
Minute history has configurable bounded retention; lifetime totals remain.

GRE probe, TCP destination probe, and UDP application verification are separate.
An open UDP port or successful ping is never reported as a successful application
handshake. The generic UI leaves UDP unverified without a protocol response.
The CI network lab independently verifies real bidirectional UDP payloads.

## Persistence, transactions and backups

The root-only controller uses `/etc/gremgr/panel.json` for versioned settings and
connections; `/var/lib/gremgr/panel.sqlite3` holds telemetry, jobs and sessions.
All network jobs are serialized, remain active after the page closes, and expose
progress. Backups are taken before network edits. Foreign prepare operations
have an independent systemd rollback timer. Local pending journals are recovered
on service start; unreachable foreign recovery retries and remains visible in UI.
Distributed changes depend on SSH availability: recovery is reported explicitly,
not silently marked successful when a peer cannot be reached.

Only own `GMP_*` chains and exact legacy pair rules are modified. No global
iptables flush, policy reset, whole-firewall restore or global conntrack flush is
used. Old broad external DNAT rules are detected conservatively, even without an
explicit destination-IP match. Docker's published UDP/51820 path is recognized
on the foreign GRE side. Existing pair profiles are imported without changing
their addresses/MTU; the web worker takes ownership without deleting the live
GRE interface and keeps their original JSON in `pairs/backups/`.

Settings offers portable ZIP backups, downloads and restore previews. Backups
contain configuration and a consistent SQLite snapshot; login secrets, live
sessions, TLS private keys and SSH private keys are excluded. The current local
panel port/login and current SSH protected ports are preserved during restore.
On a different machine, GRE connections lacking keys restore paused; reconnect
the foreign server before enabling them. The API also accepts an `address_map`
when moving source IPv4 addresses. Daily automatic backups and old application
releases have bounded retention.

Panel port changes preserve the previous management port as reserved and roll
back after 120 seconds unless an authenticated session confirms the new port.

## Privilege boundary and updates

`gremgr-web.service` runs as unprivileged `gremgr`, serves local static assets over
TLS, and talks to `gremgr-worker.service` through a group-restricted Unix socket.
The worker validates sessions, CSRF tokens and allowlisted operations. Passwords
use salted scrypt hashes. No endpoint accepts shell commands. Request sizes,
login attempts, backup expansion, telemetry and event history are bounded.

All downloaded files are pinned to one source commit and SHA256-checked against
`release.json`. The same installer updates existing installations noninteractively;
Settings schedules that updater. Existing application releases are retained for
rollback. Initial trust is the GitHub HTTPS installer/manifest; these hashes are
integrity checks, not an independent signing key.

Account recovery is intentionally local and noninteractive:

```bash
sudo gremgr --reset-password
```

Legacy `gremgr --restore` is retained only for old boot services; it has no menu.
The separate old `gre-link-tool` and `gre-tun` projects are not changed.

## Validation

```bash
PYTHONPATH=gre-manager python3 -m unittest discover -s gre-manager/tests -p 'test_*.py' -v
python3 -m unittest discover -s gre-manager -p test_pair.py -v
python3 -m unittest discover -s gre-manager -p test_mtu.py -v
python3 -m unittest discover -s gre-manager -p test_docker_wireguard.py -v
sudo mkdir -p /run/netns
sudo unshare --mount --net --fork bash gre-manager/tests/network_lab.sh
```

The network lab refuses the host network namespace and tests TCP/UDP payloads,
port 65535, mappings, multi-IP destinations, SSH 22/6111, panel 8787, counters,
kernel limiter installation, restore and unrelated firewall preservation.
GitHub Actions runs it and the full installer on disposable Ubuntu 22.04/24.04
runners. Browser acceptance covers create/edit/delete, settings, keyboard escape,
reduced motion and desktop/mobile overflow; screenshots are CI artifacts.

Explicit local development fixture (no network mutations):

```bash
cd gre-manager
python3 -m panel.demo --seed
# http://127.0.0.1:8877 ; admin / Demo-Panel-2026!
```

The direct-forwarding feature was informed by the behavior requested from
[IPTABLE-Tunnel-multi-port](https://github.com/azavaxhuman/IPTABLE-Tunnel-multi-port).
Its installer, shell menu and destructive global reset operations are not bundled.
