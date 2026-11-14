# GRE Manager 1.0 — web control plane

One installation on Iran provides three pages: **GRE**, **IPTables / direct
forwarding**, and **Settings**. There are no interactive Bash management menus.

```bash
curl -fsSL https://raw.githubusercontent.com/smorad3363/assistant-vps/master/gre.sh | sudo bash
```

The installer prints the HTTPS address and randomly generated initial username and password.
Save the password: it is printed only on first installation. The default port is
8787. Public IPv4 installations automatically request a trusted Let's Encrypt IP
certificate. A systemd timer checks renewal every six hours; expiry and errors
are visible under Settings. IP certificates are short-lived (160 hours). During
HTTP-01 validation, new TCP/80 connections on this IP are briefly redirected to
an isolated challenge listener. Existing connections remain tracked; all-port
forwarding resumes after validation, including timeout cleanup. Inbound TCP/80
must be reachable from the public Internet. The initial self-signed certificate
remains available if issuance fails. Settings also accepts a matching PEM
certificate chain and private key, which disables automatic replacement until
automatic IP certificates are explicitly re-enabled. Use Settings to change the panel port, login
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

The main connection form has input/target rows. For example, one connection can
map `5100` to `5000` and `3300` to `3000`; an empty target preserves the input port.
Untranslated rows also accept lists (`443,1000,51821`) or ranges (`8000-8100`).
The existing API `target_port` and `port_map` fields remain compatible.
All-port mode supports optional mapping rows and excludes panel/SSH and
custom reserved ports. Explicitly selecting a management port is rejected.
The same input IP/protocol/port cannot belong to two enabled connections.
Exclude a port from an existing all-port connection before assigning it elsewhere.
One active GRE is used per endpoint pair. New endpoint pairs choose a private
subnet that is free in both hosts' routing tables; existing GRE addresses stay
fixed. An exhausted candidate pool produces an explicit conflict, never an
overlapping tunnel.

Deleting a GRE removes its owned network state at both endpoints. When its
management connection is no longer referenced (including by paused profiles),
the restricted SSH key and local server record are removed as well. The foreign
helper, restore service and owned firewall chains are uninstalled only when no
other peers, panel, legacy profiles or management keys depend on them. Ordinary
SSH keys, VPN applications, shared OS packages and global network tuning are
preserved. An empty coordination lock can remain for safe concurrent bootstrap.
An SSH/cleanup failure keeps a retryable server entry in Settings; it is never
reported as a fully completed cleanup. Older foreign helpers need one reconnect
from Settings before using the new cleanup operation.

## Automatic setup and speed limits

New automatic-MTU GRE connections test full-sized payloads, cap the result at
the configured ceiling and leave 20 bytes of headroom. Saved imported MTUs are
preserved, including backup restores. Re-entering automatic mode probes both
endpoints at the configured ceiling, so repeated restores do not reduce MTU.
Manual MTU is available. IPv4 TCP MSS follows GRE MTU; reverse path
checking uses loose mode only on owned GRE devices. IPv6, default routes and VPN
applications are not changed.

Upload/download caps are aggregate **per direction per connection**, in decimal
Mbps; zero means unlimited. Optional per-port caps are applied in addition to the
connection cap. The first implementation uses scoped kernel byte-rate policing
with a brief initial burst allowance. It does not replace the host qdisc or run
a user-space traffic proxy. Excess traffic is dropped; UDP senders must tolerate the configured
cap. Rate limiting never applies to unrelated ports, SSH or panel traffic.

## Telemetry

Actual accepted-forward byte counters are sampled every second, separately for
original and reply directions. The light authenticated live endpoint updates
connection and per-port upload/download Mbps without rebuilding the page each
second. Durable history is flushed every five seconds and before rule changes;
it is not written to SQLite every second. NAT counters are not used as a traffic ledger.
Totals are persisted in SQLite across application restarts and server reboots.
A hard power loss may omit the last unsampled interval. This is operational
telemetry, not an ISP billing meter. Dates and daily totals use Asia/Tehran.

Specific lists of up to 128 ports and explicitly mapped ports are automatically counted individually. Wide
ranges and `all` retain an aggregate counter; select individual monitored ports
in connection details for a breakdown. This avoids adding 65,535 firewall rules.
Minute history has configurable bounded retention; lifetime totals remain.

GRE probe, TCP destination probe, and UDP application verification are separate.
An open UDP port or successful ping is never reported as a successful application
handshake. The generic UI leaves UDP unverified without a protocol response.
The CI network lab independently verifies real bidirectional UDP payloads.
IKE/NAT-T UDP/500 and UDP/4500 and authenticated decrypted IPsec traffic are
excluded from the foreign wildcard-UDP reply fix. This preserves transport-mode
IPsec selectors for L2TP/IPsec while retaining the fix for generic UDP services.

## Persistence, transactions and backups

The root-only controller uses `/etc/gremgr/panel.json` for versioned settings and
connections; `/var/lib/gremgr/panel.sqlite3` holds telemetry, jobs and sessions.
All network jobs are serialized, remain active after the page closes, and expose
progress. Backups are taken before network edits. Foreign prepare operations
have an independent systemd rollback timer. Local pending journals are recovered
on service start; unreachable foreign recovery retries and remains visible in UI.
Distributed changes depend on SSH availability: recovery is reported explicitly,
not silently marked successful when a peer cannot be reached.
The peer also retries expired transactions on its next authenticated request if
a rollback timer failed, so a failed timer cannot permanently block new changes.

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

The explicitly opt-in `tests/live_*` scripts are for disposable VPS acceptance.
They install real WireGuard, OpenVPN TCP/UDP and L2TP/PPP/IPsec fixtures and a
separate namespace client, check public TCP/UDP payloads and mappings, and measure
aggregate and per-port upload/download limits. They require the peer to have
already been added through the authenticated panel API and take its test SSH
password only from `LAB_PEER_PASSWORD`. Never run these fixtures on a production
VPN host. `GRE_PANEL_SKIP_ACME=1` skips public CA requests in isolated CI fixtures.

Explicit local development fixture (no network mutations):

```bash
cd gre-manager
python3 -m panel.demo --seed
# http://127.0.0.1:8877 ; admin / Demo-Panel-2026!
```

The direct-forwarding feature was informed by the behavior requested from
[IPTABLE-Tunnel-multi-port](https://github.com/azavaxhuman/IPTABLE-Tunnel-multi-port).
Its installer, shell menu and destructive global reset operations are not bundled.
