# GRE Tunnel Manager: normative implementation specification

Contract baseline version: 1.0.0; amendment 1.0.1 (2026-10-21, pre-tunnel tests). Product command: `gre-tun`. Initial product version: 1.0.0.

MUST is mandatory; MAY only identifies an explicitly optional behavior. This package is a construction contract, not evidence that a live tunnel has been built or tested.

## 1. Precedence and reproducibility

1. The user's subsequent explicit corrections take precedence and require an intentional contract-version update.
2. This SPEC defines scope and architecture. Numbered documents define their named subsystems.
3. For exact strings and menu order, `contracts/ui.en.json`, `contracts/menus.json`, and UI golden files are authoritative.
4. For stored data, schemas are authoritative, with cross-field constraints in the documents.
5. `reference/contract.py` and fixtures define exact pure-function behavior. The implementation must pass their tests; it must not alter expected results to excuse a mismatch.
6. Examples are synthetic instances, not defaults or authorized production targets. Old uploaded code/chats are intentionally absent.

If normative parts conflict, report the precise conflict; do not pick whichever is easier. Runtime IPs, timestamps, rates, counters, hostnames, and error details are variable data. Fixed text, ordering, rounding, defaults, and behavior with the same inputs/state are deterministic. Byte-identical independently generated source is not promised. A verified immutable release is needed for byte-identical deployment.

## 2. Scope

- Fresh installation; native IPv4 GRE over IPv4 with key and native TCP/UDP forwarding.
- Each host can have multiple independent peers. Iran/Foreign is a one-time descriptive label, not a technical permission or directional restriction.
- Both endpoints run this tool. Each endpoint can own local forwards; remote endpoint setup does not require per-port re-entry. Forwarding to a service on the peer itself or to a routable third-party target is supported.
- One tunnel for each unordered pair of outer IPv4 addresses. Repeated setup is idempotent, not a second tunnel.
- Exactly four main-menu options, plus Exit, as frozen in contracts.
- Port syntax is `PORT` or `LISTEN:TARGET`, with comma-separated batches. No second target-port prompt.
- Per-forward and per-tunnel current speed, rolling 1h/24h volumes and average upload/download rates. No calendar-day reset.
- Per-forward upload/download caps; Both combines TCP and UDP under one identity and one cap per direction. Caps apply to the sum of clients, not to each client.
- Simple tests, bounded logs, auto-start, automatic structural reconciliation, scoped rollback, and scoped uninstall.

Out of scope: legacy migration/cleanup, blanket firewall reset, automatic SSH access, VPN account management, client identity billing, quotas, IPv6 tunnels, UDP-wrapped GRE, L2 bridging, load balancing/failover, speed-test saturation by default, web/TUI frameworks, plugin systems, alerts to other services, automatic dependency upgrades during normal use, and an AI runtime/API.

## 3. Fixed platform and architecture

Release targets: Ubuntu Server 22.04 LTS and 24.04 LTS, systemd, x86_64 or arm64, Python >=3.10, Linux >=5.15. Other distributions are explicitly unverified, not silently advertised as supported. Capability probes are mandatory even on a matching OS; OpenVZ/container environments without GRE/NET_ADMIN/required tc actions fail clearly.

Runtime: Python standard library only. Bash is limited to installer and launcher. Use native nftables as the sole mutation backend; do not switch to iptables based on availability. Read-only inspection of iptables-legacy/nft, UFW, Docker, and firewalld is permitted for conflict detection. Use `ip`, `tc`, `nft`, `conntrack`, `systemctl`, `systemd-run`, and `ping` through argv arrays with timeouts, never shell interpolation. Optional tcpdump is for a bounded manual diagnostic only, not a polling daemon.

Persistent desired config: `/etc/gre-tun/config.json`. Statistics: `/var/lib/gre-tun/stats.sqlite3`. Ownership and pending transactions: `/var/lib/gre-tun/state/`. Source install: `/opt/gre-tun/`. Launcher: `/usr/local/bin/gre-tun`. One service: `gre-tun.service`. Locks and live state: `/run/gre-tun/`. Test logs: `/var/log/gre-tun/`. All names and templates are frozen in the supplied contracts.

Python modules: `cli`, `ui`, `config`, `validation`, `ports`, `peer`, `network`, `firewall`, `qos`, `stats`, `transactions`, `diagnostics`, `daemon`, and `uninstall` under `src/gre_tun/`. Helpers can be private functions in those modules. Do not create a different framework. `reference/contract.py` may be copied to `src/gre_tun/contract.py` unchanged.

All app output/code/comments/logs: English, plain text, LF. No Persian inside commands. No emoji, box-drawing decorations, animated spinner, ANSI color, terminal clearing, or width-dependent alternate menu. The program must work in SSH and a narrow terminal through vertical detail views.

## 4. Identity and limits

Host-local numeric IDs start at 1, increase monotonically, and are never reused while saved data exists. Tunnel display IDs are `T0001`; forward IDs `P0001`. Deleted IDs remain tombstones in state until full data deletion. A forward keeps its ID across edits, preserving attribution history; recent mixed settings are labelled in details.

GRE interface: `gtn<id>`; IFB for received traffic: `gti<id>`. Tunnel key is a deterministic nonzero 32-bit value from the outer-pair hash. Inside addressing uses nonoverlapping /30s from 10.240.0.0/12 after conflict checks; default MTU is 1400 and outer TTL 64. Inner low/high host assignment is by sorted numeric outer IPv4, not by country label.

Marks use the high byte `0x47`, the next 12 bits for the local tunnel ID and low 12 bits for the local forward ID. IDs 1..4095 are supported because this is the fixed mark encoding. Do not hide wraparound; exhausted IDs return an allocation error. Numeric route table is `45000 + tunnel_id`; policy-rule priority is `30000 + tunnel_id`. Key, mark, and name formulas are in the reference code. Probe for foreign collisions before reserving any object.

## 5. User-facing invariants

- The user never types inner addresses, interface names, route tables, fwmarks, GRE keys, qdisc handles, or service names.
- Input and destination ports can differ. Input IP and target IP are separate fields. A target can equal the remote outer IP; policy routing must handle it safely.
- A given `(listen IPv4, protocol, listen port)` has at most one active owner on a host. Both expands to two protocol reservations. Disabled forwards retain their logical reservation against this app's own duplicates, but no kernel DNAT/shaping; re-enable repeats system conflict checks.
- Opening/refreshing a screen and running status/test must not mutate forwarding or interfaces.
- Only related connections may reconnect after a port edit, disable, or removal. Never clear global conntrack. Port-cap edits do not reset connections or statistics.
- Deleting a tunnel affects its own forwards and local resources only. The remote endpoint is not magically deleted; show the fixed local-only completion notice.
- On missing data show `N/A` or the appropriate partial-coverage label, never a fabricated zero or PASS.

## 6. Forwarding and shaping invariants

Traffic routing, NAT, conntrack identity, packet accounting, and tc classes are separate explicit stages. NAT-rule counters are not usage counters. The original and reply directions must be tested separately. Host default routes and unrelated tables/rules/qdiscs remain unchanged.

Upload means the original client-to-target direction of a managed forward. Download is its reply. For a tunnel that only serves as a remote endpoint, show its interface RX/TX as endpoint traffic; per-forward statistics belong to the host where that forward is defined. Do not pretend remote per-port stats are synchronized. Tunnel logical totals sum locally owned forward IDs; transport RX/TX are separately labelled and never added to those totals.

QoS uses tc HTB with fq_codel leaves on owned GRE egress and an owned IFB for decapsulated ingress. Never replace a physical WAN root qdisc. Classification uses connection identity so two input ports mapped to the same target remain separate. No bandwidth cap is implemented as an nft packet-rate limit or just a dropping policer. See the complete network contract for fragmentation and ingress conntrack classification gates.

## 7. Safe execution and truthful completion

All mutations are serialized and journaled. Snapshot only owned objects and explicitly changed shared sysctls. Validate/stage before cutover, arm a rollback guard, verify the resulting local state, then commit. Network outage or a peer not installed yet is not a reason to undo an otherwise valid new configuration. Structural failure is.

External firewall coexistence is checked, not guaranteed for arbitrary rulesets. An ACCEPT in this app's nft table cannot override a DROP in another base chain. Detect a restrictive or unclassifiable relevant ruleset before applying and give the documented short conflict message. Do not disable UFW, Docker, firewalld, or other services. Do not require an empty host if unrelated rules are demonstrably harmless.

No claim of production readiness is permitted from pure tests alone. Integration gates cover real kernel forwarding, same-target multi-tunnel routes, two directions, limits, reboot, rollback, and uninstall on the stated OS matrix. Reports distinguish PASS, FAIL, and NOT RUN.

## Amendment 1.0.1: pre-tunnel tests (user correction, 2026-10-21)

The Test connection menu MUST work when the saved configuration has zero tunnels.
A local route/ICMP check shall not imply GRE is reachable. A temporary raw
protocol-47 challenge can validate bidirectional GRE packet passage without
creating persistent network objects, using two terminals and a shared random
nonce. Protocol 47 PASS is not keyed-tunnel/NAT/QoS acceptance. Existing schema
and pure-function contracts remain at version 1.0.0 for backward compatibility.
