# Installation, mutation, service, diagnostics, uninstall

## Installer

The AI must deliver a real `install.sh` plus a complete local release tree. Installer is root-only, noninteractive except the later first-run role/IP setup, and works from the unpacked release; no fictional download URL. Verify its manifest before copying. Validate supported OS, Python, systemd, GRE and tc modules/capabilities, disk space, known installation ownership, and dependency commands. Install missing official distro packages through apt with bounded timeouts and English summarized progress. Do not upgrade the OS, reboot, alter DNS, disable IPv6, switch firewall backends, or add third-party package repositories. If package retrieval fails, stop with a concise dependency error and leave networking unchanged.

Required packages/commands: python3, iproute2 (ip/tc/ss), nftables, conntrack, iputils-ping, systemd, coreutils, kmod. SQLite is Python stdlib. Test-only iperf3 is not a runtime dependency. tcpdump is optional. Preload ip_gre, ifb, sch_htb, sch_fq_codel, cls_fw, cls_matchall/cls_flower as used, act_ct, act_ctinfo, act_mirred; verify by isolated capability probes rather than assuming every module must appear in lsmod (some are built in).

Atomic install: unpack to a versioned staging directory under /opt, check expected files/hashes, then swap the owned application path. Preserve config/stats on reinstallation. Never overwrite an existing foreign /usr/local/bin/gre-tun or service file. No chmod 777. Source files root-owned 0644, launcher 0755, config/state directories 0700 and sensitive data 0600. First install does not create a tunnel. Reinstall with kept data runs all current conflicts/capability checks and either restores valid desired state or leaves it saved but inactive with an accurate message.

Install/enable the single systemd service from templates. The service first recovers any journal, reconciles desired state, samples stats, and then runs the bounded monitor loop. No per-port cron/timer. Removing data must not uninstall shared system packages. External resources needed during install are the distro package repositories only; runtime does not contact an AI or analytics server.

## Mutation transaction

Acquire an exclusive flock on /run/gre-tun/app.lock, timeout 5 seconds. Config writes, daemon repair, uninstall, counter-generational changes and peer import all use this lock. A second operation prints E_BUSY rather than waiting indefinitely. Read-only views use a coherent snapshot and tolerate a transaction-in-progress marker.

Sequence is fixed:

1. Read desired and actual state. Validate complete proposed config, capacity, listen sockets, NAT/rule/qdisc ownership, candidate routes and required actions. Recheck relevant external fingerprints before cutover.
2. Save the prior desired JSON and an ownership-scoped undo journal. SQLite online backup is used if schema/data changes are included. Sample affected counters once. Keep 5 bounded recovery revisions, not snapshots of all user traffic.
3. Arm an independent transient systemd rollback guard for 60 seconds. Its transaction ID references the on-disk journal; it survives the interactive shell dying. Use `systemd-run` directly with argv, not a generated shell command. The guard is local and never probes public servers.
4. Create needed inactive links/classes/routes before exposing DNAT. Validate generated nft batch with `nft -c`. Apply a native nft batch atomically; transitions that span nft/ip/tc are NOT globally atomic, so use temporary owned blocking gates for just the affected forward identities to prevent unshaped or misrouted leakage during cutover. Do not block unrelated traffic.
5. For a tuple/target/disable/delete edit, delete only the exact affected conntrack marks/identities. Reuse named counters or checkpoint an explicit new counter epoch; do not delete every connection.
6. Apply the remaining staged changes, read back exact owned objects, prove original and reply routes and live SSH/local listener preservation, and compare intended/actual. A new peer not yet installed yields Unverified, not transaction failure. ICMP is evidence, not the sole structural acceptance criterion.
7. Atomically write config (temporary file in same directory, fsync, rename, fsync directory) and ownership state; mark journal committed; disarm guard; remove temporary gates; report success.
8. Any error before commit triggers reverse-order scoped undo. The watchdog must not race the guard. If a foreign administrator changed an object after the snapshot, do not overwrite it; report E_ROLLBACK_INCOMPLETE and leave a precise recovery journal. Never hide an undo failure behind the original error.

On process restart or boot, resolve unfinished journals before ordinary reconciliation. All child commands have explicit timeouts; an apply must finish or begin rollback within 45 seconds. Guard lock acquisition/retry is bounded and journal-driven. A no-op apply writes nothing, creates no revision, resets no counters and emits `Already configured.`.

## Shared sysctls

Enable IPv4 forwarding only when a tunnel/forward requires it. Snapshot relevant per-interface IPv4 sysctls before toggling global ip_forward because a host/router transition can reset defaults. Restore unrelated observed settings immediately if that transition changes them, then set only the owned-interface values defined by the design. Persist owned needs under /etc/sysctl.d/90-gre-tun.conf. Never run a broad `sysctl --system` as an apply action.

On uninstall remove that owned file. Restore shared runtime values only if they still equal this tool's last-applied value and a fresh dependency check establishes no other forwarding consumer; otherwise leave the shared live value and report that fact. This is not a reason to retain any owned interface, NAT rule, timer or daemon. Never blindly set ip_forward=0 on a host now used by Docker/VPNs.

## Monitor

One event loop: structural check every 30 seconds; persisted accounting sample every 60 seconds; no default tcpdump/ping loop. Bounded structured queries, no per-connection scanning and no `iptables -C` loop per rule. It repairs only missing or mismatched owned structures under the same transaction lock. It does not move its own hooks to the top of foreign chains or fight another firewall manager.

At most one repair per tunnel in 180 seconds and at most three attempts in 15 minutes. Then mark Local error and require a successful explicit test/apply to clear the attempt budget. Failed ping never cycles a link. Disabled tunnels are never recreated by the monitor. Network-online ordering does not imply Internet connectivity; delayed boot addresses are retried with bounded logs.

Monitor service shutdown takes a final sample but leaves committed network objects in place; a routine daemon restart must not interrupt traffic. Uninstall uses a persistent stopping marker under the lock before stopping the service so Restart cannot recreate objects. Logs are event-only, bounded: app log max 2 MiB with 2 rotated files, last 20 test reports <=20 lines each, no packet payload, secrets or full conntrack inventory.

## Read-only diagnostics

`gre-tun test [Txxxx|all]` has network read-only behavior: it may write its own bounded report and send bounded probes, but it never changes routes, rules, sysctls, links or qdiscs. Verify configured outer pair/key/inner CIDR/MTU, link admin state, original marked path, physical peer underlay path, reply route, nft ownership/rules, relevant tc caps and service state. Structural mismatch => FAIL even if a peer answers ping.

At most three ICMP probes to the peer inner IP with one-second timeout, total <=5 seconds; capture summary RX/TX deltas over the bounded window. Optional GRE header evidence uses <=2 packets and <=5 seconds, no payload display or packet file. No observed packets in a short idle window does not prove outage. Link operational state UNKNOWN is normal for GRE and is not a failure by itself.

Results: PASS = structure valid and peer ICMP reply observed; UNVERIFIED = structure valid but reachability not proven (including blocked ICMP); FAIL = specific local structural/route/QoS fault. PASS is not proof that every destination service works. TCP connect probes, when explicitly invoked for a selected port, distinguish refused/timeout/connected. UDP service reachability is Unverified without a protocol-specific reply. Diagnostics never run iperf3 or saturate bandwidth automatically.

Each report contains version, test ID/UTC, tunnel ID/name, endpoints, structural result, underlay path, payload route, optional RTT/loss, observed RX/TX deltas, QoS structural result, final result, and report path. At most 20 lines per tunnel. Hardware/OS capability failure is a clear error, not a generic PASS.

## Uninstall

The selected menu action and the one keep-data answer authorize uninstall. Persist the stopping marker, acquire the lock, sample stats, stop/disable the owned service, cancel only owned transient rollback units after resolving their journals, withdraw owned DNAT/forwarding, remove exact marked connections, remove owned policy rules/tables, owned tc/IFB/GRE links and the owned sysctl file, and verify absence. Remove only owned launcher, app files, log files and installed unit; daemon-reload. Never flush global firewall/conntrack, alter default routes, remove unrelated Linux packages, or disable foreign units.

Keep=yes: retain config, stats, ID/tombstone counters and minimal ownership/reinstall metadata, with no active runtime objects. Remove temporary journals after verifying completion. Keep=no: also delete only this tool's config/state/history directories. A mismatch means stop and report remaining owned resources; do not recursively delete a path with unexpected ownership/symlinks. Print success only if the requested scope was removed. The remote host is not modified; print the fixed local-only note.

## Deliverable layout the implementing AI must create

`src/gre_tun/` modules; `bin/gre-tun`; `install.sh`; `templates/gre-tun.service`; unit and integration tests; frozen specification/fixtures; English README plus optional Persian quick-start; `VERSION`; `SHA256SUMS`; release ZIP; actual `TEST_RESULTS.md`. The installer must be runnable from that release. Do not ship only pseudo-code or a file that imports absent modules.
