# Network and QoS contract

This is the frozen design, not a claim that kernel integration tests have run. Implement it, verify on disposable VMs, and report any kernel incompatibility instead of silently replacing it with another backend.

## A. Underlay, GRE pair, inside network

Use keyed GRE over IPv4, protocol 47 (not TCP/UDP port 47). Preflight proves the selected outer source exists on the selected WAN, the remote outer IP is not local, and the underlay route exists without any managed GRE dependency. `ip -j route get` and `ip -d -j link` are the authoritative inspection forms; do not parse localized prose.

Outer-pair identity is the SHA256 of the two numerically sorted canonical IPv4 strings joined by `|`; use its first 16 hex characters as pair ID, and its first 32 bits (or 1 if zero) as GRE key. Allocate 16 candidate /30 networks by deterministic linear probing from the hash-derived slot in 10.240.0.0/12, skipping this host's conflicting interface addresses and nondefault connected/static routes. `0.0.0.0/0` does not conflict; a real 10.0.0.0/8 route does. Include candidates in the peer code, not an unbounded dump of host routes.

The lower numeric outer address gets subnet +1, the other +2. The initiator chooses candidate 0. The receiver chooses the earliest candidate that is free locally and no larger than the negotiated MTU can support. If it changes candidate or MTU, it outputs a revised token for the first host; it does not assume remote success. If all candidates collide, return E_ADDRESS_CONFLICT without changing the host. The initiator can supply another candidate set by New tunnel after importing the peer's conflict response through the program's internal regenerate command; the response carries only rejected candidate CIDRs and pair ID, not shell commands. Candidate generation excludes these rejected CIDRs on retry. No arbitrary inside IP is asked of the user.

Peer token: `GT1.<base64url canonical UTF-8 JSON without padding>.<lowercase SHA256 of JSON>`. Limit 8192 ASCII characters, decoded JSON <=6000 bytes, schema version 1, no compression or eval. SHA256 detects damage, not malicious tampering or authentication. Expected receiver outer IP must be assigned locally. Tokens contain no passwords/keys for SSH. Normal remote setup requires one copy/paste. Retrying the same code is idempotent. Never adopt or delete a preexisting nonowned interface with a matching name.

Default MTU 1400, further capped at selected WAN MTU minus 28 bytes (IPv4 + GRE + key); require >=1280, otherwise fail E_MTU. The setup token carries the value so both endpoints converge to the smaller capability. This is a conservative default, not proof of end-to-end PMTU. Keep PMTU discovery enabled; use a bounded DF probe in diagnostics, not a bandwidth flood. Outer TTL 64. Apply fixed TCP MSS clamping to max(inner MTU - 40) only for managed IPv4 TCP SYN/SYN-ACK and only when the advertised value is larger. UDP cannot use MSS; fragmented and large UDP must be tested.

## B. Rule ownership and underlay protection

Owned nft table: `ip gre_tun`. Owned nft objects include deterministic comments with contract version and local object IDs. Ownership is proved by the saved manifest + matching kernel object attributes, not by name alone. Owned interfaces, policy rules and route tables have the same recorded provenance. If a foreign object occupies a reserved name, table, priority, GRE pair/key, or mark namespace, stop with E_RESOURCE_CONFLICT.

Fixed chain names/priorities:

| Chain | Type/hook/priority | Purpose |
|---|---|---|
| classify | filter/prerouting/-150 | Identify original connections before DNAT; restore routing/classification mark |
| dnat | nat/prerouting/-90 | Managed destination translation |
| forward_guard | filter/forward/10 | Allow only explicit managed forwarding paths and stop leaks on owned tunnel interfaces |
| account | filter/postrouting/90 | Named per-forward directional counters on all eligible packets |
| snat | nat/postrouting/110 | Source translation for managed traffic only |
| input_guard | filter/input/10 | Scope local tunnel input and peer protocol handling |

A baseline nft transaction must first pass `nft -c -f`, then be applied as one `nft -f` batch. Update owned rules/sets in place; keep named counters. Rebuild chains atomically, not one rule at a time. Never `flush ruleset`, `iptables -F`, change a foreign base-chain policy, or restore a whole saved host firewall.

Foreign INPUT/FORWARD/NAT rules are inspected for overlapping translations, relevant DROP/REJECT, untracked flows, flowtable/hardware offload that bypasses accounting, or unsupported conntrack zones. Managed traffic uses conntrack zone 0. Reject a relevant nonzero-zone or NOTRACK rule. Accept in gre_tun cannot override another table's drop; fail a conflicting setup clearly. Foreign irrelevant rules may coexist. Unknown relevant constructs are treated as unsupported conflicts rather than silently claiming compatibility. No automated UFW/Docker/firewalld changes in v1.

## C. Original direction at the entry host

For a local logical forward F on tunnel T:

1. Match the exact listen IPv4, protocol, listen port and expected ingress WAN. Do not use a wildcard public IP or capture locally originated OUTPUT traffic in v1.
2. Before DNAT, set the connection mark for new managed connections to `0x47000000 | (T << 12) | F`. Reject incompatible existing foreign mark use; never overwrite unrelated traffic's marks.
3. On subsequent ORIGINAL packets for that managed connection, restore the mark to the packet. Do not reclassify by translated destination tuple alone.
4. DNAT to the target IPv4:target port.
5. Policy rule: exact ingress WAN plus fwmark `(0x47000000 | T<<12)/0xfffff000` -> numeric table `45000+T`, priority `30000+T`. This table routes the target through the GRE peer. It contains the inside link route and a default through peer_inner on gtnT; the default applies only to marked managed originals via the specific rule. The host main/default route is untouched.
6. Independently ensure outer GRE traffic to the physical peer uses the validated WAN/main underlay lookup even with inherited inner marks. A narrow higher-priority rule for `ipproto gre` + peer /32 -> main at `20000+T` is allowed; bind the GRE underlay device and verify marked/unmarked outer lookups. Never install a generic peer /32 rule that steals a TCP target equal to the peer's outer IP.
7. Permit only this managed original flow in forward_guard. Account once using its connection identity and ORIGINAL direction, then SNAT the packet to this tunnel's local inner IP. This preserves a unique return path. The service will see the relay address; transparent original-client-IP preservation is out of scope.
8. On GRE egress, classify by the connection-derived packet mark for the upload cap. The physical WAN root qdisc is not touched.

The policy rule's ingress match is essential: copying a connection mark onto a REPLY packet must not send that reply back down the GRE. Test this explicitly. Exclude managed GRE devices from eligibility as public ingress interfaces.

## D. Remote endpoint and reply

At the peer, accept the decapsulated payload only from the expected peer inner IPv4 on the owned GRE. If the target is an address on this peer, Linux INPUT delivers to the actual listening service; do not change the service's port/bind address. For a third-party target, permit only the authenticated-by-topology scoped GRE source path toward the normal underlay route and SNAT to the peer's selected egress source. This is scoped per tunnel, never a global MASQUERADE.

Responses to the entry inner address follow the peer's connected /30 back through the same GRE. A local service bound only to the public address requires that public target address in the forward; this must work even though it is also the outer GRE destination. Traffic to other managed inside networks or another GRE egress is denied in v1 to prevent accidental transit loops; a deliberate third-party target must exit a normal underlay interface.

Back at the entry, conntrack reverses SNAT/DNAT. A REPLY packet can retain its classification mark for accounting/QoS but does not match the original-direction routing policy because its ingress is gtnT. It routes toward the client through the original WAN. Permit only expected ESTABLISHED/RELATED replies; bound ICMP error handling is allowed, but ICMP errors are not attributed as TCP/UDP application bytes unless they match an actual managed ORIGINAL/REPLY conntrack identity. Unknown unsolicited payloads on managed GRE are dropped by owned guards; no broad cross-tunnel ACCEPT rule.

Reverse-path filtering: do not disable it globally. Set `rp_filter=2` on owned GRE devices and test return traffic with the host's normal all/default settings. Read-only validate that host-wide rp_filter/mark settings do not invalidate this design. Any additional shared sysctl change must be specifically journaled, bounded and justified; never blanket-disable every interface's protection.

## E. Per-port bandwidth caps

The cap is sustained aggregate L3 traffic per forward/direction, shared by all its clients and both protocols in Both. `0` is Unlimited. It is not a per-client allowance, not combined upload+download, and not a guaranteed throughput when the path is slower. Small token-bucket bursts are permitted. Use Mbps = 1,000,000 bits/s.

Upload: HTB root handle `1:` on owned `gtnT`, with `default 0` so unclassified/Unlimited traffic uses HTB's direct path. One limited class `1:<F in hex>` per finite upload cap, `rate=ceil=cap`, with fq_codel child handle `<0x1000+F in hex>:`. Filter by exact full managed packet mark. Do not invent an artificially low finite rate for Unlimited.

Download: owned IFB `gtiT` has HTB root handle `2:`, default 0, class `2:<F in hex>` for each finite download cap and fq_codel leaf handle `<0x2000+F in hex>:`. At decapsulated GRE ingress, recover the existing zone-0 conntrack identity before classification: tc `ct` lookup without commit/NAT, then `ctinfo cpmark`, then classify/redirect applicable reply traffic via `mirred` into the owned IFB. This is a lookup of a connection established by nftables, not another NAT implementation. Guard the direction, mark prefix and local forward ID. Unknown/unmanaged traffic must not inherit an arbitrary managed mark. Test defragmentation and re-injection semantics on the actual kernel.

All traffic that belongs to a capped managed reply must traverse its IFB class, including fragmented UDP; an unclassified fragment must not silently take the Unlimited default path. A missing/unsupported tc action or inability to prove correct fragment classification causes E_QOS_UNSUPPORTED and rolls back the requested cap change. Do not substitute a packet policer or apply a whole-WAN limit. Preserve original GRO/GSO settings unless a separately scoped, owned-interface-only normalization is required and measured in the integration test. No broad offload changes to WAN devices.

Fixed class parameters: burst and cburst = max(16384, ceil(cap_mbps*1000000/8/100)) bytes, quantum=1514; fq_codel limit=1024 packets, target=5ms, interval=100ms, ECN enabled. Only install finite-cap classes. A cap update changes that class/filter in place; it must not reset another forward's class or counter. A generation-cutover for an existing capped flow must block unclassified leakage until the new class is present. Rate statistics used for UI are accounting statistics; verify cap enforcement at the receiving test socket rather than assuming an offered-load counter cannot exceed a sender-side cap.

Release gates: one flow, many parallel flows, TCP+UDP shared cap, two independent forwards sharing a target, upload+download simultaneously, two tunnels, high-rate offered UDP, fragments and reboot. Test for a 20 Mbps cap over 30 steady-state seconds after 5 warm-up seconds: receiver throughput upper bound <=22 Mbps, with a sufficiently provisioned lab also >=16 Mbps. No lower bound is asserted for an externally congested path. Burst tolerance and protocol/header overhead must be documented in the measured result.

## F. Conflict detection

Before reservation, expand Both and check `(local IP, protocol, port)` against app config, `ss` listeners, existing DNAT/REDIRECT/TPROXY/containers, and pending transactions. A listener on 0.0.0.0 conflicts with every local IPv4 on that protocol/port. A listener on a different specific IPv4 does not automatically conflict. Inspect dual-stack `[::]` listeners and IPV6_V6ONLY behavior; if IPv4 exposure cannot be proved absent, conservatively reject that tuple. Inspect SSH listening configuration and active management endpoints; do not hardcode only 22. Never stop a process to free a port.

Use the mutation lock and recheck immediately before apply to reduce races; arbitrary external administrators can still change the host concurrently, so never promise mathematical immunity. If the ownership fingerprint changes during cutover/rollback, stop safely and report the conflict instead of overwriting foreign work. All conflict messages include the actual IP/protocol/port or resource, not a large dump.
