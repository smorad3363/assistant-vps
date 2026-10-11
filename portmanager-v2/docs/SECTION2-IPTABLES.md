# Section 2 — NAT and port tunnel management

This screen is an independent Port Manager V2 implementation inspired by the
workflow of [IPTABLE-Tunnel-multi-port](https://github.com/azavaxhuman/IPTABLE-Tunnel-multi-port),
without copying its GPL-licensed implementation.

- **1 — Forward specific ports:** enter destination IPv4, first source/destination
  port pair, and optionally more `source:destination` pairs separated by commas.
  TCP and UDP rules share each pair. The original application may use many ports.
- **2 — All except:** forwarding on selected interface/IP with explicit exclusions,
  SSH protected and timed rollback/confirmation.
- **3 — Manage owned ports:** modify/remove the V2 tunnels only.
- **4 — Browse ALL IPv4 iptables tables:** read-only, paginated view of all
  tables, builtin policies, manual rules, Docker, UFW, legacy and owned chains.
- **5 — Browse NAT forwarding:** inspect existing DNAT, SNAT, redirect,
  masquerade from every application without automatically adopting them.
- **6 — Full reset information:** a deliberate read-only warning. Destructive
  full-host flush is not offered from SSH. It needs an explicit separate
  console-only backup + verified automatic rollback procedure.

### Why an existing DNAT may block creation

Before: any foreign DNAT on the server would block *all* new tunnels.
Now: source listen IP, inbound interface, protocol, source port/port ranges,
`--dports` and All-except exclusions are considered. Only rules that
could overlap the intended forwarding remain blockers. Unrecognized or
negated selectors are conservatively considered conflicts. The exact
foreign rule appears in error details, and can be reviewed under
**Browse ALL iptables tables**. The system never deletes or silently
reorders another application's firewall rules.

**Important:** a foreign NAT entry forwarding port 8080 will still block
a different tunnel on port 8080; this is intentional and safer than
rewriting or shadowing rules that might maintain remote access.

The global flush option in the reference script is unsafe when executed
remotely and can invalidate Docker, SSH, NAT, UFW, IPv4 forwarding, and
persistent firewall state. This stage does not enable such a flush.
