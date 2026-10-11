# Port Manager V2 — unified Ports workflow

Section [2] is intentionally simple:

1. **New port forward** — TCP/UDP at once with source-to-destination port mappings.
2. **All ports except** — exclude SSH and operator-selected ports; V2 manages rollback.
3. **View/edit existing** — the SAME paged list shows saved V2 tunnels plus all
   visible manual/external NAT entries (except duplicate V2-owned kernel rows).
   Matching TCP and UDP NAT rules appear as a single `tcp+udp` item only when
   their remaining iptables selector/action tokens are identical.
4. **Full-reset safety information** — remains non-mutating.

Selecting a row shows the current settings and an Edit action. Managed
connections reuse current values automatically. For dual TCP/UDP managed
connections, the operator can update both or choose one: a one-protocol
update creates a separate managed connection for that protocol while leaving
the other protocol unchanged. This is validated as one transactional change.

For manually maintained direct `PREROUTING` or `OUTPUT` DNAT, the editor
prefills destination IPv4, destination port (when present), and existing
single source port (when present), and asks whether to apply the change to
both protocols or just one. Other selectors are retained verbatim.
Only exact displayed rule positions and arguments can be replaced.

**Safety:** a root-only journal and systemd-based 120-second rollback timer
are created BEFORE an external NAT rule is touched; the change must be
explicitly confirmed while SSH still works. If it isn't, the recorded rules
are restored by the watchdog (or immediately on declining confirmation).
If another tool alters the affected rule in the meantime, rollback refuses
to overwrite that unknown modification and retains recovery evidence.
While such a change is pending, managed V2 firewall changes are rejected.
Docker/UFW/firewalld/Kubernetes-owned rules and non-DNAT targets remain
read-only and must be edited through their owning application.

The full IPv4 iptables table browser is available at the bottom of the same
View/edit list. It is read-only for arbitrary rules; a host-wide flush is
NOT executed from the SSH UI. V1's frozen implementation is unchanged.

Test in a disposable VM and keep an out-of-band provider console before
using the foreign DNAT editor on a production host.
