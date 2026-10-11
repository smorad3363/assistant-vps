# Quick tunnel wizard — two fields instead of six

In Port Manager V2, open **Ports → New TCP + UDP port forward**.

The wizard asks only:

1. `Destination IPv4` — address of the remote VPS.
2. `Ports (5555,5555:6666,80:8080)` — one comma-separated line.

Port syntax: `5555` means source 5555 → destination 5555, while
`5555:6666` means source 5555 → destination 6666. Multiple pairs use
commas, e.g. `5555,443:8443,80:8080`. Whitespace around commas is
accepted. Duplicate source ports and invalid ports are rejected.

TCP + UDP forwarding is the default. Port Manager chooses an
external interface and a verified IPv4 anchor. **Each tunnel forwards on
every eligible local IPv4 assigned to that interface**, including secondary
addresses on eth0. It does not capture unrelated interfaces or nonlocal
routed destinations.

Production preflight verifies all interface IPs and checks listeners/NAT
collisions before installing per-IP DNAT, FORWARD and MASQUERADE rules with
their own conntrack original-destination selectors. Foreign firewall rules
are not rewritten. Existing V2 configs remain unchanged; after updating,
run `sudo portmanager2 tunnel apply` to reconcile older single-IP owned
kernel rules into multi-IP coverage.

The rule is automatically named `port-<first-source-port>-to-<target-ip>`;
when the name already exists, an increasing numeric suffix is used.
Only ASCII-safe names are generated, even if the terminal input contains
non-ASCII characters in unrelated context.

For existing connections, the name and validated source are preserved.
The destination and compact port mapping are prefilled. Explicit protocol
selection is only offered when editing a managed TCP+UDP pair, and the
120-second rollback for high-risk changes is still enforced.

For **all-except**, the destination IPv4 and excluded ports are requested;
detected SSH/admin exclusions and timed rollback remain mandatory.
