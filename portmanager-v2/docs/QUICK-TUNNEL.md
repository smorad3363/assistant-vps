# Quick tunnel wizard — two fields instead of six

In Port Manager V2, open **Ports → New TCP + UDP port forward**.

The wizard asks only:

1. `Destination IPv4` — address of the remote VPS.
2. `Ports (5555,5555:6666,80:8080)` — one comma-separated line.

Port syntax: `5555` means source 5555 → destination 5555, while
`5555:6666` means source 5555 → destination 6666. Multiple pairs use
commas, e.g. `5555,443:8443,80:8080`. Whitespace around commas is
accepted. Duplicate source ports and invalid ports are rejected.

TCP + UDP forwarding is the default. Port Manager chooses an actually
assigned IPv4/interface using host discovery and preflight checks; it does
not ask for an arbitrary source address. This remains **one interface and
one source IPv4 per tunnel**, not simultaneous bindings to every server
address. Multiple-IP bindings would require a separate schema/firewall
change.

The rule is automatically named `port-<first-source-port>-to-<target-ip>`;
when the name already exists, an increasing numeric suffix is used.
Only ASCII-safe names are generated, even if the terminal input contains
non-ASCII characters in unrelated context.

For existing connections, the name and validated source are preserved.
The destination and compact port mapping are prefilled. Explicit protocol
selection is only offered when editing a managed TCP+UDP pair, and the
normal apply confirmation and high-risk 120s rollback remain in place.

For **all-except**, the destination IPv4 and excluded ports are requested;
detected SSH/admin exclusions and timed rollback remain mandatory.
