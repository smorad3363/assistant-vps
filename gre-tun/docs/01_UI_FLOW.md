# Fixed UI and interaction flow

Use contracts/menus.json and contracts/ui.en.json verbatim. Template values are validated data. Always sort hosts/IPs numerically, tunnels by numeric ID, and forwards by numeric ID. Screens start with their title, a blank line, summary data if specified, another blank line, numbered options, a blank line, and the prompt. End lines with LF. No trailing spaces. The main screen contains no dynamic banner; it is exactly fixtures/ui/main.txt.

Print each prompt as one LF-terminated line, then read the user's input on the next line. A saved JSON config is UTF-8, sorted keys, two-space indentation and one final LF; the peer token uses compact canonical JSON instead. IDs may be selected as a decimal number or the correct case-insensitive T/P label; normalize to T0001/P0001. Zero is navigation, never a stored object ID.

## General input rules

`0` navigates back from a menu and cancels any prompt except a speed-cap prompt, where `0` means Unlimited. At cap prompts, `b` means back. Enter preserves an existing edit value; at creation it accepts only the explicitly displayed default. Empty required input re-prompts that field with E_REQUIRED. EOF or Ctrl+C before apply abandons the in-memory edit without persisting it. During apply, the transaction engine completes commit or rollback before exiting; it must not leave a partially written file. Menus do not use a recursive call stack.

A mutation has at most one summary/confirmation, `Apply changes? [Y/n]:`, with Enter=yes. Create, add, and edit show that once after collecting fields. Disable/delete use their one dedicated confirmation instead. Reading/testing never asks for confirmation. A known conflict re-prompts only the offending field after the short error; other valid fields remain filled.

`[Y/n]` accepts empty/y/yes as true and n/no as false; `[y/N]` accepts empty/n/no as false and y/yes as true, case-insensitively after stripping ASCII outer whitespace. Anything else returns E_YES_NO. Numbered menu input is ASCII digits only. No translated numerals.

## First launch

If no config exists, show SETUP, then `Server role [1=Iran, 2=Foreign]:`. This is asked once. Discover candidate global-scope usable IPv4 addresses and the underlay interface from `ip -j` and the route to the chosen peer. Do not query a public IP website. If exactly one candidate exists, use it without asking. If several exist, show a numbered IP/interface list and `Local IP:`. If none exists, return E_LOCAL_IP and stop before mutation. Role is informational and does not remove menu features.

After storing only host metadata, show the main menu. Forwarding sysctls and network objects are not enabled until the first tunnel transaction. A saved config from a keep-data uninstall is validated and re-applied on explicit reinstall as documented; do not ask all old questions again.

## Main > 1 Create tunnel

Show the fixed create submenu: New tunnel / Import setup code / Back.

### New tunnel

1. `Peer IP:` (required numeric unicast IPv4; reject local/self/loopback/multicast/unspecified/broadcast).
2. `Local IP:` only when more than one eligible source IP/interface exists. The default source for this peer is shown first.
3. `Name [{default_name}]:`, default `Tunnel N` where N is the next tunnel ID. ASCII letters/digits, spaces, `_`, `.`, `-`; 1..32 characters after outer whitespace removal.
4. Show Peer, Local, Name and the summary of one new tunnel. Ask Apply once.
5. Allocate/stage/apply local resources, then print `Tunnel created.` and `Paste this setup code on the other server:` followed by the GT1 token on one line. Print `Waiting for peer setup.` until a real test provides evidence. Do not print Connected merely because a GRE interface is UP/UNKNOWN.

No role/IP defaults from the historical chat. Ports are added from Manage after the pair is set up. This avoids a large create wizard and accidental port duplication on the remote host.

### Import setup code

Ask `Setup code:` once. Decode as data, never execute it. Verify format, bounded length, schema, SHA256 integrity, current host address, key/address consistency, and local conflicts. Show a compact summary and Apply once. Same pair + same selected settings is idempotent and says `Already configured.`. If the receiver selects a later conflict-free candidate CIDR or a smaller supported MTU, output an updated token and the fixed notice to paste it on the first server. Do not claim the first server has been updated. A changed code cannot overwrite an unrelated tunnel just because a local numeric ID matches.

If all candidates conflict, print E_ADDRESS_CONFLICT followed by conflict_code_notice and a GT1 payload with kind=conflict and rejected_cidrs equal to all offered candidates. Importing that response on the first server regenerates candidates excluding those in the response and its saved rejected set, increments revision, stages the new local proposal after one Apply confirmation, and outputs the new setup code. No failed receiver-side mutation occurs. A stale revision for a known pair is rejected; an equal revision with different content is a conflict, not silent last-write-wins. A receiver adjustment increments the revision; the creator's subsequent import stores the exact selected CIDR/MTU.

## Main > 2 Manage tunnels and ports

Show a compact tunnel list with ID, Name, Peer and Status, then `Tunnel ID (0=Back):`. On an empty list show `No tunnels configured.` and return after Enter. Selecting a tunnel opens the fixed detail menu:

List record format is exactly `{id} | {name}\nPeer: {peer_ip}\nState: {enabled_label} | Health: {health_label}\n`, followed by one blank line. Port list record is `{id} | {protocol}\nListen: {listen_ip}:{listen_port}\nTarget: {target_ip}:{target_port}\nState: {enabled_label}\n`, followed by one blank line. No width-dependent padding/truncation. Lists paginate at 10 records. Show `Page {page}/{pages}` and `n) Next page\np) Previous page` only when pages >1; n/p clamp at the ends. Stable ID selection can address an item outside the current page. The four-item main menu never gains pagination/actions.

1) Ports
2) Edit tunnel
3) Enable tunnel OR Disable tunnel (same slot; state decides exact text)
4) Show setup code
5) Delete tunnel
0) Back

Header data: Tunnel ID, Name, Local IP, Peer IP, State. Do not show kernel handles. Backend state: Enabled/Disabled; health: Connected/Unverified/Local error. Label both rather than conflating enabled with reachable.

### Ports screen

List ID, Protocol, Listen, Target, Enabled. Listen and Target include IP:port. Use one vertical record per port when displaying details; fixed list separators and widths are in the golden render function. Do not expand Both into two apparent user records. Screen actions: Add ports / Edit port / Traffic / Back. Port selection by stable P ID is required for Edit or Traffic; `all` selects the local tunnel aggregate on Traffic.

Add fields in order:

1. `Ports (443,5445:5454):` — one required input. Parse by the reference grammar, rejecting the entire batch if any item is invalid. Do not ask for a target port separately.
2. `Protocol [1=TCP, 2=UDP, 3=Both] (3):` — default Both.
3. `Listen IP [{tunnel_local_ip}]:` only if more than one eligible local IP on this tunnel's WAN exists; otherwise automatically use the tunnel local IP.
4. `Target IP [{peer_inner_ip}]:` — default the peer inner IP, but allow the peer outer IP or another routable IPv4 target after validation. Reject loopback, multicast, zero, all-ones broadcast, this host's local addresses and any address known to produce a self-loop. A target equal to the remote outer endpoint is explicitly supported.
5. Show each resulting Listen/Target/Protocol. Apply once. New caps are Unlimited; cap questions are not added to the add wizard.

Examples: `443` -> 443:443; `5445:5454` -> 5445:5454; `443,5445:5454,8080` creates three logical forwards. Outer spaces around tokens/colon are permitted; signs, non-ASCII digits, empty items, ranges, protocol suffixes and duplicate listen ports in one batch are rejected. Port 0 is invalid. A leading zero is normalized as decimal.

One batch is at most 256 mappings and 2048 input characters. Preserve input order when allocating IDs; display subsequently by ID. Batch application is all-or-nothing. The runtime validates protocol-specific tuple conflicts after expansion, independently of this syntax-only parser.

### Edit port

Select one P ID, then show the port menu: Edit mapping / Speed limits / Enable or Disable / Delete / Back.

Edit mapping asks four fields in the same order as Add (but exactly one mapping in Ports), with current values displayed and Enter preserving them. No automatic edits to other forwards. Show one summary and Apply once. Display `Existing connections on this port will reconnect.` when a live tuple, target or protocol changes. The actual transaction deletes only that forward's conntrack entries. A no-op edit does not restart anything, allocate a new ID or reset counters.

Speed limits asks `Upload limit in Mbps [current] (0=Unlimited, b=Back):` then the Download equivalent. Integer 0..100000 is accepted; `unlimited` is an alias for 0, case-insensitive. Enter preserves the cap. Do not ask TCP/UDP separately for Both. Apply once. The cap is a sustained class ceiling with bounded bursts, not a guaranteed available throughput. Zero removes the class/filter limitation, not the port.

Disable says `Disable this port? [y/N]:`; Delete says `Delete this port? [y/N]:`. Enable is a transaction after current conflict checks and needs no second confirmation. Remove only its own active connections and network objects; retained aggregate history is keyed by its tombstoned ID.

### Edit tunnel

Fields: Name, Local IP, Peer IP, each with current value. Enter keeps. No user-facing internal-network field. A name-only edit has no dataplane mutation. Changing an outer endpoint creates a new pair identity and setup code; regenerate compatible inside addressing and preserve the local tunnel ID and its local forward IDs. Show `Update the other server with the new setup code.` and the affected connection notice before one Apply confirmation. Disable, stage the new pair, flush only affected managed connections, apply and verify locally; rollback if local checks fail. A changed peer cannot be declared Connected until tested. The user must import the updated code on the other server.

Show setup code displays the most recent selected pair configuration without changing it. Delete tunnel uses `Delete this tunnel and its ports? [y/N]:`; completed text explains that only this server was changed. Disabling retains desired config and history, withdraws its forwarding and QoS, and keeps or lowers the owned link only according to the network lifecycle; it does not disturb other peers.

## Traffic screen

Title and labels come from ui.en.json. Show Listen, Target, Protocol, Current upload/download (Mbps), Upload limit, Download limit; then Last 1h and Last 24h, each with Upload, Download, Total in decimal MB/GB, Avg upload/download in Mbps, and Coverage as integer seconds, rounded down: `Complete ({seconds} s)` or `Partial ({seconds} s)`. Empty coverage: N/A. Partial coverage is explicit. If a forward's target/tuple changed within either window show `Includes earlier settings.`. Follow the exact line order and colon-space layout in fixtures/ui/traffic.example.txt.

Show the snapshot once; commands `r=Refresh`, `0=Back`. Refresh takes a bounded two-second counter observation for current speed. It must not start an endless dashboard, poll the kernel on every keystroke, or alter the config. The daemon collects persisted historical samples independently of the UI.

Remote endpoints without local forwards show `No local port forwards.` plus separately labelled `Tunnel RX`/`Tunnel TX` interface totals and current rates. They must not fabricate per-port counts belonging to another host. To inspect a port, use the host where its Listen IP is configured.

## Main > 3 Test connection

List tunnel IDs and allow `all`, then one selection prompt. Test immediately, read-only to network state. One report <=20 lines per tunnel and total runtime <=12 seconds per tunnel (all tests sequential with progress `Testing Txxxx...`). Result PASS means exactly that the tested peer inner ICMP request/reply succeeded and structural checks passed. No ICMP plus valid structure is UNVERIFIED, with bounded activity evidence. Structural mismatch is FAIL even if ping replies. Port TCP probes are optional from an explicit port detail test command, never a UDP-open assertion. Details in diagnostics contract.

## Main > 4 Uninstall

Print the fixed warning that this host's managed tunnels/forwards will stop. Ask only `Keep saved settings and traffic history? [Y/n, 0=Cancel]:`. Enter/y=yes removes runtime/program objects but preserves owned config/history; n=no also deletes saved config/history; 0 cancels. There is no additional confirmation chain. A short verified completion result is required; failed removals must be listed, not hidden behind a success message. Keep mode stores enough identity to reinstall and resume with all normal conflict checks. It must not leave active forwarding just to preserve settings.

## CLI parity

The menu is the default. Automation/test commands are frozen in contracts/cli_contract.json. JSON output uses machine keys, not translated labels. Invalid invocations exit 2; validation/conflict exits 3; apply failure with completed rollback exits 4; failed/incomplete rollback exits 5; diagnostic FAIL exits 6; UNVERIFIED exits 7. Success and deliberate cancel exit 0. Raw child stdout/stderr goes only to a bounded diagnostic detail, not into the English UI as a replacement message.
