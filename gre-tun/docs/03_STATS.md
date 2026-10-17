# Traffic accounting and rolling statistics

## Meaning

A logical forward owns one stable ID. TCP+UDP in Both feeds the same two named nft counters: ORIGINAL -> upload; REPLY -> download. Match connection mark, direction and expected interfaces; count each eligible L3 packet once. Count IP header and retransmissions, not just application payload. Exclude outer GRE overhead. Counters describe traffic at the defined forwarding hook; they are not proof of delivery and can include packets dropped later by a queue/network. Physical interface statistics, remote-endpoint traffic and provider billing are separate measures and must never be added to per-forward usage.

Do not use NAT-chain counters, parse `ss` byte totals, count with tcpdump, or maintain a Python object for every client connection. One long-lived connection must accumulate throughout its lifetime, not only on its first packet. If foreign flow offload bypasses the hook for managed flows, reject the configuration or explicitly exclude those flows through a tested owned integration; do not silently undercount.

## Storage

Use the exact SQLite DDL in reference/schema.sql. WAL, foreign_keys=ON, busy_timeout=5000, synchronous=FULL. Use transactions, parameterized SQL, and SQLite online backup for snapshots; copying just the main DB file while WAL is active is invalid.

Collect all owned named counters once every 60 seconds using a single structured nft query where possible. Persist nonoverlapping intervals with integer UTC milliseconds, integer byte deltas, boot_id and counter epoch. Keep >=25 hours (90,000 seconds) plus the current baseline. Prune expired complete intervals in one bounded transaction. One interval can carry both directions. Store samples for idle configured forwards as known zero intervals; do not store unknown gaps as zero. Do not launch one daemon/timer per forward.

Checkpoint the counter baseline and the delta in the same SQLite commit. On graceful stop, final-sample before closing. On abrupt crash, committed history remains; the latest <=60 seconds may be unrecorded. Across reboot or counter recreation, establish a new baseline; never turn a reset into a giant positive value, a negative rate or double-counted total. Do not subtract counters from different epochs. A counter removed by an edit/delete is sampled immediately before the network transaction and its history kept independently.

Restore only recent schema-compatible data, keep timestamps original, and do not concatenate duplicated samples on reinstall. Normal stop/restart within a boot with valid matching baseline can recover a delta if its interval is <=90 seconds. If the gap exceeds 90 seconds, or boot/counter epoch changes, record a gap and start a baseline; do not spread unknown traffic across an hour. A wall-clock jump inconsistent with monotonic elapsed time by >5 seconds closes the epoch and marks a gap. Clock maintenance does not modify historical timestamps.

## Rolling windows and formula

At wall time `now_ms`, window is `[now_ms - W*1000, now_ms)`, where W is 3600 or 86400. Include the overlap of each known sample interval. For a partial overlap, prorate bytes uniformly by overlap_duration/interval_duration. This is a bounded-resolution estimate, not an exact sub-minute traffic trace. Samples must not overlap per item/epoch. Gaps have no coverage and no inferred bytes.

Window upload/down bytes = sum of prorated per-interval directional bytes, rounded to whole bytes using ROUND_HALF_UP only after summation. Total bytes = rounded upload + rounded download. Coverage_ms = union of known overlapped intervals. Average directional Mbps = unrounded prorated directional bytes * 8 * 1000 / coverage_ms / 1,000,000, rounded HALF_UP to two decimals. Known idle time contributes to the denominator. Unknown downtime does not; Coverage shows the difference. No coverage => bytes and averages are null and UI N/A. Partial coverage => label Partial with actual duration. A host offline for an hour must not display a measured one-hour average of zero.

Current speed uses two reads of the same epoch's counter separated by approximately two monotonic seconds, not division by the historical 1h total. Measure actual elapsed time. Counter reset, timeout, less than one second elapsed or a disappeared object => N/A. Historical windows are calculated using `as_of` equal to the latest completed persisted observation, displayed as `Updated: <UTC>`; a direct current-rate refresh does not pretend to update history beyond its saved samples. Sample the current partial interval before a Traffic screen only through the daemon's serialized sampler request, not through a second independent writer.

Display volume as decimal MB with two decimals below 1,000,000,000 bytes, and GB with two decimals at/above that threshold. Zero bytes is `0.00 MB`. Speeds are `N.NN Mbps`. Caps are integer `N Mbps` or Unlimited. Reference implementation fixes rounding and example outputs.

## Edit, disable, delete and aggregate semantics

Editing a forward preserves its ID and history. Increment generation for changes to listen tuple, protocol, target, or tunnel placement. Capture old generation metadata. Within the lookback window show `Includes earlier settings.` rather than silently labelling all historical traffic with the new target. Cap/name changes do not create a traffic generation.

Disable: history retained; known disabled time is zero traffic while the collector is running. Re-enable does not reset previous windows. Delete: stop active collection after the final sample; keep the tombstoned ID/history for the 25h retention window, but exclude it from current live port list. Tunnel aggregate includes the historical forwards that belonged to it during the relevant intervals, including recent deleted ports, so totals do not suddenly drop on deletion. Do not simply join every old interval to the forward's current tunnel ID.

For a tunnel average, sum contemporaneous per-forward contributions into time segments; require every expected constituent's interval to be known for a segment to call the aggregate coverage complete. If one collector observation failed for one port, show partial coverage rather than assuming zero. Live instantaneous tunnel logical speed sums available per-forward deltas from the same observation pair; if any required value is unknown, mark the aggregate partial. Endpoint-only tunnel interface RX/TX is a separate view, not a reconstructed remote per-port breakdown.

## Required tests

Use fixed timestamps and integer byte counts: full/partial/empty windows, idle intervals, exact boundaries, sample overlap rejection, counter decrease/epoch change, restart recovery without duplication, >90-second gap, wall-clock jump, decimal MB/GB conversion, deleted-forward inclusion, target edits, a one-hour window with 20 minutes of unknown downtime, and long-lived TCP/UDP traffic. At least one real-kernel test transfers known data in a single persistent connection and confirms both named counters continue growing.
