# ADR-0003 — Scheduled per-port bandwidth limits

## New all-ports and local-port limit mode

- A JSON schedule record can optionally contain `interface`, a kernel
  interface name. This enables policing a local listening TCP/UDP port even
  when it has no V2 NAT tunnel.
- `port=0`, `protocol=tcp,udp` and required `interface` selects a
  **single aggregate** whole-interface IPv4 police via `tc matchall`, for
  both ingress and egress. This may include SSH and other IPv4 services.
  It is **not** one independent police quota for every possible port.
- All-port policies conflict with individual port policies on the same
  interface; remove old policies first, do not stack rate policers silently.
- Live CLI picks a default interface from measured interface traffic and
  asks for explicit confirmation before applying an all-port cap.
- No V1 root qdisc, global iptables table or non-V2 clsact is touched.
  V1 installations or foreign qdisc ownership remain blocked.

## 2.1.0-rc.1 implementation update

A V2-owned `tc clsact` **police/drop** implementation is available in
`pm2/shaping.py`. It resolves only **enabled V2 tunnel ports** to their
own interface, attaches flower ingress rules for `upload_mbps` and egress
rules for `download_mbps`, and samples the configured policy via the
V2-owned minute timer. This is rate **policing**, not HTB queueing; excess
packets can be dropped (TCP typically backs off).

`limits schedule-install --file plan.json` validates, writes an atomic
schedule, reconciles the kernel and activates the V2 timer.
`limits schedule-list` and `limits schedule-apply` are also implemented,
and option 05 in the text menu provides an editable wizard.

**Safety:** refuses to change tc if frozen V1 is installed or a foreign
clsact/filter exists. No V1 `tc` state or root qdisc is touched. V2-only
clsact filters have recorded preferences and owner state; updates are
journaled and rollback when possible, otherwise E_ROLLBACK preserves
evidence. Shaping cannot be enabled on a port not bound to exactly one
active V2 `ports` tunnel. A single scheduled policy needs explicit
IANA timezone and an enabled start-day calendar.

Open qualification: full guest reboot/SSH loss, adverse drift, high-rate
iperf performance, DST clock-step cases on the real tc backend, and
long-lived multi-provider coexistence are not guaranteed by unit tests.



Status: **accepted specification + preview engine implemented; 2.1 enforcement is NOT available**.

## User story / example

User creates: port 443, TCP/UDP, Saturday–Wednesday (ISO 5,6,0,1,2),
18:00 until 02:00 the next day, download 20 Mbit/s and upload 10 Mbit/s.
Outside the window, the port's **explicit base profile** must apply, or
unlimited if the base profile is 0/0. No command should guess a base profile
from existing V1 or other `tc` state.

Sample: [scheduled-limits.example.json](../examples/scheduled-limits.example.json).

## Exact schema and precedence

A schedule is an object with exactly `id` (ASCII unique 1–32),
`port` (integer 1..65535), `protocol` (`tcp`, `udp`, `tcp,udp`),
`timezone` (IANA, e.g. `Asia/Tehran`), `days` (sorted unique ISO
weekdays 0=Monday..6=Sunday), `start` and `end` (`HH:MM` 24h),
`download_mbps` and `upload_mbps` (integer 0..100000, 0=unlimited),
and `enabled` (JSON Boolean).

- Start inclusive, end exclusive. Crossing midnight attributes the after-
  midnight portion to the *start day*. Equal clocks = full 24h start day.
- Reject overlapping enabled rules per port/protocol, even if different
  schedule IDs. Do not silently pick an arbitrary last rule or priority.
- Reject multiple IANA timezones on same port/protocol. DST spring gaps
  never fire; repeated wall-clock minutes at autumn rollback are handled
  idempotently by comparing *desired state*, not triggering one-shot actions.
- Evaluate at a timezone-aware instant using `zoneinfo`. No use of
  manually-changing server timezone. Wall-clock display always lists timezone.
- Even without a scheduled match, never implicitly keep a stale scheduled
  limit. The future 2.1 backend must revert to an **explicit** validated base
  profile, with a persistent owner inventory for both schedule and base.
- Clock adjustment, reboot, daylight-saving changes and missed timer ticks
  require immediate full desired-state reconciliation, without duplicate
  qdisc classes/filters or traffic interruption where supported.

## Mandatory safety barrier

In V2 2.0, `limits set/remove/schedule-add/schedule-remove/schedule-apply`
**MUST fail** as `E_CONFLICT` when V1 or foreign qdisc ownership is present,
otherwise `E_UNSUPPORTED`. Only pure read-only `limits schedule-preview`
is available, with explicit `network_mutation: false`.

Do not call `tc qdisc del dev IF root`, `tc qdisc del dev IF ingress`
or change any V1 `PORTMANAGER_ACCT` rules. Before enabling enforcement
in 2.1: implement V2-owned ingress/egress qdisc adapter or a separately
approved migration path, exclusive owner markers, per-port conflict detection,
durable base profiles, atomic stage + restore on partial failures, a uniquely
owned systemd timer and integration tests with V1 present.

No enforcement against V1-owned `tc` is allowed, including when scheduled
transition time arrives. If a profile can't be applied, retain previous
ownership evidence and emit `E_CONFLICT` plus a visible diagnostic, not
`OK` or a guessed rate.

## Planned end-user commands (2.1; **NOT ACTIVE** in 2.0)

```text
portmanager2 limits schedule list
portmanager2 limits schedule add --port 443 --protocol tcp,udp --timezone Asia/Tehran --days 5,6,0,1,2 --from 18:00 --to 02:00 --dl 20 --ul 10 --dry-run
portmanager2 limits schedule remove <id> --dry-run
portmanager2 limits schedule preview --at 2026-10-09T18:30:00+03:30
```

2.0 read-only *development* preview command:

```bash
portmanager2 limits schedule-preview --file example.json --at 2026-10-12T20:00:00+00:00 --json
```

## Release tests — AT-041..AT-050

| ID | Scenario | Acceptance |
| --- | --- | --- |
| 041 | Mon 18:00 through Tue 02:00 | Correct start/day and midnight cutoff |
| 042 | Weekly overlap on same port/proto | E_CONFLICT, no tc changes |
| 043 | TCP/UDP independent | Each proto matched only by its own schedule |
| 044 | Nonexistent DST minute | Skipped; no spurious time-window action |
| 045 | Repeated DST minute | Reconcile idempotently, no duplicate filters |
| 046 | Different IANA zones on same port | E_CONFLICT |
| 047 | Out of window | Restores explicit base rate / unlimited |
| 048 | V1 or foreign qdisc on interface | E_CONFLICT and zero mutation |
| 049 | Reboot/time jump/missed tick | Desired state recovered, no V1 writes |
| 050 | 1,000 repeated schedule transitions | No duplicate qdisc/filter, no leak, no CPU spikes |

Implementation checkpoint 2026-10-09: pure `pm2/limit_windows.py`
and regression tests for 041..046 exist. Actual qdisc/timer tests 047..050
are **NOT TESTED** and 2.1 enforcement is **NOT IMPLEMENTED**.
