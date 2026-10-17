# Build roadmap and release gates

The build agent continues through the following milestones without pausing for routine design permission. A milestone is complete only when its stated evidence exists. Contract tests already in this package are read-only and are not live-network acceptance.

## M1: deterministic contracts and CLI

Implement the fixed Python layout, menu state machine, string catalog, port grammar, canonical JSON, exact error/exit codes, configuration validation, peer token codec, data schemas and root/OS checks. Reuse the pure reference behavior. Compare full menu/prompt fixtures, including whitespace and English wording. Test EOF/Ctrl+C/no-op edits. A non-TTY invocation must require explicit CLI arguments, not hang waiting for a menu.

## M2: fresh installation and one tunnel pair

Implement installer/service and a real two-host pair. Check outer source selection, automatic /30/key assignment, peer code import, candidate conflict response/retry, MTU negotiation, idempotent reimport and a disabled state. Verify no default-route change, no foreign firewall modification and no physical-WAN qdisc change. Confirm a peer IP equal to target IP works without a routing loop.

## M3: multiple tunnels and forwarding

Implement TCP, UDP, Both, batches, remapped ports, multiple local IPv4 addresses on the tunnel's WAN, edits/disables/deletes and exact connection cleanup. Test 2 entry hosts x 2 peer hosts (four independent tunnels). Removing one cannot change the other three. Test two distinct local forwards to the same destination through different tunnels and prove both paths using per-interface counters/captures. Test local peer services and a third-party target behind a peer. Confirm the reverse path and no accidental cross-GRE transit.

## M4: accounting and QoS

Implement SQLite history/epochs, rolling windows, current rate, coverage and generation tracking. Test persistent single connections to catch first-packet-only accounting mistakes. Implement class-based upload/download caps and fragmented reply classification. Verify shared TCP+UDP cap, all-clients aggregate cap, uncapped forwards unaffected, same-target identity separation, deletion/recreation, counter resets, simultaneous directions, and no WAN qdisc modification.

## M5: lifecycle and diagnostics

Inject failures between every mutation stage, kill the foreground process, expire the independent rollback guard, and restart the service/VM with an unfinished journal. Verify scoped undo, no counter duplication, SSH session preservation and accurate reporting of incomplete rollback. Test peer ICMP blocked while real TCP/UDP still works; result must be UNVERIFIED and no link reset. Test an incorrect outer pair with a ping response; result must remain FAIL. Test quiet tunnels and GRE operstate UNKNOWN. Reports and logs stay bounded.

## M6: uninstall, full regression and release

Uninstall with keep=yes, verify every owned active resource is gone, reinstall and restore saved definitions/history. Repeat with keep=no and verify clean setup. Check foreign sentinel routes, rules, nft tables, sockets, tc configuration and a normal SSH connection before/after each operation. Produce source/release ZIP, installation commands, SHA256 manifest and actual test report. Mark unrun cases NOT RUN. No release-ready claim while a critical gate is unrun/failed.

## Isolated lab and commands

Use disposable Ubuntu 22.04/24.04 VMs. Within each, network namespaces and veth links may simulate clients, entries, peers and service targets. Namespace names must start `gttest-`; every mutating `ip`, `nft`, `tc`, sysctl and app test command must target the intended test namespace or the disposable VM, never the developer's real WAN. Do not run tests against addresses from old chats. Use documentation IPv4 ranges only inside the isolated lab. Verify namespace cleanup with a finally/trap handler.

The build must supply:

```bash
python3 -m unittest discover -s tests/unit -v
sudo bash tests/integration/run.sh
sudo bash tests/integration/reboot-check.sh
```

The latter two scripts must be real, reject an unmarked/non-disposable test host, and state prerequisites. The reboot check uses a VM snapshot/reboot, not a fake process restart. If this environment cannot perform VM tests, deliver these scripts and a NOT RUN explanation; do not request production credentials. No benchmark is inferred from the user's hardware or user-count targets.

## Acceptance matrix

| ID | Scenario | Required result |
|---|---|---|
| UI-01 | gre-tun default launch | Exact four-option menu; English only |
| UI-02 | Add 443,5445:5454,8080 | Three mappings; no target-port question |
| UI-03 | Edit one field and Enter others | Others unchanged; one confirmation |
| UI-04 | EOF, invalid token, back | No partial saved mutation |
| NET-01 | Real two-ended GRE | Payload in both directions; exact outer path |
| NET-02 | Same outer pair imported twice | No duplicate interface/rule/ID |
| NET-03 | Four-tunnel mesh | Independent paths; one removal isolated |
| NET-04 | Target equals peer outer IP | TCP/UDP work; outer GRE never loops |
| NET-05 | Two tunnels share target | Correct per-forward table and replies |
| NET-06 | Third-party target | Scoped peer SNAT and return routing work |
| NET-07 | UDP fragments/large packets | Correct routing/accounting/capping; no bypass |
| CON-01 | Local TCP wildcard listener | Matching IPv4 TCP input blocked; UDP checked separately |
| CON-02 | Dual-stack wildcard listener | IPv4 exposure detected or conservative conflict |
| CON-03 | Same port different specific IP | Allowed when truly disjoint |
| CON-04 | Existing DNAT/REDIRECT/TPROXY | Overlap blocked without deleting it |
| CON-05 | Foreign DROP/NOTRACK/flowtable/zone | Relevant conflict reported; no false coexistence |
| CON-06 | Existing reserved name/mark/table | Refused; foreign object unchanged |
| QOS-01 | 20 Mbps cap, 30-second steady sample | <=22 Mbps receiver; >=16 in capable lab |
| QOS-02 | Many clients + Both | One shared cap per direction |
| QOS-03 | Two ports to same target | Independent counters/classes/limits |
| QOS-04 | Cap edit/unlimited | Immediate scoped class update; other traffic unchanged |
| QOS-05 | Reply with inherited ctmark | No policy-route loop; IFB class used |
| STA-01 | Single long-lived connection | Counters grow beyond first packet |
| STA-02 | Fixed 1h/24h fixtures | Reference exact bytes/rounding/coverage |
| STA-03 | Restart, epoch reset and gap | No negative/huge/duplicated volume |
| STA-04 | Idle or disabled known interval | Zero bytes with real covered time |
| STA-05 | Edited/deleted port history | Attribution retained with correct label/tunnel |
| LIFE-01 | Repeated apply | No duplicates, restarts or counter reset |
| LIFE-02 | Failed cutover / killed shell | Scoped rollback guard restores prior owned state |
| LIFE-03 | Reboot | Desired state/caps return; saved history retained |
| LIFE-04 | Keep-data uninstall/reinstall | Active objects gone, saved state restores safely |
| LIFE-05 | Delete-data uninstall | No owned residual state or active objects |
| TEST-01 | ICMP blocked but service active | UNVERIFIED; no destructive heal |
| TEST-02 | Structure mismatch with ping reply | FAIL, never PASS |
| TEST-03 | Quiet tunnel / UNKNOWN link | No fabricated outage; bounded output |
| OWN-01 | Foreign sentinels and SSH | Byte/semantic-equivalent state survives all operations |

Also run both supported OS versions on x86_64. arm64 support requires an actual arm64 test (or explicitly remains NOT RUN in the delivered matrix). Technical ID capacity is not a performance claim. Benchmark 16 tunnels and 128 logical forwards with concurrent traffic; record CPU, memory, conntrack usage and collector cost, without declaring an unsupported user-count guarantee.

## Reporting format

TEST_RESULTS.md records date, git commit/release hash, distro/kernel/architecture, command, case IDs, result and bounded evidence. Distinguish expected failure-case PASS from an unhandled error. Bundle the original frozen contract test results as well as new tests. A useful final answer includes the release link, ready-to-copy install/run command, test totals, and material NOT RUN limitations; not pages of internal logs.
