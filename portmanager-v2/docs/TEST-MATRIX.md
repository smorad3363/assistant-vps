# Acceptance gate status — source of truth

Spec: [PM2-SPEC-001.fa.md](PM2-SPEC-001.fa.md). See
[PROGRESS.md](PROGRESS.md) for latest CI run and checkpoint.

No test is PASS without actual execution evidence. The GitHub runner is a
disposable Ubuntu 24.04 VM; **it is not a full V1+V2 deployed VPS**.

| Gate / IDs | Current result | Evidence required |
| --- | --- | --- |
| Gate A — V1 directory frozen, Bash, Python, ShellCheck, SHA256 | PASS at previous HEAD; recheck latest | GitHub workflow |
| Gate B — Phase-1 CLI and service ownership tests | Pending latest CI | unittest job for 3.10 and 3.12 |
| AT-001 actual install V1 via original URL | NOT TESTED | VM original installer |
| AT-002 V1 alias identical result | PARTIAL | delegated URL/exit mocked only |
| AT-003 V2-only install/version | Previously PASS; recheck latest | isolated VM |
| AT-004 V1 present then V2 install, fingerprint | NOT TESTED | dedicated sandbox VM |
| AT-005 V2 repeated install no duplicate | Previously PASS; recheck latest | isolated VM |
| AT-006 V2 uninstall while V1 installed | NOT TESTED | dedicated sandbox VM |
| AT-007 V2 purge while V1 installed | NOT TESTED | VM manual confirm + fingerprint |
| AT-022 dry-run no mutation, all mutators | PARTIAL | no NAT mutators implemented |
| Gate C / AT-008..022 network | NOT TESTED | netns and VM TCP/UDP NAT |
| Gate D V1/V2 coexistence | NOT TESTED | V1 installed VM + fingerprint |
| Gate E failure injection, reboot | PARTIAL | unit rollback mocked; full VM required |
| Gate F release | BLOCKED | 0 P0/P1 + docs + manual approval |

New Phase-1 regression checks:
- V1 alias points to the unmodified original URL and propagates errors, without
  executing the genuine installer in a shared CI host.
- The installer installs **disabled** service units with recorded checksums,
  never enables them, removes them on uninstall and leaves V1 paths unchanged.
- Mocked unit lifecycle: new install, idempotent install, modified/foreign/
  symlinked/masked/active units block deletion; failed daemon-reload rolls back.
- Installer and CLI uninstall share an exclusive nonblocking mutation lock.
- Before/after `iptables-save` and `tc qdisc show` equality on ephemeral runner.
