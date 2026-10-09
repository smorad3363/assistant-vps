# Port Manager V2 development CLI

Version: `2.0.0-dev.1`. Stable command contract:
[PM2-SPEC-001.fa.md](PM2-SPEC-001.fa.md), section 4.

Currently implemented:
- `portmanager2 --version`, `help`
- `portmanager2 doctor --json`: read-only; labels unimplemented checks
- `portmanager2 status --json`: read-only bootstrap status
- `portmanager2 limits list --json`: intentionally unsupported limits
- `portmanager2 uninstall --dry-run`, `uninstall --yes`
- `portmanager2 uninstall --purge` with **extra interactive confirmation**

Other tunnel/NAT/sampling commands are reserved and return
`E_UNSUPPORTED`/exit 8, with no network changes.

JSON response keys: `ok`, `code`, `message`, `details`, `request_id`.
See normative error code table in spec for exit meanings.
Temporary phase-1 systemd units are installed **disabled**. V1 is `portmanager`
and is neither altered nor invoked by V2.
