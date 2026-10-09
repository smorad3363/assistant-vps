#!/usr/bin/env bash
# Explicit V1 selector: safely restore archived V1 after V2 and never write
# through a V2 symlink. Original V1 source/payload is frozen separately.
set -Eeuo pipefail
REF="${PORTMANAGER_INSTALL_REF:-master}"
[[ "$REF" =~ ^[A-Za-z0-9._/-]+$ ]] || { echo 'Invalid source ref' >&2; exit 2; }
ORIGINAL="https://raw.githubusercontent.com/smorad3363/assistant-vps/$REF/portmanager-v1/legacy-install.sh"
[[ $(id -u) == 0 ]] || { echo 'Run as root/sudo' >&2; exit 1; }
command -v curl >/dev/null || { echo 'curl required' >&2; exit 1; }
command -v python3 >/dev/null || { echo 'python3 required for safe V1 restore' >&2; exit 1; }

tmp="$(mktemp)"
trap 'rm -f -- "$tmp"' EXIT
# Obtain a fully parsed, frozen fallback installer before disturbing V2.
curl --proto '=https' --tlsv1.2 -fsSL --retry 2 "$ORIGINAL" -o "$tmp"
[[ -s "$tmp" ]] || { echo 'Empty V1 installer' >&2; exit 1; }
bash -n "$tmp"

V1="/usr/local/bin/portmanager"
V2="/usr/local/bin/portmanager2"
V2_TARGET="/opt/portmanager2/current/bin/portmanager2"
ARCHIVE="/var/lib/portmanager2/legacy-v1"
# Check archive ownership and hashes BEFORE tearing down an installed V2.
python3 - "$ARCHIVE" <<'PY'
import hashlib, json, sys
from pathlib import Path
base = Path(sys.argv[1])
m, b = base / "archive.json", base / "portmanager.v1"
if base.is_symlink() or m.is_symlink() or b.is_symlink():
    raise SystemExit("E_CONFLICT: unsafe legacy backup symlink")
if not m.exists():
    if b.exists():
        raise SystemExit("E_CONFLICT: unowned legacy binary backup")
    raise SystemExit(0)
try:
    meta = json.loads(m.read_text(encoding="utf-8"))
except (OSError, ValueError):
    raise SystemExit("E_CONFLICT: archived V1 manifest corrupt")
if (meta.get("product") != "portmanager2-v1-archive" or
        not b.is_file() or
        hashlib.sha256(b.read_bytes()).hexdigest() != meta.get("sha256")):
    raise SystemExit("E_CONFLICT: archived V1 has incorrect ownership/hash")
PY
# A broken/unknown symlink MUST NOT be overwritten by the old installer.
if [[ -L "$V1" && "$(readlink "$V1")" != "$V2_TARGET" ]]; then
  echo 'E_CONFLICT: unknown portmanager symlink; refusing to replace' >&2
  exit 5
fi

if [[ -x "$V2" ]]; then
  # Do not silently disconnect tunnels/SSH; demand explicit tunnel
  # disable/delete on V2 before a version rollback. Saved V2 state is kept.
  python3 - <<'PY'
import json
from pathlib import Path
p = Path("/etc/portmanager2/config.json")
if p.is_symlink() or not p.is_file():
    raise SystemExit("E_CONFLICT: cannot verify V2 tunnel status before rollback")
try:
    cfg = json.loads(p.read_text(encoding="utf-8"))
except (OSError, ValueError):
    raise SystemExit("E_CONFLICT: unreadable V2 tunnel configuration")
if cfg.get("schema_version") != 1 or not isinstance(cfg.get("tunnels"), list):
    raise SystemExit("E_CONFLICT: unknown V2 tunnel configuration")
if any(t.get("enabled") for t in cfg["tunnels"]):
    raise SystemExit("E_CONFLICT: active V2 tunnels must be disabled before V1 rollback")
PY
  # V2 knows exactly which kernel rules, tc filters and services it owns.
  "$V2" uninstall --dry-run >/dev/null || {
    echo 'E_CONFLICT: cannot safely uninstall V2; V1 not touched' >&2
    exit 5
  }
  "$V2" uninstall --yes || {
    echo 'E_CONFLICT: V2 uninstall blocked; V1 not touched' >&2
    exit 5
  }
fi
# The original Bash installer uses install -m on the destination. If V2
# still owns the public symlink, it would overwrite the V2 program itself.
[[ ! -L "$V1" ]] || { echo 'E_CONFLICT: still a symlink; refusing V1 write' >&2; exit 5; }

if [[ -f "$ARCHIVE/archive.json" ]]; then
  # Restore the *exact saved legacy binary*, rather than updating the old
  # algorithm to an unrelated/latest V1 revision.
  install -m 0755 "$ARCHIVE/portmanager.v1" "$V1"
  bash -n "$V1"
  "$V1" install
else
  # Fresh explicit V1 selection; install original pinned legacy payload.
  bash "$tmp"
fi

# Restore only archived V1 cron lines, without discarding other jobs added
# since the V2 migration. Preserve V1's original custom schedule choices.
python3 - "$ARCHIVE" <<'PY'
import json, subprocess, sys
from pathlib import Path
m=Path(sys.argv[1]) / "archive.json"
if not m.exists():
    raise SystemExit(0)
data=json.loads(m.read_text(encoding="utf-8"))
jobs=data.get("disabled_cron", [])
if not isinstance(jobs,list) or not all(isinstance(x,str) for x in jobs):
    raise SystemExit("E_CONFLICT: corrupt archived cron settings")
p=subprocess.run(["crontab","-l"],text=True,capture_output=True,check=False)
if p.returncode not in (0,1):
    raise SystemExit("E_CONFLICT: cannot read cron for restoration")
current=p.stdout if p.returncode==0 else ""
existing=set(current.splitlines(keepends=True))
missing=[line for line in jobs if line not in existing]
if missing:
    text=current+("" if not current or current.endswith("\n") else "\n")+"".join(missing)
    result=subprocess.run(["crontab","-"],input=text,text=True,capture_output=True,check=False)
    if result.returncode:
        raise SystemExit("E_APPLY: archived V1 cron restoration failed")
PY
echo 'Port Manager V1 selected: run portmanager'
echo 'Saved V2 configuration remains under /etc/portmanager2 for future upgrades.'
