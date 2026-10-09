#!/usr/bin/env bash
# Port Manager V2 development installer. Does not touch iptables, tc or V1.
set -Eeuo pipefail
export LC_ALL=C
REPO="smorad3363/assistant-vps"
REF="${PORTMANAGER2_REF:-master}"
ROOT="/opt/portmanager2"
BIN="/usr/local/bin/portmanager2"
ETC="/etc/portmanager2"
DATA="/var/lib/portmanager2"
LOG="/var/log/portmanager2"
LAUNCHER_TARGET="$ROOT/current/bin/portmanager2"

fatal() { printf '[portmanager2] ERROR: %s\n' "$*" >&2; exit 1; }
log() { printf '[portmanager2] %s\n' "$*"; }

[[ "$(id -u)" == 0 ]] || fatal "Run as root."
for command in curl python3 sha256sum tar cp mv mkdir readlink mktemp ln chmod bash grep rm cat flock; do
  command -v "$command" >/dev/null 2>&1 || fatal "Missing required tool: $command"
done
python3 -c 'import sys; assert sys.version_info >= (3, 10)' \
  || fatal "Python 3.10+ required"
[[ "$REF" =~ ^[A-Za-z0-9._/-]+$ ]] || fatal "Invalid Git ref"
[[ ! -L /run/lock/portmanager2.lock ]] || fatal "V2 lock path is an unsafe symlink"
exec 9>/run/lock/portmanager2.lock
flock -n 9 || fatal "Another Port Manager V2 operation holds the lock"
[[ ! -e "$BIN" || -L "$BIN" ]] || fatal "Refusing to overwrite existing $BIN"
if [[ -L "$BIN" ]]; then
  [[ "$(readlink "$BIN")" == "$LAUNCHER_TARGET" ]] \
    || fatal "$BIN does not belong to Port Manager V2"
fi
[[ ! -e "$ROOT/current" || -L "$ROOT/current" ]] \
  || fatal "Unrecognized $ROOT/current"
if [[ -L "$ROOT/current" ]]; then
  current_target="$(readlink "$ROOT/current")"
  [[ "$current_target" =~ ^releases/[A-Za-z0-9._-]+$ ]] \
    || fatal "Unknown/escaping release target: $current_target"
fi

# Never adopt or overwrite someone else's directory.
python3 - "$ROOT" "$ETC" "$DATA" "$LOG" <<'PY'
import json
from pathlib import Path
import sys
for value in sys.argv[1:]:
    directory = Path(value)
    if directory.is_symlink():
        raise SystemExit(f"Refusing symlink directory: {directory}")
    if directory.exists() and not directory.is_dir():
        raise SystemExit(f"Not a directory: {directory}")
    marker = directory / (".owner.json" if value.endswith("/portmanager2") and value.startswith("/opt/") else "owner.json")
    # The log directory may exist without a marker after interrupted installs.
    if directory.exists() and any(directory.iterdir()) and not marker.is_file():
        raise SystemExit(f"Unowned nonempty V2 path: {directory}")
    if marker.is_symlink():
        raise SystemExit(f"Owner marker must not be a symlink: {marker}")
    if value == "/etc/portmanager2":
        for name in ("config.json", "owner.json"):
            if (directory / name).is_symlink():
                raise SystemExit(f"Unsafe symlink in V2 configuration: {name}")
        config_file = directory / "config.json"
        if config_file.is_file():
            try:
                config = json.loads(config_file.read_text(encoding="utf-8"))
            except (ValueError, OSError) as exc:
                raise SystemExit(f"Invalid V2 config: {exc}")
            if not isinstance(config, dict) or config.get("schema_version") != 1:
                raise SystemExit("Unsupported V2 config schema; refusing migration")
    if marker.is_file():
        try:
            owner = json.loads(marker.read_text(encoding="utf-8"))
        except (ValueError, OSError) as exc:
            raise SystemExit(f"Unreadable owner marker: {marker}: {exc}")
        if owner.get("product") != "portmanager2":
            raise SystemExit(f"Unrecognized owner marker: {marker}")
PY

tmp="$(mktemp -d)"
stage=""
new_release=""
old_pointer=""
swapped=0
created_launcher=0
cleanup() {
  local status=$?
  if ((status != 0)); then
    if ((swapped == 1)); then
      if [[ -n "$old_pointer" ]]; then
        ln -s "$old_pointer" "$ROOT/.current.rollback.$$"
        mv -Tf "$ROOT/.current.rollback.$$" "$ROOT/current"
      else
        rm -f -- "$ROOT/current"
      fi
    fi
    if ((created_launcher == 1)) && [[ -L "$BIN" ]] && [[ "$(readlink "$BIN")" == "$LAUNCHER_TARGET" ]]; then
      rm -f -- "$BIN"
    fi
    if [[ -n "$stage" && -d "$stage" ]]; then rm -rf -- "$stage"; fi
    if [[ -n "$new_release" && -d "$new_release" ]]; then
      rm -rf -- "$new_release"
    fi
    printf '[portmanager2] Failed; active release reverted if previously set.\n' >&2
  fi
  rm -rf -- "$tmp"
}
trap cleanup EXIT

# Resolve a mutable ref to a *full, recorded commit* BEFORE fetching its files.
log "Resolving Git ref: $REF"
curl --proto '=https' --tlsv1.2 -fsSL --retry 2 \
  "https://api.github.com/repos/$REPO/commits/$REF" -o "$tmp/ref.json" \
  || fatal "Cannot resolve Git ref"
SHA="$(python3 - "$tmp/ref.json" <<'PY'
import json, re, sys
value = json.load(open(sys.argv[1], encoding="utf-8")).get("sha", "")
if not re.fullmatch(r"[0-9a-f]{40}", value):
    raise SystemExit("Invalid commit SHA returned by GitHub")
print(value)
PY
)" || fatal "Invalid GitHub response"
log "Pinned source commit: $SHA"
curl --proto '=https' --tlsv1.2 -fsSL --retry 2 \
  "https://codeload.github.com/$REPO/tar.gz/$SHA" -o "$tmp/source.tar.gz" \
  || fatal "Cannot download pinned source archive"
mkdir "$tmp/source"
tar -xzf "$tmp/source.tar.gz" --no-same-owner --strip-components=1 -C "$tmp/source"
[[ -f "$tmp/source/portmanager-v2/manifest.sha256" ]] \
  || fatal "Source has no V2 checksum manifest"
(cd "$tmp/source/portmanager-v2" && sha256sum --check --strict manifest.sha256) \
  || fatal "V2 source integrity check failed"
VERSION="$(cat "$tmp/source/portmanager-v2/VERSION")"
[[ "$VERSION" =~ ^2\.[0-9]+\.[0-9]+(-[A-Za-z0-9.]+)?$ ]] \
  || fatal "Unexpected version string"
release_id="$VERSION-${SHA:0:12}"
new_release="$ROOT/releases/$release_id"

mkdir -p -- "$ROOT/releases" "$ETC" "$DATA" "$LOG"
chmod 0755 "$ROOT" "$ROOT/releases"
chmod 0700 "$ETC" "$DATA" "$LOG"
if [[ -f "$ROOT/.owner.json" ]]; then
  : # validated before creation
else
  printf '{"product":"portmanager2","schema_version":1}\n' > "$ROOT/.owner.json"
  chmod 0600 "$ROOT/.owner.json"
fi

# Stage on same filesystem for atomic directory rename.
if [[ -e "$new_release" ]]; then
  (cd "$new_release" && sha256sum --check --strict manifest.sha256) \
    || fatal "Existing release directory integrity mismatch"
  new_release="" # do not remove an existing release during rollback
else
  stage="$ROOT/releases/.$release_id.staging.$$"
  mkdir -m 0700 "$stage"
  cp -a "$tmp/source/portmanager-v2/." "$stage/"
  chmod 0755 "$stage/bin/portmanager2"
  bash -n "$stage/bin/portmanager2"
  python3 -m compileall -q "$stage/pm2" || fatal "Python compile failed"
  "$stage/bin/portmanager2" --version | grep -Fxq "$VERSION" \
    || fatal "CLI smoke test failed"
  mv "$stage" "$ROOT/releases/$release_id"
  stage=""
fi

# Create isolated initial state only if missing, atomically (O_EXCL).
python3 - "$ETC" "$DATA" "$LOG" "$SHA" <<'PY'
from pathlib import Path
import json
import os
import sys
etc, data, log = map(Path, sys.argv[1:4])
sha = sys.argv[4]
objects = (
    (etc / "owner.json", {"product": "portmanager2", "schema_version": 1, "source_commit": sha}),
    (etc / "config.json", {"schema_version": 1, "generation": 0, "tunnels": []}),
    (data / "owner.json", {"product": "portmanager2", "schema_version": 1}),
    (data / "state.json", {"desired_generation": 0, "applied_generation": 0,
                           "last_error": None, "applied_at": None,
                           "backend": None, "interface_snapshot": {}}),
    (log / "owner.json", {"product": "portmanager2", "schema_version": 1}),
)
for path, value in objects:
    if path.exists() or path.is_symlink():
        continue
    fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600)
    with os.fdopen(fd, "w", encoding="utf-8") as stream:
        json.dump(value, stream, indent=2)
        stream.write("\n")
        stream.flush()
        os.fsync(stream.fileno())
PY

if [[ -L "$ROOT/current" ]]; then old_pointer="$(readlink "$ROOT/current")"; fi
ln -s "releases/$release_id" "$ROOT/.current.install.$$"
mv -Tf "$ROOT/.current.install.$$" "$ROOT/current"
swapped=1

if [[ ! -L "$BIN" ]]; then
  ln -s "$LAUNCHER_TARGET" "$BIN"
  created_launcher=1
fi
"$BIN" --version | grep -Fxq "$VERSION" || fatal "Activation smoke test failed"
"$BIN" doctor --json >/dev/null || fatal "Read-only doctor smoke test failed"

# Services exist but are disabled until their engines are implemented/tested.
# Service module handles unit preflight, atomic writes and unit rollback.
PYTHONPATH="$ROOT/current" python3 -m pm2.services install \
  || fatal "Could not safely install V2 systemd units"
if [[ "${PORTMANAGER2_ENABLE_SERVICES:-0}" == "1" ]]; then
  PYTHONPATH="$ROOT/current" python3 -c 'from pm2.services import activate; print(activate())' \
    || fatal "Could not safely activate V2-only systemd units"
fi
new_release=""
swapped=0
trap - EXIT
rm -rf -- "$tmp"
log "Installed DEVELOPMENT $VERSION (commit $SHA)"
log "Run: portmanager2"
log "Development installer: systemd activation opt-in via PORTMANAGER2_ENABLE_SERVICES=1; V1 untouched."
