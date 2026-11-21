#!/usr/bin/env bash
# Verify a real v1.2.0 install, failed upgrade, and the pinned HTTPS upgrade.
set -euo pipefail
[[ ${GITHUB_ACTIONS:-} == true && ${EUID:-1} == 0 ]]
[[ ${GREMGR_RELEASE_REF:-} =~ ^[a-f0-9]{40}$ ]]
repo=$(cd "$(dirname "$0")/../.." && pwd)
previous=0a418b20bdd16501d432cf61a95d60a7893cd03a
temporary=$(mktemp -d)
trap 'rm -rf -- "$temporary"' EXIT
export GRE_PANEL_SKIP_ACME=1
mkdir "$temporary/previous"
git -c "safe.directory=$repo" -C "$repo" archive "$previous" gre-manager |
  tar -xf - -C "$temporary/previous"
old_source=$temporary/previous/gre-manager
bash "$old_source/install.sh" --source-dir "$old_source" --port 8876 >"$temporary/first-login"
gremgr --version | grep -Fx 1.2.0
old_release=$(readlink -f /opt/gremgr/current)

env PYTHONPATH="$old_source" python3 - "$temporary/legacy-backup" <<'PY'
from pathlib import Path
import sys
from panel.store import Store
store = Store()
settings = store.config()
settings["settings"]["retention_days"] = 19
store.save(settings)
store.sample({("abcde12345", "all"): (150, 350)}, "v1-release")
Path(sys.argv[1]).write_bytes(store.backup())
PY
cp /etc/gremgr/panel.json "$temporary/panel-before"

cp -a "$repo/gre-manager" "$temporary/broken"
sed -i '/^ExecStart=/c ExecStart=/usr/bin/false' "$temporary/broken/gremgr-web.service"
python3 "$temporary/broken/build-release.py" WORKTREE
if bash "$repo/gre.sh" --source-dir "$temporary/broken" --update-only --port 8877; then
  echo 'The intentionally broken cross-version update unexpectedly succeeded.' >&2
  exit 1
fi
[[ $(readlink -f /opt/gremgr/current) == "$old_release" ]]
cmp "$temporary/panel-before" /etc/gremgr/panel.json
systemctl is-active --quiet gremgr-worker.service gremgr-web.service
gremgr --version | grep -Fx 1.2.0
echo 'A failed upgrade from 1.2.0 restored the previous application, configuration and services.'

curl -fsSL --retry 2 --connect-timeout 10 --max-time 90 \
  "https://raw.githubusercontent.com/smorad3363/assistant-vps/$GREMGR_RELEASE_REF/gre.sh" -o "$temporary/gre.sh"
bash "$temporary/gre.sh" --release-ref "$GREMGR_RELEASE_REF" --update-only
gremgr --version | grep -Fx 2.1.0
systemctl is-active --quiet gremgr-worker.service gremgr-web.service
cmp /opt/gremgr/current/release.json "$repo/gre-manager/release.json"

env PYTHONPATH=/opt/gremgr/current python3 - "$temporary/first-login" "$temporary/legacy-backup" <<'PY'
import json, ssl, sys, urllib.request
from pathlib import Path
from panel.controller import Controller
from panel.store import Store

entries = dict(line.split(": ", 1) for line in Path(sys.argv[1]).read_text().splitlines() if ": " in line)
url = "https://127.0.0.1:8876"
request = urllib.request.Request(url + "/api/login",
    data=json.dumps({"username": entries["Username"], "password": entries["Password"]}).encode(),
    headers={"Content-Type": "application/json", "Origin": url})
with urllib.request.urlopen(request, context=ssl._create_unverified_context(), timeout=8) as response:
    assert response.status == 200 and response.headers["Set-Cookie"].startswith("gremgr_session=")
store = Store()
settings = store.config()["settings"]
assert (settings["port"], settings["retention_days"], settings["telemetry_limit_mib"], settings["backup_limit_mib"]) == (8876, 19, 256, 128)
record, = store.stats("abcde12345")["totals"]
assert (record["up"], record["down"]) == (150, 350)
config, telemetry = store.read_backup(Path(sys.argv[2]).read_bytes())
assert config["settings"]["retention_days"] == 19
Controller.validate_telemetry(telemetry)
PY
echo 'The pinned HTTPS upgrade to 2.1.0 retained v1 credentials, the custom panel port, totals and a readable v1 backup.'
