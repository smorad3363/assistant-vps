#!/usr/bin/env bash
# Exercise both installer entry points and recovery from a broken candidate.
set -euo pipefail
[[ ${GITHUB_ACTIONS:-} == true && ${EUID:-1} == 0 ]]
repo=$(cd "$(dirname "$0")/../.." && pwd)
source_dir=$repo/gre-manager
temporary=$(mktemp -d)
fixture_monitor=/etc/systemd/system/gremgr-peer-monitor.service
owns_monitor=false
cleanup() {
  if $owns_monitor; then
    systemctl stop gremgr-peer-monitor.service || true
    rm -f -- "$fixture_monitor"
    systemctl daemon-reload || true
  fi
  rm -rf -- "$temporary"
}
trap cleanup EXIT
export GRE_PANEL_SKIP_ACME=1

python3 "$source_dir/build-release.py" WORKTREE
cp -a "$source_dir" "$temporary/candidate"
sed -i '/^ExecStart=/c ExecStart=/usr/bin/false' "$temporary/candidate/gremgr-web.service"
python3 "$temporary/candidate/build-release.py" WORKTREE
first_install=false
if [[ ! -e /opt/gremgr/current ]]; then
  first_install=true
  if ! systemctl cat gremgr-peer-monitor.service >/dev/null 2>&1; then
    cat >"$fixture_monitor" <<'UNIT'
[Unit]
Description=Disposable existing GRE Manager peer monitor fixture
[Service]
ExecStart=/usr/bin/sleep infinity
UNIT
    owns_monitor=true
    systemctl daemon-reload
    systemctl start gremgr-peer-monitor.service
  fi
  if bash "$source_dir/install.sh" --source-dir "$temporary/candidate" --port 8878 >"$temporary/failed-init"; then
    echo 'The broken first installation unexpectedly succeeded.' >&2
    exit 1
  fi
  [[ ! -e /opt/gremgr/current && ! -L /opt/gremgr/current && ! -e /etc/gremgr/panel.json ]]
  if grep -Fq 'Password:' "$temporary/failed-init"; then
    echo 'Failed installation disclosed unusable credentials.' >&2
    exit 1
  fi
  if $owns_monitor; then systemctl is-active --quiet gremgr-peer-monitor.service; fi
fi
bash "$source_dir/install.sh" --source-dir "$source_dir" --port 8877 >"$temporary/install-output"
if $first_install; then
  python3 - "$temporary/install-output" <<'PY'
import json, ssl, sys, urllib.request
from pathlib import Path
entries = dict(line.split(': ', 1) for line in Path(sys.argv[1]).read_text().splitlines() if ': ' in line)
assert entries['Username'].startswith('admin_') and entries['Password']
url = 'https://127.0.0.1:8877'
request = urllib.request.Request(url + '/api/login', data=json.dumps({'username': entries['Username'],
    'password': entries['Password']}).encode(), headers={'Content-Type':'application/json', 'Origin':url})
context = ssl._create_unverified_context()
with urllib.request.urlopen(request, context=context, timeout=8) as response:
    assert response.status == 200 and response.headers['Set-Cookie'].startswith('gremgr_session=')
print('Fresh install retry restored the previous peer monitor and issued working credentials.')
PY
fi
fresh=$(readlink -f /opt/gremgr/current)
bash "$repo/gre.sh" --source-dir "$source_dir" --update-only
stable=$(readlink -f /opt/gremgr/current)
[[ $fresh != "$stable" ]]
cmp "$stable/release.json" "$source_dir/release.json"
cp -a /etc/gremgr/panel.json "$temporary/stable.json"

if bash "$repo/gre.sh" --source-dir "$temporary/candidate" --update-only --port 8878; then
  echo 'The broken update unexpectedly succeeded.' >&2
  exit 1
fi
[[ $(readlink -f /opt/gremgr/current) == "$stable" ]]
cmp /etc/gremgr/panel.json "$temporary/stable.json"
systemctl is-active --quiet gremgr-worker.service
systemctl is-active --quiet gremgr-web.service
curl --noproxy '*' -kfSs --retry 5 --retry-connrefused https://127.0.0.1:8877/ -o "$temporary/panel.html"
grep -Fq 'GRE Manager' "$temporary/panel.html"
echo 'Both installer commands worked. Release, panel configuration and services recovered after update failure.'
