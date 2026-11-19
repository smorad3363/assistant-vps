#!/usr/bin/env bash
# Exercise both installer entry points and recovery from a broken candidate.
set -euo pipefail
[[ ${GITHUB_ACTIONS:-} == true && ${EUID:-1} == 0 ]]
repo=$(cd "$(dirname "$0")/../.." && pwd)
source_dir=$repo/gre-manager
temporary=$(mktemp -d)
trap 'rm -rf -- "$temporary"' EXIT
export GRE_PANEL_SKIP_ACME=1

python3 "$source_dir/build-release.py" WORKTREE
bash "$source_dir/install.sh" --source-dir "$source_dir" --port 8877
fresh=$(readlink -f /opt/gremgr/current)
bash "$repo/gre.sh" --source-dir "$source_dir" --update-only
stable=$(readlink -f /opt/gremgr/current)
[[ $fresh != "$stable" ]]
cmp "$stable/release.json" "$source_dir/release.json"
cp -a /etc/gremgr/panel.json "$temporary/stable.json"

cp -a "$source_dir" "$temporary/candidate"
sed -i '/^ExecStart=/c ExecStart=/usr/bin/false' "$temporary/candidate/gremgr-web.service"
python3 "$temporary/candidate/build-release.py" WORKTREE
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
