#!/usr/bin/env bash
# Short permanent entry point; gre-manager/install.sh remains available.
set -Eeuo pipefail
args=("$@")
ref=master
for ((index=0; index<${#args[@]}; index++)); do
  if [[ ${args[index]} == --source-dir ]]; then
    source_dir=${args[index+1]:-}
    [[ -n $source_dir && -f $source_dir/install.sh ]] || { echo 'Provide a GRE Manager source directory.' >&2; exit 1; }
    exec bash "$source_dir/install.sh" "$@"
  fi
  if [[ ${args[index]} == --release-ref ]]; then
    ref=${args[index+1]:-}
    [[ "$ref" =~ ^[a-f0-9]{40}$ ]] || { echo 'Supply the 40-character release manifest commit.' >&2; exit 1; }
  fi
done
work=$(mktemp)
trap 'rm -f "$work"' EXIT
curl -fsSL --retry 2 --connect-timeout 10 --max-time 90 \
  "https://raw.githubusercontent.com/smorad3363/assistant-vps/$ref/gre-manager/install.sh" -o "$work"
bash "$work" "$@"
