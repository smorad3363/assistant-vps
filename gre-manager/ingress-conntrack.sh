#!/usr/bin/env bash
# Bound idle TCP NAT state on a GRE ingress host and apply it at boot.
set -euo pipefail

if (( EUID != 0 )); then
  echo 'Run as root on the GRE ingress host.' >&2
  exit 1
fi

exec 9>/run/lock/gremgr-ingress-conntrack.lock
flock -x 9
key=net.netfilter.nf_conntrack_tcp_timeout_established
if ! current=$(sysctl -n "$key" 2>/dev/null); then
  modprobe nf_conntrack
  current=$(sysctl -n "$key")
fi
[[ "$current" =~ ^[1-9][0-9]*$ ]]
timeout=$((current < 7200 ? current : 7200))

module_file=/etc/modules-load.d/gremgr-conntrack.conf
profile=/etc/sysctl.d/99-zzz-gremgr-ingress-conntrack.conf
mkdir -p /etc/modules-load.d /etc/sysctl.d
module_tmp=$(mktemp "${module_file}.XXXXXX")
profile_tmp=
trap 'rm -f -- "$module_tmp" ${profile_tmp:+"$profile_tmp"}' EXIT
profile_tmp=$(mktemp "${profile}.XXXXXX")
printf '%s\n' nf_conntrack > "$module_tmp"
printf '# GRE ingress idle TCP conntrack timeout (seconds).\n%s = %s\n' "$key" "$timeout" > "$profile_tmp"
chmod 644 "$module_tmp" "$profile_tmp"

sysctl -qw "$key=$timeout"
[[ $(sysctl -n "$key") == "$timeout" ]]
mv -fT -- "$module_tmp" "$module_file"
mv -fT -- "$profile_tmp" "$profile"
printf '%s = %s\n' "$key" "$timeout"
