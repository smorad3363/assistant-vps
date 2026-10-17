#!/usr/bin/env bash
set -euo pipefail
# Runs only on a disposable VM; all mutations are confined to gttest-* netns.
if [[ ! -f /etc/gre-tun-test-disposable-vm ]]; then
  echo 'NOT RUN: /etc/gre-tun-test-disposable-vm missing (disposable lab required).' >&2
  exit 77
fi
if [[ "${EUID}" -ne 0 ]]; then echo 'NOT RUN: root is required.' >&2; exit 77; fi
for cmd in ip nft tc conntrack curl; do
  command -v "$cmd" >/dev/null || { echo "NOT RUN: $cmd is missing" >&2; exit 77; }
done
ROOT="$(cd "$(dirname "$0")/../.." && pwd -P)"
BASE="$(mktemp -d /tmp/gttest.XXXXXXXX)"
ENTRY='gttest-entry'; PEER='gttest-peer'; SERVER_PID=''
cleanup() {
  if [[ -n "$SERVER_PID" ]]; then kill "$SERVER_PID" 2>/dev/null || true; wait "$SERVER_PID" 2>/dev/null || true; fi
  ip netns del "$ENTRY" 2>/dev/null || true
  ip netns del "$PEER" 2>/dev/null || true
  rm -rf -- "$BASE"
}
trap cleanup EXIT
if ip netns list | grep -qE '^gttest-(entry|peer)( |$)'; then
  echo 'FAIL: existing laboratory namespace name occupied; refusing takeover.' >&2
  exit 1
fi
# The host's real interfaces, addresses, routes and firewall are untouched.
ip netns add "$ENTRY"
ip netns add "$PEER"
ip link add ve-entry type veth peer name ve-peer
ip link set ve-entry netns "$ENTRY"
ip link set ve-peer netns "$PEER"
for ns in "$ENTRY" "$PEER"; do ip -n "$ns" link set lo up; done
ip -n "$ENTRY" address add 192.0.2.1/30 dev ve-entry
ip -n "$PEER" address add 192.0.2.2/30 dev ve-peer
ip -n "$ENTRY" link set ve-entry up
ip -n "$PEER" link set ve-peer up
ip netns exec "$ENTRY" sysctl -qw net.ipv4.ip_forward=1
ip netns exec "$PEER" sysctl -qw net.ipv4.ip_forward=1
ip netns exec "$ENTRY" sysctl -qw net.ipv4.conf.all.rp_filter=0
ip netns exec "$PEER" sysctl -qw net.ipv4.conf.all.rp_filter=0
# Independent directories avoid sharing desired state or app ownership.
for ns in entry peer; do mkdir -p "$BASE/$ns/"; done
# Apply GRE endpoint (no locally owned forwards).
GTBASE="$BASE" GTSIDE='peer' PYTHONPATH="$ROOT/src" GRE_TUN_STATE_DIR="$BASE/peer/state" \
 GRE_TUN_EXPERIMENTAL_LAB=1 ip netns exec "$PEER" python3 - <<'PY'
import os
from gre_tun import config,network,peer
c=config.empty_config('foreign')
c['tunnels'].append(peer.make_tunnel(1,'192.0.2.2','192.0.2.1','ve-peer','Peer'))
c['next_tunnel_id']=2
print(network.apply(c),flush=True)
PY
GTBASE="$BASE" GTSIDE='entry' PYTHONPATH="$ROOT/src" GRE_TUN_STATE_DIR="$BASE/entry/state" \
 GRE_TUN_EXPERIMENTAL_LAB=1 ip netns exec "$ENTRY" python3 - <<'PY'
from gre_tun import config,network,peer
c=config.empty_config('iran')
c['tunnels'].append(peer.make_tunnel(1,'192.0.2.1','192.0.2.2','ve-entry','Entry'))
c['next_tunnel_id']=2
c['forwards'].append({'id':1,'tunnel_id':1,'listen_ip':'192.0.2.1','protocol':'tcp',
  'listen_port':65432,'target_ip':'192.0.2.2','target_port':65433,
  'enabled':True,'upload_mbps':0,'download_mbps':0,'generation':1,
  'created_at':'2026-01-01T00:00:00Z'})
c['next_forward_id']=2
print(network.apply(c),flush=True)
PY
# The service only listens on the PEER outer IPv4. Target==peer outer IP
# is an important routing-loop regression scenario.
ip netns exec "$PEER" python3 -u - <<'PY' &
from http.server import BaseHTTPRequestHandler,HTTPServer
class Handler(BaseHTTPRequestHandler):
    def do_GET(self):
        body=b'GRE_LAB_OK'
        self.send_response(200);self.send_header('Content-Length',str(len(body)))
        self.end_headers();self.wfile.write(body)
    def log_message(self,*args):pass
HTTPServer(('192.0.2.2',65433),Handler).serve_forever()
PY
SERVER_PID=$!
sleep 1
if ! out="$(ip netns exec "$PEER" curl -4 --max-time 8 -fsS http://192.0.2.1:65432/)"; then
  echo 'FAIL: TCP connection timed out. Owned-only namespace diagnostics:' >&2
  for ns in "$ENTRY" "$PEER"; do
    echo "-- $ns routes --" >&2
    ip -n "$ns" -4 route show table main >&2 || true
    ip -n "$ns" -4 route show table 45001 >&2 || true
    ip -n "$ns" -4 rule show >&2 || true
    ip -n "$ns" -s link show gtn1 >&2 || true
    ip netns exec "$ns" nft -a list table ip gre_tun >&2 || true
  done
  exit 1
fi
[[ "$out" == 'GRE_LAB_OK' ]] || { echo "FAIL: unexpected payload: $out" >&2; exit 1; }
ip netns exec "$ENTRY" nft -j list table ip gre_tun | python3 -c 'import json,sys; j=json.load(sys.stdin); cs=[i["counter"] for i in j["nftables"] if "counter" in i]; assert any(c["name"]=="p0001u" and c["bytes"]>0 for c in cs), cs; assert any(c["name"]=="p0001d" and c["bytes"]>0 for c in cs), cs'
echo 'PASS: NET-01 two GRE endpoints, NET-04 target==peer outer IP, forward TCP both directions, named counters.'
