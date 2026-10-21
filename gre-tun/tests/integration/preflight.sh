#!/usr/bin/env bash
# Pure network-namespace GRE protocol-47 handshake, without a GRE interface.
set -euo pipefail
[[ ${EUID} -eq 0 ]] || { echo 'NOT RUN: root needed' >&2; exit 77; }
[[ -f /etc/gre-tun-test-disposable-vm ]] || { echo 'NOT RUN: disposable test host marker required' >&2; exit 77; }
ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
SUFFIX="${BASHPID}"
A="gtpa-${SUFFIX}"; B="gtpb-${SUFFIX}"
PIDA=''
VETH_A="ga${SUFFIX}"; VETH_B="gb${SUFFIX}"; CREATED=0
cleanup(){
  if [[ -n "$PIDA" ]]; then kill "$PIDA" 2>/dev/null || true; wait "$PIDA" 2>/dev/null || true; fi
  if [[ "$CREATED" == 1 ]]; then ip link del "$VETH_A" 2>/dev/null || true; fi
  ip netns del "$A" 2>/dev/null || true
  ip netns del "$B" 2>/dev/null || true
  rm -f "/tmp/gt-preflight-${SUFFIX}"-*.log
}
trap cleanup EXIT
ip netns add "$A"
ip netns add "$B"
ip link add "$VETH_A" type veth peer name "$VETH_B"
CREATED=1
ip link set "$VETH_A" netns "$A"
ip link set "$VETH_B" netns "$B"
ip -n "$A" addr add 11.250.47.1/30 dev "$VETH_A"
ip -n "$B" addr add 11.250.47.2/30 dev "$VETH_B"
ip -n "$A" link set lo up
ip -n "$B" link set lo up
ip -n "$A" link set "$VETH_A" up
ip -n "$B" link set "$VETH_B" up
TOKEN='19f0a1b2c3d4e5f60718293a4b5c6d7e'
ip netns exec "$A" env PYTHONPATH="$ROOT/src" timeout 12 python3 -m gre_tun.cli test --listen --peer 11.250.47.2 --token "$TOKEN" --seconds 9 >"/tmp/gt-preflight-${SUFFIX}-listen.log" 2>&1 &
PIDA=$!
sleep 0.5
ip netns exec "$B" env PYTHONPATH="$ROOT/src" timeout 12 python3 -m gre_tun.cli test --probe --peer 11.250.47.1 --token "$TOKEN" --seconds 5 >"/tmp/gt-preflight-${SUFFIX}-probe.log" 2>&1 || {
  cat "/tmp/gt-preflight-${SUFFIX}-probe.log"; cat "/tmp/gt-preflight-${SUFFIX}-listen.log"; exit 1;
}
wait "$PIDA" || { cat "/tmp/gt-preflight-${SUFFIX}-listen.log"; exit 1; }
PIDA=''
grep -q 'GRE path: PASS' "/tmp/gt-preflight-${SUFFIX}-listen.log"
grep -q 'GRE path: PASS' "/tmp/gt-preflight-${SUFFIX}-probe.log"
if ip -n "$A" link show gtn1 >/dev/null 2>&1 || ip -n "$B" link show gtn1 >/dev/null 2>&1; then
  echo 'FAIL: created a persistent tunnel unexpectedly' >&2;exit 1
fi
echo 'PASS: authenticated GRE protocol-47 challenge/response with zero GRE tunnel interfaces.'
