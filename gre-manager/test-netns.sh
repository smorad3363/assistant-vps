#!/usr/bin/env bash
# Run inside unshare --mount --net --fork. Never touch the host network.
set -Eeuo pipefail
BASE=$(cd -- "$(dirname -- "$0")" && pwd)
[[ $(readlink /proc/self/ns/net) != $(readlink /proc/1/ns/net) ]] || { echo 'Refusing host namespace'; exit 1; }
mount --make-rprivate /
mkdir -p /run/netns
mount -t tmpfs tmpfs /run/netns
work=$(mktemp -d)
cleanup() {
  for ns in ir fi client; do
    for pid in $(ip netns pids "$ns" 2>/dev/null); do kill "$pid" 2>/dev/null || true; done
    ip netns del "$ns" 2>/dev/null || true
  done
  rm -rf "$work"
}
trap cleanup EXIT
ip link add brlab type bridge
ip link set brlab up
for ns in ir fi client; do
  ip netns add "$ns"
  ip link add "v-$ns" type veth peer name wan0 netns "$ns"
  ip link set "v-$ns" master brlab
  ip link set "v-$ns" up
  ip -n "$ns" link set lo up
  ip -n "$ns" link set wan0 up
done
ip -n ir addr add 10.101.0.1/24 dev wan0
ip -n fi addr add 10.101.0.2/24 dev wan0
ip -n fi addr add 10.101.0.22/24 dev wan0
ip -n client addr add 10.101.0.3/24 dev wan0
python3 - "$BASE" "$work" <<'PY'
import importlib.util,json,sys
from pathlib import Path
spec=importlib.util.spec_from_file_location('pair',Path(sys.argv[1])/'pair.py')
p=importlib.util.module_from_spec(spec);spec.loader.exec_module(p)
for role,a,b in [('iran','10.101.0.1','10.101.0.2'),('foreign','10.101.0.2','10.101.0.1')]:
 identity,tunnel,local,peer,key=p.pair_values(a,b)
 c=dict(id=identity,tunnel=tunnel,local_tun=local,peer_tun=peer,key=key,role=role,outer_local=a,outer_peer=b,service_ip=a if role=='iran' else '10.101.0.22',wan='wan0',mtu=1400,ports=[[443,18080],[18081,18080],[65535,65535]] if role=='iran' else 'all')
 p.save(Path(sys.argv[2])/('ir' if role=='iran' else 'fi')/(identity+'.json'),c)
Path(sys.argv[2]+'/id').write_text(identity)
PY
identity=$(cat "$work/id")
for ns in ir fi; do
  ip netns exec "$ns" iptables -P INPUT DROP
  ip netns exec "$ns" iptables -P FORWARD DROP
  ip netns exec "$ns" iptables -A INPUT -p tcp --dport 22 -m comment --comment lab-baseline -j ACCEPT
  ip netns exec "$ns" env GRE_PAIR_CONFIG_DIR="$work/$ns" python3 "$BASE/pair.py" up "$identity"
done
cat > "$work/echo.py" <<'PY'
import socket,threading,time,sys
def listen(port,kind,host,reply=None):
 s=socket.socket(socket.AF_INET,kind);s.bind((host,port))
 if kind==socket.SOCK_STREAM:s.listen(8)
 def serve():
  while True:
   if kind==socket.SOCK_DGRAM:
    b,a=s.recvfrom(65535);s.sendto(b,a)
   else:
    c,a=s.accept()
    with c:
     if reply:c.sendall(reply);continue
     while True:
      b=c.recv(65536)
      if not b:break
      c.sendall(b)
 threading.Thread(target=serve,daemon=True).start()
if sys.argv[1]=='ir':listen(22,socket.SOCK_STREAM,'10.101.0.1',b'IRAN-SSH')
else:
 for port in (443,18080,18081,65535):
  for kind in (socket.SOCK_STREAM,socket.SOCK_DGRAM):listen(port,kind,'10.101.0.22')
print('READY',flush=True)
time.sleep(180)
PY
ip netns exec ir python3 -u "$work/echo.py" ir > "$work/ir.log" &
ip netns exec fi python3 -u "$work/echo.py" fi > "$work/fi.log" &
for _ in $(seq 1 50); do
  if grep -q READY "$work/ir.log" && grep -q READY "$work/fi.log"; then break; fi
  sleep 0.1
done
cat > "$work/client.py" <<'PY'
import socket,os
for port in (443,18081,65535):
 for kind in (socket.SOCK_STREAM,socket.SOCK_DGRAM):
  with socket.socket(socket.AF_INET,kind) as s:
   s.settimeout(3);s.connect(('10.101.0.1',port))
   payload=os.urandom(131072 if kind==socket.SOCK_STREAM else 1372)
   s.sendall(payload);data=b''
   while len(data)<len(payload):data+=s.recv(65535)
   assert data==payload
with socket.create_connection(('10.101.0.1',22),timeout=3) as s:assert s.recv(100)==b'IRAN-SSH'
print('PASS: TCP, UDP, port mapping/boundary, public-IP-bound destination and local SSH')
PY
ip netns exec client python3 "$work/client.py"
# Idempotent restore must not duplicate rules or reject its own keyed tunnel.
ip netns exec ir env GRE_PAIR_CONFIG_DIR="$work/ir" python3 "$BASE/pair.py" up "$identity"
before=$(ip netns exec ir iptables-save | grep -c 'gmp:')
ip netns exec ir env GRE_PAIR_CONFIG_DIR="$work/ir" python3 "$BASE/pair.py" up "$identity"
test "$before" = "$(ip netns exec ir iptables-save | grep -c 'gmp:')"
# Reconfigure to all ports using the old configuration for exact cleanup.
ip netns exec ir env GRE_PAIR_CONFIG_DIR="$work/ir" python3 "$BASE/pair.py" down "$identity"
python3 - "$work/ir/$identity.json" <<'PY'
import json,sys
p=sys.argv[1];c=json.load(open(p));c['ports']='all';json.dump(c,open(p,'w'))
PY
ip netns exec ir env GRE_PAIR_CONFIG_DIR="$work/ir" python3 "$BASE/pair.py" up "$identity"
ip netns exec client python3 "$work/client.py"
for ns in ir fi; do
  ip netns exec "$ns" env GRE_PAIR_CONFIG_DIR="$work/$ns" python3 "$BASE/pair.py" down "$identity"
  ! ip netns exec "$ns" iptables-save | grep -q 'gmp:'
  ip netns exec "$ns" iptables-save | grep -q lab-baseline
done
echo 'PASS: all ports, keyed GRE restore, no duplicate rules, owned-rule cleanup'
