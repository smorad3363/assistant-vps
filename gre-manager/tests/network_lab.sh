#!/usr/bin/env bash
# Run only in disposable network AND mount namespaces. No public server access.
set -Eeuo pipefail
[[ ${EUID:-$(id -u)} == 0 ]] || { echo 'Root required'; exit 77; }
[[ $(readlink /proc/self/ns/net) != $(readlink /proc/1/ns/net) ]] || { echo 'Refusing host network namespace'; exit 77; }
mount --make-rprivate /
lab=$(mktemp -d)
cleanup() {
  local result=$?
  if ((result)); then
    for role in ir fo; do
      echo "Network failure diagnostics: $role"
      ip netns exec "gm-$role" iptables-save -c || true
      ip netns exec "gm-$role" ip -4 route || true
      ip netns exec "gm-$role" conntrack -L 2>/dev/null | tail -25 || true
    done
  fi
  ip netns del gm-ir 2>/dev/null || true
  ip netns del gm-fo 2>/dev/null || true
  ip netns del gm-client 2>/dev/null || true
  rm -rf "$lab"
}
trap cleanup EXIT
mkdir -p "$lab/netns"
mount --bind "$lab/netns" /run/netns
export PYTHONPATH
PYTHONPATH=$(realpath "$(dirname "$0")/..")
ip link add gm-br type bridge
ip link set gm-br up
for spec in 'ir 10' 'fo 20' 'client 30'; do
  read -r role suffix <<< "$spec"
  ip netns add "gm-$role"
  ip link add "v-$role" type veth peer name eth0 netns "gm-$role"
  ip link set "v-$role" master gm-br
  ip link set "v-$role" up
  ip -n "gm-$role" link set lo up
  ip -n "gm-$role" link set eth0 up
  ip -n "gm-$role" addr add "192.0.2.$suffix/24" dev eth0
done
ip -n gm-fo addr add 192.0.2.21/24 dev eth0
ip netns exec gm-ir iptables -P FORWARD DROP
ip netns exec gm-ir iptables -P INPUT DROP
ip netns exec gm-ir iptables -A INPUT -p tcp -m multiport --dports 22,6111 -m comment --comment BASELINE-SSH -j ACCEPT
ip netns exec gm-ir iptables -A INPUT -p udp -m multiport --dports 22,6111,8787 -m comment --comment BASELINE-UDP-LOCAL -j ACCEPT
ip netns exec gm-ir iptables -A INPUT -i lo -j ACCEPT
ip netns exec gm-fo iptables -P INPUT DROP
ip netns exec gm-fo iptables -P FORWARD DROP
ip netns exec gm-fo iptables -A INPUT -i lo -j ACCEPT
for proto in tcp udp; do
  ip netns exec gm-fo iptables -A INPUT -i eth0 -p "$proto" -s 192.0.2.10 -m comment --comment BASELINE-DIRECT -j ACCEPT
done
cat > "$lab/echo.py" <<'PY'
import socket,threading,time,sys
label=sys.argv[1].encode()
def listen(port,udp):
 s=socket.socket(socket.AF_INET,socket.SOCK_DGRAM if udp else socket.SOCK_STREAM)
 s.setsockopt(socket.SOL_SOCKET,socket.SO_REUSEADDR,1);s.bind(('0.0.0.0',port))
 if udp:
  while True:
   data,peer=s.recvfrom(65535);s.sendto(label+b':'+data,peer)
 else:
  s.listen()
  while True:
   c,_=s.accept()
   with c:
    data=c.recv(65535);c.sendall(label+b':'+data)
ports=[22,6111,8787] if label==b'IRAN' else [80,1000,51820,51821,65535]
for port in ports:
 for udp in (False,True): threading.Thread(target=listen,args=(port,udp),daemon=True).start()
time.sleep(120)
PY
ip netns exec gm-ir python3 "$lab/echo.py" IRAN &
ir_echo=$!
ip netns exec gm-fo python3 "$lab/echo.py" FOREIGN &
fo_echo=$!
cat > "$lab/apply.py" <<'PY'
import json,sys
from panel.engine import Engine,pair_values
from panel.store import Paths
from panel.model import DEFAULTS,connection
role,home,mode=sys.argv[1:]
settings=dict(DEFAULTS,ssh_ports=[22,6111])
c=connection({'kind':'gre' if mode=='gre' else 'direct','listen_ip':'192.0.2.10','target_host':'192.0.2.20','ports':'all','port_map':{'8080':80},'server_id':'abcdef0123','service_ip':'192.0.2.21','mtu':1400,'mtu_mode':'manual','monitor_ports':[1000,51821]},settings)
c['id']='abcdef0123'
if role=='fo':
 g=pair_values('192.0.2.20','192.0.2.10');g['mtu']=1400
 c={'id':c['id'],'kind':'peer','gre':g,'service_ip':'192.0.2.21','enabled':True}
cfg={'settings':settings,'connections':[c],'web_enabled':role=='ir'}
paths=Paths(home)
previous=json.loads((paths.etc/'lab-previous.json').read_text()) if (paths.etc/'lab-previous.json').exists() else dict(cfg,connections=[])
Engine(paths).apply(cfg,previous)
(paths.etc/'lab-previous.json').write_text(json.dumps(cfg))
PY
sleep .5
ip netns exec gm-ir python3 "$lab/apply.py" ir "$lab/ir" direct
cat > "$lab/client.py" <<'PY'
import socket,sys,time
port=int(sys.argv[1]);expected=sys.argv[2].encode();payload=b'payload-'+bytes(range(64))
for udp in (False,True):
 s=socket.socket(socket.AF_INET,socket.SOCK_DGRAM if udp else socket.SOCK_STREAM);s.settimeout(3)
 if udp:s.sendto(payload,('192.0.2.10',port));data,peer=s.recvfrom(65535);assert peer[1]==port,(port,peer)
 else:s.connect(('192.0.2.10',port));s.sendall(payload);data=s.recv(65535)
 assert data==expected+b':'+payload,(port,udp,data)
 s.close()
print('TCP+UDP payload and response source verified:',port)
PY
for port in 1000 51821 65535 8080; do ip netns exec gm-client python3 "$lab/client.py" "$port" FOREIGN; done
for port in 22 6111 8787; do ip netns exec gm-client python3 "$lab/client.py" "$port" IRAN; done
ip netns exec gm-fo python3 "$lab/apply.py" fo "$lab/fo" gre
ip netns exec gm-ir python3 "$lab/apply.py" ir "$lab/ir" gre
for port in 1000 51821 65535 8080; do ip netns exec gm-client python3 "$lab/client.py" "$port" FOREIGN; done
for port in 22 6111 8787; do ip netns exec gm-client python3 "$lab/client.py" "$port" IRAN; done
# Reapply without flushing conntrack or unrelated rules.
ip netns exec gm-ir python3 "$lab/apply.py" ir "$lab/ir" gre
ip netns exec gm-client python3 "$lab/client.py" 51821 FOREIGN
ip netns exec gm-ir iptables-save | grep -F BASELINE-SSH
ip netns exec gm-fo iptables-save | grep -F BASELINE-DIRECT
ip netns exec gm-ir python3 - "$lab/ir" <<'PY'
from panel.engine import Engine
from panel.store import Paths,Store
import json,sys
paths=Paths(sys.argv[1]);engine=Engine(paths);store=Store(paths)
counts,epoch=engine.counters();store.sample(counts,epoch)
assert counts[('abcdef0123','all')][0]>0 and counts[('abcdef0123','all')][1]>0,counts
assert counts[('abcdef0123','51821')][1]>0,counts
old=json.loads((paths.etc/'lab-previous.json').read_text())
# Real kernel validation of the byte-rate limiter, aggregate and per-port.
new=json.loads(json.dumps(old));new['connections'][0]['upload_mbps']=2;new['connections'][0]['download_mbps']=2
new['connections'][0]['port_limits']={'51821':{'up':1,'down':1}}
engine.apply(new,old)
print('Counters and kernel bandwidth rules verified')
(paths.etc/'lab-limited.json').write_text(json.dumps(new))
PY
ip netns exec gm-client python3 - <<'PY'
import socket,threading,time
s=socket.socket(socket.AF_INET,socket.SOCK_DGRAM);s.settimeout(.15)
s.bind(('0.0.0.0',0))
received=0;stop=threading.Event()
def read():
 global received
 while not stop.is_set():
  try: data,_=s.recvfrom(65535);received+=len(data)
  except socket.timeout: pass
reader=threading.Thread(target=read);reader.start()
payload=b'x'*1024;started=time.monotonic()
while time.monotonic()-started<3:
 s.sendto(payload,('192.0.2.10',51821));time.sleep(.0005)
time.sleep(.2);stop.set();reader.join();s.close()
assert 20000<received<700000,('1 Mbps port cap not respected',received)
print('Measured UDP cap: received bytes over 3 seconds:',received)
PY
ip netns exec gm-ir python3 - "$lab/ir" <<'PY'
from panel.engine import Engine
from panel.store import Paths
import json,sys
paths=Paths(sys.argv[1]);old=json.loads((paths.etc/'lab-limited.json').read_text())
Engine(paths).apply(dict(old,connections=[]),old)
PY
ip netns exec gm-client python3 "$lab/client.py" 22 IRAN
ip netns exec gm-ir iptables-save | grep -F BASELINE-SSH
kill "$ir_echo" "$fo_echo" 2>/dev/null || true
echo 'PASS: GRE/direct TCP+UDP, mappings, protected SSH/panel, counters, rate rules, scoped cleanup.'
