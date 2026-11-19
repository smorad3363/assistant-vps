#!/usr/bin/env bash
# Boot both ends of an isolated GRE link on disposable GitHub Actions runners.
set -euo pipefail
[[ "${GITHUB_ACTIONS:-}" == true ]]
repo=$(cd "$(dirname "$0")/../.." && pwd)
lab=$(mktemp -d)
suffix=${lab: -5}
bridge=gmb${suffix}
taps=()
vm_pids=()
bridge_created=false

cleanup() {
  local status=$? pid tap console
  if ((status)); then
    for console in "$lab"/*/console; do [[ ! -f $console ]] || tail -n 75 "$console"; done
  fi
  for pid in "${vm_pids[@]}"; do kill "$pid" 2>/dev/null || true; done
  for pid in "${vm_pids[@]}"; do wait "$pid" 2>/dev/null || true; done
  for tap in "${taps[@]}"; do sudo ip link del "$tap" 2>/dev/null || true; done
  if $bridge_created; then sudo ip link del "$bridge" 2>/dev/null || true; fi
  rm -rf -- "$lab"
}
trap cleanup EXIT

images=https://cloud.debian.org/images/cloud/bookworm/latest
image=debian-12-genericcloud-amd64.qcow2
curl --fail --retry 3 --location --silent --show-error "$images/SHA512SUMS" --output "$lab/SHA512SUMS"
curl --fail --retry 3 --location --silent --show-error "$images/$image" --output "$lab/$image"
(
  cd "$lab"
  awk -v image="$image" '$2 == image || $2 == "*" image {print; ++n} END {exit(n != 1)}' SHA512SUMS | sha512sum --check
)
ssh-keygen -q -t ed25519 -N '' -f "$lab/key"
sudo ip link add "$bridge" type bridge
bridge_created=true
sudo ip link set "$bridge" up

start_vm() {
  local side=$1 ssh_port=$2 host_port=$3 mac=$4 address=$5
  local root=$lab/$side tap=gm${side}${suffix}
  mkdir "$root"
  sudo ip tuntap add dev "$tap" mode tap user "$(id -u)"
  taps+=("$tap")
  sudo ip link set "$tap" master "$bridge"
  sudo ip link set "$tap" up
  qemu-img create -q -F qcow2 -b "$lab/$image" -f qcow2 "$root/disk.qcow2"
  qemu-img resize "$root/disk.qcow2" 6G >/dev/null
  cat >"$root/user-data" <<EOF
#cloud-config
users:
  - name: fixture
    shell: /bin/bash
    sudo: ALL=(ALL) NOPASSWD:ALL
    ssh_authorized_keys:
      - $(cat "$lab/key.pub")
ssh_pwauth: false
EOF
  printf 'instance-id: gremgr-%s\nlocal-hostname: gremgr-%s\n' "$side" "$side" >"$root/meta-data"
  cloud-localds "$root/seed.img" "$root/user-data" "$root/meta-data"
  printf '%s %s\n' "$mac" "$address" >"$root/link"
  local forward=hostfwd=tcp:127.0.0.1:$ssh_port-:22
  if [[ -n $host_port ]]; then forward+=,hostfwd=tcp:127.0.0.1:$host_port-:5100; fi
  qemu-system-x86_64 -machine accel=kvm:tcg -smp 2 -m 1536 -display none -monitor none \
    -serial "file:$root/console" -drive "file=$root/disk.qcow2,format=qcow2,if=virtio" \
    -drive "file=$root/seed.img,format=raw,readonly=on,if=virtio" -nic "user,model=virtio-net-pci,$forward" \
    -netdev "tap,id=gre,ifname=$tap,script=no,downscript=no" -device "virtio-net-pci,netdev=gre,mac=$mac" &
  vm_pids+=("$!")
}

guest() {
  local port=$1
  shift
  ssh -i "$lab/key" -p "$port" -o IdentitiesOnly=yes -o ConnectTimeout=3 -o BatchMode=yes \
    -o StrictHostKeyChecking=accept-new -o "UserKnownHostsFile=$lab/known_hosts" fixture@127.0.0.1 "$@"
}
ready() {
  local port=$1 initial=${2:-} current
  for ((i=0; i<100; i++)); do
    current=$(guest "$port" cat /proc/sys/kernel/random/boot_id 2>/dev/null || true)
    if [[ $current != "$initial" && -n $current ]]; then printf '%s\n' "$current"; return; fi
    sleep 3
  done
  return 1
}

install_side() {
  local side=$1 port=$2 mac address
  read -r mac address <"$lab/$side/link"
  guest "$port" sudo cloud-init status --wait
  tar -C "$repo" -cf - gre-manager | guest "$port" tar -xf -
  guest "$port" sudo bash -s -- "$mac" "$address" <<'GUEST'
set -euo pipefail
cat >/usr/local/sbin/gremgr-fixture-network <<'SCRIPT'
#!/usr/bin/env bash
set -euo pipefail
sleep 4
for interface in /sys/class/net/*; do
  if [[ $(cat "$interface/address") == "$1" ]]; then
    ip link set "${interface##*/}" up
    ip addr replace "$2/24" dev "${interface##*/}"
    exit 0
  fi
done
exit 1
SCRIPT
chmod 0755 /usr/local/sbin/gremgr-fixture-network
cat >/etc/systemd/system/gremgr-fixture-network.service <<EOF
[Unit]
Before=gremgr-worker.service
[Service]
Type=oneshot
ExecStart=/usr/local/sbin/gremgr-fixture-network $1 $2
RemainAfterExit=yes
[Install]
WantedBy=multi-user.target
EOF
systemctl daemon-reload
systemctl enable --now gremgr-fixture-network.service
env GRE_PANEL_SKIP_ACME=1 bash /home/fixture/gre-manager/install.sh --source-dir /home/fixture/gre-manager
systemctl is-active gremgr-worker.service
GUEST
}

start_vm in 25222 25251 52:54:00:32:60:01 198.51.100.50
start_vm out 25223 '' 52:54:00:32:60:02 198.51.100.51
boot_in=$(ready 25222)
boot_out=$(ready 25223)
install_side in 25222 &
setup_in=$!
install_side out 25223 &
setup_out=$!
wait "$setup_in"
wait "$setup_out"
guest 25223 sudo bash -s <<'GUEST'
set -euo pipefail
cat >/usr/local/sbin/gremgr-fixture-echo.py <<'PY'
import socketserver
class Echo(socketserver.BaseRequestHandler):
    def handle(self):
        self.request.sendall(b"reboot:" + self.request.recv(128))
with socketserver.ThreadingTCPServer(("198.51.100.51", 25244), Echo) as server:
    server.serve_forever()
PY
cat >/etc/systemd/system/gremgr-fixture-echo.service <<'UNIT'
[Unit]
Requires=gremgr-fixture-network.service
After=gremgr-fixture-network.service
[Service]
ExecStart=/usr/bin/python3 /usr/local/sbin/gremgr-fixture-echo.py
[Install]
WantedBy=multi-user.target
UNIT
systemctl daemon-reload
systemctl enable --now gremgr-fixture-echo.service
GUEST

node() {
  guest "$1" 'cd /opt/gremgr/current && sudo python3 -c "from panel.store import Paths, topology_node_id; print(topology_node_id(Paths()))"'
}
owner=$(node 25222)
receiver=$(node 25223)
PYTHONPATH="$repo/gre-manager" python3 - "$owner" "$receiver" >"$lab/change.json" <<'PY'
import json, sys, uuid
from panel.v2_config import normalize_group
src, dst = sys.argv[1:]
def identity(): return uuid.uuid4().hex
group_id = identity()
group = normalize_group({"id": group_id, "name": "GRE reboot", "limits": {"up": 10, "down": 20}, "listeners": [{
    "id": identity(), "node_id": src, "ip": "10.0.2.15", "outer_ip": "198.51.100.50", "protocols": ["tcp"],
    "ports": "all", "port_map": {"5100": 25244}, "members": [{"id": identity(), "node_id": dst, "method": "gre",
    "service_ip": "198.51.100.51", "outer_ip": "198.51.100.51", "mtu": 1280}],
}]})
print(json.dumps({"id": identity(), "owner": src, "group_id": group_id, "group": group, "expected_revision": 0,
                  "participants": [dst, src], "joining": [dst]}))
PY
request='import json, sys; from panel.agent import v2_participant; from panel.engine import Engine; from panel.store import Paths; p=Paths(); peer=v2_participant(p, Engine(p)); change=json.load(sys.stdin); assert peer.request(change["owner"], sys.argv[1], change)["phase"] == sys.argv[1] + ("d" if sys.argv[1] == "prepare" else "ted")'
for stage in prepare commit; do
  for port in 25223 25222; do
    guest "$port" "cd /opt/gremgr/current && sudo python3 -c '$request' '$stage'" <"$lab/change.json"
  done
done

verify_flow() {
  python3 - <<'PY'
import socket
with socket.create_connection(("127.0.0.1", 25251), timeout=5) as connection:
    connection.sendall(b"fresh")
    assert connection.recv(64) == b"reboot:fresh"
PY
}
verify_restored() {
  for ((i=0; i<30; i++)); do
    if guest 25222 systemctl is-active --quiet gremgr-worker.service &&
       guest 25223 systemctl is-active --quiet gremgr-worker.service gremgr-fixture-echo.service && verify_flow; then return; fi
    sleep 2
  done
  return 1
}
verify_restored
guest 25223 sudo systemctl reboot || true
boot_out=$(ready 25223 "$boot_out")
verify_restored
guest 25222 sudo systemctl reboot || true
boot_in=$(ready 25222 "$boot_in")
verify_restored
guest 25222 sudo systemctl reboot || true
guest 25223 sudo systemctl reboot || true
ready 25222 "$boot_in" >/dev/null
ready 25223 "$boot_out" >/dev/null
verify_restored
guest 25222 sudo iptables-save -t filter >"$lab/restored-filter"
python3 - "$lab/restored-filter" <<'PY'
import re, sys
from pathlib import Path
text = Path(sys.argv[1]).read_text()
rates = [int(value) * {"": 1, "k": 1024, "m": 1024 * 1024}[unit]
         for value, unit in re.findall(r"--hashlimit-above (\d+)([km]?)b/s", text)]
for expected in (1250000, 2500000):
    assert any(abs(rate - expected) < expected * .01 for rate in rates), (expected, rates)
PY
echo 'PASS: both Debian 12 boot IDs changed. Fresh SSH and mapped GRE payload passed after each reboot and the joint reboot.'
