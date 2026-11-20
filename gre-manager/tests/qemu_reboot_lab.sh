#!/usr/bin/env bash
# Boot both ends of an isolated GRE link on disposable GitHub Actions runners.
set -euo pipefail
[[ "${GITHUB_ACTIONS:-}" == true ]]
repo=$(cd "$(dirname "$0")/../.." && pwd)
lab=$(mktemp -d)
method=${GREMGR_REBOOT_METHOD:-gre}
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
if [[ $method == l2tpv2 ]]; then image=debian-12-generic-amd64.qcow2; fi
sums=SHA512SUMS
checksum=sha512sum
os_release='Debian 12'
if [[ ${GREMGR_REBOOT_OS:-} == ubuntu22 ]]; then
  images=https://cloud-images.ubuntu.com/jammy/current
  image=jammy-server-cloudimg-amd64.img
  sums=SHA256SUMS
  checksum=sha256sum
  os_release='Ubuntu 22.04'
fi
curl --fail --retry 3 --location --silent --show-error "$images/$sums" --output "$lab/$sums"
curl --fail --retry 3 --location --silent --show-error "$images/$image" --output "$lab/$image"
(
  cd "$lab"
  awk -v image="$image" '$2 == image || $2 == "*" image {print; ++n} END {exit(n != 1)}' "$sums" | "$checksum" --check
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
  local side=$1 port=$2 mac address attempt status
  read -r mac address <"$lab/$side/link"
  for ((attempt=1; attempt<=6; attempt++)); do
    status=0
    guest "$port" sudo cloud-init status --wait || status=$?
    if ((status != 255)); then break; fi
    sleep 3
  done
  ((status == 0))
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
  if [[ $method == l2tpv2 ]]; then
    guest "$port" 'sudo apt-get update -qq && sudo env DEBIAN_FRONTEND=noninteractive apt-get install -y -qq xl2tpd ppp'
    guest "$port" 'uname -r && sudo modprobe ppp_generic && sudo modprobe l2tp_ppp && sudo test -c /dev/ppp'
    guest "$port" 'sudo install -d -m 700 /etc/gremgr/ppp-credentials && sudo install -m 600 /dev/stdin /etc/gremgr/ppp-credentials/lab' <"$lab/ppp-secret"
  fi
  if [[ ${GREMGR_REBOOT_OS:-} == ubuntu22 ]]; then
    guest "$port" 'grep -E "^VERSION_ID=\"?22\.04\"?$" /etc/os-release && uname -r'
    guest "$port" 'if ! sudo modprobe -nq l2tp_eth; then sudo apt-get update -qq && sudo env DEBIAN_FRONTEND=noninteractive apt-get install -y -qq "linux-modules-extra-$(uname -r)"; fi; sudo modprobe l2tp_eth'
  fi
}

start_vm in 25222 25251 52:54:00:32:60:01 198.51.100.50
start_vm out 25223 '' 52:54:00:32:60:02 198.51.100.51
boot_in=$(ready 25222)
boot_out=$(ready 25223)
echo "Both $os_release guests have fresh SSH connections. Installing the panel and transport dependencies."
if [[ $method == l2tpv2 ]]; then openssl rand -hex 32 >"$lab/ppp-secret"; fi
install_side in 25222 &
setup_in=$!
install_side out 25223 &
setup_out=$!
wait "$setup_in"
wait "$setup_out"
echo "Both $os_release endpoints are ready to configure ${method^^}."
guest 25223 sudo bash -s -- "$method" <<'GUEST'
set -euo pipefail
cat >/usr/local/sbin/gremgr-fixture-echo.py <<'PY'
import socket, socketserver, sys
class Echo(socketserver.BaseRequestHandler):
    def handle(self):
        self.request.sendall(b"reboot:" + self.request.recv(128))
class Echo6(socketserver.ThreadingTCPServer):
    address_family = socket.AF_INET6
    def server_bind(self):
        self.socket.setsockopt(socket.IPPROTO_IPV6, socket.IPV6_V6ONLY, 1)
        super().server_bind()
listener = Echo6(("::", 25244), Echo) if sys.argv[1] == "sit" else socketserver.ThreadingTCPServer(("198.51.100.51", 25244), Echo)
with listener as server:
    server.serve_forever()
PY
cat >/etc/systemd/system/gremgr-fixture-echo.service <<UNIT
[Unit]
Requires=gremgr-fixture-network.service
After=gremgr-fixture-network.service
[Service]
ExecStart=/usr/bin/python3 /usr/local/sbin/gremgr-fixture-echo.py $1
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
PYTHONPATH="$repo/gre-manager" python3 - "$owner" "$receiver" "$method" >"$lab/change.json" <<'PY'
import json, sys, uuid
from panel.v2_config import normalize_group
src, dst, method = sys.argv[1:]
def identity(): return uuid.uuid4().hex
group_id = identity()
member = {"id": identity(), "node_id": dst, "method": method, "service_ip": "198.51.100.51",
          "outer_ip": "198.51.100.51", "mtu": 1280}
if method == "l2tpv2":
    member["l2tpv2"] = {"lac": "ingress", "ingress": {"port": 37401, "credential": "lab"},
                       "destination": {"port": 37402, "credential": "lab"}}
if method == "l2tpv3":
    member["l2tpv3"] = {"ingress": {"tunnel_id": 21701, "session_id": 21711, "port": 37001},
                       "destination": {"tunnel_id": 21702, "session_id": 21712, "port": 37002}}

if method == "geneve":
    member["geneve"] = {"vni": 814321}
forwarding = {"protocols": ["tcp"], "ports": "all", "port_map": {"5100": 25244}}
group_policy = {"limits": {"up": 10, "down": 20}}
if method == "sit":
    member["sit"] = {"ingress": "fd49:1e81:7ca::1/64", "destination": "fd49:1e81:7ca::2/64"}
    forwarding, group_policy = {}, {}
group = normalize_group({"id": group_id, "name": method.upper() + " reboot", **group_policy, "listeners": [{
    "id": identity(), "node_id": src, "ip": "10.0.2.15", "outer_ip": "198.51.100.50", **forwarding, "members": [member],
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
  if [[ $method == sit ]]; then
    guest 25222 python3 - <<'PY'
import socket
with socket.create_connection(("fd49:1e81:7ca::2", 25244), timeout=5) as connection:
    connection.sendall(b"fresh")
    assert connection.recv(64) == b"reboot:fresh"
PY
    return
  fi
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
echo "Initial ${method^^} payload passed."
guest 25223 sudo systemctl reboot || true
boot_out=$(ready 25223 "$boot_out")
verify_restored
echo "Destination boot ID changed and payload passed."
guest 25222 sudo systemctl reboot || true
boot_in=$(ready 25222 "$boot_in")
verify_restored
echo "Ingress boot ID changed and payload passed."
guest 25222 sudo systemctl reboot || true
guest 25223 sudo systemctl reboot || true
ready 25222 "$boot_in" >/dev/null
ready 25223 "$boot_out" >/dev/null
verify_restored
if [[ $method == l2tpv2 ]]; then
  for port in 25222 25223; do guest "$port" ip -o -4 addr show | grep -Eq 'p2-[0-9a-f]{12} .* peer '; done
fi
guest 25222 sudo iptables-save -t filter >"$lab/restored-filter"
if [[ $method == sit ]]; then
  grep -Eq -- '-s 198\.51\.100\.51/32 -d 198\.51\.100\.50/32 .* -p (41|ipv6) -j ACCEPT' "$lab/restored-filter"
  echo 'PASS: both Debian 12 boot IDs changed. Fresh SSH and SIT IPv6 payload passed after each reboot and the joint reboot.'
  exit 0
fi
python3 - "$lab/restored-filter" <<'PY'
import re, sys
from pathlib import Path
text = Path(sys.argv[1]).read_text()
rates = [int(value) * {"": 1, "k": 1024, "m": 1024 * 1024}[unit]
         for value, unit in re.findall(r"--hashlimit-above (\d+)([km]?)b/s", text)]
for expected in (1250000, 2500000):
    assert any(abs(rate - expected) < expected * .01 for rate in rates), (expected, rates)
PY
echo "PASS: both $os_release boot IDs changed. Fresh SSH and mapped ${method^^} payload passed after each reboot and the joint reboot."
