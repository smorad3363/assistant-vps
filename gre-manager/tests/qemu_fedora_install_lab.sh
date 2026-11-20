#!/usr/bin/env bash
# Fedora cloud boot with a signed image and the same install/rollback fixture.
set -euo pipefail
[[ ${GITHUB_ACTIONS:-} == true ]]
repo=$(cd "$(dirname "$0")/../.." && pwd)
lab=$(mktemp -d)
vm_pid=
cleanup() {
  local status=$?
  if ((status)) && [[ -f $lab/console ]]; then tail -n 65 "$lab/console"; fi
  if [[ -n $vm_pid ]]; then kill "$vm_pid" 2>/dev/null || true; wait "$vm_pid" 2>/dev/null || true; fi
  rm -rf -- "$lab"
}
trap cleanup EXIT
base=https://download.fedoraproject.org/pub/fedora/linux/releases/44/Cloud/x86_64/images
image=Fedora-Cloud-Base-Generic-44-1.7.x86_64.qcow2
checksums=Fedora-Cloud-44-1.7-x86_64-CHECKSUM
fetch() { curl -fsSL --retry 3 --connect-timeout 15 --max-time 270 "$1" -o "$2"; }
fetch https://fedoraproject.org/fedora.gpg "$lab/fedora.gpg"
fetch "$base/$checksums" "$lab/$checksums"
gpgv --keyring "$lab/fedora.gpg" "$lab/$checksums"
fetch "$base/$image" "$lab/$image"
(
  cd "$lab"
  awk -v image="$image" '$1 == "SHA256" && $2 == "(" image ")" {print $4 "  " image; ++n} END {exit(n != 1)}' "$checksums" |
    sha256sum --check
)
qemu-img create -q -F qcow2 -b "$lab/$image" -f qcow2 "$lab/disk.qcow2"
qemu-img resize "$lab/disk.qcow2" 10G >/dev/null
ssh-keygen -q -t ed25519 -N '' -f "$lab/key"
cat >"$lab/user-data" <<EOF
#cloud-config
users:
  - name: fixture
    shell: /bin/bash
    sudo: ALL=(ALL) NOPASSWD:ALL
    ssh_authorized_keys:
      - $(cat "$lab/key.pub")
ssh_pwauth: false
EOF
printf 'instance-id: gremgr-fedora\nlocal-hostname: gremgr-fedora\n' >"$lab/meta-data"
cloud-localds "$lab/seed.img" "$lab/user-data" "$lab/meta-data"
qemu-system-x86_64 -machine accel=kvm:tcg -smp 2 -m 2048 -display none -monitor none \
  -object rng-random,id=guest-rng,filename=/dev/urandom -device virtio-rng-pci,rng=guest-rng \
  -serial "file:$lab/console" -drive "file=$lab/disk.qcow2,format=qcow2,if=virtio" \
  -drive "file=$lab/seed.img,format=raw,readonly=on,if=virtio" \
  -nic user,model=virtio-net-pci,hostfwd=tcp:127.0.0.1:25333-:22 &
vm_pid=$!

guest() {
  ssh -i "$lab/key" -p 25333 -o IdentitiesOnly=yes -o ConnectTimeout=4 -o BatchMode=yes \
    -o StrictHostKeyChecking=accept-new -o "UserKnownHostsFile=$lab/known_hosts" fixture@127.0.0.1 "$@"
}
ready() {
  local current previous=${1:-}
  for attempt in {1..140}; do
    current=$(guest cat /proc/sys/kernel/random/boot_id 2>/dev/null || true)
    if [[ $current =~ ^[a-f0-9-]{36}$ && $current != "$previous" ]]; then printf '%s\n' "$current"; return; fi
    sleep 2
  done
  return 1
}
first_boot=$(ready)
guest sudo cloud-init status --wait
tar -C "$repo" -cf - gre.sh gre-manager | guest tar -xf -
guest sudo env GITHUB_ACTIONS=true bash /home/fixture/gre-manager/tests/install_rollback_lab.sh
guest sudo systemctl reboot || true
ready "$first_boot" >/dev/null
guest systemctl is-active --quiet gremgr-worker.service
guest systemctl is-active --quiet gremgr-web.service
guest curl --noproxy '*' -kfSs --retry 5 --retry-connrefused https://127.0.0.1:8877/ | grep -F 'GRE Manager'
echo 'Fedora 44: dnf installation, upgrade, automatic rollback and a genuine reboot passed.'
