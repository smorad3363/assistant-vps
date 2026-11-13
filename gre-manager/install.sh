#!/usr/bin/env bash
# Verified, noninteractive install/update of GRE Manager and direct forwarding.
set -Eeuo pipefail
[[ ${EUID:-$(id -u)} == 0 ]] || { echo 'Run with sudo/root.' >&2; exit 1; }
[[ -d /run/systemd/system ]] || { echo 'A running systemd host is required.' >&2; exit 1; }
SOURCE_DIR=""
PANEL_PORT=""
while (($#)); do
  case "$1" in
    --source-dir) SOURCE_DIR=$(realpath "$2"); shift 2 ;;
    --port) PANEL_PORT=$2; shift 2 ;;
    --update-only|--no-wizard) shift ;;
    *) echo "Unknown installation option: $1" >&2; exit 1 ;;
  esac
done
if [[ -n "$PANEL_PORT" && ! "$PANEL_PORT" =~ ^[0-9]{4,5}$ ]]; then
  echo 'Panel port must be between 1024 and 65535.' >&2; exit 1
fi
if command -v apt-get >/dev/null; then
  missing=0
  for binary in python3 ip iptables curl openssl ssh sshpass modprobe flock; do
    command -v "$binary" >/dev/null || missing=1
  done
  if ((missing)); then
    apt-get update -qq
    DEBIAN_FRONTEND=noninteractive apt-get install -y -qq python3 iproute2 iptables iputils-ping curl openssl openssh-client sshpass kmod util-linux ca-certificates tzdata >/dev/null
  fi
elif command -v dnf >/dev/null; then
  dnf install -y -q python3 iproute iptables iputils curl openssl openssh-clients sshpass kmod util-linux ca-certificates tzdata
else
  echo 'Supported installers: Debian/Ubuntu apt, or dnf-based Linux.' >&2; exit 1
fi
install -d -m 700 /etc/gremgr /var/lib/gremgr /etc/gremgr/backups /etc/gremgr/tls
exec 9>/run/lock/gremgr-install.lock
flock -x 9
work=$(mktemp -d)
trap 'rm -rf "$work"' EXIT
BASE='https://raw.githubusercontent.com/smorad3363/assistant-vps'
if [[ -n "$SOURCE_DIR" ]]; then
  cp "$SOURCE_DIR/release.json" "$work/release.json"
else
  curl -fsSL --retry 2 --connect-timeout 10 --max-time 90 "$BASE/master/gre-manager/release.json" -o "$work/release.json"
fi
python3 - "$work/release.json" > "$work/files" <<'PY'
import json,re,sys
m=json.load(open(sys.argv[1]))
if m.get('schema')!=1 or not re.fullmatch(r'[0-9a-f]{40}|WORKTREE',m.get('revision','')):
 raise SystemExit('Invalid release revision.')
files=m.get('files',{})
required={'install.sh','gremgr.sh','pair.py','legacy-restore.sh','gremgr-worker.service','gremgr-web.service','panel/worker.py','panel/web.py','panel/engine.py','panel/controller.py','panel/static/index.html','panel/static/app.js','panel/static/style.css'}
if not required.issubset(files) or len(files)>100: raise SystemExit('Incomplete package manifest.')
for path,digest in files.items():
 if not re.fullmatch(r'[a-zA-Z0-9_./@-]+',path) or path.startswith('/') or '..' in path.split('/') or not re.fullmatch(r'[0-9a-f]{64}',digest):
  raise SystemExit('Invalid manifest path or digest.')
 print(path+' '+digest)
PY
REVISION=$(python3 -c 'import json,sys;print(json.load(open(sys.argv[1]))["revision"])' "$work/release.json")
VERSION=$(python3 -c 'import json,sys;print(json.load(open(sys.argv[1]))["version"])' "$work/release.json")
[[ "$VERSION" =~ ^[0-9]+\.[0-9]+\.[0-9]+$ ]] || { echo 'Invalid version.' >&2; exit 1; }
[[ -n "$SOURCE_DIR" || "$REVISION" != WORKTREE ]] || { echo 'A development manifest cannot be downloaded.' >&2; exit 1; }
while read -r file digest; do
  mkdir -p "$work/package/$(dirname "$file")"
  if [[ -n "$SOURCE_DIR" ]]; then
    cp "$SOURCE_DIR/$file" "$work/package/$file"
  else
    curl -fsSL --retry 2 --connect-timeout 10 --max-time 90 "$BASE/$REVISION/gre-manager/$file" -o "$work/package/$file"
  fi
  printf '%s  %s\n' "$digest" "$work/package/$file" | sha256sum -c --status
done < "$work/files"
python3 -m compileall -q "$work/package/panel"
bash -n "$work/package/install.sh" "$work/package/gremgr.sh" "$work/package/legacy-restore.sh"
getent group gremgr >/dev/null || groupadd --system gremgr
id gremgr >/dev/null 2>&1 || useradd --system --gid gremgr --home-dir /nonexistent --no-create-home --shell /usr/sbin/nologin gremgr
release="/opt/gremgr/releases/$VERSION-$REVISION-$(date +%s)"
install -d -m 755 "$release"
cp -a "$work/package/." "$release/"
find "$release" -type d -exec chmod 755 {} +
find "$release" -type f -exec chmod 644 {} +
chmod 755 "$release/gremgr.sh" "$release/legacy-restore.sh" "$release/install.sh" "$release/pair.py"
cp "$work/release.json" "$release/release.json"
backup="/etc/gremgr/backups/install-$(date +%Y%m%d-%H%M%S)-$$"
install -d -m 700 "$backup"
old_release=""
if [[ -e /opt/gremgr/current ]]; then old_release=$(readlink -f /opt/gremgr/current); fi
for target in /usr/local/sbin/gremgr /usr/local/sbin/gremgr-pair /etc/systemd/system/gremgr-worker.service /etc/systemd/system/gremgr-web.service; do
  [[ ! -e "$target" ]] || cp -aL "$target" "$backup/$(basename "$target")"
done
if [[ -n "$old_release" ]]; then printf '%s\n' "$old_release" > "$backup/previous-release"; fi
ln -s "$release" /opt/gremgr/current.new
mv -Tf /opt/gremgr/current.new /opt/gremgr/current
install -m 755 "$release/gremgr.sh" /usr/local/sbin/gremgr
install -m 755 "$release/pair.py" /usr/local/sbin/gremgr-pair
install -m 644 "$release/gremgr-worker.service" /etc/systemd/system/gremgr-worker.service
install -m 644 "$release/gremgr-web.service" /etc/systemd/system/gremgr-web.service
if [[ -n "$PANEL_PORT" ]]; then
  (cd "$release" && python3 -m panel.cli init --port "$PANEL_PORT")
else
  (cd "$release" && python3 -m panel.cli init)
fi
if [[ ! -s /etc/gremgr/tls/cert.pem || ! -s /etc/gremgr/tls/key.pem ]]; then
  openssl req -x509 -newkey ed25519 -nodes -keyout /etc/gremgr/tls/key.pem -out /etc/gremgr/tls/cert.pem -days 365 -subj '/CN=GRE Manager' >/dev/null 2>&1
  chmod 600 /etc/gremgr/tls/key.pem /etc/gremgr/tls/cert.pem
fi
install -d -m 750 -o root -g gremgr /run/gremgr
systemctl daemon-reload
systemctl enable gremgr-worker.service gremgr-web.service >/dev/null
systemctl restart gremgr-worker.service
systemctl restart gremgr-web.service
PORT=$(python3 -c 'import json;print(json.load(open("/etc/gremgr/panel.json"))["settings"]["port"])')
ready=0
for attempt in {1..30}; do
  if curl --noproxy '*' -kfsS --connect-timeout 1 --max-time 2 "https://127.0.0.1:$PORT/" -o /dev/null 2>/dev/null; then ready=1; break; fi
  sleep 1
done
if (( ! ready )); then
  echo "The panel did not become ready. Installation backup: $backup" >&2
  if [[ -n "$old_release" && -d "$old_release" ]]; then
    ln -s "$old_release" /opt/gremgr/current.rollback
    mv -Tf /opt/gremgr/current.rollback /opt/gremgr/current
    for target in /usr/local/sbin/gremgr /usr/local/sbin/gremgr-pair /etc/systemd/system/gremgr-worker.service /etc/systemd/system/gremgr-web.service; do
      saved="$backup/$(basename "$target")"
      [[ ! -f "$saved" ]] || cp -a "$saved" "$target"
    done
    systemctl daemon-reload
    systemctl restart gremgr-worker.service gremgr-web.service || true
    echo 'Previous program release restored.' >&2
  fi
  exit 1
fi
echo "GRE Manager $VERSION installed. All management is in the web panel."
python3 - <<'PY'
import json,subprocess
c=json.load(open('/etc/gremgr/panel.json'))['settings']
if c.get('hostname'): ips=[c['hostname']]
else:
 try: ips=[subprocess.check_output(['ip','-j','-4','route','get','1.1.1.1'],text=True)];ips=[json.loads(ips[0])[0].get('prefsrc','SERVER_IP')]
 except Exception: ips=['SERVER_IP']
for ip in ips: print('Panel: https://'+ip+':'+str(c['port']))
print('Initial HTTPS certificate is self-signed; replace it under Settings if needed.')
PY
# Keep application rollbacks bounded; never removes configuration or history.
python3 - <<'PY'
import pathlib,shutil
base=pathlib.Path('/opt/gremgr/releases');current=pathlib.Path('/opt/gremgr/current').resolve()
others=sorted((p for p in base.iterdir() if p.is_dir() and p!=current),key=lambda p:p.stat().st_mtime,reverse=True)
for p in others[2:]: shutil.rmtree(p)
PY
