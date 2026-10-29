#!/usr/bin/env bash
# Installs a read-only scheduled health monitor. Does not touch Xray, WARP or routing.
set -Eeuo pipefail
[[ "$(id -u)" -eq 0 ]] || { echo "Run with sudo/root" >&2; exit 1; }
ROOT="/opt/warp-gemini"
SCRIPT="$ROOT/health.py"
[[ -f "$SCRIPT" ]] || { echo "Missing $SCRIPT; run main WARP installer first." >&2; exit 1; }
python3 -m py_compile "$SCRIPT"
ln -sfn "$SCRIPT" /usr/local/bin/warp-health
chmod 755 "$SCRIPT"
cat > /etc/systemd/system/warp-gemini-health.service <<'SERVICE'
[Unit]
Description=Read-only Gemini WARP network and exit IP monitoring
After=network-online.target
Wants=network-online.target
[Service]
Type=oneshot
User=root
ExecStart=/usr/local/bin/warp-health check
TimeoutStartSec=100
NoNewPrivileges=true
PrivateTmp=true
SERVICE
cat > /etc/systemd/system/warp-gemini-health.timer <<'TIMER'
[Unit]
Description=Periodic read-only Gemini WARP health monitor
[Timer]
OnBootSec=3min
OnUnitActiveSec=20min
RandomizedDelaySec=60
Persistent=true
[Install]
WantedBy=timers.target
TIMER
systemctl daemon-reload
systemctl enable --now warp-gemini-health.timer
echo "WARP Gemini read-only health timer enabled (about every 20 min)."
echo "Run: sudo warp-health check"
echo "Run: sudo warp-health report"
