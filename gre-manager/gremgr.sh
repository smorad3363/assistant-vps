#!/usr/bin/env bash
# No interactive menus. Existing legacy boot restore remains available.
set -Eeuo pipefail
case "${1:-}" in
  --restore) exec bash /opt/gremgr/current/legacy-restore.sh ;;
  --version) cd /opt/gremgr/current; exec python3 -c 'from panel import __version__; print(__version__)' ;;
  --reset-password) cd /opt/gremgr/current; exec python3 -m panel.cli reset-password ;;
  --recover) cd /opt/gremgr/current; exec python3 -m panel.cli recover ;;
  *) cd /opt/gremgr/current; exec python3 -m panel.cli status ;;
esac
