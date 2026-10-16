#!/usr/bin/env bash
# Full, ownership-verified Port Manager V2 removal.
# No global iptables flush, qdisc reset, V1 rollback or third-party cleanup.
set -Eeuo pipefail
export LC_ALL=C

[[ "$(id -u)" -eq 0 ]] || { echo '[portmanager] Run as root/sudo.' >&2; exit 1; }
mode=apply
yes=0
for arg in "$@"; do
  case "$arg" in
    --dry-run) mode=preview ;;
    --yes) yes=1 ;;
    -h|--help)
      printf '%s\n' \
        'Usage: install.sh | sudo bash -s -- uninstall [--dry-run|--yes]' \
        '  --dry-run   Show ownership checks and removal plan, change nothing' \
        '  --yes       Confirm irreversible deletion of V2 program, state, logs, and saved V1 archive' \
        'Without --yes, type REMOVE-PORTMANAGER2 in the server terminal.'
      exit 0 ;;
    *) echo "[portmanager] Unknown option: $arg" >&2; exit 2 ;;
  esac
done
command -v python3 >/dev/null 2>&1 || { echo '[portmanager] python3 is required.' >&2; exit 1; }

# Keep the runtime's own safety/ownership code authoritative. This script must
# not guess which firewall rules, tc filters or systemd units belong to V2.
python3 -I - "$mode" "$yes" <<'PY'
import argparse
import json
import os
import shlex
from pathlib import Path
import shutil
import sys

# Isolated Python startup prevents root importing a foreign pm2 from CWD.
sys.path.insert(0, '/opt/portmanager2/current')
mode, confirmed = sys.argv[1], sys.argv[2] == "1"
opt = Path('/opt/portmanager2')
current = opt / 'current'
launcher = Path('/usr/local/bin/portmanager2')
if (not current.is_symlink() or not launcher.is_symlink() or
        os.readlink(launcher) != '/opt/portmanager2/current/bin/portmanager2' or
        not (current / 'pm2' / 'cli.py').is_file()):
    raise SystemExit('[portmanager] V2 installation not found or does not match its known layout; no changes made.')

try:
    from pm2 import cli, firewall, history_collector, migration
    from pm2.errors import PM2Error
except (ImportError, OSError) as exc:
    raise SystemExit(f'[portmanager] Cannot load installed V2 ownership checks: {exc}')

paths = (Path('/etc/portmanager2'), Path('/var/lib/portmanager2'),
         Path('/var/log/portmanager2'))
markers = ((opt, '.owner.json'),) + tuple((p, 'owner.json') for p in paths)


def owned_paths_preflight():
    for directory, marker_name in markers:
        marker = directory / marker_name
        if directory.is_symlink() or not directory.is_dir() or marker.is_symlink() or not marker.is_file():
            raise PM2Error('E_CONFLICT', f'Unowned/missing Port Manager V2 path: {directory}')
        try:
            value = json.loads(marker.read_text(encoding='utf-8'))
        except (OSError, ValueError) as exc:
            raise PM2Error('E_CONFLICT', f'Unreadable Port Manager V2 owner: {marker}') from exc
        if not isinstance(value, dict) or value.get('product') != 'portmanager2' or value.get('schema_version') != 1:
            raise PM2Error('E_CONFLICT', f'Unrecognized Port Manager V2 owner: {marker}')
    archive = paths[1] / 'legacy-v1'
    if archive.is_symlink():
        raise PM2Error('E_CONFLICT', 'Legacy V1 archive is an unsafe symlink')
    saved = migration._load_marker()  # validates archive integrity and SHA-256
    if archive.exists() and not archive.is_dir():
        raise PM2Error('E_CONFLICT', 'Invalid legacy V1 archive location')
    if archive.is_dir() and saved is None and any(archive.iterdir()):
        raise PM2Error('E_CONFLICT', 'Unrecognized legacy V1 archive contents')
    if saved is not None:
        current_cron = migration._read_cron()
        # The installer froze V1 jobs on cut-over; do not delete their saved
        # executable while somebody has explicitly re-enabled those jobs.
        _, removed = migration._split_cron(current_cron)
        if removed:
            raise PM2Error('E_CONFLICT', 'Active legacy V1 cron entries detected; resolve before full removal')
    return saved is not None


def history_references_preflight():
    """Reject references to history chains outside their own verified hooks."""
    from pm2 import auto_monitor
    for direction, (builtin, chain, _) in history_collector.CHAINS.items():
        expected = ['-A', builtin, '-m', 'comment', '--comment',
                    history_collector.HOOK, '-j', chain]
        for raw in auto_monitor._ipt('-S').splitlines():
            tokens = shlex.split(raw)
            if '-j' in tokens and tokens[tokens.index('-j') + 1:tokens.index('-j') + 2] == [chain]:
                if tokens != expected:
                    raise PM2Error('E_CONFLICT', f'Foreign reference to V2 history chain: {chain}')


def prepare():
    has_v1_archive = owned_paths_preflight()
    if cli.V1_BIN.is_file() and not cli.V1_BIN.is_symlink():
        raise PM2Error('E_CONFLICT', 'An active V1 binary exists; full V2-only removal cannot remove V1 safely')
    plan = cli.uninstall(argparse.Namespace(dry_run=True, yes=False, purge=False))
    hist, monitored = history_collector._inspect()
    history_references_preflight()
    return has_v1_archive, plan, hist, monitored


def main():
    # Dry run does not acquire or mutate the global lock.
    legacy, plan, hist, monitored = prepare()
    print('[portmanager] Verified Port Manager V2 removal plan:')
    for item in plan.get('would_remove', []):
        print(f'  - {item}')
    for item in paths:
        print(f'  - {item}/ (all V2-owned configuration, data and logs)')
    if legacy:
        print('  - archived V1 recovery binary/cron snapshot (inside V2 data)')
    print(f'  - verified PM2_HIST_RX/TX accounting chains ({len(monitored)} tracked protocol/port pairs)')
    print('[portmanager] Unrelated iptables rules, host tc qdiscs, Docker, UFW, and system settings are NOT reset.')
    if legacy:
        print('[portmanager] WARNING: Legacy V1 kernel rules/tc or independent V1 files are NOT removed by this V2 uninstaller.')
    if mode == 'preview':
        print('[portmanager] Dry run: no changes made.')
        return
    if not confirmed:
        try:
            with open('/dev/tty', 'r+', encoding='utf-8') as tty:
                tty.write('Type REMOVE-PORTMANAGER2 to permanently delete V2 and its saved data: ')
                tty.flush()
                answer = tty.readline().strip()
        except OSError:
            raise PM2Error('E_VALIDATION', 'Interactive confirmation unavailable; pass --yes explicitly')
        if answer != 'REMOVE-PORTMANAGER2':
            raise PM2Error('E_VALIDATION', 'Uninstall cancelled')
    with cli.mutation_lock():
        # Recheck immediately before any changes; refusing drift is safer than
        # partial cleanup on a shared firewall host.
        legacy, _, hist, monitored = prepare()
        # The exclusive lock prevents a racing V2 writer. All chain/links
        # have already passed exact ownership checks before mutation.
        cli.uninstall(argparse.Namespace(dry_run=False, yes=True, purge=False))
        # The V2 sampler is disabled and the release is gone; modules already
        # loaded in this process can now safely remove its accounting hooks.
        history_collector._clear(hist)
        for directory in paths:
            if directory.is_symlink() or not directory.is_dir():
                raise PM2Error('E_CONFLICT', f'V2 data directory changed during removal: {directory}')
            shutil.rmtree(directory)
        remaining, _ = history_collector._inspect()
        if any(hooked or present for _, _, hooked, present in remaining):
            raise PM2Error('E_APPLY', 'V2 history chains remain after removal')
        if firewall.owned_footprint_present(firewall.snapshot()):
            raise PM2Error('E_APPLY', 'V2 firewall footprint remains after removal')
    print('[portmanager] Port Manager V2 executable, owned services, filters, history chains, and data removed.')
    if legacy:
        print('[portmanager] NOTE: Pre-existing V1 firewall/tc artifacts may remain; no foreign or legacy rules were flushed.')


try:
    main()
except PM2Error as exc:
    print(f'[portmanager] {exc.code}: {exc.message}', file=sys.stderr)
    raise SystemExit(exc.exit_code)
except (OSError, ValueError) as exc:
    print(f'[portmanager] Removal stopped: {exc}', file=sys.stderr)
    raise SystemExit(6)
PY
