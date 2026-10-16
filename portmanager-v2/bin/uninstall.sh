#!/usr/bin/env bash
# Full, ownership-verified Port Manager V2 removal.
# No global iptables flush, qdisc reset, V1 rollback or third-party cleanup.
set -Eeuo pipefail
export LC_ALL=C

[[ "$(id -u)" -eq 0 ]] || { echo '[portmanager] Run as root/sudo.' >&2; exit 1; }
mode=apply
yes=0
data_choice=ask
for arg in "$@"; do
  case "$arg" in
    --dry-run) mode=preview ;;
    --yes) yes=1 ;;
    --keep-data) data_choice=keep ;;
    --purge-data) data_choice=purge ;;
    -h|--help)
      printf '%s\n' \
        'Usage: sudo bash -s -- uninstall [--dry-run] [--keep-data|--purge-data] [--yes]' \
        '  --keep-data    Keep settings, traffic database and logs for reinstall' \
        '  --purge-data   Delete all V2 saved data; reinstall starts from zero' \
        '  --dry-run      Print removal plan without modifying system' \
        'Without flags, only asks whether to keep previous data; --yes defaults to keep.'
      exit 0 ;;
    *) echo "[portmanager] Unknown option: $arg" >&2; exit 2 ;;
  esac
done
command -v python3 >/dev/null 2>&1 || { echo '[portmanager] python3 is required.' >&2; exit 1; }

# Keep the runtime's own safety/ownership code authoritative. This script must
# not guess which firewall rules, tc filters or systemd units belong to V2.
python3 -I - "$mode" "$yes" "$data_choice" <<'PY'
import argparse
import json
import os
import shlex
from pathlib import Path
import shutil
import sys

# Isolated Python startup prevents root importing a foreign pm2 from CWD.
sys.path.insert(0, '/opt/portmanager2/current')
mode, confirmed, data_choice = sys.argv[1], sys.argv[2] == "1", sys.argv[3]
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
    # Single decision: preserve data, or delete it to start fresh.
    choice = data_choice
    if mode != 'preview' and choice == 'ask':
        if confirmed:
            choice = 'keep'
        else:
            try:
                with open('/dev/tty', 'r+', encoding='utf-8') as tty:
                    tty.write('Keep saved Port Manager data for next install? [Y/n]: ')
                    tty.flush()
                    answer = tty.readline().strip().lower()
            except OSError:
                raise PM2Error('E_VALIDATION', 'No terminal: specify --keep-data or --purge-data')
            if answer not in ('', 'y', 'yes', 'n', 'no'):
                print('[portmanager] Cancelled: answer Y or N.', file=sys.stderr)
                return
            choice = 'purge' if answer in ('n', 'no') else 'keep'
    legacy, plan, hist, monitored = prepare()
    if mode == 'preview':
        print('[portmanager] V2 removal plan:')
        for item in plan.get('would_remove', []):
            print(f'  - {item}')
        print(f'  - verified traffic-counter chains ({len(monitored)} port/protocol pairs)')
        for directory in paths:
            action = 'delete' if choice == 'purge' else 'keep'
            print(f'  - {action} {directory}/')
        print('[portmanager] Unrelated GRE/Docker/UFW/legacy-V1 system rules are untouched.')
        return
    with cli.mutation_lock():
        # Validate owners again after acquiring the exclusive mutation lock.
        legacy, _, hist, monitored = prepare()
        cli.uninstall(argparse.Namespace(dry_run=False, yes=True, purge=False))
        # The owned sampler/timers have stopped, so its verified history
        # counters can now be deleted without affecting other iptables chains.
        history_collector._clear(hist)
        remaining, _ = history_collector._inspect()
        if any(hooked or present for _, _, hooked, present in remaining):
            raise PM2Error('E_APPLY', 'V2 history chains remain after removal')
        if firewall.owned_footprint_present(firewall.snapshot()):
            raise PM2Error('E_APPLY', 'V2 firewall footprint remains after removal')
        if choice == 'purge':
            for directory in paths:
                if directory.is_symlink() or not directory.is_dir():
                    raise PM2Error('E_CONFLICT', f'V2 data directory changed: {directory}')
                shutil.rmtree(directory)
    if choice == 'keep':
        print('[portmanager] V2 program and owned system rules removed. Saved data kept for next install.')
    else:
        print('[portmanager] V2 program, owned rules and saved data removed. Next install starts from zero.')
    if legacy:
        print('[portmanager] NOTE: Independent V1 firewall/tc rules have not been modified.')


try:
    main()
except PM2Error as exc:
    print(f'[portmanager] {exc.code}: {exc.message}', file=sys.stderr)
    raise SystemExit(exc.exit_code)
except (OSError, ValueError) as exc:
    print(f'[portmanager] Removal stopped: {exc}', file=sys.stderr)
    raise SystemExit(6)
PY
