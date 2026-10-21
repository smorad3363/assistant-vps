"""Bounded read-only diagnostics; no network configuration is changed.

A responsive public IPv4 address is NOT evidence of a working GRE tunnel.
The only PASS signal is a matching, recorded owned GRE interface with an
inner-address ICMP echo reply. ICMP-blocked peers remain UNVERIFIED.
"""
from datetime import datetime, timezone
import json
import subprocess
from .config import read
from .contract import inside_addresses
from . import network


def status():
    c = read()
    if not c:
        return {"contract_version":"1.0.0","config_revision":0,"tunnels":[],"forwards":[],"service":"Unconfigured","pending_transaction":False}
    return {"contract_version":"1.0.0","config_revision":c["config_revision"],
            "tunnels":[{"id":f"T{t['id']:04d}","peer_ip":t["peer_ip"],"state":"Not applied"} for t in c["tunnels"]],
            "forwards":[{"id":f"P{f['id']:04d}","listen_port":f["listen_port"],"state":"Not applied"} for f in c["forwards"]],
            "service":"Development preview","pending_transaction":False}


def _run(argv, timeout=3):
    """Read-only command runner that never exposes raw command output."""
    try:
        return subprocess.run(argv, capture_output=True, text=True, check=False, timeout=timeout)
    except (FileNotFoundError, PermissionError, subprocess.TimeoutExpired, OSError):
        return None


def _link(name):
    command = _run(['ip', '-d', '-j', 'link', 'show', 'dev', name])
    if command is None or command.returncode:
        return None
    try:
        links = json.loads(command.stdout)
        return links[0] if isinstance(links, list) and links else None
    except (ValueError, IndexError, TypeError):
        return None


def _inner_assigned(device, address):
    command = _run(['ip', '-j', '-4', 'addr', 'show', 'dev', device])
    if command is None or command.returncode:
        return False
    try:
        return any(info.get('local') == address for link in json.loads(command.stdout)
                   for info in link.get('addr_info', []))
    except (ValueError, TypeError, KeyError):
        return False


def test(tunnel_id=None):
    """Probe only explicitly configured tunnels, in no more than 10s each."""
    c = read()
    targets = [t for t in (c or {}).get('tunnels', [])
               if tunnel_id is None or t['id'] == tunnel_id]
    if not targets:
        return []
    try:
        state = network.read_state()
        owned = {t['id']:t for t in (state or {}).get('tunnels', [])}
        ownership_error = False
    except (OSError, ValueError, KeyError, TypeError):
        owned = {}
        ownership_error = True
    results = []
    for t in targets:
        name = f"gtn{t['id']}"
        structure, reachability, result = 'NOT_APPLIED', 'NOT_RUN', 'UNVERIFIED'
        reason = 'No managed GRE interface is installed; saved configuration is not an active tunnel.'
        link = _link(name)
        if ownership_error:
            structure, result = 'OWNERSHIP_ERROR', 'FAIL'
            reason = 'Saved ownership state is invalid or inaccessible. No network changes were made.'
        elif link is not None and t['id'] not in owned:
            structure, result = 'FOREIGN_INTERFACE', 'FAIL'
            reason = f'Interface {name} exists but is not recorded as owned. It was not touched.'
        elif t['id'] in owned and link is None:
            structure, result = 'MISSING_INTERFACE', 'FAIL'
            reason = f'Owned interface {name} is missing. No network changes were made.'
        elif t['id'] in owned and link is not None:
            saved = owned[t['id']]
            expected = ('local_ip','peer_ip','inside_cidr','key')
            linkinfo = link.get('linkinfo') or {}
            kind = linkinfo.get('info_kind')
            data = linkinfo.get('info_data') or {}
            if (kind != 'gre' or any(saved.get(k) != t.get(k) for k in expected)
                    or data.get('local') != t['local_ip'] or data.get('remote') != t['peer_ip']):
                structure, result = 'MISMATCH', 'FAIL'
                reason = 'Owned interface type, kernel endpoint addresses or saved tunnel identity do not match.'
            elif 'UP' not in link.get('flags', []):
                structure, result = 'DOWN', 'FAIL'
                reason = 'Owned GRE interface is down.'
            else:
                inside = inside_addresses(t['inside_cidr'], t['local_ip'], t['peer_ip'])
                local_inner, peer_inner = inside['local_inner'], inside['peer_inner']
                if not _inner_assigned(name, local_inner):
                    structure, result = 'ADDRESS_MISMATCH', 'FAIL'
                    reason = f'GRE interface does not have its expected local inner address {local_inner}.'
                else:
                    structure = 'PRESENT'
                    echo = _run(['ping', '-4', '-n', '-c', '1', '-W', '2', '-I', name, peer_inner], timeout=4)
                    if echo is not None and echo.returncode == 0:
                        reachability, result = 'INNER_ICMP_OK', 'PASS'
                        reason = 'The configured inner GRE peer replied to ICMP. This does not prove port forwarding or QoS.'
                    else:
                        reachability = 'INNER_ICMP_UNVERIFIED'
                        reason = 'No inner ICMP reply; the peer may be unavailable or block ICMP. TCP/UDP is untested.'
        results.append({"contract_version":"1.0.0", "test_id":f"TEST-{t['id']:04d}",
                        "timestamp_utc":datetime.now(timezone.utc).strftime('%Y-%m-%dT%H:%M:%SZ'),
                        "tunnel_id":f"T{t['id']:04d}", "structure":structure,
                        "reachability":reachability, "result":result, "log_path":None,
                        "device":name, "peer_ip":t['peer_ip'], "reason":reason})
    return results
