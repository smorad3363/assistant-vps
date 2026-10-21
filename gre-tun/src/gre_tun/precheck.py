"""GRE peer readiness and optional short-lived protocol-47 challenge.

Neither passive nor active checks create an interface, address, route, firewall
rule, persistent process or configuration. This module must remain read-only
except for its explicitly requested, bounded GRE probe packets.
"""
from __future__ import annotations
import ipaddress
import json
import os
import select
import socket
import struct
import subprocess
import time

# Ethertype reserved for local experimental use: avoids an IPv4 inner packet.
ETHERTYPE = 0x88B5
SIGNATURE = b'GT-PREFLIGHT-1\x00'
HELLO = b'H'
ACK = b'A'
MAX_WAIT = 120


def validate_peer(value):
    try:
        peer = ipaddress.IPv4Address(value)
    except (ValueError, ipaddress.AddressValueError):
        raise ValueError('Peer must be an IPv4 address.') from None
    if not peer.is_global or peer.is_multicast or peer.is_unspecified or peer.is_loopback:
        raise ValueError('Peer must be a public unicast IPv4 address.')
    return str(peer)


def validate_token(value):
    if not isinstance(value, str) or len(value) != 32 or any(c not in '0123456789abcdefABCDEF' for c in value):
        raise ValueError('Use a 32-character hex token shared privately between the two hosts.')
    return bytes.fromhex(value)


def run(args, timeout=5):
    try:
        return subprocess.run(args, capture_output=True, text=True, timeout=timeout, check=False)
    except (OSError, subprocess.TimeoutExpired):
        return None


def passive(peer_ip):
    """Read-only diagnostics; PASS never implies live GRE protocol traversal."""
    peer_ip = validate_peer(peer_ip)
    checks = []
    route = run(['ip', '-j', '-4', 'route', 'get', peer_ip])
    source = device = None
    if route and route.returncode == 0:
        try:
            data = json.loads(route.stdout)[0]
            source, device = data.get('prefsrc', data.get('src')), data.get('dev')
        except (ValueError, IndexError, KeyError, TypeError):
            pass
    good_route = bool(source and device and source != peer_ip)
    checks.append({'name': 'IPv4 route to peer', 'status': 'PASS' if good_route else 'FAIL',
                   'detail': f'{source} via {device}' if good_route else 'No usable source/interface returned by ip route get.'})
    if source:
        try:
            source_global = ipaddress.IPv4Address(source).is_global
        except ValueError:
            source_global = False
        checks.append({'name': 'Public local source', 'status': 'PASS' if source_global else 'WARN',
                       'detail': source if source_global else f'{source} is not a public IPv4; NAT may require additional configuration.'})
    # Read-only checks cannot establish that GRE forwarding is available end-to-end.
    checks.append({'name': 'GRE kernel capability', 'status': 'UNKNOWN',
                   'detail': 'Not proven by read-only inspection; protocol-47 active challenge and a lab tunnel are required.'})
    ping = run(['ping', '-4', '-n', '-c', '1', '-W', '2', peer_ip], timeout=4)
    icmp = bool(ping and ping.returncode == 0)
    checks.append({'name': 'Public IPv4 ICMP', 'status': 'PASS' if icmp else 'UNKNOWN',
                   'detail': 'Echo reply received.' if icmp else 'No ICMP reply (could be filtered; not proof GRE is blocked).'})
    raw = os.geteuid() == 0
    checks.append({'name': 'Raw-socket privilege', 'status': 'PASS' if raw else 'WARN',
                   'detail': 'Root available for optional GRE challenge.' if raw else 'Active challenge requires root / CAP_NET_RAW.'})
    return {'peer_ip': peer_ip, 'source_ip': source, 'interface': device,
            'checks': checks, 'gre_path': 'NOT_TESTED',
            'summary': 'Local readiness only. Protocol 47 is NOT verified by route or ping.'}


def packet(kind, token):
    if kind not in (HELLO, ACK) or len(token) != 16:
        raise ValueError('Invalid probe frame.')
    # RFC 2784 GRE version 0, no optional fields, experimental inner protocol.
    return struct.pack('!HH', 0, ETHERTYPE) + SIGNATURE + kind + token


def unpack(data, expected_ip, token):
    """Accept only a matching unfragmented IPv4 packet from the exact peer."""
    if len(data) < 20:
        return None
    ihl = (data[0] & 15) * 4
    if data[0] >> 4 != 4 or ihl < 20 or len(data) < ihl + 4 + len(SIGNATURE) + 17:
        return None
    if data[9] != socket.IPPROTO_GRE or (struct.unpack('!H', data[6:8])[0] & 0x3fff):
        return None
    if socket.inet_ntoa(data[12:16]) != expected_ip:
        return None
    if struct.unpack('!HH', data[ihl:ihl + 4]) != (0, ETHERTYPE):
        return None
    content = data[ihl + 4:]
    if len(content) != len(SIGNATURE) + 17 or not content.startswith(SIGNATURE):
        return None
    if content[-16:] != token:
        return None
    if content[len(SIGNATURE):len(SIGNATURE) + 1] not in (HELLO, ACK):
        return None
    return content[len(SIGNATURE):len(SIGNATURE) + 1]


def exchange(peer_ip, token_hex, listen=False, seconds=None):
    """Two-sided GRE protocol probe with no tunnel or network mutations.

    Listener responds only once to an exact, nonce-authenticated challenge.
    Sender transmits at most three small GRE packets then waits for one ACK.
    """
    peer_ip = validate_peer(peer_ip)
    token = validate_token(token_hex)
    seconds = max(1, min(int(seconds if seconds is not None else (120 if listen else 10)), MAX_WAIT))
    if os.geteuid() != 0:
        raise PermissionError('Root / CAP_NET_RAW is required for protocol-47 probing.')
    try:
        sock = socket.socket(socket.AF_INET, socket.SOCK_RAW, socket.IPPROTO_GRE)
    except OSError as exc:
        raise OSError(f'GRE raw socket unavailable: {exc}') from exc
    with sock:
        sock.setblocking(False)
        deadline = time.monotonic() + seconds
        next_send = 0.0
        sent = 0
        while time.monotonic() < deadline:
            now = time.monotonic()
            if not listen and sent < 3 and now >= next_send:
                sock.sendto(packet(HELLO, token), (peer_ip, 0))
                sent += 1
                next_send = now + 1.0
            ready, _, _ = select.select([sock], [], [], min(0.5, max(0.0, deadline - time.monotonic())))
            if not ready:
                continue
            try:
                data, _ = sock.recvfrom(65535)
            except BlockingIOError:
                continue
            kind = unpack(data, peer_ip, token)
            if listen and kind == HELLO:
                sock.sendto(packet(ACK, token), (peer_ip, 0))
                return {'result': 'PASS', 'direction': 'incoming GRE request and outgoing GRE reply',
                        'detail': 'Matched authenticated protocol-47 challenge from specified IPv4.'}
            if not listen and kind == ACK:
                return {'result': 'PASS', 'direction': 'outgoing GRE request and incoming GRE reply',
                        'detail': 'Matched authenticated protocol-47 response from specified IPv4.'}
    return {'result': 'UNVERIFIED', 'direction': 'listen' if listen else 'probe',
            'detail': 'No matching GRE response in the bounded window. Firewall, peer readiness, route or transport may be responsible.'}
