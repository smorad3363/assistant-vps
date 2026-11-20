"""Timed, receiver-accounted TCP traffic between two approved endpoints."""
from contextlib import ExitStack, suppress
import hmac
import secrets
import select
import socket
import time

from .model import PanelError

SECOND = 1_000_000_000
STREAMS = 2
CHUNK = 16 * 1024
START_DELAY = 20


def direction_lengths(duration_s, maximum=300):
    if type(duration_s) is not int or not 2 <= duration_s <= maximum:
        raise PanelError(f"Use an integer duration from 2 through {maximum} seconds.", "duration", "duration_s")
    return duration_s // 2, (duration_s + 1) // 2


class Receipt:
    def __init__(self, start, seconds, budget):
        self.start = start
        self.limit = start + seconds * SECOND
        self.budget = budget
        self.bytes = 0
        self.bins = [0] * seconds

    def record(self, size, now):
        if not self.start <= now < self.limit:
            return
        count = min(size, self.budget - self.bytes)
        self.bytes += count
        self.bins[(now - self.start) // SECOND] += count

    def snapshot(self, when, reason):
        elapsed = max(0, min(when, self.limit) - self.start)
        seconds = elapsed // SECOND
        return {"received_bytes": self.bytes, "peak_second_bytes": max(self.bins[:seconds], default=None),
                "elapsed_ns": elapsed, "complete_seconds": seconds, "reason": reason}


def report(outbound, inbound):
    directions = {"outbound": outbound, "inbound": inbound}
    received = [sample["received_bytes"] for sample in directions.values() if sample is not None]
    peaks = [(sample["peak_second_bytes"], side) for side, sample in directions.items()
             if sample is not None and sample["peak_second_bytes"] is not None]
    peak, side = max(peaks, key=lambda item: item[0], default=(None, None))
    return {"received_bytes": sum(received) if received else None, "peak_mbps": peak * 8 / 1_000_000 if peak is not None else None,
            "peak_direction": side, "directions": directions,
            "finished": all(sample and sample["reason"] == "finished" for sample in directions.values())}


def scoped_socket(address, device=None):
    sock = socket.socket(socket.AF_INET6 if ":" in address else socket.AF_INET, socket.SOCK_STREAM)
    try:
        if device:
            sock.setsockopt(socket.SOL_SOCKET, socket.SO_BINDTODEVICE, device.encode() + b"\0")
        if sock.family == socket.AF_INET6:
            sock.setsockopt(socket.IPPROTO_IPV6, socket.IPV6_V6ONLY, 1)
        sock.bind((address, 0))
        return sock
    except OSError:
        sock.close()
        raise


def open_receiver(address, device=None):
    sock = scoped_socket(address, device)
    try:
        sock.listen(STREAMS)
        return sock
    except OSError:
        sock.close()
        raise


def read_exact(sock, size):
    received = bytearray()
    while len(received) < size:
        part = sock.recv(size - len(received))
        if not part:
            break
        received.extend(part)
    return received


def proof(token, side, identifier):
    return hmac.digest(token, b"gremgr benchmark " + side + identifier, "sha256")


def receive(listener, peer, token, seconds, budget, checkpoint=lambda _: None, cancelled=lambda: False):
    streams = {}
    deadline = time.monotonic() + START_DELAY
    with ExitStack() as owned:
        while len(streams) < STREAMS:
            wait = deadline - time.monotonic()
            if wait <= 0 or cancelled():
                return None
            if not select.select([listener], [], [], min(.1, wait))[0]:
                continue
            sock, address = listener.accept()
            with ExitStack() as incoming:
                incoming.enter_context(sock)
                if address[0] != peer:
                    continue
                sock.settimeout(min(.5, wait))
                try:
                    hello = read_exact(sock, 49)
                except OSError:
                    continue
                index = hello[0] if hello else STREAMS
                if (len(hello) != 49 or index >= STREAMS or index in streams
                        or not hmac.compare_digest(hello[17:], proof(token, b"client", hello[:17]))):
                    continue
                streams[index] = sock, hello[:17]
                owned.enter_context(incoming.pop_all())
        try:
            for sock, identifier in streams.values():
                sock.sendall(proof(token, b"server", identifier))
            for sock, identifier in streams.values():
                start = proof(token, b"start", identifier)
                sock.settimeout(START_DELAY)
                if not hmac.compare_digest(read_exact(sock, len(start)), start):
                    return None
                sock.setblocking(False)
        except OSError:
            return None
        meter = Receipt(time.monotonic_ns(), seconds, budget)
        current = [sock for sock, _ in streams.values()]
        sampled = 0
        while True:
            now = time.monotonic_ns()
            if cancelled():
                reason = "cancelled"
                break
            if now >= meter.limit:
                reason = "finished"
                break
            if meter.bytes >= budget:
                reason = "byte_budget"
                break
            if len(current) < STREAMS:
                reason = "connection_lost"
                break
            for sock in select.select(current, [], [], min(.1, (meter.limit - now) / SECOND))[0]:
                remaining = budget - meter.bytes
                if remaining == 0:
                    break
                try:
                    payload = sock.recv(min(CHUNK, remaining))
                    if payload:
                        meter.record(len(payload), time.monotonic_ns())
                    else:
                        current.remove(sock)
                except BlockingIOError:
                    continue
                except OSError:
                    current.remove(sock)
            now = time.monotonic_ns()
            if (now - meter.start) // SECOND > sampled:
                checkpoint(meter.snapshot(now, "active"))
                sampled = (now - meter.start) // SECOND
        result = meter.snapshot(now, reason)
        checkpoint(result)
        return result


def send(source, peer, port, token, seconds, rate, budget, *, device=None, cancelled=lambda: False):
    """Send an aggregate rate in bytes per second across exactly two TCP streams."""
    if rate <= 0 or budget <= 0:
        raise ValueError("The test requires a positive byte rate and budget.")
    zeros = memoryview(bytes(CHUNK))
    sent = 0
    with ExitStack() as stack:
        streams = []
        for index in range(STREAMS):
            sock = stack.enter_context(scoped_socket(source, device))
            sock.settimeout(START_DELAY / 2)
            sock.connect((peer, port))
            identifier = bytes([index]) + secrets.token_bytes(16)
            sock.sendall(identifier + proof(token, b"client", identifier))
            sock.setsockopt(socket.SOL_SOCKET, socket.SO_SNDBUF, CHUNK * 2)
            streams.append((sock, identifier))
        for sock, identifier in streams:
            sock.settimeout(START_DELAY)
            expected = proof(token, b"server", identifier)
            if not hmac.compare_digest(read_exact(sock, len(expected)), expected):
                return sent
        for sock, identifier in streams:
            sock.sendall(proof(token, b"start", identifier))
            sock.setblocking(False)
        streams = [sock for sock, _ in streams]
        started = time.monotonic_ns()
        limit = started + seconds * SECOND + SECOND // 4
        while time.monotonic_ns() < limit and not cancelled():
            now = time.monotonic_ns()
            allowed = min(budget, (now - started) * rate // SECOND) - sent
            if allowed <= 0:
                # Keep both streams open until the receiver records its budget or deadline.
                time.sleep(.005)
                continue
            ready = select.select([], streams, [], .05)[1]
            for sock in ready:
                count = min(len(zeros), max(1, allowed // len(ready)), budget - sent)
                try:
                    transferred = sock.send(zeros[:count])
                except BlockingIOError:
                    continue
                except OSError:
                    return sent
                sent += transferred
            streams.reverse()
        for sock in streams:
            with suppress(OSError):
                sock.shutdown(socket.SHUT_WR)
    return sent
