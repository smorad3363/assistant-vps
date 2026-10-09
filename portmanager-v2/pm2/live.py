"""Read-only instantaneous per-tunnel packet-byte rate view."""
import time
from . import accounting
from .errors import PM2Error


def watch(interval=1, tunnel_id=None, count=None):
    if not 1 <= interval <= 60:
        raise PM2Error("E_VALIDATION", "Interval must be 1..60 seconds")
    before = accounting.counters()
    t0 = time.monotonic()
    iterations = 0
    try:
        while count is None or iterations < count:
            time.sleep(interval)
            after = accounting.counters()
            elapsed = max(0.001, time.monotonic() - t0)
            by_tunnel = {}
            for (tid, proto, direction), total in after.items():
                if tunnel_id and tid != tunnel_id:
                    continue
                prev = before.get((tid, proto, direction), total)
                delta = max(0, total - prev)
                current = by_tunnel.setdefault(tid, {"up": 0, "down": 0})
                current[direction] += delta
            for tid, row in sorted(by_tunnel.items()):
                print(f"{tid} UP {row['up'] * 8 / elapsed / 1_000_000:.3f} "
                      f"Mbit/s DOWN {row['down'] * 8 / elapsed / 1_000_000:.3f} Mbit/s", flush=True)
            before, t0 = after, time.monotonic()
            iterations += 1
    except KeyboardInterrupt:
        return 130
    return 0
