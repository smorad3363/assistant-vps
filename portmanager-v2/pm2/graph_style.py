"""Shared sampled 60-second graph used by Port Manager V2 terminal views."""
import math

WINDOW = 60
BARS = "▁▂▃▄▅▆▇█"


def summarize(samples, now, columns=60):
    """One-minute weighted bars; missing observations remain blank."""
    columns = max(1, min(120, int(columns)))
    step = WINDOW / columns
    start = now - WINDOW
    sums_up = [0.0] * columns
    sums_down = [0.0] * columns
    covered = [0.0] * columns
    for end, duration, up, down in samples:
        if end > now or duration <= 0:
            continue
        lo, hi = max(start, end - duration), min(now, end)
        if hi <= lo:
            continue
        first = max(0, math.floor((lo - start) / step))
        last = min(columns - 1, math.ceil((hi - start) / step) - 1)
        for i in range(first, last + 1):
            duration_in_bucket = max(0., min(hi, start + (i + 1) * step)
                                     - max(lo, start + i * step))
            covered[i] += duration_in_bucket
            sums_up[i] += max(0., up) * duration_in_bucket
            sums_down[i] += max(0., down) * duration_in_bucket
    coverage = sum(min(n, step) for n in covered)

    def bars(sums):
        values = [total / n if n else None for total, n in zip(sums, covered)]
        peak = max((v for v in values if v is not None), default=0.)
        return "".join(" " if v is None else BARS[min(7, int(v * 7 / peak))]
                       if peak else BARS[0] for v in values)

    total_weight = sum(covered)
    return {"up_mbps": sum(sums_up) / total_weight if total_weight else None,
            "down_mbps": sum(sums_down) / total_weight if total_weight else None,
            "coverage_seconds": round(min(WINDOW, coverage), 1),
            "graph_up": bars(sums_up), "graph_down": bars(sums_down)}


def avg_text(rate, coverage):
    if rate is None or not coverage:
        return "--"
    return f"{rate:.2f}{'*' if coverage < WINDOW - .01 else ''}"


def rate_text(rate):
    return (f"{rate * 1000:.2f} Kbit/s" if 0 <= rate < 1
            else f"{rate:.2f} Mbit/s")
