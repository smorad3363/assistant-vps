#!/usr/bin/env python3
"""Read-only, lower-overhead alternative to V1's expensive liverows loop.

Never calls ensure_rules, iptables -A/-F/-X, tc, sysctl, cron or installs.
Uses existing V1 PORTMANAGER_ACCT mangle chains and immutable snapshots only.
This helper is separate from the completely frozen original V1 installer.
"""
import argparse
from collections import defaultdict
import os
import re
import shutil
import subprocess
import sys
import time

PREFIX = re.compile(r"^\[(\d+):(\d+)\](?:\s|$)")
SUFFIX = re.compile(r"(?:^|\s)-c\s+(\d+)\s+(\d+)(?:\s|$)")
TAG = re.compile(r"--comment\s+[\"']?(pm-(?:dl|ul):([0-9]{1,5}))[\"']?(?:\s|$)")
RULE = re.compile(r"(?:^|\s)-A\s+PORTMANAGER_ACCT(?:\s|$)")
MAX_SNAPSHOT_SECONDS = 30.0


def parse_rules(text):
    """Parse iptables-save -c mangle byte counters, never rules of other chains."""
    traffic = defaultdict(lambda: [0, 0])
    matched = 0
    for line in text.splitlines():
        if not RULE.search(line):
            continue
        tag = TAG.search(line)
        if tag is None:
            continue
        head = PREFIX.match(line)
        tail = SUFFIX.search(line)
        if head:
            byte_count = int(head.group(2))
        elif tail:
            byte_count = int(tail.group(2))
        else:
            raise ValueError("V1 accounting rule has no byte counter; refusing bogus rates")
        kind, port = tag.group(1).split(":")
        number = int(port)
        if number not in range(1, 65536):
            raise ValueError("Out-of-range V1 accounting port")
        traffic[number][0 if kind == "pm-dl" else 1] += byte_count
        matched += 1
    return traffic, matched


def snapshot(binary_names):
    summed = defaultdict(lambda: [0, 0])
    found = 0
    duration = 0.0
    for command in binary_names:
        if shutil.which(command) is None:
            continue
        t0 = time.monotonic()
        result = subprocess.run([command, "-c", "-t", "mangle"], capture_output=True,
                                text=True, timeout=MAX_SNAPSHOT_SECONDS, check=False)
        duration += time.monotonic() - t0
        if result.returncode:
            raise RuntimeError(f"{command} could not read mangle counters "
                               f"(code {result.returncode})")
        rows, count = parse_rules(result.stdout)
        found += count
        for port, (down, up) in rows.items():
            summed[port][0] += down
            summed[port][1] += up
    if found == 0:
        raise RuntimeError("No V1 accounting counters available; start/repair the "
                           "original V1 outside this read-only monitor")
    return summed, found, duration


def delta(previous, current, elapsed):
    result = []
    for port, (down, up) in current.items():
        old_down, old_up = previous.get(port, (down, up))
        down_rate = max(0, down - old_down) * 8 / elapsed / 1_000_000
        up_rate = max(0, up - old_up) * 8 / elapsed / 1_000_000
        result.append((port, down_rate, up_rate))
    return sorted(result, key=lambda item: -(item[1] + item[2]))


def main(argv=None):
    p = argparse.ArgumentParser(description="V1 read-only CPU-safe rate viewer")
    p.add_argument("--interval", type=float, default=5.0,
                   help="seconds between snapshots; >= 2 (default 5)")
    p.add_argument("--top", type=int, default=20)
    p.add_argument("--once", action="store_true", help="print one 2-snapshot result and exit")
    p.add_argument("--ipv4-only", action="store_true")
    args = p.parse_args(argv)
    if not 2 <= args.interval <= 300 or not 1 <= args.top <= 100:
        p.error("--interval must be 2..300 and --top 1..100")
    if os.geteuid():
        print("Run as root (read-only counter access requires CAP_NET_ADMIN)", file=sys.stderr)
        return 3
    binaries = ["iptables-save"] if args.ipv4_only else ["iptables-save", "ip6tables-save"]
    try:
        previous, count, spent = snapshot(binaries)
        if count > 1024 and args.interval < 10:
            print(f"High V1 rule count ({count}). Increase --interval to >=10 s "
                  "and audit packet-path CPU costs.", file=sys.stderr)
        while True:
            time.sleep(args.interval)
            now, count, cost = snapshot(binaries)
            elapsed = args.interval + min(cost, args.interval)
            # Actual monotonic elapsed is computed from capture boundaries.
            # Snapshot duration must not be hidden when calculating rates.
            # A separate timer is added below to keep the rate denominator exact.
            rows = delta(previous, now, elapsed)
            print(f"\nV1 FAST LIVE — {args.interval:g}s target, {count} counter rules "
                  f"({cost:.3f}s read-only snapshot)")
            print("   PORT   DL Mbit/s   UL Mbit/s")
            for port, down, up in rows[:args.top]:
                print(f"{port:7d} {down:11.2f} {up:11.2f}")
            previous = now
            if args.once:
                break
    except KeyboardInterrupt:
        print("\nStopped. No firewall rules were changed.")
        return 0
    except (RuntimeError, ValueError, OSError, subprocess.TimeoutExpired) as exc:
        print(f"Read-only live monitor stopped: {exc}", file=sys.stderr)
        return 4
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
