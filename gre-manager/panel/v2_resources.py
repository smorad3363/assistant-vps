"""Read host metrics and keep conntrack admission independent of system tuning."""
from contextlib import suppress
import json
from pathlib import Path
import shutil
import time

from .store import atomic_json


def read(path):
    with suppress(OSError):
        return path.read_text().strip()
    return ""


def number(path):
    with suppress(ValueError):
        return int(read(path))
    return None


def conntrack(proc=Path("/proc")):
    table = proc / "sys/net/netfilter"
    used = number(table / "nf_conntrack_count")
    maximum = number(table / "nf_conntrack_max")
    return {"used": used, "maximum": maximum, "percent": 100 * used / maximum if used is not None and maximum else None}


def admission_pressure(settings, previous, proc=Path("/proc")):
    limits = settings.get("v2_conntrack_guard")
    if not limits:
        return False
    percent = conntrack(proc)["percent"]
    if percent is None:
        return previous
    return percent >= limits["high"] if not previous else percent > limits["low"]


def pressure_file(paths):
    return paths.run / "conntrack-busy"


def boot_id():
    return read(Path("/proc/sys/kernel/random/boot_id"))


class HostSampler:
    def __init__(self, paths, proc=Path("/proc"), net=Path("/sys/class/net"), clock=time.monotonic):
        self.paths, self.proc, self.net, self.clock = paths, proc, net, clock
        self.previous = None
        self.last_persist = 0
        self.path = paths.var / "v2-host-metrics.json"

    def snapshot(self):
        now = self.clock()
        epoch = read(self.proc / "sys/kernel/random/boot_id")
        cpu = next((row.split()[1:9] for row in read(self.proc / "stat").splitlines() if row.startswith("cpu ")), [])
        cpu = tuple(map(int, cpu))
        memory = {}
        for line in read(self.proc / "meminfo").splitlines():
            name, _, value = line.partition(":")
            if name in {"MemTotal", "MemAvailable", "SwapTotal", "SwapFree"}:
                memory[name] = int(value.split()[0]) * 1024
        interfaces = {}
        if self.net.is_dir():
            for device in sorted(self.net.iterdir()):
                stats = device / "statistics"
                counters = {key: number(stats / key) for key in ("rx_bytes", "tx_bytes", "rx_packets", "tx_packets",
                                                                 "rx_errors", "tx_errors", "rx_dropped", "tx_dropped")}
                interfaces[device.name] = {"ifindex": number(device / "ifindex"), **counters}
        previous = self.previous
        result = {"checked": time.time(), "boot_id": epoch, "memory_bytes": memory, "cpu_percent": None,
                  "interfaces": interfaces, "conntrack": conntrack(self.proc), "disk_free_bytes": shutil.disk_usage(self.paths.var).free}
        if previous and previous["epoch"] == epoch and now > previous["time"]:
            if len(cpu) == len(previous["cpu"]) == 8:
                deltas = [item - old for item, old in zip(cpu, previous["cpu"])]
                if min(deltas) >= 0 and sum(deltas):
                    result["cpu_percent"] = {name: 100 * ticks / sum(deltas) for name, ticks in zip(
                        ("user", "nice", "system", "idle", "iowait", "irq", "softirq", "steal"), deltas)}
            for name, counters in interfaces.items():
                old = previous["interfaces"].get(name, {})
                if counters["ifindex"] != old.get("ifindex"):
                    continue
                for key in ("rx_bytes", "tx_bytes", "rx_packets", "tx_packets"):
                    if counters[key] is not None and old.get(key) is not None and counters[key] >= old[key]:
                        counters[key + "_per_second"] = (counters[key] - old[key]) / (now - previous["time"])
        self.previous = {"epoch": epoch, "cpu": cpu, "time": now, "interfaces": interfaces}
        if now - self.last_persist >= 5 and result["disk_free_bytes"] >= 512 * 1024 * 1024:
            atomic_json(self.path, result)
            self.last_persist = now
        return result


def last_metrics(paths):
    return json.loads(read(paths.var / "v2-host-metrics.json") or "null")
