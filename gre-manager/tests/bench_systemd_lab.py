"""Verify actual transient leases and forced-stop cleanup on disposable CI hosts."""
from contextlib import suppress
import os
from pathlib import Path
import tempfile
import time
import uuid

from panel.engine import Engine, run
from panel.model import PanelError
from panel.store import Paths, topology_node_id
from panel.v2_bench_agent import configure, key_for, test_link, validate


def wait(paths, engine, owner, payload, predicate):
    deadline = time.monotonic() + 12
    status = {}
    while time.monotonic() < deadline:
        status = configure(paths, engine, owner, "benchmark/status", payload)
        if predicate(status):
            return status
        time.sleep(.15)
    raise AssertionError(status)


def lab(root, interface):
    first, second = "198.18.55.1", "198.18.55.2"
    run("ip", "link", "add", "dev", interface, "type", "dummy")
    units = []
    try:
        for address in (first, second):
            run("ip", "addr", "add", address + "/32", "dev", interface)
        run("ip", "link", "set", "dev", interface, "up")
        a, b = [Paths(Path(root) / node) for node in ("a", "b")]
        ea, eb = Engine(a), Engine(b)
        owner = topology_node_id(a)
        os.environ["GRE_PANEL_HOME"] = str(Path(root) / "b")
        for force in (False, True):
            payload = {"job_id": uuid.uuid4().hex, "method": "gre", "direction": 0, "nodes": [owner, topology_node_id(b)],
                       "first": first, "second": second, "seconds": 5, "rate": 200_000, "budget": 1_000_000}
            task = key_for(payload)
            approvals = [configure(paths, engine, owner, "benchmark/offer", payload)["approval"]
                         for paths, engine in ((a, ea), (b, eb))]
            with suppress(PanelError):
                configure(b, eb, owner, "benchmark/start", dict(payload, approvals=approvals[:1]))
                raise AssertionError("A single offer was accepted.")
            link = test_link(owner, validate(payload, eb, b))["tunnel"]
            unit = "gremgr-bench-" + task + ".service"
            units.append(unit)
            configure(b, eb, owner, "benchmark/start", dict(payload, approvals=approvals))
            wait(b, eb, owner, payload, lambda status: status["phase"] == "ready")
            assert run("ip", "link", "show", "dev", link).returncode == 0
            if force:
                run("systemctl", "kill", "--kill-who=main", "--signal=SIGKILL", unit)
            else:
                configure(b, eb, owner, "benchmark/cancel", payload)
            wait(b, eb, owner, payload, lambda status: status.get("cleaned") and status["phase"] in {"failed", "interrupted"})
            configure(a, ea, owner, "benchmark/cancel", payload)
            assert run("ip", "link", "show", "dev", link, check=False).returncode
            assert "gmpbench:" + task not in run("iptables-save", "-t", "filter").stdout
        print("Benchmark leases negotiated both offers and cleaned up after explicit cancellation and SIGKILL.")
    finally:
        for unit in units:
            run("systemctl", "stop", unit, check=False)
        run("ip", "link", "del", "dev", interface, check=False)


if __name__ == "__main__":
    assert os.geteuid() == 0 and os.environ.get("GITHUB_ACTIONS") == "true"
    with tempfile.TemporaryDirectory(prefix="gremgr-bench-") as local:
        lab(local, "gm-bc-" + uuid.uuid4().hex[:6])
