"""Duration, receiver accounting, and real TCP transport contracts."""
from concurrent.futures import ThreadPoolExecutor
import random
import secrets
import tempfile
import time
import unittest

from panel.model import PanelError
from panel.store import Paths
from panel.v2_bench_agent import key_for
from panel.v2_bench_jobs import Benchmarks, receiver_receipt
from panel.v2_benchmark import SECOND, Receipt, direction_lengths, open_receiver, receive, report, send


class BenchmarkTests(unittest.TestCase):
    def test_coordinator_checks_both_hosts_and_reuses_an_existing_job_id(self):
        nodes = ["a" * 32, "b" * 32]
        addresses = ["192.0.2.11", "192.0.2.12"]
        calls = []
        started = set()
        requested = {}

        def remote(node, operation, payload):
            if operation == "benchmark/capabilities":
                side = nodes.index(node)
                return {"node_id": node, "addresses": [addresses[side]], "methods": ["gre", "ipip"],
                        "max_seconds": 300 - 10 * side, "rate": 1000 - 100 * side, "bytes": 10000}
            direction = payload["direction"]
            if operation == "benchmark/offer":
                return {"approval": {"node_id": node, "task_key": key_for(payload)}}
            if operation == "benchmark/start":
                calls.append((node, direction, payload["seconds"], payload["rate"]))
                requested[direction] = payload["seconds"]
                if "port" in payload:
                    started.add(direction)
                return {"phase": "starting"}
            if operation == "benchmark/status":
                response = {"node_id": node, "task_key": key_for(payload)}
                if direction not in started:
                    return dict(response, phase="ready", port=23501)
                seconds = requested[direction]
                sample = {"received_bytes": 10, "peak_second_bytes": 9, "reason": "finished", "elapsed_ns": seconds * SECOND,
                          "complete_seconds": seconds}
                return dict(response, phase="done", cleaned=True, receipt=sample)
            return {"phase": "stopping"}

        with tempfile.TemporaryDirectory() as root:
            coordinator = Benchmarks(Paths(root), remote)
            try:
                request = {"nodes": nodes, "first": addresses[0], "second": addresses[1],
                           "methods": [{"method": "gre", "duration_s": 37}], "id": "c" * 32}
                plan = coordinator.plan(request)
                self.assertEqual((plan["max_seconds"], plan["transfer_seconds"], plan["rate"]), (290, 37, 900))
                self.assertLessEqual(plan["estimated_bytes"], 10000)
                with self.assertRaisesRegex(PanelError, "belongs to each paired node"):
                    coordinator.plan(dict(request, second="203.0.113.4"))
                request["digest"] = plan["digest"]
                job = coordinator.start(request)
                self.assertEqual(coordinator.start(request)["id"], job["id"])
                deadline = time.monotonic() + 3
                job = coordinator.status(job["id"])
                while job["phase"] != "done" and time.monotonic() < deadline:
                    time.sleep(.025)
                    job = coordinator.status(job["id"])
                self.assertEqual(job["phase"], "done")
                self.assertEqual(job["results"]["gre"]["received_bytes"], 20)
                self.assertEqual(calls, [(nodes[1], 0, 18, 900), (nodes[0], 0, 18, 900),
                                         (nodes[0], 1, 19, 900), (nodes[1], 1, 19, 900)])
            finally:
                coordinator.close()

    def test_terminal_receipt_requires_full_time_and_coherent_volume(self):
        sample = {"received_bytes": 100, "peak_second_bytes": 75, "reason": "finished", "elapsed_ns": 2 * SECOND,
                  "complete_seconds": 2}
        self.assertEqual(receiver_receipt(sample, 2, 200), sample)
        for change in ({"elapsed_ns": SECOND}, {"complete_seconds": 1}, {"received_bytes": 201}, {"peak_second_bytes": 101}):
            with self.assertRaises(PanelError):
                receiver_receipt(dict(sample, **change), 2, 200)

    def test_duration_is_an_exact_integer_and_preserves_the_odd_second(self):
        for duration in range(2, 301):
            outward, inward = direction_lengths(duration)
            self.assertEqual(outward + inward, duration)
            self.assertIn(inward - outward, (0, 1))
        self.assertEqual(direction_lengths(37), (18, 19))
        for invalid in (True, 0, 1, 301, 3.0, None, "30"):
            with self.assertRaises(PanelError):
                direction_lengths(invalid)
        with self.assertRaises(PanelError):
            direction_lengths(37, maximum=35)

    def test_report_uses_receiver_totals_and_the_best_fully_observed_second(self):
        left = Receipt(0, 18, 1_000_000_000)
        right = Receipt(0, 19, 1_000_000_000)
        for index in range(10):
            left.record(5_000_000, index * SECOND)
        right.record(8_000_000, SECOND + 100)
        right.record(4_500_000, SECOND + 200)
        for index in range(2, 19):
            right.record(5_000_000 + (2_500_000 if index == 2 else 0), index * SECOND)
        result = report(left.snapshot(18 * SECOND, "finished"), right.snapshot(19 * SECOND, "finished"))
        self.assertEqual((result["received_bytes"], result["peak_mbps"], result["peak_direction"]), (150_000_000, 100, "inbound"))
        self.assertIsNone(report(None, None)["received_bytes"])
        last = right.snapshot(SECOND + 300, "connection_lost")
        self.assertEqual(last["peak_second_bytes"], 0)

    def test_recording_ignores_data_outside_time_window_and_cannot_exceed_budget(self):
        rng = random.Random(84251)
        for _ in range(120):
            measurements = sorted((rng.randrange(-SECOND, 3 * SECOND), rng.randrange(100)) for _ in range(20))
            budget = rng.randrange(1, 900)
            observation = Receipt(0, 2, budget)
            for at, amount in measurements:
                observation.record(amount, at)
            result = observation.snapshot(2 * SECOND, "finished")
            self.assertEqual(result["received_bytes"], min(budget, sum(x for at, x in measurements if 0 <= at < 2 * SECOND)))
            self.assertLessEqual(result["peak_second_bytes"], result["received_bytes"])

    def test_timed_tcp_payload_and_partial_byte_budget(self):
        for budget, reason in ((500_000, "finished"), (40_000, "byte_budget")):
            token = secrets.token_bytes(32)
            snapshots = []
            with open_receiver("127.0.0.1") as listener, ThreadPoolExecutor(max_workers=1) as pool:
                task = pool.submit(receive, listener, "127.0.0.2", token, 1, budget, snapshots.append)
                sent = send("127.0.0.2", "127.0.0.1", listener.getsockname()[1], token, 1, 200_000, budget)
                result = task.result(timeout=2)
            self.assertEqual(result["reason"], reason)
            self.assertLessEqual(result["received_bytes"], sent)
            self.assertEqual(snapshots[-1], result)
            if reason == "finished":
                self.assertEqual(result["elapsed_ns"], SECOND)
                self.assertGreater(result["received_bytes"], 140_000)
                self.assertEqual(result["peak_second_bytes"], result["received_bytes"])
            else:
                self.assertEqual(result["received_bytes"], budget)
                self.assertIsNone(result["peak_second_bytes"])
