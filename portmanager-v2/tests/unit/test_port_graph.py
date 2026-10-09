"""Live 10-minute per-port graph: performance, counters, JSON and visualization."""
import io
import json
import tempfile
import time
import unittest
from pathlib import Path
from unittest import mock

from pm2 import accounting, port_graph, sampler


TID = "aaaacccc-1111-4444-8888-0123456789ab"


class PortGraphTests(unittest.TestCase):
    def test_single_snapshot_decodes_distinct_original_ports(self):
        raw = """
* mangle
[3:3000] -A PM2_ACCOUNT -p tcp -m conntrack --ctorigdstport 443 --ctdir ORIGINAL -m comment --comment pm2:aaaacccc-1111-4444-8888-0123456789ab:up
[4:5000] -A PM2_ACCOUNT -p tcp -m conntrack --ctorigdstport 443 --ctdir REPLY -m comment --comment pm2:aaaacccc-1111-4444-8888-0123456789ab:down
[7:7000] -A PM2_ACCOUNT -p udp -m conntrack --ctorigdstport 2053 --ctdir ORIGINAL -m comment --comment pm2:aaaacccc-1111-4444-8888-0123456789ab:up
[2:200] -A PM2_ACCOUNT -p tcp -m comment --comment pm2:aaaacccc-1111-4444-8888-0123456789ab:up
[1:55555] -A FOREIGN -m comment --comment pm2:aaaacccc-1111-4444-8888-0123456789ab:up
COMMIT
"""
        keyed = accounting.parse_counters(raw, by_port=True)
        self.assertEqual(keyed[(TID, "tcp", "up", 443)], 3000)
        self.assertEqual(keyed[(TID, "tcp", "down", 443)], 5000)
        self.assertEqual(keyed[(TID, "udp", "up", 2053)], 7000)
        self.assertEqual(keyed[(TID, "tcp", "up", None)], 200)
        aggregated = accounting.parse_counters(raw)
        self.assertEqual(aggregated[(TID, "tcp", "up")], 3200)
        self.assertEqual(len(keyed), 4)

    def test_v1_monitored_ports_visible_without_v1_mutation(self):
        raw = (
            '[5:1000] -A PORTMANAGER_ACCT -p tcp -m comment --comment pm-ul:443\n'
            '[7:2100] -A PORTMANAGER_ACCT -p tcp -m comment --comment pm-dl:443\n'
            '[3:1200] -A PORTMANAGER_ACCT -m comment --comment pm-ul:2083\n'
        )
        counters = accounting.parse_counters(raw, by_port=True, include_v1=True)
        self.assertEqual(counters[("v1", "tcp", "up", 443)], 1000)
        self.assertEqual(counters[("v1", "tcp", "down", 443)], 2100)
        self.assertEqual(counters[("v1", "all", "up", 2083)], 1200)
        self.assertEqual(accounting.parse_counters(raw, by_port=True), {})
        labels = port_graph.add_v1_labels({}, counters)
        self.assertEqual(labels[("v1", "tcp", 443)], "V1 monitored")
        self.assertEqual(port_graph.add_v1_labels({}, counters, "some-other-tunnel"), {})
        baseline = {k: v - 100 for k, v in counters.items()}
        rates = port_graph.deltas(baseline, counters, 2.0, labels)
        self.assertGreater(rates[("v1", "tcp", 443)]["up"], 0)

    def test_counter_reset_and_first_seen_never_spike(self):
        label = {(TID, "tcp", 443): "mytunnel"}
        key = (TID, "tcp", "up", 443)
        result = port_graph.deltas({key: 12345}, {key: 100}, 2, label)
        self.assertEqual(result[(TID, "tcp", 443)]["up"], 0)
        new = port_graph.deltas({}, {key: 20000}, 2, label)
        self.assertEqual(new[(TID, "tcp", 443)]["up"], 0)
        good = port_graph.deltas({key: 10000}, {key: 110000}, 2, label)
        self.assertAlmostEqual(good[(TID, "tcp", 443)]["up"], 0.4)

    def test_weighted_10min_includes_partial_boundary(self):
        now = 1000
        history = [(390, 100, 5, 2), (700, 100, 10, 4),
                   (900, 100, 20, 6), (1000, 100, 40, 8)]
        avg = port_graph.weighted(history, now)
        # Last 600s are [400..1000], first row ended 390 and is excluded.
        self.assertAlmostEqual(avg["up"], (10+20+40) / 3)
        self.assertEqual(avg["coverage"], 300)
        self.assertTrue(avg["down"] > 0)

    def test_historical_rolling_average_does_not_look_ahead(self):
        # At t=500, a sample whose end time is 550 did not exist yet.
        history = [(490, 10, 4.0, 6.0), (550, 100, 100.0, 200.0)]
        avg = port_graph.weighted(history, 500)
        self.assertEqual(avg["coverage"], 10)
        self.assertEqual(avg["up"], 4.0)
        self.assertEqual(avg["down"], 6.0)

    def test_no_false_ten_minute_coverage_when_just_started(self):
        avg = port_graph.weighted([(103, 3, 10, 20)], 103)
        self.assertEqual(avg["coverage"], 3)
        self.assertEqual(avg["up"], 10)
        self.assertEqual(port_graph.weighted([], 103)["up"], None)

    def test_sparkline_gaps_and_10min(self):
        graph = port_graph.sparkline([(600, 10, 1, 0)], 600, "up", buckets=12)
        self.assertEqual(len(graph), 12)
        self.assertIn(" ", graph)
        self.assertTrue(graph.endswith("▇") or graph.endswith("█"))

    def test_sparkline_is_of_rolling_ten_minute_means(self):
        # At t=1000 the mean includes 10-minute tail; earlier points show
        # a different mean, which distinguishes a moving-average graph from
        # a chart of raw 25-second instant rates.
        points = [(400, 100, 2.0, 4.0), (650, 100, 2.0, 4.0),
                  (900, 100, 20.0, 40.0), (1000, 100, 20.0, 40.0)]
        trace = port_graph.sparkline(points, 1000, "up", buckets=12)
        self.assertEqual(len(trace), 12)
        self.assertNotEqual(trace[0], trace[-1])
        self.assertNotEqual(trace[-1], " ")

    def test_zero_ports_hidden_unless_all(self):
        labels = {(TID, "tcp", 443): "up",
                  (TID, "udp", 2053): "idle"}
        histories = {(TID, "tcp", 443): [(100, 2, 1.0, 0.0)]}
        only = port_graph.frame(labels, {}, histories, 100)
        self.assertEqual(len(only["rows"]), 1)
        self.assertEqual(only["rows"][0]["listen_port"], 443)
        both = port_graph.frame(labels, {}, histories, 100, active_only=False)
        self.assertEqual(len(both["rows"]), 2)

    def test_all_except_has_explicit_aggregate_scope(self):
        labels = {(TID, "tcp", 0): "all"}
        frames = port_graph.frame(
            labels, {}, {(TID, "tcp", 0): [(100, 2, 2, 2)]}, 100)
        self.assertEqual(frames["rows"][0]["scope"], "all_except_aggregate")
        self.assertIsNone(frames["rows"][0]["listen_port"])

    def test_refresh_adapts_to_large_ruleset_and_slow_iptable_reads(self):
        self.assertEqual(port_graph.refresh_interval(2, 10, 0.01), 2)
        self.assertEqual(port_graph.refresh_interval(2, 500, 0.01), 5)
        self.assertEqual(port_graph.refresh_interval(2, 1500, 0.01), 10)
        self.assertEqual(port_graph.refresh_interval(2, 20, 2), 10)
        with self.assertRaises(Exception):
            port_graph.refresh_interval(1, 10, 0)

    def test_sqlite_bounded_history_and_reopen(self):
        with tempfile.TemporaryDirectory() as tmp:
            filename = Path(tmp) / "traffic.sqlite3"
            with mock.patch.object(sampler, "DB", filename):
                db = sampler.connect()
                key = (TID, "tcp", 443)
                port_graph.record(db, 100, 2, {key: {"up": 1, "down": 3}})
                port_graph.record(db, 2500, 2, {key: {"up": 4, "down": 6}})
                db.close()
                reopened = sampler.connect()
                series = port_graph.history(reopened, 2500, {key: "edge"})
                self.assertEqual(len(series[key]), 1)
                self.assertAlmostEqual(series[key][0][2], 4)
                reopened.close()

    def test_watch_once_json_single_read_per_tick(self):
        with tempfile.TemporaryDirectory() as tmp:
            p = Path(tmp)
            (p / "config.json").write_text(json.dumps({
                "schema_version": 1, "generation": 0,
                "tunnels": [{
                    "id": TID, "name": "A", "enabled": True,
                    "mode": "ports", "listen_ip": "192.0.2.2",
                    "target_ip": "192.0.2.3", "interface": "eth0",
                    "protocols": ["tcp"], "mapping": [{"listen_port": 443,
                                                         "target_port": 8443}],
                    "exclude": []
                }]}))
            with (mock.patch.object(port_graph.transaction, "CONFIG", p / "config.json"),
                  mock.patch.object(sampler, "DB", p / "traffic.sqlite3"),
                  mock.patch.object(port_graph.os, "geteuid", return_value=0),
                  mock.patch.object(port_graph.time, "sleep", return_value=None),
                  mock.patch.object(port_graph.accounting, "counters", side_effect=[
                      {(TID, "tcp", "up", 443): 10},
                      {(TID, "tcp", "up", 443): 125010},
                  ]) as counted):
                from contextlib import redirect_stdout
                output = io.StringIO()
                with redirect_stdout(output):
                    rc = port_graph.watch(refresh=2, once=True, json_mode=True)
            self.assertEqual(rc, 0)
            self.assertEqual(counted.call_count, 2)
            parsed = json.loads(output.getvalue())
            self.assertEqual(parsed["window_seconds"], 600)
            self.assertGreater(parsed["rows"][0]["now_up_mbps"], 0)
            self.assertTrue(parsed["refresh_is_read_only"])


if __name__ == "__main__":
    unittest.main()
