"""Background history must retain accurate per-port windows after Live exits."""
import tempfile
import unittest
from pathlib import Path
from unittest import mock

from pm2 import accounting, history_collector, port_graph, sampler


class HistoryCollectorTests(unittest.TestCase):
    def test_hist_rules_are_exact_owned_counter_only(self):
        rule = ("-A PM2_HIST_RX -p tcp -m tcp -m conntrack "
                "--ctdir ORIGINAL --ctorigdstport 443 "
                "-m comment --comment pm2hist:tcp:443:down")
        self.assertEqual(history_collector._rule_ports(
            rule, "PM2_HIST_RX", "down"), ("tcp", 443))
        self.assertIsNone(history_collector._rule_ports(
            rule + " -j DROP", "PM2_HIST_RX", "down"))

    def test_parser_ignores_background_rules_unless_requested(self):
        raw = ("[1:1200] -A PM2_HIST_RX -p tcp --ctorigdstport 443 "
               "-m comment --comment pm2hist:tcp:443:down\n"
               "[1:400] -A PM2_HIST_TX -p tcp --ctorigdstport 443 "
               "-m comment --comment pm2hist:tcp:443:up")
        self.assertEqual(accounting.parse_counters(raw, by_port=True), {})
        result = accounting.parse_counters(raw, by_port=True, include_history=True)
        self.assertEqual(result[("auto", "tcp", "down", 443)], 1200)
        self.assertEqual(result[("auto", "tcp", "up", 443)], 400)

    def test_external_dnat_ports_are_counted_without_local_listener(self):
        foreign = [
            {"target": "DNAT", "protocol": "tcp", "port": "8080"},
            {"target": "DNAT", "protocol": "udp", "port": "4343"},
            {"target": "SNAT", "protocol": "tcp", "port": "8080"},
        ]
        with (mock.patch.object(history_collector, "_tracked_elsewhere", return_value=set()),
              mock.patch.object(history_collector.system_rules, "detect_nat",
                                return_value=(foreign, None)),
              mock.patch.object(history_collector.auto_monitor, "discover",
                                return_value=[("tcp", 5555)]),
              mock.patch.object(history_collector.auto_monitor, "run",
                                return_value="")):
            selected = history_collector._select_ports()
        self.assertEqual(selected, {("tcp", 8080), ("udp", 4343), ("tcp", 5555)})

    def test_minute_samples_survive_viewer_exit_and_skip_offline_gaps(self):
        ports = {("tcp", 443)}
        inspected = ([("PREROUTING", "PM2_HIST_RX", True, True),
                      ("POSTROUTING", "PM2_HIST_TX", True, True)], ports)
        data = [
            {("auto", "tcp", 443, "up"): 100, ("auto", "tcp", 443, "down"): 100},
            {("auto", "tcp", 443, "up"): 60100, ("auto", "tcp", 443, "down"): 120100},
            {("auto", "tcp", 443, "up"): 90000, ("auto", "tcp", 443, "down"): 160000},
        ]
        with tempfile.TemporaryDirectory() as folder:
            with (mock.patch.object(sampler, "DB", Path(folder) / "traffic.sqlite3"),
                  mock.patch.object(history_collector.os, "geteuid", return_value=0),
                  mock.patch.object(history_collector, "_inspect", return_value=inspected),
                  mock.patch.object(history_collector, "_history_counters", side_effect=data),
                  mock.patch.object(history_collector, "_tracked_elsewhere", return_value=set()),
                  mock.patch.object(history_collector.system_rules, "detect_nat",
                                    return_value=([], None)),
                  mock.patch.object(history_collector, "_select_ports", return_value=ports),
                  mock.patch.object(history_collector.usage_ledger, "boot_id",
                                    return_value="11111111-1111-4111-8111-111111111111"),
                  mock.patch.object(history_collector, "_install") as install):
                first = history_collector.collect(timestamp=1000)
                second = history_collector.collect(timestamp=1060)
                third = history_collector.collect(timestamp=1400)
                install.assert_not_called()
            self.assertEqual(first["samples_written"], 0)
            self.assertEqual(second["samples_written"], 1)
            self.assertEqual(third["samples_written"], 0)  # 340s downtime
            with mock.patch.object(sampler, "DB", Path(folder) / "traffic.sqlite3"):
                db = sampler.connect()
            try:
                labels = {("auto", "tcp", 443): "test port"}
                rows = port_graph.history(db, 1400, labels)[("auto", "tcp", 443)]
                self.assertEqual(len(rows), 1)
                self.assertEqual(rows[0][1], 60)
                self.assertAlmostEqual(rows[0][2], 0.008)
                self.assertAlmostEqual(rows[0][3], 0.016)
            finally:
                db.close()


    def test_sampler_writes_exact_kernel_byte_deltas_to_ledger(self):
        ports = {("tcp", 8080)}
        inspected = ([("PREROUTING", "PM2_HIST_RX", True, True),
                      ("POSTROUTING", "PM2_HIST_TX", True, True)], ports)
        states = [
            {("auto", "tcp", 8080, "up"): 10000,
             ("auto", "tcp", 8080, "down"): 20000},
            {("auto", "tcp", 8080, "up"): 110000,
             ("auto", "tcp", 8080, "down"): 220000}
        ]
        with tempfile.TemporaryDirectory() as folder:
            with (mock.patch.object(sampler, "DB", Path(folder) / "traffic.sqlite3"),
                  mock.patch.object(history_collector.os, "geteuid", return_value=0),
                  mock.patch.object(history_collector.usage_ledger, "boot_id",
                                    return_value="11111111-1111-4111-8111-111111111111"),
                  mock.patch.object(history_collector, "_inspect", return_value=inspected),
                  mock.patch.object(history_collector, "_history_counters", side_effect=states),
                  mock.patch.object(history_collector, "_select_ports", return_value=ports),
                  mock.patch.object(history_collector, "_install") as install):
                now = 1791588300
                first = history_collector.collect(timestamp=now)
                second = history_collector.collect(timestamp=now + 60)
                install.assert_not_called()
                self.assertEqual(first["byte_intervals_written"], 0)
                self.assertEqual(second["byte_intervals_written"], 1)
                db = sampler.connect()
                row = db.execute(
                    "SELECT upload_bytes, download_bytes, start_utc, end_utc "
                    "FROM pm2_port_byte_intervals").fetchone()
                self.assertEqual(row[:2], (100000, 200000))
                self.assertEqual(row[2:], (now, now + 60))
                db.close()


if __name__ == "__main__":
    unittest.main()
