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
                  mock.patch.object(history_collector.auto_monitor, "discover",
                                    return_value=list(ports)),
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


if __name__ == "__main__":
    unittest.main()
