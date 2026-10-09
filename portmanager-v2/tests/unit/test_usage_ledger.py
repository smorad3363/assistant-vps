"""Billing-conscious byte ledger: conservative bounds and reboot-safe deltas."""
import csv
import tempfile
import unittest
from pathlib import Path
from unittest import mock

from pm2 import history_collector, sampler, usage_ledger


class PortUsageTests(unittest.TestCase):
    def test_timezone_parse_and_invalid_clock(self):
        self.assertEqual(
            usage_ledger.parse_datetime("2026-10-10 03:30", "Asia/Tehran"),
            usage_ledger.parse_datetime("2026-10-10 00:00", "UTC"))
        from pm2.errors import PM2Error
        with self.assertRaises(PM2Error):
            usage_ledger.parse_datetime("2026-13-10 20:00", "UTC")
        with self.assertRaises(PM2Error):
            usage_ledger.parse_datetime("2026-10-10 20:00", "Nowhere/Zone")

    def test_only_complete_intervals_are_known_and_partials_bound(self):
        # Request 00:00:30-00:02:30; samples cross both endpoints.
        rows = [
            (0, 60, "auto", "tcp", 1001, 60, 120),
            (60, 120, "auto", "tcp", 1001, 200, 400),
            (120, 180, "auto", "tcp", 1001, 80, 160),
        ]
        items = usage_ledger.summarize(rows, 30, 150)
        self.assertEqual(len(items), 1)
        row = items[0]
        self.assertEqual(row["upload_bytes_lower"], 200)
        self.assertEqual(row["download_bytes_lower"], 400)
        self.assertEqual(row["upload_bytes_upper"], 340)
        self.assertEqual(row["download_bytes_upper"], 680)
        self.assertEqual(row["boundary_uncertain_bytes"], 420)
        self.assertEqual(row["missing_seconds"], 0)

    def test_missing_intervals_not_zero_and_no_fake_backfill(self):
        items = usage_ledger.summarize([
            (0, 60, "auto", "udp", 4343, 10, 20),
            (120, 180, "auto", "udp", 4343, 10, 20),
        ], 0, 180)
        self.assertEqual(items[0]["missing_seconds"], 60)
        self.assertEqual(items[0]["total_bytes_lower"], 60)

    def test_duplicate_auto_and_v2_counters_do_not_double_billing(self):
        rows = [(0, 60, "auto", "tcp", 8080, 40, 60),
                (0, 60, "aaaacccc-1111-4444-8888-0123456789ab",
                 "tcp", 8080, 35, 65)]
        items = usage_ledger.summarize(rows, 0, 60)
        self.assertEqual(items[0]["total_bytes_lower"], 100)
        self.assertTrue(items[0]["overlapping_sources"])
        self.assertEqual(len(items[0]["sources"]), 1)

    def test_legacy_combined_tcp_udp_port_is_reported(self):
        rows = [(0, 60, "v1", "all", 2083, 100, 220),
                (0, 60, "v1", "all", 0, 500000, 500000)]
        entries = usage_ledger.summarize(rows, 0, 60)
        self.assertEqual(len(entries), 1)
        self.assertEqual(entries[0]["protocol"], "all")
        self.assertEqual(entries[0]["port"], 2083)
        self.assertEqual(entries[0]["total_bytes_lower"], 320)

    def test_port_zero_aggregates_excluded(self):
        rows = [(0, 60, "v1", "all", 0, 100000, 200000),
                (0, 60, "auto", "tcp", 22, 10, 15)]
        result = usage_ledger.summarize(rows, 0, 60)
        self.assertEqual(len(result), 1)
        self.assertEqual(result[0]["port"], 22)

    def test_persistent_db_report_from_arbitrary_date_and_csv(self):
        with tempfile.TemporaryDirectory() as folder:
            with mock.patch.object(sampler, "DB", Path(folder) / "bytes.sqlite"):
                db = sampler.connect()
                start = usage_ledger.parse_datetime("2026-10-10 00:00", "UTC")
                with db:
                    usage_ledger.record(db, [
                        (start, start + 60, "auto", "tcp", 1001, 1000000000, 2000000000),
                        (start+60, start + 120, "auto", "tcp", 1001, 3000000000, 4000000000),
                    ])
                db.close()
                result = usage_ledger.report("2026-10-10 00:00",
                                             "2026-10-10 00:02", "UTC")
                self.assertEqual(result["intervals_read"], 2)
                self.assertEqual(result["ports"][0]["upload_bytes_lower"], 4000000000)
                self.assertEqual(result["ports"][0]["download_bytes_lower"], 6000000000)
                self.assertTrue(result["not_provider_billable"])
                data = list(csv.DictReader(usage_ledger.to_csv(result).splitlines()))
                self.assertEqual(data[0]["port"], "1001")
                self.assertEqual(data[0]["download_bytes_lower"], "6000000000")
                blank = usage_ledger.report("2026-10-09 10:00",
                                            "2026-10-09 11:00", "UTC")
                self.assertEqual(blank["ports"], [])
                self.assertIn("No recorded byte intervals", blank["warnings"][0])

    def test_reboot_baseline_requires_identical_boot_id(self):
        with tempfile.TemporaryDirectory() as folder:
            with mock.patch.object(sampler, "DB", Path(folder) / "bytes.sqlite"):
                db = sampler.connect()
                usage_ledger.init(db)
                self.assertFalse(usage_ledger.baseline_matches(db, "boot-a"))
                with db:
                    usage_ledger.remember_boot(db, "boot-a")
                self.assertTrue(usage_ledger.baseline_matches(db, "boot-a"))
                self.assertFalse(usage_ledger.baseline_matches(db, "boot-b"))
                db.close()

    def test_background_collector_can_track_more_than_24_ports(self):
        with (mock.patch.object(history_collector, "_tracked_elsewhere", return_value=set()),
              mock.patch.object(history_collector.system_rules, "detect_nat",
                                return_value=([], None)),
              mock.patch.object(history_collector.auto_monitor, "discover",
                                return_value=[("tcp", p) for p in range(1, 51)])
                                as discovery,
              mock.patch.object(history_collector.auto_monitor, "run",
                                return_value="")):
            result = history_collector._select_ports()
        self.assertEqual(len(result), 50)
        discovery.assert_called_once_with(existing=set(), limit=64)

    def test_stable_port_selection_avoids_reinstall_on_busy_rank_changes(self):
        with (mock.patch.object(history_collector, "_tracked_elsewhere", return_value=set()),
              mock.patch.object(history_collector.system_rules, "detect_nat",
                                return_value=([], None)),
              mock.patch.object(history_collector.auto_monitor, "discover",
                                return_value=[("tcp", p) for p in range(1, 25)])):
            chosen = history_collector._select_ports({("tcp", 24), ("tcp", 23)})
        self.assertEqual(len(chosen), 24)
        self.assertIn(("tcp", 24), chosen)
        self.assertIn(("tcp", 23), chosen)


if __name__ == "__main__":
    unittest.main()
