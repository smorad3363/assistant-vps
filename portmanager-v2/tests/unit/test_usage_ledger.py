"""Billing-conscious byte ledger: conservative bounds and reboot-safe deltas."""
import csv
import tempfile
import unittest
from pathlib import Path
from unittest import mock

from pm2 import history_collector, sampler, usage_ledger


class PortUsageTests(unittest.TestCase):
    def test_live_volume_windows_count_recorded_bytes_not_mbps(self):
        with tempfile.TemporaryDirectory() as folder:
            with mock.patch.object(sampler, "DB", Path(folder) / "traffic.sqlite3"):
                db = sampler.connect()
                now = 2_000_000_000.0
                with db:
                    usage_ledger.record(db, [
                        (now-300,now-240,"auto","tcp",8080,400_000_000,600_000_000),
                        (now-240,now-180,"auto","tcp",8080,200_000_000,300_000_000),
                        (now-7200,now-7140,"auto","tcp",8080,100_000_000,100_000_000),
                        (now-600,now-540,"auto","udp",4343,25_000_000,75_000_000),
                        (now-300,now-240,"v1","tcp",8080,400_000_000,600_000_000)
                    ])
                windows = usage_ledger.live_window_volumes(db, now)
                first = windows[("tcp",8080)]
                self.assertEqual(first["10m"]["bytes"], 1_500_000_000)
                self.assertEqual(first["1h"]["bytes"], 1_500_000_000)
                self.assertEqual(first["8h"]["bytes"], 1_700_000_000)
                self.assertEqual(first["24h"]["bytes"], 1_700_000_000)
                self.assertEqual(windows[("udp",4343)]["10m"]["bytes"], 100_000_000)
                self.assertLess(first["10m"]["coverage_seconds"], 600)
                self.assertEqual(first["10m"]["possible_bytes"], 1_500_000_000)
                db.close()

    def test_live_volume_partial_boundary_never_invents_byte_fraction(self):
        with tempfile.TemporaryDirectory() as folder:
            with mock.patch.object(sampler, "DB", Path(folder) / "traffic.sqlite3"):
                db = sampler.connect()
                now = 2_000_000_000.0
                with db:
                    usage_ledger.record(db, [
                        (now-620,now-570,"auto","tcp",1001,300,700)
                    ])
                volumes = usage_ledger.live_window_volumes(
                    db, now, periods={"10m":600})
                partial = volumes[("tcp",1001)]["10m"]
                self.assertEqual(partial["bytes"], 0)
                self.assertEqual(partial["possible_bytes"], 1000)
                self.assertEqual(partial["coverage_seconds"], 30)
                db.close()

    def test_real_nic_rx_tx_totals_are_independent_from_ports(self):
        with tempfile.TemporaryDirectory() as folder:
            with mock.patch.object(sampler, "DB", Path(folder) / "traffic.sqlite3"):
                db = sampler.connect()
                start = usage_ledger.parse_datetime("2026-10-10 00:00", "UTC")
                with db:
                    usage_ledger.record(db, [
                        (start, start + 60, "auto", "tcp", 8080, 7_000, 9_000),
                        (start, start + 60, "auto", "tcp", 1001, 7_000, 9_000)
                    ])
                    self.assertEqual(usage_ledger.record_interfaces(
                        db, {"eth0": (1_000, 2_000), "docker0": (100, 200)},
                        start, False), 0)
                    self.assertEqual(usage_ledger.record_interfaces(
                        db, {"eth0": (9_000, 14_000), "docker0": (2_100, 4_200)},
                        start+60, True), 2)
                db.close()
                result = usage_ledger.report(
                    "2026-10-10 00:00", "2026-10-10 00:01", "UTC")
                self.assertEqual(result["server"]["interface"], "eth0")
                self.assertEqual(result["server"]["download_bytes_lower"], 8_000)
                self.assertEqual(result["server"]["upload_bytes_lower"], 12_000)
                # Port counters deliberately overlap, so never mistake their
                # addition for independent physical NIC consumption.
                self.assertEqual(result["monitored_port_sum"]["download_bytes_lower"], 18_000)
                self.assertEqual(result["monitored_port_sum"]["upload_bytes_lower"], 14_000)
                self.assertEqual(result["daily"][0]["server"]["download_bytes_lower"], 8_000)

    def test_nic_reboot_and_counter_reset_never_create_false_usage(self):
        with tempfile.TemporaryDirectory() as folder:
            with mock.patch.object(sampler, "DB", Path(folder) / "traffic.sqlite3"):
                db = sampler.connect()
                with db:
                    self.assertEqual(usage_ledger.record_interfaces(
                        db, {"eth0": (1_000, 1_000)}, 1_000, False), 0)
                    self.assertEqual(usage_ledger.record_interfaces(
                        db, {"eth0": (2_000, 3_000)}, 1_060, True), 1)
                    self.assertEqual(usage_ledger.record_interfaces(
                        db, {"eth0": (100, 100)}, 1_120, True), 0)
                    self.assertEqual(usage_ledger.record_interfaces(
                        db, {"eth0": (10_000, 10_000)}, 1_180, False), 0)
                    self.assertEqual(usage_ledger.record_interfaces(
                        db, {"eth0": (11_000, 13_000)}, 1_240, True), 1)
                rows = db.execute(
                    "SELECT download_bytes, upload_bytes "
                    "FROM pm2_nic_byte_intervals ORDER BY end_utc").fetchall()
                self.assertEqual(rows, [(1_000, 2_000), (1_000, 3_000)])
                db.close()

    def test_no_combined_nic_sum_and_missing_history_remains_unknown(self):
        self.assertEqual(usage_ledger.choose_server_interface(
            ["eth0", "docker0"]), "eth0")
        self.assertEqual(usage_ledger.choose_server_interface(
            ["eth0", "ens18", "docker0"]), "eth0")
        self.assertEqual(usage_ledger.choose_server_interface(
            ["docker0", "vethabc"]), None)
        empty = usage_ledger.network_totals([], 0, 86400)
        self.assertFalse(empty["has_samples"])
        self.assertEqual(empty["missing_seconds"], 86400)
        partial = usage_ledger.network_totals(
            [(0, 60, 1000, 3000)], 30, 120)
        self.assertEqual(partial["download_bytes_lower"], 0)
        self.assertEqual(partial["download_bytes_upper"], 3000)
        self.assertEqual(partial["upload_bytes_upper"], 1000)
        self.assertEqual(partial["missing_seconds"], 60)

    def test_nic_history_expires_with_port_rows(self):
        with tempfile.TemporaryDirectory() as folder:
            with mock.patch.object(sampler, "DB", Path(folder) / "traffic.sqlite3"):
                db = sampler.connect()
                start = 2_000_000_000.0
                with db:
                    usage_ledger.record_interfaces(
                        db, {"eth0": (100, 200)}, start-15*86400-60, False)
                    usage_ledger.record_interfaces(
                        db, {"eth0": (200, 300)}, start-15*86400, True)
                    usage_ledger.record_interfaces(
                        db, {"eth0": (300, 400)}, start-60, True)
                    usage_ledger.record_interfaces(
                        db, {"eth0": (400, 500)}, start, True)
                    usage_ledger.prune(db, start)
                rows = db.execute(
                    "SELECT end_utc FROM pm2_nic_byte_intervals").fetchall()
                self.assertEqual(rows, [(start,)])
                db.close()

    def test_daily_download_and_upload_are_separate_in_local_timezone(self):
        tz = "Asia/Tehran"
        start = usage_ledger.parse_datetime("2026-10-10 00:00", tz)
        end = usage_ledger.parse_datetime("2026-10-12 00:00", tz)
        rows = [
            (start + 60, start + 120, "auto", "tcp", 8080,
             1_000_000_000, 3_000_000_000),
            (start + 86400 + 60, start + 86400 + 120, "auto", "tcp",
             8080, 2_000_000_000, 4_000_000_000),
            (start + 60, start + 120, "auto", "udp", 4343, 500, 900)
        ]
        days = usage_ledger.daily_breakdown(rows, start, end, tz)
        self.assertEqual([day["date"] for day in days],
                         ["2026-10-10", "2026-10-11"])
        first = next(p for p in days[0]["ports"] if p["port"] == 8080)
        second = next(p for p in days[1]["ports"] if p["port"] == 8080)
        self.assertEqual(first["upload_bytes_lower"], 1_000_000_000)
        self.assertEqual(first["download_bytes_lower"], 3_000_000_000)
        self.assertEqual(second["upload_bytes_lower"], 2_000_000_000)
        self.assertEqual(second["download_bytes_lower"], 4_000_000_000)
        self.assertTrue(any(p["port"] == 4343 for p in days[0]["ports"]))
        self.assertFalse(any(p["port"] == 4343 for p in days[1]["ports"]))

    def test_midnight_crossing_bytes_are_uncertain_not_divided_or_double_verified(self):
        tz = "Asia/Tehran"
        midnight = usage_ledger.parse_datetime("2026-10-11 00:00", tz)
        days = usage_ledger.daily_breakdown([
            (midnight - 30, midnight + 30, "auto", "tcp",
             1001, 1_000, 3_000)
        ], midnight - 60, midnight + 60, tz)
        self.assertEqual(len(days), 2)
        for day in days:
            port = day["ports"][0]
            self.assertEqual(port["download_bytes_lower"], 0)
            self.assertEqual(port["upload_bytes_lower"], 0)
            self.assertEqual(port["download_bytes_upper"], 3_000)
            self.assertEqual(port["upload_bytes_upper"], 1_000)
            self.assertEqual(port["boundary_uncertain_bytes"], 4_000)
            self.assertEqual(port["missing_seconds"], 30)

    def test_daily_explicit_no_samples_is_not_reported_as_zero(self):
        start = usage_ledger.parse_datetime("2026-10-10 00:00", "UTC")
        days = usage_ledger.daily_breakdown([
            (start + 60, start + 120, "auto", "tcp", 1001, 1, 1),
        ], start, start + 2 * 86400, "UTC")
        self.assertTrue(days[0]["has_samples"])
        self.assertFalse(days[1]["has_samples"])
        self.assertEqual(days[1]["ports"], [])
        result = {"from": "2026-10-10 00:00", "to": "2026-10-12 00:00",
                  "timezone": "UTC", "daily": days}
        parsed = list(csv.DictReader(usage_ledger.to_daily_csv(result).splitlines()))
        self.assertEqual(len(parsed), 2)
        self.assertEqual(parsed[0]["upload_bytes_lower"], "1")
        self.assertEqual(parsed[0]["download_bytes_lower"], "1")
        self.assertEqual(parsed[1]["date"], "2026-10-11")
        self.assertEqual(parsed[1]["has_samples"], "False")
        self.assertEqual(parsed[1]["download_bytes_lower"], "")
        self.assertIn("NO SAMPLES", usage_ledger.pretty_daily(result))

    def test_local_dst_day_can_have_23_or_25_hours(self):
        for date, expected in (("2026-03-08", 23), ("2026-11-01", 25)):
            start = usage_ledger.parse_datetime(
                f"{date} 00:00", "America/New_York")
            end_day = "2026-03-09" if expected == 23 else "2026-11-02"
            end = usage_ledger.parse_datetime(
                f"{end_day} 00:00", "America/New_York")
            day = usage_ledger.daily_breakdown(
                [], start, end, "America/New_York")
            self.assertEqual(len(day), 1)
            self.assertEqual(day[0]["period_seconds"], expected * 3600)

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

    def test_fourteen_day_retention_prunes_only_expired_byte_intervals(self):
        with tempfile.TemporaryDirectory() as folder:
            with mock.patch.object(sampler, "DB", Path(folder) / "traffic.sqlite3"):
                db = sampler.connect()
                now = 2_000_000_000.0
                cutoff = now - usage_ledger.RETENTION_SECONDS
                with db:
                    usage_ledger.record(db, [
                        (cutoff - 120, cutoff - 60, "auto", "tcp", 1001, 11, 12),
                        (cutoff - 60, cutoff, "auto", "tcp", 1001, 21, 22),
                        (cutoff, cutoff + 60, "auto", "tcp", 1001, 31, 32),
                        (now - 60, now, "auto", "tcp", 1001, 41, 42),
                    ])
                    self.assertEqual(usage_ledger.prune(db, now), 2)
                    self.assertEqual(usage_ledger.prune(db, now), 0)
                rows = db.execute(
                    "SELECT upload_bytes FROM pm2_port_byte_intervals "
                    "ORDER BY end_utc").fetchall()
                self.assertEqual(rows, [(31,), (41,)])
                self.assertEqual(usage_ledger.RETENTION_DAYS, 14)
                db.close()

    def test_report_exposes_available_history_when_requested_time_is_empty(self):
        with tempfile.TemporaryDirectory() as folder:
            with mock.patch.object(sampler, "DB", Path(folder) / "traffic.sqlite3"):
                db = sampler.connect()
                stamp = usage_ledger.parse_datetime("2026-10-10 02:00", "UTC")
                with db:
                    usage_ledger.record(db, [
                        (stamp, stamp + 60, "auto", "tcp", 4343, 1024, 1024)
                    ])
                db.close()
                empty = usage_ledger.report(
                    "2026-10-10 00:00", "2026-10-10 00:30", "UTC")
                self.assertEqual(empty["ports"], [])
                self.assertEqual(empty["first_recorded_utc"], stamp)
                self.assertEqual(empty["latest_recorded_utc"], stamp + 60)
                self.assertEqual(empty["retention_days"], 14)
                self.assertIn("Recorded data exists outside", empty["warnings"][1])

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
                self.assertEqual(result["daily"][0]["date"], "2026-10-10")
                self.assertEqual(result["daily"][0]["ports"][0]["upload_bytes_lower"], 4000000000)
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
