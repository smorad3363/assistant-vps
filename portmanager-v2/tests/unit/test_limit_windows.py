"""Deterministic weekday, overnight, timezone and conflict evaluation tests."""
from datetime import datetime, timezone
import json
import tempfile
import unittest
from pathlib import Path

from pm2 import limit_windows as win
from pm2.errors import PM2Error


def rule(**edits):
    template = {
        "id": "weekday", "port": 443, "protocol": "tcp,udp",
        "timezone": "UTC", "days": [0, 1, 2, 3, 4],
        "start": "18:00", "end": "02:00",
        "download_mbps": 20, "upload_mbps": 10, "enabled": True
    }
    template.update(edits)
    return template


def dt(iso):
    return datetime.fromisoformat(iso.replace("Z", "+00:00"))


class ScheduledLimitTests(unittest.TestCase):
    def test_weekday_overnight_crosses_midnight_and_next_day(self):
        policies = [rule()]
        win.validate(policies)
        monday_night = win.evaluate(policies, dt("2026-10-12T20:00:00Z"))
        tuesday_early = win.evaluate(policies, dt("2026-10-13T01:30:00Z"))
        tuesday_late = win.evaluate(policies, dt("2026-10-13T02:00:00Z"))
        saturday_early = win.evaluate(policies, dt("2026-10-17T01:00:00Z"))
        saturday_night = win.evaluate(policies, dt("2026-10-17T23:00:00Z"))
        self.assertEqual(len(monday_night["would_apply"]), 1)
        self.assertEqual(len(tuesday_early["would_apply"]), 1)
        self.assertEqual(tuesday_late["would_apply"], [])
        self.assertEqual(len(saturday_early["would_apply"]), 1)
        self.assertEqual(saturday_night["would_apply"], [])
        self.assertFalse(monday_night["network_mutation"])

    def test_week_wrapping_sunday_to_monday(self):
        p = [rule(days=[6], start="23:00", end="03:00")]
        self.assertEqual(len(win.evaluate(p, dt("2026-10-12T01:00:00Z"))["would_apply"]), 1)

    def test_overlapping_windows_rejected(self):
        a = rule(id="one", days=[0], start="18:00", end="23:00")
        b = rule(id="two", days=[0], start="22:59", end="23:59")
        with self.assertRaises(PM2Error) as err:
            win.validate([a, b])
        self.assertEqual(err.exception.code, "E_CONFLICT")

    def test_tcp_udp_nonoverlap_allowed(self):
        p = [rule(id="a", days=[0], protocol="tcp"),
             rule(id="b", days=[0], protocol="udp")]
        self.assertTrue(win.validate(p))

    def test_different_timezones_same_port_rejected(self):
        p = [rule(id="a", days=[0], protocol="tcp"),
             rule(id="b", days=[1], protocol="tcp", timezone="Europe/Berlin")]
        with self.assertRaises(PM2Error):
            win.validate(p)

    def test_equal_start_end_means_full_day(self):
        p = [rule(days=[0], start="00:00", end="00:00")]
        self.assertEqual(len(win.evaluate(p, dt("2026-10-12T23:58:00Z"))["would_apply"]), 1)
        self.assertEqual(win.evaluate(p, dt("2026-10-13T00:00:00Z"))["would_apply"], [])

    def test_invalid_clock_port_rate_and_days_rejected(self):
        for edited in ({"start": "24:00"}, {"port": 0},
                       {"upload_mbps": -1}, {"download_mbps": 1.2},
                       {"days": [1, 0]}, {"enabled": 1},
                       {"timezone": "../etc/passwd"}):
            with self.subTest(edited=edited):
                with self.assertRaises(PM2Error):
                    win.validate([rule(**edited)])

    def test_preview_file_validates_and_never_mutates(self):
        data = {"schema_version": 1, "policies": [rule()]}
        with tempfile.TemporaryDirectory() as folder:
            path = Path(folder) / "schedule.json"
            content = json.dumps(data)
            path.write_text(content)
            out = win.preview_json_file(path, "2026-10-12T20:00:00Z")
            self.assertEqual(len(out["would_apply"]), 1)
            self.assertEqual(path.read_text(), content)
            self.assertFalse(out["network_mutation"])
            with self.assertRaises(PM2Error):
                win.preview_json_file(path, "bad_timestamp")
            path.unlink()
            path.symlink_to(Path(folder) / "missing")
            with self.assertRaises(PM2Error):
                win.preview_json_file(path, "2026-10-12T20:00:00Z")

    def test_datetime_requires_timezone(self):
        with self.assertRaises(PM2Error):
            win.evaluate([rule()], datetime(2026, 10, 12, 20, 0))

    def test_daylight_saving_forward_missing_hour_not_fabricated(self):
        # 2026-03-29 02:00 Europe/Berlin jumps to 03:00.
        p = [rule(days=[6], start="02:00", end="03:30", timezone="Europe/Berlin")]
        self.assertEqual(win.evaluate(p, dt("2026-03-29T01:00:00Z"))["would_apply"][0]["port"], 443)
        self.assertEqual(win.evaluate(p, dt("2026-03-29T01:30:00Z"))["would_apply"], [])


if __name__ == "__main__":
    unittest.main()
