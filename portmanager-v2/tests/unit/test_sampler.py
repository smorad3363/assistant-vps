"""SQLite coverage, counter resets and zero-coverage reports."""
import tempfile
import unittest
from pathlib import Path
from unittest import mock

from pm2 import sampler, backup


class SamplerTests(unittest.TestCase):
    def setUp(self):
        tmp = tempfile.TemporaryDirectory()
        self.addCleanup(tmp.cleanup)
        self.base = Path(tmp.name)
        for module, name, value in (
            (sampler, "DB", self.base / "traffic.sqlite3"),
            (sampler, "CONFIG", self.base / "config.json"),
        ):
            patch = mock.patch.object(module, name, value)
            patch.start()
            self.addCleanup(patch.stop)
        (self.base / "config.json").write_text(
            '{"generation":0,"schema_version":1,"tunnels":[]}')

    def test_no_database_returns_nullable_rates(self):
        report = sampler.report("1h")
        self.assertEqual(report["coverage_seconds"], 0)
        self.assertIsNone(report["upload_mbps"])

    def test_old_tunnel_traffic_samples_expire_after_fourteen_days(self):
        ident = "77cafed5-c41d-4107-a18e-ef9cda90cb5e"
        old = 1_000_000
        now = old + 14 * 86400 + 120
        with mock.patch.object(sampler.os, "geteuid", return_value=0):
            sampler.sample(old, {(ident, "tcp", "up"): 100})
            sampler.sample(now, {(ident, "tcp", "up"): 1000})
        db = sampler.connect()
        try:
            rows = db.execute(
                "SELECT timestamp_utc FROM samples ORDER BY timestamp_utc"
            ).fetchall()
            self.assertEqual(rows, [(now,)])
            baseline = db.execute(
                "SELECT last_time FROM samples_latest WHERE tunnel_id=?",
                (ident,)).fetchone()
            self.assertEqual(baseline[0], now)
        finally:
            db.close()

    def test_accumulate_and_epoch_reset_without_negative_spike(self):
        id = "77cafed5-c41d-4107-a18e-ef9cda90cb5e"
        with mock.patch.object(sampler.os, "geteuid", return_value=0):
            sampler.sample(100, {(id, "tcp", "up"): 150, (id, "tcp", "down"): 110})
            sampler.sample(110, {(id, "tcp", "up"): 350, (id, "tcp", "down"): 310})
            sampler.sample(120, {(id, "tcp", "up"): 10, (id, "tcp", "down"): 7})
        db = sampler.connect()
        try:
            rows = db.execute(
                "SELECT direction,delta_bytes,counter_epoch FROM samples "
                "WHERE timestamp_utc=120").fetchall()
        finally:
            db.close()
        self.assertEqual({row[1] for row in rows}, {0})
        self.assertEqual({row[2] for row in rows}, {1})
        with mock.patch.object(sampler.time, "time", return_value=122):
            report = sampler.report("1h")
        self.assertEqual(report["upload_bytes"], 200)
        self.assertEqual(report["download_bytes"], 200)
        self.assertGreater(report["coverage_seconds"], 0)


if __name__ == "__main__":
    unittest.main()
