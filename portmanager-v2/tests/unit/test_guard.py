"""120s guard: schedule BEFORE apply, fail closed, confirm and rollback IDs."""
import tempfile
import time
import unittest
from pathlib import Path
from unittest import mock

from pm2 import guard
from pm2.errors import PM2Error


class GuardTests(unittest.TestCase):
    def setUp(self):
        temp = tempfile.TemporaryDirectory()
        self.addCleanup(temp.cleanup)
        self.protected = Path(temp.name) / "protected.json"
        patch = mock.patch.object(guard, "PROTECTED", self.protected)
        patch.start()
        self.addCleanup(patch.stop)
        self.old = {"generation": 0, "schema_version": 1, "tunnels": []}
        self.new = {"generation": 1, "schema_version": 1, "tunnels": []}
        self.runtime = {"firewall": {}, "applied_generation": 0}

    def test_guard_rejects_duplicate_protection(self):
        guard.config.atomic_json(self.protected, {
            "product": "portmanager2", "change_id": "invalid",
            "original_config": self.old, "original_state": self.runtime,
            "expires_at": time.time() + 120, "desired_generation": 1
        })
        with mock.patch.object(guard.os, "geteuid", return_value=0):
            with self.assertRaises(PM2Error):
                guard.apply(self.new)

    def test_schedule_failure_never_applies_rules(self):
        with (mock.patch.object(guard.os, "geteuid", return_value=0),
              mock.patch.object(guard.transaction, "state", return_value=(self.old, self.runtime)),
              mock.patch.object(guard.transaction, "preflight"),
              mock.patch.object(guard, "_schedule", side_effect=PM2Error("E_APPLY", "timer unavailable")),
              mock.patch.object(guard.transaction, "apply") as apply):
            with self.assertRaises(PM2Error):
                guard.apply(self.new)
            apply.assert_not_called()
        self.assertFalse(self.protected.exists())

    def test_timer_armed_before_apply(self):
        def apply_after_timer(*_args, **_kwargs):
            self.assertTrue(self.protected.is_file())
            return {"changed": True, "generation": 1}
        with (mock.patch.object(guard.os, "geteuid", return_value=0),
              mock.patch.object(guard.transaction, "state", return_value=(self.old, self.runtime)),
              mock.patch.object(guard.transaction, "preflight"),
              mock.patch.object(guard, "_schedule") as schedule,
              mock.patch.object(guard.transaction, "apply", side_effect=apply_after_timer)):
            outcome = guard.apply(self.new)
            schedule.assert_called_once()
        self.assertIn("pending_confirmation", outcome)
        self.assertEqual(outcome["rollback_after_seconds"], 120)

    def test_confirmation_refuses_wrong_id_without_cancel(self):
        with mock.patch.object(guard.os, "geteuid", return_value=0), mock.patch.object(
                guard, "_cancel") as cancel:
            with self.assertRaises(PM2Error):
                guard.confirm("00000000-0000-4000-8000-000000000001")
            cancel.assert_not_called()

    def test_risky_listener_change(self):
        tunnel = dict(id="old", enabled=True, mode="ports", listen_ip="10.0.0.2",
                      interface="eth0")
        before = dict(tunnels=[tunnel])
        after = dict(tunnels=[dict(tunnel, listen_ip="10.0.0.3")])
        self.assertTrue(guard.risky(before, after))
        self.assertFalse(guard.risky(before, before))


if __name__ == "__main__":
    unittest.main()
