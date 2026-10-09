"""Failure injection: an uncertain kernel rollback retains durable evidence."""
import json
import tempfile
import unittest
from pathlib import Path
from unittest import mock

from pm2 import transaction, config
from pm2.errors import PM2Error


class TransactionTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        base = Path(self.tmp.name)
        self.paths = {
            "CONFIG": base / "config.json",
            "STATE": base / "state.json",
            "PENDING": base / "pending.json",
        }
        for name, path in self.paths.items():
            patch = mock.patch.object(transaction, name, path)
            patch.start()
            self.addCleanup(patch.stop)
        self.original = {"schema_version": 1, "generation": 0, "tunnels": []}
        self.candidate = {"schema_version": 1, "generation": 1, "tunnels": []}
        self.runtime = {"backend": None, "applied_generation": 0, "firewall": {}}
        config.atomic_json(self.paths["CONFIG"], self.original)
        config.atomic_json(self.paths["STATE"], self.runtime)

    def test_success_removes_pending(self):
        with (mock.patch.object(transaction.os, "geteuid", return_value=0),
              mock.patch.object(transaction, "preflight", return_value={
                  "backend": "nf_tables", "forwarding_activation_required": False
              }),
              mock.patch.object(transaction.firewall, "reconcile",
                                return_value={}) as reconcile):
            outcome = transaction.apply(self.candidate)
        self.assertTrue(outcome["changed"])
        self.assertFalse(self.paths["PENDING"].exists())
        self.assertEqual(config.load(self.paths["CONFIG"])["generation"], 1)
        reconcile.assert_called_once()

    def test_kernel_rollback_failure_keeps_pending(self):
        with (mock.patch.object(transaction.os, "geteuid", return_value=0),
              mock.patch.object(transaction, "preflight", return_value={
                  "backend": "nf_tables", "forwarding_activation_required": False
              }),
              mock.patch.object(transaction.firewall, "reconcile",
                                side_effect=PM2Error("E_ROLLBACK", "Uncertain kernel state"))):
            with self.assertRaises(PM2Error) as exc:
                transaction.apply(self.candidate)
        self.assertEqual(exc.exception.code, "E_ROLLBACK")
        self.assertTrue(self.paths["PENDING"].exists())
        evidence = json.loads(self.paths["PENDING"].read_text())
        self.assertEqual(evidence["original_generation"], 0)
        self.assertEqual(config.load(self.paths["CONFIG"])["generation"], 0)

    def test_pending_journal_blocks_future_apply(self):
        self.paths["PENDING"].write_text('{"product":"portmanager2"}')
        with mock.patch.object(transaction.discovery, "audit",
                               side_effect=AssertionError("should not query network")):
            with self.assertRaises(PM2Error) as exc:
                transaction.preflight(self.candidate, self.runtime)
        self.assertEqual(exc.exception.code, "E_CONFLICT")


if __name__ == "__main__":
    unittest.main()
