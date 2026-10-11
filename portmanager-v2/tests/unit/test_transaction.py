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

    def test_same_config_refreshes_narrow_rules_to_all_local_ipv4s(self):
        from pm2.validation import make_tunnel
        t = make_tunnel(name="port-8086", listen_ip="77.90.10.180",
                        interface="eth0", mode="ports", protocol="tcp,udp",
                        mapping="8086", target_ip="2.29.39.22")
        self.original["tunnels"] = [t]
        config.atomic_json(self.paths["CONFIG"], self.original)
        ips = {"eth0": ["77.90.10.179", "77.90.10.180"]}
        with (mock.patch.object(transaction.os, "geteuid", return_value=0),
              mock.patch.object(transaction, "preflight", return_value={
                  "backend": "nf_tables",
                  "forwarding_activation_required": False,
                  "interface_ips": ips}),
              mock.patch.object(transaction.firewall, "reconcile",
                                return_value={}) as reconcile):
            outcome = transaction.apply(self.original)
        self.assertTrue(outcome["changed"])
        self.assertEqual(outcome["generation"], 0)
        self.assertEqual(config.load(self.paths["CONFIG"])["generation"], 0)
        self.assertEqual(len(reconcile.call_args.args[0]["PM2_NAT_PRE"]), 4)

    def test_same_config_matching_rules_does_not_reinstall(self):
        from pm2.validation import make_tunnel
        t = make_tunnel(name="port-8086", listen_ip="77.90.10.180",
                        interface="eth0", mode="ports", protocol="tcp,udp",
                        mapping="8086", target_ip="2.29.39.22")
        self.original["tunnels"] = [t]
        config.atomic_json(self.paths["CONFIG"], self.original)
        ips = {"eth0": ["77.90.10.179", "77.90.10.180"]}
        compiled = transaction.firewall.compile_rules(self.original, ips)
        self.runtime["firewall"] = {
            table: {chain: compiled[chain]
                    for own_table, chain in transaction.firewall.ORDER
                    if own_table == table}
            for table in transaction.firewall.CHAINS
        }
        config.atomic_json(self.paths["STATE"], self.runtime)
        with (mock.patch.object(transaction.os, "geteuid", return_value=0),
              mock.patch.object(transaction, "preflight", return_value={
                  "backend": "nf_tables",
                  "forwarding_activation_required": False,
                  "interface_ips": ips}),
              mock.patch.object(transaction.firewall, "reconcile") as reconcile):
            result = transaction.apply(self.original)
        self.assertFalse(result["changed"])
        reconcile.assert_not_called()

    def test_pending_journal_blocks_future_apply(self):
        self.paths["PENDING"].write_text('{"product":"portmanager2"}')
        with mock.patch.object(transaction.discovery, "audit",
                               side_effect=AssertionError("should not query network")):
            with self.assertRaises(PM2Error) as exc:
                transaction.preflight(self.candidate, self.runtime)
        self.assertEqual(exc.exception.code, "E_CONFLICT")


if __name__ == "__main__":
    unittest.main()
