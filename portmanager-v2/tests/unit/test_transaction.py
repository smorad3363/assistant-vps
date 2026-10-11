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

    def test_preflight_marks_fully_missing_owned_firewall_for_repair(self):
        runtime = {
            "backend": "nf_tables",
            "applied_generation": 0,
            "firewall": {
                "nat": {"PM2_NAT_PRE": [["-p", "tcp"]],
                        "PM2_NAT_POST": [["-p", "tcp"]]},
                "filter": {"PM2_FORWARD": [["-j", "ACCEPT"]]},
                "mangle": {"PM2_ACCOUNT": [["-p", "tcp"]]},
            },
        }
        empty_kernel = {name: [] for name in transaction.firewall.CHAINS}
        with (mock.patch.object(transaction.discovery, "audit",
                                return_value={"backend": "nf_tables",
                                              "interface_ips": {}}),
              mock.patch.object(transaction.forwarding, "preflight",
                                return_value={"forwarding_enabled": True}),
              mock.patch.object(transaction.firewall, "snapshot",
                                return_value=empty_kernel)):
            report = transaction.preflight(self.original, runtime)
        self.assertTrue(report["repair_missing_firewall"])

    def test_preflight_repairs_missing_nat_when_other_owned_chains_are_intact(self):
        runtime = {
            "backend": "nf_tables",
            "applied_generation": 0,
            "firewall": {
                "nat": {"PM2_NAT_PRE": [["-p", "tcp"]],
                        "PM2_NAT_POST": [["-p", "tcp"]]},
                "filter": {"PM2_FORWARD": [["-j", "ACCEPT"]]},
                "mangle": {"PM2_ACCOUNT": [["-p", "tcp"]]},
            },
        }
        kernel = {name: [] for name in transaction.firewall.CHAINS}
        kernel["filter"] = [
            ["-N", "PM2_FORWARD"],
            transaction.firewall._hook("PM2_FORWARD"),
            ["-A", "PM2_FORWARD", "-j", "ACCEPT"],
        ]
        kernel["mangle"] = [
            ["-N", "PM2_ACCOUNT"],
            transaction.firewall._hook("PM2_ACCOUNT"),
            ["-A", "PM2_ACCOUNT", "-p", "tcp"],
        ]
        with (mock.patch.object(transaction.discovery, "audit",
                                return_value={"backend": "nf_tables",
                                              "interface_ips": {}}),
              mock.patch.object(transaction.forwarding, "preflight",
                                return_value={"forwarding_enabled": True}),
              mock.patch.object(transaction.firewall, "snapshot",
                                return_value=kernel)):
            report = transaction.preflight(self.original, runtime)
        self.assertTrue(report["repair_missing_firewall"])
        self.assertEqual(set(report["missing_owned_chains"]),
                         {"PM2_NAT_PRE", "PM2_NAT_POST"})
        baseline = report["_repair_previous_firewall"]
        self.assertEqual(baseline["nat"], {})
        self.assertIn("PM2_FORWARD", baseline["filter"])
        self.assertIn("PM2_ACCOUNT", baseline["mangle"])

    def test_preflight_still_rejects_partial_owned_firewall(self):
        runtime = {
            "backend": "nf_tables",
            "applied_generation": 0,
            "firewall": {
                "nat": {"PM2_NAT_PRE": [["-p", "tcp"]],
                        "PM2_NAT_POST": [["-p", "tcp"]]},
                "filter": {"PM2_FORWARD": [["-j", "ACCEPT"]]},
                "mangle": {"PM2_ACCOUNT": [["-p", "tcp"]]},
            },
        }
        partial = {name: [] for name in transaction.firewall.CHAINS}
        partial["nat"] = [["-N", "PM2_NAT_PRE"]]
        with (mock.patch.object(transaction.discovery, "audit",
                                return_value={"backend": "nf_tables",
                                              "interface_ips": {}}),
              mock.patch.object(transaction.forwarding, "preflight",
                                return_value={"forwarding_enabled": True}),
              mock.patch.object(transaction.firewall, "snapshot",
                                return_value=partial)):
            with self.assertRaises(PM2Error) as exc:
                transaction.preflight(self.original, runtime)
        self.assertEqual(exc.exception.code, "E_CONFLICT")

    def test_apply_rebuilds_from_empty_kernel_not_stale_inventory(self):
        from pm2.validation import make_tunnel
        tunnel = make_tunnel(
            name="port-8086", listen_ip="77.90.10.180", interface="eth0",
            mode="ports", protocol="tcp,udp", mapping="8086",
            target_ip="2.29.39.22")
        self.original["tunnels"] = [tunnel]
        config.atomic_json(self.paths["CONFIG"], self.original)
        stale = {
            "nat": {"PM2_NAT_PRE": [["old"]], "PM2_NAT_POST": [["old"]]},
            "filter": {"PM2_FORWARD": [["old"]]},
            "mangle": {"PM2_ACCOUNT": [["old"]]},
        }
        self.runtime.update({
            "backend": "nf_tables", "applied_generation": 0,
            "firewall": stale,
        })
        config.atomic_json(self.paths["STATE"], self.runtime)
        installed = {
            "nat": {"PM2_NAT_PRE": [["new-pre"]],
                    "PM2_NAT_POST": [["new-post"]]},
            "filter": {"PM2_FORWARD": [["new-forward"]]},
            "mangle": {"PM2_ACCOUNT": [["new-account"]]},
        }
        with (mock.patch.object(transaction.os, "geteuid", return_value=0),
              mock.patch.object(transaction, "preflight", return_value={
                  "backend": "nf_tables",
                  "forwarding_activation_required": False,
                  "interface_ips": {"eth0": [
                      "77.90.10.179", "77.90.10.180", "77.90.11.100"]},
                  "repair_missing_firewall": True,
                  "_repair_previous_firewall": {},
              }),
              mock.patch.object(transaction.firewall, "reconcile",
                                return_value=installed) as reconcile):
            outcome = transaction.apply(self.original)
        self.assertTrue(outcome["changed"])
        self.assertTrue(outcome["repaired_missing_firewall"])
        self.assertEqual(reconcile.call_args.args[1], {})
        saved_state = json.loads(self.paths["STATE"].read_text())
        self.assertEqual(saved_state["firewall"], installed)
        self.assertFalse(self.paths["PENDING"].exists())

    def test_pending_journal_blocks_future_apply(self):
        self.paths["PENDING"].write_text('{"product":"portmanager2"}')
        with mock.patch.object(transaction.discovery, "audit",
                               side_effect=AssertionError("should not query network")):
            with self.assertRaises(PM2Error) as exc:
                transaction.preflight(self.candidate, self.runtime)
        self.assertEqual(exc.exception.code, "E_CONFLICT")


if __name__ == "__main__":
    unittest.main()
