"""Firewall must never call a global flush or modify V1; no root required."""
import unittest
from unittest import mock

from pm2 import firewall, validation
from pm2.errors import PM2Error


class FirewallTests(unittest.TestCase):
    def setUp(self):
        self.t = validation.make_tunnel(
            name="relay", listen_ip="192.0.2.11", interface="eth0",
            mode="ports", protocol="tcp,udp", mapping="443:8443,2053:2053",
            target_ip="198.51.100.10"
        )
        self.cfg = {"generation": 1, "schema_version": 1, "tunnels": [self.t]}

    def test_prepared_tcp_udp_dest_ports(self):
        r = firewall.compile_rules(self.cfg)
        dnat = r["PM2_NAT_PRE"]
        self.assertEqual(len(dnat), 4)
        self.assertTrue(any("198.51.100.10:8443" in a for a in dnat))
        self.assertTrue(any("198.51.100.10:2053" in a for a in dnat))
        self.assertEqual(len(r["PM2_NAT_POST"]), 4)
        self.assertEqual(len(r["PM2_FORWARD"]), 8)
        self.assertEqual(len(r["PM2_ACCOUNT"]), 8)
        self.assertTrue(all("--ctorigdstport" in row for row in r["PM2_ACCOUNT"]))
        self.assertTrue(all("--ctdir" in row for row in r["PM2_ACCOUNT"]))
        for row in r["PM2_NAT_POST"]:
            self.assertIn("--ctorigdstport", row)
            self.assertIn("-d", row)

    def test_disable_outputs_no_kernel_rules(self):
        self.t["enabled"] = False
        self.assertFalse(any(firewall.compile_rules(self.cfg).values()))

    def test_foreign_chain_collision_fails(self):
        snapshot = {name: [] for name in firewall.CHAINS}
        snapshot["nat"] = [["-N", "PM2_NAT_PRE"]]
        with self.assertRaises(PM2Error) as err:
            firewall.check_inventory(snapshot, {})
        self.assertEqual(err.exception.code, "E_CONFLICT")

    def test_unmodified_empty_state_no_kernel_mutation(self):
        with mock.patch.object(firewall, "snapshot", return_value={
            t: [] for t in firewall.CHAINS}), mock.patch.object(
                firewall, "ipt", side_effect=AssertionError("unexpected mutation")):
            outcome = firewall.reconcile(
                firewall.compile_rules({"tunnels": []}), {})
        self.assertEqual(outcome, {})

    def test_changes_never_flush_entire_table(self):
        with mock.patch.object(firewall, "run", return_value=""):
            prior = {"nat": {"PM2_NAT_PRE": [], "PM2_NAT_POST": []},
                     "filter": {"PM2_FORWARD": []},
                     "mangle": {"PM2_ACCOUNT": []}}
            firewall._remove(prior)
            # call recorded argv from mock in a separate scope to check:
        with mock.patch.object(firewall, "ipt") as wrapped:
            firewall._remove(prior)
            calls = [call.args for call in wrapped.call_args_list]
            self.assertTrue(all(args[1] != "-F" or len(args) == 3
                                for args in calls), calls)
            self.assertTrue(all("PORTMANAGER_ACCT" not in str(args)
                                for args in calls))

    def test_all_except_excludes_are_separate_rules(self):
        self.t = validation.make_tunnel(
            name="all", listen_ip="192.0.2.11", interface="eth0",
            mode="all-except", protocol="tcp", exclude="22,10022,443",
            ack_all_ports=True, target_ip="198.51.100.10"
        )
        self.cfg["tunnels"] = [self.t]
        pre = firewall.compile_rules(self.cfg)["PM2_NAT_PRE"]
        self.assertEqual(len(pre), 4)
        self.assertEqual(len([x for x in pre if "RETURN" in x]), 3)


if __name__ == "__main__":
    unittest.main()
