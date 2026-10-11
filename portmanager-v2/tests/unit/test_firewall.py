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

    def test_tcp_udp_5555_same_numeric_port_and_local_ipv4(self):
        """Service aliases in iptables -L are not different port numbers."""
        connection = validation.make_tunnel(
            name="port-5555-to-2-29-39-22",
            listen_ip="77.90.10.180", interface="eth0",
            mode="ports", protocol="tcp,udp", mapping="5555",
            target_ip="2.29.39.22")
        compiled = firewall.compile_rules({"tunnels": [connection]})
        dnat = compiled["PM2_NAT_PRE"]
        self.assertEqual(len(dnat), 2)
        self.assertEqual({row[row.index("-p") + 1] for row in dnat},
                         {"tcp", "udp"})
        for row in dnat:
            self.assertEqual(row[row.index("-i") + 1], "eth0")
            self.assertEqual(row[row.index("-d") + 1], "77.90.10.180")
            self.assertEqual(row[row.index("--dport") + 1], "5555")
            self.assertEqual(row[row.index("--to-destination") + 1],
                             "2.29.39.22:5555")
        self.assertEqual(len(compiled["PM2_NAT_POST"]), 2)
        self.assertEqual(len(compiled["PM2_FORWARD"]), 4)

    def test_host_secondary_ipv4s_are_forwarded_with_original_dst_snat(self):
        tunnel = validation.make_tunnel(
            name="port-8086-to-2-29-39-22", listen_ip="77.90.10.180",
            interface="eth0", mode="ports", protocol="tcp,udp",
            mapping="8086", target_ip="2.29.39.22")
        cfg = {"tunnels": [tunnel]}
        ips = {"eth0": ["77.90.10.179", "77.90.10.180", "77.90.11.100"]}
        compiled = firewall.compile_rules(cfg, ips)
        self.assertEqual(len(compiled["PM2_NAT_PRE"]), 6)
        self.assertEqual(len(compiled["PM2_NAT_POST"]), 6)
        self.assertEqual(len(compiled["PM2_FORWARD"]), 12)
        self.assertEqual(len(compiled["PM2_ACCOUNT"]), 12)
        for address in ips["eth0"]:
            for proto in ("tcp", "udp"):
                dnat = [row for row in compiled["PM2_NAT_PRE"]
                        if row[row.index("-d") + 1] == address
                        and row[row.index("-p") + 1] == proto]
                self.assertEqual(len(dnat), 1)
                self.assertEqual(dnat[0][dnat[0].index("--dport") + 1], "8086")
                self.assertEqual(dnat[0][dnat[0].index("--to-destination") + 1],
                                 "2.29.39.22:8086")
                # Never SNAT every connection to 2.29.39.22, only V2's
                # original destination on the same assigned source IP.
                post = [row for row in compiled["PM2_NAT_POST"]
                        if "--ctorigdst" in row
                        and row[row.index("--ctorigdst") + 1] == address
                        and row[row.index("-p") + 1] == proto]
                self.assertEqual(len(post), 1)
                self.assertIn("--ctorigdstport", post[0])

    def test_drifted_interface_ip_is_rejected_before_compile(self):
        with self.assertRaises(PM2Error):
            firewall.compile_rules(self.cfg, {"eth0": ["192.0.2.12"]})

    def test_runtime_matches_kernel_normalized_iptables_save(self):
        cfg = {"tunnels": [validation.make_tunnel(
            name="port-8086", listen_ip="77.90.10.180", interface="eth0",
            mode="ports", protocol="tcp,udp", mapping="8086",
            target_ip="2.29.39.22")]}
        compiled = firewall.compile_rules(cfg, {
            "eth0": ["77.90.10.179", "77.90.10.180"]})
        inventory = {}
        for table, chains in firewall.CHAINS.items():
            inventory[table] = {}
            for chain in chains:
                rows = []
                for original in compiled[chain]:
                    row = list(original)
                    # iptables -S expands IPv4 /32 and inserts protocol matcher.
                    for option in ("-d", "-s"):
                        if option in row and "/" not in row[row.index(option) + 1]:
                            row[row.index(option) + 1] += "/32"
                    if "--dport" in row:
                        proto = row[row.index("-p") + 1]
                        p = row.index("-p")
                        row[p + 2:p + 2] = ["-m", proto]
                    rows.append(row)
                inventory[table][chain] = rows
        self.assertTrue(firewall.matches_compiled_inventory(compiled, inventory))
        inventory["nat"]["PM2_NAT_PRE"].pop()
        self.assertFalse(firewall.matches_compiled_inventory(compiled, inventory))

    def test_disable_outputs_no_kernel_rules(self):
        self.t["enabled"] = False
        self.assertFalse(any(firewall.compile_rules(self.cfg).values()))

    def test_foreign_chain_collision_fails(self):
        snapshot = {name: [] for name in firewall.CHAINS}
        snapshot["nat"] = [["-N", "PM2_NAT_PRE"]]
        with self.assertRaises(PM2Error) as err:
            firewall.check_inventory(snapshot, {})
        self.assertEqual(err.exception.code, "E_CONFLICT")

    def test_complete_owned_footprint_loss_is_repairable(self):
        snapshot = {name: [] for name in firewall.CHAINS}
        inventory = {
            "nat": {"PM2_NAT_PRE": [["-p", "tcp"]],
                    "PM2_NAT_POST": [["-p", "tcp"]]},
            "filter": {"PM2_FORWARD": [["-j", "ACCEPT"]]},
            "mangle": {"PM2_ACCOUNT": [["-p", "tcp"]]},
        }
        self.assertTrue(firewall.inventory_completely_missing(snapshot, inventory))

    def test_partial_owned_footprint_is_never_auto_repairable(self):
        inventory = {
            "nat": {"PM2_NAT_PRE": [["-p", "tcp"]],
                    "PM2_NAT_POST": [["-p", "tcp"]]},
            "filter": {"PM2_FORWARD": [["-j", "ACCEPT"]]},
            "mangle": {"PM2_ACCOUNT": [["-p", "tcp"]]},
        }
        cases = []
        snap = {name: [] for name in firewall.CHAINS}
        snap["nat"] = [["-N", "PM2_NAT_PRE"]]
        cases.append(snap)
        snap = {name: [] for name in firewall.CHAINS}
        snap["nat"] = [["-A", "PREROUTING", "-m", "comment", "--comment",
                        "pm2:owned-hook", "-j", "PM2_NAT_PRE"]]
        cases.append(snap)
        snap = {name: [] for name in firewall.CHAINS}
        snap["filter"] = [["-A", "FORWARD", "-m", "comment", "--comment",
                           "pm2:orphan:forward", "-j", "ACCEPT"]]
        cases.append(snap)
        for snapshot in cases:
            with self.subTest(snapshot=snapshot):
                self.assertFalse(
                    firewall.inventory_completely_missing(snapshot, inventory))
                with self.assertRaises(PM2Error):
                    firewall.check_inventory(snapshot, inventory)

    def test_missing_nat_with_intact_filter_mangle_is_repairable(self):
        inventory = {
            "nat": {"PM2_NAT_PRE": [["-p", "tcp"]],
                    "PM2_NAT_POST": [["-p", "tcp"]]},
            "filter": {"PM2_FORWARD": [["-j", "ACCEPT"]]},
            "mangle": {"PM2_ACCOUNT": [["-p", "tcp"]]},
        }
        snapshot = {name: [] for name in firewall.CHAINS}
        snapshot["filter"] = [
            ["-N", "PM2_FORWARD"],
            firewall._hook("PM2_FORWARD"),
            ["-A", "PM2_FORWARD", "-j", "ACCEPT"],
        ]
        snapshot["mangle"] = [
            ["-N", "PM2_ACCOUNT"],
            firewall._hook("PM2_ACCOUNT"),
            ["-A", "PM2_ACCOUNT", "-p", "tcp"],
        ]
        actual, missing = firewall.repairable_inventory(snapshot, inventory)
        self.assertEqual(set(missing),
                         {("nat", "PM2_NAT_PRE"), ("nat", "PM2_NAT_POST")})
        self.assertEqual(actual["filter"]["PM2_FORWARD"], [["-j", "ACCEPT"]])
        self.assertEqual(actual["mangle"]["PM2_ACCOUNT"], [["-p", "tcp"]])
        self.assertEqual(actual["nat"], {})

    def test_no_saved_inventory_is_not_a_repair_case(self):
        snapshot = {name: [] for name in firewall.CHAINS}
        self.assertFalse(firewall.inventory_completely_missing(snapshot, {}))

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
