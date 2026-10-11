"""Only overlapping foreign NAT rules should block Port Manager tunnels."""
import unittest

from pm2 import nat_conflicts
from pm2.validation import make_tunnel


class NatConflictTests(unittest.TestCase):
    def tunnel(self, **kw):
        args = dict(name="demo", listen_ip="192.0.2.10", interface="eth0",
                    target_ip="198.51.100.5", mode="ports",
                    protocol="tcp,udp", mapping="8080:8080")
        args.update(kw)
        return make_tunnel(**args)

    def test_unrelated_port_or_destination_is_allowed(self):
        rules = ("-A DOCKER -p tcp --dport 8443 -j DNAT --to-destination 172.17.0.2:443\n"
                 "-A PREROUTING -d 203.0.113.2/32 -p tcp --dport 8080 "
                 "-j DNAT --to-destination 10.0.0.2\n")
        self.assertEqual(nat_conflicts.find_conflicts(rules, [self.tunnel()]), [])

    def test_same_port_conflicts_with_rule_details(self):
        rule = "-A PREROUTING -p tcp --dport 8080 -j DNAT --to-destination 10.0.0.1"
        found = nat_conflicts.find_conflicts(rule, [self.tunnel()])
        self.assertEqual(found[0]["tunnel"], "demo")
        self.assertIn("PREROUTING", found[0]["rule"])

    def test_other_interface_is_allowed(self):
        rule = "-A PREROUTING -i eth1 -p tcp --dport 8080 -j DNAT --to-destination 10.0.0.1"
        self.assertEqual(nat_conflicts.find_conflicts(rule, [self.tunnel()]), [])

    def test_multiport_and_ranges(self):
        rule = "-A DOCKER -p tcp -m multiport --dports 80,8000:8090 -j DNAT --to-destination 10.0.0.1"
        self.assertTrue(nat_conflicts.find_conflicts(rule, [self.tunnel()]))
        self.assertFalse(nat_conflicts.find_conflicts(rule, [
            self.tunnel(mapping="9000:9000")]))

    def test_all_except_does_not_capture_excluded_foreign_port(self):
        t = self.tunnel(mode="all-except", mapping=None,
                        exclude="22,8080", ack_all_ports=True)
        rule = "-A PREROUTING -p tcp --dport 8080 -j DNAT --to-destination 10.0.0.1"
        self.assertEqual(nat_conflicts.find_conflicts(rule, [t]), [])
        self.assertTrue(nat_conflicts.find_conflicts(rule.replace("8080", "8081"), [t]))

    def test_broad_and_negated_fail_closed(self):
        broad = "-A PREROUTING -p tcp -j DNAT --to-destination 10.0.0.1"
        negated = "-A PREROUTING ! -p udp --dport 8080 -j DNAT --to-destination 10.0.0.1"
        self.assertTrue(nat_conflicts.find_conflicts(broad, [self.tunnel()]))
        self.assertTrue(nat_conflicts.find_conflicts(negated, [self.tunnel()]))

    def test_existing_broad_fallback_after_pm2_hook_is_legal(self):
        t = self.tunnel(mapping="8086:8086", listen_ip="77.90.10.180")
        snapshot = (
            "*nat\n"
            "-A PREROUTING -m comment --comment pm2:owned-hook -j PM2_NAT_PRE\n"
            "-A PREROUTING -p tcp -m multiport --dports 8086 "
            "-j DNAT --to-destination 2.29.39.22\n"
            "-A PREROUTING -p udp -m multiport --dports 8086 "
            "-j DNAT --to-destination 2.29.39.22\n"
            "COMMIT\n")
        # V2 handles its exact address at PREROUTING #1; a broader later
        # rule can still forward the same port on other assigned IPv4s.
        self.assertEqual(nat_conflicts.blocking_conflicts(snapshot, [t]), [])

    def test_first_v2_install_allows_identical_older_forward(self):
        t = self.tunnel()
        existing = (
            "*nat\n-A PREROUTING -p tcp --dport 8080 "
            "-j DNAT --to-destination 198.51.100.5:8080\nCOMMIT\n")
        self.assertEqual(nat_conflicts.blocking_conflicts(existing, [t]), [])

    def test_foreign_rule_ahead_of_existing_hook_blocks(self):
        t = self.tunnel()
        snapshot = (
            "*nat\n"
            "-A PREROUTING -p tcp --dport 8080 -j DNAT "
            "--to-destination 198.51.100.42\n"
            "-A PREROUTING -m comment --comment pm2:owned-hook -j PM2_NAT_PRE\n"
            "COMMIT\n")
        conflicts = nat_conflicts.blocking_conflicts(snapshot, [t])
        self.assertEqual(len(conflicts), 1)
        self.assertIn("8080", conflicts[0]["rule"])

    def test_other_destination_before_hook_does_not_block(self):
        t = self.tunnel()
        snapshot = (
            "*nat\n"
            "-A PREROUTING -d 203.0.113.23 -p tcp --dport 8080 -j DNAT "
            "--to-destination 198.51.100.42\n"
            "-A PREROUTING -j PM2_NAT_PRE\n"
            "COMMIT\n")
        self.assertEqual(nat_conflicts.blocking_conflicts(snapshot, [t]), [])

    def test_earlier_external_chain_dnat_blocks(self):
        t = self.tunnel()
        snapshot = (
            "*nat\n"
            "-A PREROUTING -j CUSTOM_TUNNEL\n"
            "-A PREROUTING -j PM2_NAT_PRE\n"
            "-A CUSTOM_TUNNEL -p tcp --dport 8080 -j DNAT "
            "--to-destination 198.51.100.42\n"
            "COMMIT\n")
        self.assertTrue(nat_conflicts.blocking_conflicts(snapshot, [t]))

    def test_different_foreign_destination_after_hook_would_be_shadowed(self):
        t = self.tunnel(listen_ip="77.90.10.179", mapping="8086:8086",
                        target_ip="2.29.39.22")
        snapshot = ("*nat\n-A PREROUTING -j PM2_NAT_PRE\n"
                    "-A PREROUTING -p tcp --dport 8086 "
                    "-j DNAT --to-destination 198.51.100.8\nCOMMIT\n")
        self.assertTrue(nat_conflicts.blocking_conflicts(snapshot, [t]))

    def test_identical_dds_forward_after_hook_is_allowed(self):
        t = self.tunnel(listen_ip="77.90.10.179", mapping="8086:8086",
                        target_ip="2.29.39.22")
        snapshot = ("*nat\n-A PREROUTING -j PM2_NAT_PRE\n"
                    "-A PREROUTING -p tcp -m multiport --dports 8086 "
                    "-j DNAT --to-destination 2.29.39.22\n"
                    "-A PREROUTING -p udp -m multiport --dports 8086 "
                    "-j DNAT --to-destination 2.29.39.22\nCOMMIT\n")
        self.assertEqual(nat_conflicts.blocking_conflicts(snapshot, [t]), [])

    def test_different_destination_port_is_not_same_forwarding(self):
        t = self.tunnel(listen_ip="77.90.10.179", mapping="8086:6666",
                        target_ip="2.29.39.22")
        snapshot = ("*nat\n-A PREROUTING -j PM2_NAT_PRE\n"
                    "-A PREROUTING -p tcp --dport 8086 "
                    "-j DNAT --to-destination 2.29.39.22\nCOMMIT\n")
        self.assertTrue(nat_conflicts.blocking_conflicts(snapshot, [t]))

    def test_first_install_checks_existing_different_target(self):
        t = self.tunnel(listen_ip="77.90.10.179", mapping="8086:8086",
                        target_ip="2.29.39.22")
        snapshot = ("*nat\n-A PREROUTING -p tcp --dport 8086 "
                    "-j DNAT --to-destination 198.51.100.8\nCOMMIT\n")
        self.assertTrue(nat_conflicts.blocking_conflicts(snapshot, [t]))

    def test_owned_and_disabled_rules_not_considered(self):
        own = "-A PM2_NAT_PRE -p tcp --dport 8080 -j DNAT --to-destination 10.0.0.1"
        self.assertFalse(nat_conflicts.find_conflicts(own, [self.tunnel()]))
        foreign = own.replace("PM2_NAT_PRE", "DOCKER")
        self.assertFalse(nat_conflicts.find_conflicts(foreign, [
            self.tunnel(enabled=False)]))


if __name__ == "__main__":
    unittest.main()
