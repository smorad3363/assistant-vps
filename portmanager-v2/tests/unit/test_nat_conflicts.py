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

    def test_owned_and_disabled_rules_not_considered(self):
        own = "-A PM2_NAT_PRE -p tcp --dport 8080 -j DNAT --to-destination 10.0.0.1"
        self.assertFalse(nat_conflicts.find_conflicts(own, [self.tunnel()]))
        foreign = own.replace("PM2_NAT_PRE", "DOCKER")
        self.assertFalse(nat_conflicts.find_conflicts(foreign, [
            self.tunnel(enabled=False)]))


if __name__ == "__main__":
    unittest.main()
