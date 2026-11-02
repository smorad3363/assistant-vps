"""Foreign all-port GRE traffic must be visible without local listeners."""
import unittest
from unittest import mock

from pm2 import auto_monitor, history_collector, system_rules
from pm2.errors import PM2Error


def flow(proto, port, target_port=None, target="10.255.0.2"):
    return (f"{proto} 6 120 ESTABLISHED src=198.51.100.8 dst=192.0.2.1 "
            f"sport=50000 dport={port} src={target} dst=10.255.0.1 "
            f"sport={port if target_port is None else target_port} dport=40000")


class ForwardedDiscoveryTests(unittest.TestCase):
    def test_original_ports_remaps_udp_and_snat_rejection(self):
        text = "\n".join([flow("tcp", 2053, 443), flow("tcp", 2053, 443),
                          flow("udp", 51820), flow("tcp", 8086),
                          flow("tcp", 443, target="192.0.2.1"),
                          "tcp malformed dport=22", flow("tcp", 70000)])
        self.assertEqual(auto_monitor.parse_forwarded(text),
                         {("tcp", 2053): 2, ("udp", 51820): 1, ("tcp", 8086): 1})

    def test_no_listeners_discovers_dnat_and_respects_cap_and_existing(self):
        def run(argv, **kwargs):
            if argv[0] == "conntrack":
                self.assertEqual(argv, ["conntrack", "-L", "-f", "ipv4", "--dst-nat"])
                return "\n".join([flow("tcp", 2053)] * 3 +
                                 [flow("tcp", 8086), flow("udp", 51820)])
            return ""
        with mock.patch.object(auto_monitor, "run", side_effect=run):
            self.assertEqual(auto_monitor.discover(limit=2),
                             [("tcp", 2053), ("tcp", 8086)])
            self.assertEqual(auto_monitor.discover(existing={("tcp", 2053)}, limit=1),
                             [("tcp", 8086)])

    def test_missing_conntrack_preserves_listener_discovery(self):
        def run(argv, **kwargs):
            if argv[0] == "conntrack":
                raise PM2Error("E_DEPENDENCY", "conntrack unavailable")
            return "tcp LISTEN 0 128 0.0.0.0:22 0.0.0.0:*" if "-lntu" in argv else ""
        with mock.patch.object(auto_monitor, "run", side_effect=run):
            self.assertEqual(auto_monitor.discover(), [("tcp", 22)])

    def test_all_except_does_not_track_excluded_port_or_drop_idle_forward(self):
        rules = system_rules.parse_nat(
            "-A PREROUTING -p tcp -m tcp ! --dport 22 -j DNAT --to-destination 10.255.0.2\n"
            "-A PREROUTING -p udp -j DNAT --to-destination 10.255.0.2\n")
        with (mock.patch.object(history_collector, "_tracked_elsewhere", return_value=set()),
              mock.patch.object(system_rules, "detect_nat", return_value=(rules, None)),
              mock.patch.object(auto_monitor, "discover", return_value=[("tcp", 2053)]),
              mock.patch.object(auto_monitor, "run", return_value="")):
            selected = history_collector._select_ports(
                {("tcp", 8086), ("tcp", 22), ("udp", 51820)})
        self.assertEqual(selected, {("tcp", 2053), ("tcp", 8086), ("udp", 51820)})

    def test_idle_port_removed_when_dnat_no_longer_covers_it(self):
        rule = system_rules.parse_nat(
            "-A PREROUTING -p tcp --dport 8000:8100 -j DNAT --to-destination 10.0.0.2")[0]
        self.assertTrue(history_collector._forwards_port(rule, "tcp", 8086))
        self.assertFalse(history_collector._forwards_port(rule, "tcp", 2053))
        self.assertFalse(history_collector._forwards_port(rule, "udp", 8086))


if __name__ == "__main__":
    unittest.main()
