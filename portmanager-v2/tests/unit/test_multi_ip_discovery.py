"""Expand V2 forwarding only to real IPv4s bound to the chosen interface."""
import json
import unittest
from unittest import mock

from pm2 import discovery, validation
from pm2.errors import PM2Error


class InterfaceIpv4Tests(unittest.TestCase):
    def setUp(self):
        self.tunnel = validation.make_tunnel(
            name="port-8086-to-2-29-39-22", listen_ip="77.90.10.180",
            interface="eth0", mode="ports", protocol="tcp,udp",
            mapping="8086", target_ip="2.29.39.22")

    def commands(self, argv, **kwargs):
        if argv[:2] == ["systemctl", "is-active"]:
            return "inactive"
        if argv == ["iptables-save"]:
            return "*nat\n-A PREROUTING -j PM2_NAT_PRE\nCOMMIT\n"
        if argv == ["iptables-save", "-t", "nat"]:
            return "*nat\n-A PREROUTING -j PM2_NAT_PRE\nCOMMIT\n"
        if argv == ["ip", "-j", "-4", "addr", "show"]:
            return json.dumps([
                {"ifname": "eth0", "flags": ["UP"],
                 "addr_info": [
                     {"family": "inet", "local": "77.90.10.180"},
                     {"family": "inet", "local": "77.90.10.179"},
                     {"family": "inet", "local": "77.90.11.100"},
                 ]},
                {"ifname": "wgcf", "flags": ["UP"],
                 "addr_info": [{"family": "inet", "local": "172.16.0.2"}]},
            ])
        if argv == ["ss", "-H", "-lntu"]:
            return ""
        if argv == ["ip", "-j", "-4", "route", "get", "2.29.39.22"]:
            return '[{"dev": "eth0", "gateway": "77.90.10.1"}]'
        if argv == ["iptables", "--version"]:
            return "iptables v1.8.9 (nf_tables)"
        raise AssertionError("unexpected command: " + repr(argv))

    def test_all_three_public_ipv4s_same_ethernet(self):
        with (mock.patch.object(discovery, "run", side_effect=self.commands),
              mock.patch.object(discovery.shutil, "which", return_value="/sbin/x"),
              mock.patch.object(discovery.nat_conflicts, "blocking_conflicts",
                                return_value=[]) as overlaps):
            outcome = discovery.audit([self.tunnel])
        self.assertEqual(outcome["interface_ips"], {
            "eth0": ["77.90.10.179", "77.90.10.180", "77.90.11.100"]})
        expanded = overlaps.call_args.args[1]
        self.assertEqual({row["listen_ip"] for row in expanded},
                         set(outcome["interface_ips"]["eth0"]))
        self.assertEqual({row["interface"] for row in expanded}, {"eth0"})

    def test_service_on_secondary_ipv4_blocks_unsafe_port_takeover(self):
        def commands(argv, **kwargs):
            if argv == ["ss", "-H", "-lntu"]:
                return "tcp LISTEN 0 128 77.90.10.179:8086 0.0.0.0:*\n"
            return self.commands(argv, **kwargs)
        with (mock.patch.object(discovery, "run", side_effect=commands),
              mock.patch.object(discovery.shutil, "which", return_value="/sbin/x"),
              mock.patch.object(discovery.nat_conflicts, "blocking_conflicts",
                                return_value=[])):
            with self.assertRaises(PM2Error) as err:
                discovery.audit([self.tunnel])
        self.assertEqual(err.exception.code, "E_CONFLICT")


if __name__ == "__main__":
    unittest.main()
