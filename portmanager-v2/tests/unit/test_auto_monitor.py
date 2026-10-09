"""Debian/Ubuntu friendly auto-monitor, global cap and truthful averages."""
import json
import tempfile
import unittest
from datetime import datetime, timezone
from pathlib import Path
from unittest import mock

from pm2 import accounting, auto_monitor as am, limit_windows, port_graph, shaping, simple_ui
from pm2.errors import PM2Error


class AutoMonitorTests(unittest.TestCase):
    def test_parse_busy_local_listeners_no_ipv6_loopback(self):
        s = ("tcp LISTEN 0 4096 0.0.0.0:443 0.0.0.0:*\n"
             "udp UNCONN 0 0 0.0.0.0:2053 0.0.0.0:*\n"
             "tcp LISTEN 0 128 127.0.0.1:5432 0.0.0.0:*\n"
             "tcp LISTEN 0 128 [::1]:22 [::]:*\n")
        self.assertEqual(am.parse_listeners(s), {("tcp", 443), ("udp", 2053)})
        self.assertEqual(am.parse_established("0 0 10.0.0.2:443 1.1.1.1:50000\n"
                                              "ESTAB 0 0 10.0.0.2:443 1.1.1.1:50000"), {443: 2})

    def test_discover_prefers_busy_ports(self):
        def fake(argv, timeout=12):
            if "-lntu" in argv:
                return "\n".join(f"tcp LISTEN 0 128 0.0.0.0:{port} 0.0.0.0:*"
                                 for port in range(3000, 3030))
            return "\n".join("0 0 192.0.2.1:3029 198.51.100.1:55555"
                             for _ in range(5))
        with mock.patch.object(am, "run", side_effect=fake):
            ports = am.discover()
        self.assertEqual(len(ports), am.MAX_PORTS)
        self.assertEqual(ports[0], ("tcp", 3029))

    def test_exact_owned_chain_rule_validation(self):
        line = ("-A PM2_VIEW_RX -p tcp -m conntrack --ctdir ORIGINAL "
                "--ctorigdstport 443 -m comment --comment pm2view:tcp:443:down")
        self.assertTrue(am._valid_counter(line, "PM2_VIEW_RX", "down"))
        self.assertFalse(am._valid_counter(line + " -j DROP", "PM2_VIEW_RX", "down"))
        self.assertFalse(am._valid_counter(line.replace("pm2view:", "foreign:"),
                                               "PM2_VIEW_RX", "down"))

    def test_auto_counter_bytes_and_interface_traffic(self):
        s = ('[10:250000] -A PM2_VIEW_RX -p tcp -m conntrack '
             '--ctorigdstport 443 --ctdir ORIGINAL -m comment '
             '--comment pm2view:tcp:443:down\n'
             '[20:550000] -A PM2_VIEW_TX -p tcp -m conntrack '
             '--ctorigdstport 443 --ctdir REPLY -m comment '
             '--comment pm2view:tcp:443:up\n')
        data = accounting.parse_counters(s, by_port=True, include_probe=True)
        self.assertEqual(data[("auto", "tcp", "down", 443)], 250000)
        self.assertEqual(data[("auto", "tcp", "up", 443)], 550000)
        self.assertEqual(accounting.parse_counters(s), {})
        net = am.interface_rates({"eth0": (100, 200)},
                                 {"eth0": (1000100, 1000200)}, 2.0)
        self.assertAlmostEqual(net[0]["rx_mbps"], 4.0)

    def test_averages_all_four_windows_sorted_by_ten_minute(self):
        now = 100000.0
        labels = {("auto", "tcp", 443): "Xray", ("auto", "udp", 2053): "Sing-box"}
        hist = {("auto", "tcp", 443): [(now, 5, 100, 50)],
                ("auto", "udp", 2053): [(now, 5, 10, 2)]}
        data = port_graph.frame(labels, {}, hist, now, active_only=False)
        self.assertEqual(data["rows"][0]["listen_port"], 443)
        self.assertEqual(set(data["rows"][0]["averages"]),
                         {"10m", "1h", "8h", "24h"})
        self.assertEqual(data["rows"][0]["averages"]["24h"]["coverage_seconds"], 5)

    def test_ipv4_all_ports_requires_explicit_iface(self):
        rule = {
            "id": "all", "port": 0, "protocol": "tcp,udp",
            "interface": "eth0", "timezone": "UTC", "days": list(range(7)),
            "start": "00:00", "end": "00:00",
            "download_mbps": 50, "upload_mbps": 50, "enabled": True
        }
        self.assertTrue(limit_windows.validate([rule]))
        with (mock.patch.object(shaping, "_V1", Path("/missing-portmanager-v1")),
              mock.patch.object(shaping, "_LEGACY_ARCHIVE", Path("/missing-archive-v1"))):
            desired = shaping.desired_filters({"policies": [rule]}, [],
                                              datetime(2026, 10, 12, tzinfo=timezone.utc))
        self.assertEqual(len(desired), 2)
        self.assertEqual({x["port"] for x in desired}, {0})
        self.assertEqual({x["proto"] for x in desired}, {"all"})
        with self.assertRaises(PM2Error):
            limit_windows.validate([dict(rule, interface=None)])

    def test_global_tc_uses_matchall_not_packet_accept_drop(self):
        f = {"iface": "eth0", "direction": "egress", "proto": "all",
             "port": 0, "mbps": 50, "pref": 41000}
        with mock.patch.object(shaping, "_tc") as call:
            shaping._filter_add(f)
        argv = call.call_args.args[0]
        self.assertIn("matchall", argv)
        self.assertNotIn("flower", argv)
        self.assertIn("police", argv)

    def test_live_port_selection_can_limit_entire_interface(self):
        fakeframe = {
            "rows": [{"listen_port": 443, "protocol": "tcp",
                      "tunnel_id": "auto", "name": "Local"}],
            "interfaces": [{"interface": "eth0", "rx_mbps": 510.0, "tx_mbps": 25.0}]
        }
        def simulate(**kwargs):
            kwargs["on_frame"](fakeframe)
            return 130
        with (mock.patch.object(simple_ui, "_ask", side_effect=["ALL"]),
              mock.patch.object(simple_ui.port_graph, "watch", side_effect=simulate),
              mock.patch.object(simple_ui, "_limit") as limits,
              mock.patch.object(simple_ui, "_title")):
            simple_ui._live()
        limits.assert_called_once_with(0, "eth0")

    def test_live_port_selection_passes_protocol_and_interface(self):
        fakeframe = {
            "rows": [{"listen_port": 2053, "protocol": "udp",
                      "tunnel_id": "auto", "name": "Sing-box"}],
            "interfaces": [{"interface": "eth0", "rx_mbps": 250.0, "tx_mbps": 75.0}]
        }
        def simulate(**kwargs):
            kwargs["on_frame"](fakeframe)
            return 130
        with (mock.patch.object(simple_ui, "_ask", side_effect=["2053"]),
              mock.patch.object(simple_ui.port_graph, "watch", side_effect=simulate),
              mock.patch.object(simple_ui, "_limit") as limits,
              mock.patch.object(simple_ui, "_title")):
            simple_ui._live()
        limits.assert_called_once_with(2053, "eth0", "udp")

    def test_live_q_selection_sets_exact_port_on_selected_nic(self):
        frame = {"rows": [{"listen_port": 2053, "protocol": "udp",
                           "tunnel_id": "auto", "name": "Local"}],
                 "interfaces": [{"interface": "eth0", "rx_mbps": 2,
                                 "tx_mbps": 3},
                                {"interface": "wgcf", "rx_mbps": 1,
                                 "tx_mbps": 1}]}
        def simulate(**kwargs):
            kwargs["on_frame"](frame)
            kwargs["on_select"](frame["rows"][0], "wgcf")
            return 0
        with (mock.patch.object(simple_ui, "_ask") as asked,
              mock.patch.object(simple_ui.port_graph, "watch", side_effect=simulate),
              mock.patch.object(simple_ui, "_limit") as limits,
              mock.patch.object(simple_ui, "_title")):
            simple_ui._live()
        limits.assert_called_once_with(2053, "wgcf", "udp")
        asked.assert_not_called()

    def test_live_g_sets_entire_selected_interface_limit(self):
        frame = {"rows": [], "interfaces": [
            {"interface": "eth0", "rx_mbps": 1, "tx_mbps": 2},
            {"interface": "wgcf", "rx_mbps": 2, "tx_mbps": 1}]}
        def simulate(**kwargs):
            kwargs["on_frame"](frame)
            kwargs["on_select"](None, "wgcf")
            return 0
        with (mock.patch.object(simple_ui, "_ask"),
              mock.patch.object(simple_ui.port_graph, "watch", side_effect=simulate),
              mock.patch.object(simple_ui, "_limit") as limits,
              mock.patch.object(simple_ui, "_title")):
            simple_ui._live()
        limits.assert_called_once_with(0, "wgcf")

    def test_warp_default_route_does_not_hide_physical_eth0(self):
        def run(argv, timeout=5):
            if argv[:3] == ["ip", "-4", "route"]:
                return "1.1.1.1 via 10.1.1.1 dev wgcf src 10.1.1.2"
            return json.dumps([{
                "ifname": "eth0",
                "addr_info": [{"family": "inet", "local": "192.0.2.10"}]
            }, {
                "ifname": "wgcf",
                "addr_info": [{"family": "inet", "local": "10.1.1.2"}]
            }])
        with mock.patch("pm2.discovery.run", side_effect=run):
            self.assertEqual(simple_ui._network_defaults(), ("eth0", "192.0.2.10"))

    def test_sshd_nonstandard_port_excluded_from_all_tunnel(self):
        ss = ('tcp LISTEN 0 128 0.0.0.0:2222 0.0.0.0:* '
              'users:(("sshd",pid=123,fd=3))\n')
        with mock.patch("pm2.discovery.run", return_value=ss):
            self.assertEqual(simple_ui._protected_ssh_ports(), "22,2222")

    def test_simple_menu_throughput_and_limit_options_are_three(self):
        with (mock.patch.object(simple_ui.os, "isatty", return_value=True),
              mock.patch.object(simple_ui, "_ask", return_value="0"),
              mock.patch.object(simple_ui, "_title"),
              mock.patch("builtins.print") as out):
            self.assertEqual(simple_ui.menu(), 0)
        displayed = "\n".join(str(x.args) for x in out.call_args_list)
        self.assertIn("LIVE", displayed)
        self.assertIn("IPTABLES", displayed)
        self.assertIn("EDIT", displayed)


if __name__ == "__main__":
    unittest.main()
