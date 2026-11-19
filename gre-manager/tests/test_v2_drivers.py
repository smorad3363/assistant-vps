"""Kernel command and ownership contracts for v2 tunnel drivers."""
import copy
import random
import tempfile
import unittest

from panel.engine import Engine, build_rules, external_carrier_forward, udp_carrier_matches
from panel.model import DEFAULTS, PanelError
from panel.store import Paths
from panel.v2_config import normalize_group
from panel.v2_drivers import driver_for
from panel.v2_forwarding import gre_link, topology_views
from test_v2_forwarding import data, key


class DriverTests(unittest.TestCase):
    def test_existing_gre_keeps_its_key_and_command(self):
        group = data([{"id": key(4), "node_id": key(5), "method": "gre", "service_ip": "203.0.113.20"}])
        listener = group["listeners"][0]
        link = gre_link(key(3), listener, listener["members"][0])
        driver = driver_for(link)
        self.assertEqual(driver.create(link, "eth1"), ["ip", "tunnel", "add", link["tunnel"], "mode", "gre",
                                                        "local", "192.0.2.11", "remote", "203.0.113.20",
                                                        "key", link["key"], "ttl", 64, "dev", "eth1"])
        self.assertTrue(driver.owns(link, {"linkinfo": {"info_kind": "gre", "info_data": {"local": link["outer_local"],
                                                     "remote": link["outer_peer"], "ikey": str(link["key"])}}}))

    def test_ipip_reverses_endpoints_and_rejects_unowned_devices(self):
        rng = random.Random(404)
        for _ in range(40):
            group = data([{"id": key(4), "node_id": key(5), "method": "ipip",
                           "service_ip": f"203.0.113.{rng.randint(1, 254)}", "ttl": rng.randint(0, 255)}])
            listener = group["listeners"][0]
            member = listener["members"][0]
            source = gre_link(key(3), listener, member)
            target = gre_link(key(3), listener, member, receiving=True)
            self.assertEqual(group, normalize_group(group))
            self.assertEqual(source["local_tun"], target["peer_tun"])
            self.assertEqual(source["outer_local"], target["outer_peer"])
            driver = driver_for(source)
            self.assertNotIn("key", driver.create(source, "eth1"))
            self.assertEqual(driver.firewall(source), ["-p", "4"])
            info = {"info_kind": "ipip", "info_data": {"local": source["outer_local"], "remote": source["outer_peer"],
                                                     "ttl": (member["ttl"] + 1) % 256}}
            self.assertFalse(driver.owns(source, {"linkinfo": info}))
            row = {"linkinfo": info, "ifalias": driver.marker(source)}
            self.assertTrue(driver.owns(source, row))
            self.assertIn("change", driver.refresh(source, info, "eth1"))
            info["info_kind"] = "gre"
            self.assertFalse(driver.owns(source, row))

    def test_unkeyed_endpoint_collision_is_rejected(self):
        original = data([{"id": key(4), "node_id": key(5), "method": "ipip", "service_ip": "203.0.113.20",
                          "outer_ip": "203.0.113.21"}])
        duplicate = copy.deepcopy(original)
        duplicate["id"] = key(8)
        duplicate["listeners"][0]["members"][0]["service_ip"] = "203.0.113.22"
        state = {"groups": {group["id"]: {"active": True, "owner": key(3), "group": group}
                            for group in (original, duplicate)}, "operations": {}}
        view = topology_views({"settings": DEFAULTS, "connections": []}, state, key(3))
        with tempfile.TemporaryDirectory() as root:
            engine = Engine(Paths(root))
            engine.interfaces = lambda: {"192.0.2.10": "eth0", "192.0.2.11": "eth1"}
            with self.assertRaisesRegex(PanelError, "same outer addresses"):
                engine.preflight(view)
        compiled = build_rules(view, {"192.0.2.10": "eth0", "192.0.2.11": "eth1"})["filter"]["GMP_INPUT"]
        self.assertTrue(any(["-p", "4"] == rule[-4:-2] for rule in compiled))

    def test_vxlan_preserves_vnis_ownership_and_scoped_udp(self):
        rng = random.Random(4789)
        for vni in [1, 16777215, *rng.sample(range(2, 16777215), 32)]:
            group = data([{"id": key(4), "node_id": key(5), "method": "vxlan", "service_ip": "203.0.113.20",
                           "vxlan": {"vni": vni}}])
            self.assertEqual(group, normalize_group(group))
            listener = group["listeners"][0]
            member = listener["members"][0]
            left = gre_link(key(3), listener, member)
            right = gre_link(key(3), listener, member, receiving=True)
            self.assertEqual((left["tunnel"], left["local_tun"], left["outer_local"]),
                             (right["tunnel"], right["peer_tun"], right["outer_peer"]))
            driver = driver_for(left)
            self.assertIn("nolearning", driver.create(left, "eth1"))
            row = {"ifalias": driver.marker(left), "linkinfo": {"info_kind": "vxlan", "info_data": {
                "id": vni, "local": left["outer_local"], "remote": left["outer_peer"], "port": 4789}}}
            self.assertTrue(driver.owns(left, row))
            self.assertFalse(driver.owns(dict(left, vni=vni - 1), row))
        self.assertTrue(udp_carrier_matches("-p udp -d 192.0.2.0/24 --dport 4000:5000".split(), left))
        self.assertFalse(udp_carrier_matches("-p tcp -d 192.0.2.0/24 --dport 4789".split(), left))
        self.assertFalse(udp_carrier_matches("-p udp ! -s 203.0.113.20 --dport 4789".split(), left))
        self.assertTrue(udp_carrier_matches("! -p tcp -d 192.0.2.11 --dport 4789".split(), left))
        rules = "-A PREROUTING -i eth1 -j CUSTOM\n-A CUSTOM -p udp --dport 4789 -j REDIRECT"
        self.assertTrue(external_carrier_forward(rules, left, "eth1"))
        self.assertFalse(external_carrier_forward(rules, left, "eth0"))
        self.assertFalse(external_carrier_forward(rules.replace("4789", "4790"), left, "eth1"))
        compiled = topology_views({"settings": DEFAULTS, "connections": []},
                                  {"groups": {group["id"]: {"active": True, "owner": key(3), "group": group}}, "operations": {}}, key(3))
        rule = ["-i", "eth1", "-s", "203.0.113.20", "-d", "192.0.2.11", "-p", "udp", "--dport", "4789", "-j", "ACCEPT"]
        self.assertIn(rule, build_rules(compiled, {"192.0.2.10": "eth0", "192.0.2.11": "eth1"})["nat"]["GMP_PRE"])
