"""Kernel command and ownership contracts for v2 tunnel drivers."""
import copy
import base64
import json
import random
import subprocess
import tempfile
import unittest
from unittest.mock import patch

from panel.engine import Engine, build_rules, external_carrier_forward, udp_carrier_matches
from panel.model import DEFAULTS, PanelError
from panel.store import Paths
from panel.v2_config import l2tpv2_settings, normalize_group
from panel.v2_drivers import driver_for, local_wireguard_key
from panel.v2_forwarding import gre_link, topology_views
from test_v2_forwarding import data, key


class DriverTests(unittest.TestCase):
    def test_l2tpv2_rejects_a_connected_foreign_udp_binding(self):
        transport = driver_for({"method": "l2tpv2"})
        link = {"tunnel": "p2-b0b000000001", "listen_port": 37401, "credential": "lab"}

        def run(*args):
            if args[:2] == ("ss", "-H"):
                self.assertIn("-uanp", args)
                output = 'ESTAB 0 0 192.0.2.10:37401 203.0.113.20:9009 users:(("foreign",pid=42,fd=5))'
            else:
                output = '[]'
            return subprocess.CompletedProcess(args, 0, output, "")

        with patch.object(transport, "available", return_value=True), patch.object(transport, "credential"), patch.object(transport, "status", return_value={}):
            with self.assertRaisesRegex(PanelError, "different UDP socket"):
                transport.check([link], {}, None, run)

    def test_l2tpv2_uses_distinct_roles_and_scopes_public_and_inner_traffic(self):
        settings = {"lac": "destination", "ingress": {"port": 37401, "credential": "in-lab"},
                    "destination": {"port": 37402, "credential": "out-lab"}}
        group = data([{"id": key(4), "node_id": key(5), "method": "l2tpv2", "service_ip": "203.0.113.20", "l2tpv2": settings}])
        listener = group["listeners"][0]
        member = listener["members"][0]
        first, second = (gre_link(key(3), listener, member, receiving=side) for side in (False, True))
        self.assertFalse(first["lac"])
        self.assertTrue(second["lac"])
        self.assertEqual(first["peer_tun"], second["local_tun"])
        self.assertEqual(driver_for(first).firewall(first), ["-p", "udp", "--sport", 37402, "--dport", 37401])
        state = {"groups": {group["id"]: {"active": True, "owner": key(3), "group": group}}, "operations": {}}
        config = {"settings": DEFAULTS, "connections": []}
        view = topology_views(config, state, key(3))
        rules = build_rules(view, {"192.0.2.10": "eth0", "192.0.2.11": "eth0"})
        self.assertTrue(any(rule[-7:] == ["-d", first["peer_tun"], "!", "-o", first["tunnel"], "-j", "DROP"]
                            for rule in rules["filter"]["GMP_FWD"]))
        for ref in ("../chap", "/temp/file", "a\npassword", "", 42):
            with self.subTest(ref=ref), self.assertRaises(PanelError):
                l2tpv2_settings(dict(settings, ingress={"port": 37401, "credential": ref}))

    def test_vxlan_falls_back_to_kernel_text_when_detailed_json_is_malformed(self):
        driver = driver_for({"method": "vxlan"})
        def tool(*args, **kwargs):
            if "-j" in args and "-d" in args:
                output = '[{"ifindex":15,"ifname":"v2-123456789012","linkinfo":{"info_data":{"port":4789 localbypass}}}]'
            elif "-j" in args:
                output = '[{"ifindex":15,"ifname":"v2-123456789012","ifalias":"gremgr:v2:1234567890"}]'
            else:
                output = ("15: v2-123456789012: <BROADCAST> mtu 1280 \\    link/ether 76:22:18:d7:2f:aa"
                          " \\    vxlan id 4 remote 203.0.113.20 local 192.0.2.11 dev eth1 srcport 0 0 dstport 4789 nolearning")
            return subprocess.CompletedProcess(args, 0, output, "")
        row, = driver.inspect(tool)
        self.assertEqual(row["linkinfo"]["info_data"], {"id": 4, "learning": False, "remote": "203.0.113.20",
                                                        "local": "192.0.2.11", "link": "eth1", "port": 4789})
        self.assertTrue(driver.owns({"vni": 4, "id": "1234567890", "outer_local": "192.0.2.11",
                                     "outer_peer": "203.0.113.20", "listen_port": 4789}, row))
    def test_wireguard_materializes_local_key_and_returns_only_public_key(self):
        private_key = base64.b64encode(bytes([9]) * 32).decode()
        public_key = base64.b64encode(bytes([43]) * 32).decode()
        calls = []

        def tool(*args, **kwargs):
            calls.append(args)
            if args[-1] == "pubkey":
                self.assertEqual(kwargs["input"], private_key + "\n")
            return subprocess.CompletedProcess(args, 0, (private_key if args[-1] == "genkey" else public_key) + "\n", "")

        with tempfile.TemporaryDirectory() as root:
            paths = Paths(root)
            self.assertEqual(local_wireguard_key(paths, tool, create=True), public_key)
            self.assertEqual(local_wireguard_key(paths, tool, create=True), public_key)
            secret = paths.etc / "wireguard.key"
            self.assertEqual(secret.stat().st_mode & 0o777, 0o600)
            self.assertEqual(calls.count(("wg", "genkey")), 1)

    def test_wireguard_protects_only_the_configured_udp_carriage(self):
        keys = [base64.b64encode(bytes([byte]) * 32).decode() for byte in (1, 2)]
        group = data([{"id": key(4), "node_id": key(5), "method": "wireguard", "service_ip": "203.0.113.20",
                        "wireguard": {"ingress": {"port": 35379, "public_key": keys[0]},
                                      "destination": {"port": 35389, "public_key": keys[1]}}}])
        listener = group["listeners"][0]
        member = listener["members"][0]
        left, right = (gre_link(key(3), listener, member, receiving=side) for side in (False, True))
        self.assertEqual(left["peer_public_key"], right["public_key"])
        self.assertEqual(right["peer_port"], left["listen_port"])
        self.assertEqual(left["peer_tun"], right["local_tun"])
        self.assertGreater(left["keepalive"], 0)
        self.assertEqual(right["keepalive"], 0)
        state = {"groups": {group["id"]: {"active": True, "owner": key(3), "group": group}}, "operations": {}}
        rendered = topology_views({"settings": DEFAULTS, "connections": []}, state, key(3))
        pre = build_rules(rendered, {"192.0.2.10": "eth0", "192.0.2.11": "eth0"})["nat"]["GMP_PRE"]
        self.assertIn(["-i", "eth0", "-s", "203.0.113.20", "-d", "192.0.2.11", "-p", "udp", "--dport", "35379", "-j", "ACCEPT"], pre)
        self.assertNotIn("private-key", repr(rendered))

    def test_boot_with_a_missing_wireguard_key_preserves_other_paths_and_saved_intent(self):
        keys = [base64.b64encode(bytes([byte]) * 32).decode() for byte in (1, 2)]
        group = data([{"id": key(4), "node_id": key(5), "method": "wireguard", "service_ip": "203.0.113.20",
                       "wireguard": {"ingress": {"port": 35379, "public_key": keys[0]},
                                     "destination": {"port": 35389, "public_key": keys[1]}}},
                      {"id": key(6), "node_id": key(7), "method": "gre", "service_ip": "203.0.113.21"}])
        state = {"groups": {group["id"]: {"active": True, "owner": key(3), "group": group}}, "operations": {}}
        saved = copy.deepcopy(state)
        config = {"settings": DEFAULTS, "connections": []}
        with tempfile.TemporaryDirectory() as root:
            paths = Paths(root)
            restored = topology_views(config, state, key(3), paths=paths)
            self.assertEqual(restored["v2_driver_unavailable"], {group["id"] + ":" + key(4): "wireguard_key"})
            self.assertEqual([x.get("method", "gre") for x in restored["v2_devices"]], ["gre"])
            self.assertEqual([m["enabled"] for m in restored["v2_listeners"][0][2]["members"]], [False, True])
            self.assertEqual(state, saved)
            with patch("panel.v2_forwarding.local_wireguard_key", return_value=keys[0]):
                restored = topology_views(config, state, key(3), paths=paths)
            self.assertEqual(len(restored["v2_devices"]), 2)

    def test_wireguard_rejects_mismatched_source_and_an_unrelated_udp_socket(self):
        local_key = base64.b64encode(bytes([1]) * 32).decode()
        link = {"tunnel": "w2-example", "outer_local": "192.0.2.11", "outer_peer": "203.0.113.20",
                "public_key": local_key, "listen_port": 35379, "peer_public_key": "peer"}

        def tool(*args, **kwargs):
            output = json.dumps([{"prefsrc": source, "dev": "eth0"}]) if args[0] == "ip" else ""
            if args[0] == "ss":
                output = "UNCONN 0 0 192.0.2.11:35379 0.0.0.0:*\n"
            return subprocess.CompletedProcess(args, 0, output, "")

        with tempfile.TemporaryDirectory() as root, patch("panel.engine.local_wireguard_key", return_value=local_key):
            engine = Engine(Paths(root), tool)
            source = "192.0.2.10"
            with self.assertRaisesRegex(PanelError, "source address and interface"):
                engine.check_wireguard([link], {link["outer_local"]: "eth0"})
            source = link["outer_local"]
            with self.assertRaisesRegex(PanelError, "already listens on the WireGuard port"):
                engine.check_wireguard([link], {source: "eth0"})

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

    def test_gretap_uses_two_way_keys_and_owns_only_its_l2_device(self):
        rng = random.Random(224411)
        for selected in [None, 1, 4294967295, *rng.sample(range(2, 4294967295), 32)]:
            group = data([{"id": key(4), "node_id": key(5), "method": "gretap", "service_ip": "203.0.113.20",
                           "gretap": {"key": selected} if selected else {}}])
            self.assertEqual(group, normalize_group(group))
            listener = group["listeners"][0]
            left, right = (gre_link(key(3), listener, listener["members"][0], receiving=side) for side in (False, True))
            self.assertEqual(left["local_tun"], right["peer_tun"])
            self.assertEqual(left["key"], right["key"])
            if selected:
                self.assertEqual(left["key"], selected)
            driver = driver_for(left)
            args = driver.create(left, "eth0")
            self.assertEqual(args[args.index("type") + 1], "gretap")
            info = {"info_kind": "gretap", "info_data": {"local": left["outer_local"], "remote": left["outer_peer"],
                                                         "ikey": str(left["key"]), "okey": str(left["key"])}}
            self.assertFalse(driver.owns(left, {"linkinfo": info}))
            self.assertTrue(driver.owns(left, {"linkinfo": info, "ifalias": driver.marker(left)}))

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
