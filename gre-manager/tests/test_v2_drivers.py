"""Kernel command and ownership contracts for v2 tunnel drivers."""
import copy
import base64
import json
import random
import subprocess
import tempfile
import unittest
from unittest.mock import patch

from panel.engine import Engine, build_rules
from panel.model import DEFAULTS, PanelError
from panel.store import Paths
from panel.v2_config import normalize_group
from panel.v2_drivers import driver_for, local_wireguard_key
from panel.v2_forwarding import gre_link, topology_views
from test_v2_forwarding import data, key


class DriverTests(unittest.TestCase):
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
