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
from panel.v2_bench_agent import test_link
from panel.v2_config import l2tpv2_settings, normalize_group, sit_settings
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

    def test_sit_keeps_ipv6_and_its_exact_outer_filter_separate_from_ipv4_forwarding(self):
        member = {"id": key(4), "node_id": key(5), "method": "sit", "outer_ip": "203.0.113.20",
                  "sit": {"ingress": "fd00:1234::1/64", "destination": "fd00:1234::2/64"}}
        group = data([dict(member, method="gre", service_ip=member["outer_ip"])])
        listener = group["listeners"][0]
        listener.update(ports="all", protocols=[], target_port=None, port_map={}, members=[member])
        group = normalize_group(group)
        self.assertEqual(group, normalize_group(group))
        state = {"groups": {group["id"]: {"active": True, "owner": key(3), "group": group}}, "operations": {}}
        config = {"settings": DEFAULTS, "connections": []}
        first, second = [topology_views(config, state, node) for node in (key(3), key(5))]
        left, right = [view["v2_devices"][0] for view in (first, second)]
        self.assertEqual((left["local_tun"], left["prefix_length"], left["peer_tun"]), ("fd00:1234::1", 64, right["local_tun"]))
        for view, link in ((first, left), (second, right)):
            self.assertEqual((view["connections"], view["v2_listeners"]), ([], []))
            rules = build_rules(view, {link["outer_local"]: "eth0"})
            carrier = ["-i", "eth0", "-s", link["outer_peer"], "-d", link["outer_local"], "-p", "41", "-j", "ACCEPT"]
            self.assertEqual(rules["nat"]["GMP_PRE"], [carrier])
            self.assertEqual(rules["filter"]["GMP_INPUT"], [carrier])
            foreign = f"-A PREROUTING -d {link['outer_local']} -p ipv6 -j DNAT --to-destination 198.51.100.1"
            self.assertTrue(external_carrier_forward(foreign, link, "eth0"))
            self.assertFalse(external_carrier_forward(foreign.replace("-p ipv6", "-p udp --dport 41"), link, "eth0"))
        with tempfile.TemporaryDirectory() as root, patch("panel.v2_forwarding.ipv6_enabled", return_value=False):
            restored = topology_views(config, state, key(3), paths=Paths(root))
            self.assertEqual(restored["v2_devices"], [])
            self.assertEqual(restored["v2_driver_unavailable"], {group["id"] + ":" + key(4): "ipv6_disabled"})
            self.assertEqual(restored["v2_unavailable_devices"], [left])
            self.assertEqual(topology_views(config, state, key(3), paths=Paths(root), require_keys_for=group["id"])["v2_devices"], [left])
        pending = {"groups": {}, "operations": {"op": {"phase": "prepared", "owner": key(3), "change": {"group": group}}}}
        self.assertEqual(topology_views(config, pending, key(3))["v2_devices"], [])
        self.assertEqual(topology_views(config, pending, key(3), require_keys_for=group["id"])["v2_devices"], [left])
        for settings in ({"draining": True}, {"weight": 2}, {"limits": {"up": 10}}):
            rejected = copy.deepcopy(group)
            rejected["listeners"][0]["members"][0].update(settings)
            with self.assertRaises(PanelError):
                normalize_group(rejected)
        mixed = copy.deepcopy(group)
        other = copy.deepcopy(data([dict(member, id=key(9), method="gre", service_ip=member["outer_ip"])])["listeners"][0])
        mixed["listeners"].append(dict(other, id=key(8)))
        self.assertEqual(len(normalize_group(mixed)["listeners"]), 2)
        with self.assertRaises(PanelError):
            normalize_group(dict(mixed, limits={"up": 100}))

    def test_sit_address_canonicalization_and_invalid_subnets(self):
        randomizer = random.Random(6141)
        for _ in range(250):
            subnet = "fd25:" + format(randomizer.randrange(65536), "x")
            endpoints = {"ingress": subnet + "::1/64", "destination": subnet + "::2/64"}
            self.assertEqual(sit_settings({side: ip.upper() for side, ip in endpoints.items()}), endpoints)
            with self.assertRaises(PanelError):
                sit_settings(dict(endpoints, destination=endpoints["ingress"]))
        for endpoint in ("ff02::1/64", "fd00::2%eth0/64", "fd00::2/48", "fd00::2/64", "fe80::2/64", "fd25::1/64", 42):
            with self.subTest(endpoint=endpoint), self.assertRaises(PanelError):
                sit_settings({"ingress": "fd25::1/64", "destination": endpoint})

    def test_sit_benchmark_derives_a_temporary_ipv6_subnet_per_direction(self):
        request = {"job_id": key(1), "method": "sit", "direction": 0, "first": "192.0.2.1", "second": "192.0.2.2"}
        left, right = [test_link(key(2), dict(request, side=side)) for side in (0, 1)]
        self.assertEqual(left["peer_tun"], right["local_tun"])
        self.assertEqual(left["family"], 6)
        self.assertNotEqual(left["local_tun"], test_link(key(2), dict(request, side=0, direction=1))["local_tun"])

    def test_l2tp_has_reversed_ids_and_leaves_an_adjacent_session(self):
        group = data([{"id": key(4), "node_id": key(5), "method": "l2tpv3", "service_ip": "203.0.113.20",
                       "l2tpv3": {"ingress": {"tunnel_id": 100, "session_id": 101, "port": 37001},
                                  "destination": {"tunnel_id": 200, "session_id": 201, "port": 37002}}}])
        parent = group["listeners"][0]
        member = parent["members"][0]
        left, right = [gre_link(key(3), parent, member, receiving=target) for target in (False,True)]
        self.assertEqual((left["tunnel_id"], left["session_id"], left["listen_port"]),
                         (right["peer_tunnel_id"], right["peer_session_id"], right["peer_port"]))
        driver = driver_for(left)
        self.assertIn("0x00000065", driver.firewall(left)[-1])
        known = [driver.session(left), dict(driver.session(left), session_id=999, interface="adjacent")]
        calls = []
        interface = {"ifname": left["tunnel"], "link_type": "ether", "ifalias": "external-owner"}

        def tool(*args, **kwargs):
            calls.append(args)
            rows = [driver.expected(left)] if args[-1] == "tunnel" else known if args[-1] == "session" else [interface]
            if "del" in args:
                known.pop(0)
            return subprocess.CompletedProcess(args, 0, json.dumps(rows), "")

        with tempfile.TemporaryDirectory() as home:
            from panel.store import atomic_json
            paths = Paths(home)
            driver.remove(left, paths, tool)
            self.assertEqual(calls, [])
            atomic_json(driver.journal(paths, left), driver.receipt(left))
            driver.remove(left, paths, tool)
            self.assertFalse(any("del" in call for call in calls))
            interface["ifalias"] = ""
            driver.remove(left, paths, tool)
            self.assertFalse(any("del" in call for call in calls))
            # Only a pending creation receipt can claim an unmarked kernel session.
            atomic_json(driver.journal(paths, left), driver.receipt(left, "pending"))
            driver.remove(left, paths, tool)
            deletes = [call for call in calls if "del" in call]
            self.assertEqual(deletes, [("ip", "l2tp", "del", "session", "tunnel_id", 100, "session_id", 101)])
            self.assertTrue(driver.journal(paths, left).is_file())

    def test_a_saved_geneve_route_loss_leaves_other_methods_ready(self):
        group = data([{"id": key(4), "node_id": key(5), "method": "geneve", "service_ip": "203.0.113.20", "geneve": {"vni": 800}},
                      {"id": key(6), "node_id": key(7), "method": "gre", "service_ip": "203.0.113.21"}])
        state = {"groups": {group["id"]: {"active": True, "owner": key(3), "group": group}}, "operations": {}}
        settings = {"settings": DEFAULTS, "connections": []}
        with tempfile.TemporaryDirectory() as root:
            paths = Paths(root)
            with patch("panel.engine.run", side_effect=PanelError("route missing")):
                restored = topology_views(settings, state, key(3), paths=paths)
            self.assertEqual(restored["v2_driver_unavailable"], {group["id"] + ":" + key(4): "geneve_route"})
            self.assertEqual([driver_for(link).method for link in restored["v2_devices"]], ["gre"])
            self.assertTrue(group["listeners"][0]["members"][0]["enabled"])
            with patch("panel.engine.run", return_value=subprocess.CompletedProcess([], 0, '[{"prefsrc":"192.0.2.11","dev":"eth1"}]', "")):
                recovered = topology_views(settings, state, key(3), paths=paths)
            self.assertEqual([driver_for(link).method for link in recovered["v2_devices"]], ["geneve", "gre"])

    def test_geneve_validates_the_route_source_and_owns_its_vni(self):
        group = data([{"id": key(4), "node_id": key(5), "method": "geneve", "service_ip": "203.0.113.20",
                       "geneve": {"vni": 15000}}])
        listener = group["listeners"][0]
        link = gre_link(key(3), listener, listener["members"][0])
        driver = driver_for(link)
        self.assertEqual(link["listen_port"], 6081)
        self.assertNotIn("local", driver.create(link, "eth1"))
        attrs = {"id": 15000, "port": 6081, "remote": link["outer_peer"]}
        row = {"ifalias": driver.marker(link), "linkinfo": {"info_kind": "geneve", "info_data": attrs}}
        self.assertTrue(driver.owns(link, row))
        self.assertFalse(driver.owns(dict(link, outer_peer="203.0.113.21"), row))

        def tool(*args, **kwargs):
            return subprocess.CompletedProcess(args, 0, '[{"prefsrc":"192.0.2.10","dev":"eth1"}]', "")

        with tempfile.TemporaryDirectory() as root:
            engine = Engine(Paths(root), tool)
            with self.assertRaisesRegex(PanelError, "route to the GENEVE endpoint"):
                engine.check_udp_overlays([link], {link["outer_local"]: "eth1"})

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
