"""Properties and compatibility of the v2 forwarding compiler."""
import random
import subprocess
import tempfile
import unittest
from unittest.mock import patch
import uuid

from panel.agent import v2_participant
from panel.demo import DemoEngine
from panel.engine import build_rules, discovered_ssh_ports
from panel.model import DEFAULTS, PanelError, connection
from panel.store import Paths, Store
from panel.v2_config import local_claims, normalize_group, participant_order
from panel.v2_forwarding import active_members, gre_link, installed_topology, require_ssh_protection, topology_views, with_ssh_protection


def key(index):
    return uuid.UUID(int=index).hex


def data(members):
    return normalize_group({"id": key(1), "name": "Fixture", "listeners": [{
        "id": key(2), "node_id": key(3), "ip": "192.0.2.10", "outer_ip": "192.0.2.11",
        "ports": "5100", "port_map": {"5100": 5000}, "members": members,
    }]})


class ForwardingTests(unittest.TestCase):
    def test_managed_direct_mapping_checks_the_destination_management_port(self):
        address = "203.0.113.20"
        group = data([{"id": key(4), "node_id": key(5), "method": "direct", "managed": True, "service_ip": address}])
        change = {"group": group, "group_id": group["id"], "owner": key(3), "participants": [key(3), key(5)]}
        addresses = {address: "eth0"}
        config = {"settings": dict(DEFAULTS, ssh_ports=[5000])}
        with self.assertRaisesRegex(PanelError, "protected ports"):
            local_claims(change, key(5), config, addresses)
        change["group"]["listeners"][0]["port_map"]["5100"] = 6000
        self.assertFalse(local_claims(change, key(5), config, addresses))
        config["ssh_discovery_error"] = "Unavailable SSH discovery"
        with self.assertRaisesRegex(PanelError, "Unavailable SSH discovery"):
            local_claims(change, key(5), config, addresses)

    def test_discovery_combines_bound_addresses_runtime_daemons_and_systemd_sockets(self):
        output = {
            "sshd": "port 22\nport 35555\nlistenaddress 127.0.0.1:43157\nlistenaddress [::]:57777\n",
            "ss": 'LISTEN 0 128 0.0.0.0:34471 0.0.0.0:* users:(("sshd",pid=40,fd=3))\n'
                  'LISTEN 0 128 [::]:54321 [::]:* users:(("systemd",pid=1,fd=7))\n'
                  'LISTEN 0 128 0.0.0.0:6111 0.0.0.0:* users:(("python",pid=50,fd=4))\n',
            "systemctl": "[::]:54321 ssh.socket ssh.service\n/run/example.socket other.socket other.service\n",
        }
        with patch.dict("os.environ", {"SSH_CONNECTION": "192.0.2.1 42100 192.0.2.2 23351"}), \
                patch("panel.engine.run", side_effect=lambda tool, *_, **__: subprocess.CompletedProcess([], 0, output[tool])):
            self.assertEqual(discovered_ssh_ports(), [22, 23351, 34471, 35555, 43157, 54321, 57777])
        with patch("panel.engine.run", return_value=subprocess.CompletedProcess([], 0, "", "Cannot open netlink socket")):
            with self.assertRaisesRegex(PanelError, "verify the host's SSH"):
                discovered_ssh_ports()

    def test_incomplete_discovery_retains_previous_and_manual_ports(self):
        with tempfile.TemporaryDirectory() as root:
            paths = Paths(root)
            config = {"settings": dict(DEFAULTS, ssh_ports=[2222]), "connections": []}
            with patch("panel.engine.discovered_ssh_ports", return_value=[30001]):
                with_ssh_protection(config, paths, remember=True)
            with patch("panel.engine.discovered_ssh_ports", side_effect=PanelError("Cannot inspect SSH")):
                view = with_ssh_protection(config, paths)
            self.assertEqual(view["settings"]["ssh_ports"], [2222, 30001])
            view["v2_listeners"] = [(None, None, {"protocols": ["udp"]})]
            require_ssh_protection(view)
            view["v2_listeners"][0][2]["protocols"].append("tcp")
            with self.assertRaisesRegex(PanelError, "Cannot inspect SSH"):
                require_ssh_protection(view)
            require_ssh_protection(view, view)

    def test_single_direct_matches_legacy_dnat_and_management_protection(self):
        legacy = connection({"kind": "direct", "listen_ip": "192.0.2.10", "target_host": "203.0.113.20",
                             "ports": "5100", "port_map": {"5100": 5000}}, DEFAULTS)
        group = data([{"id": key(4), "node_id": key(5), "method": "direct", "service_ip": "203.0.113.20"}])
        config = {"settings": dict(DEFAULTS, ssh_ports=[22, 6111]), "connections": [], "web_enabled": True}
        state = {"groups": {group["id"]: {"active": True, "owner": key(3), "group": group}}, "operations": {}}
        interface = {"192.0.2.10": "eth0"}
        left = build_rules(dict(config, connections=[legacy]), interface)["nat"]["GMP_PRE"]
        right = build_rules(topology_views(config, state, key(3)), interface)["nat"]["GMP_PRE"]
        self.assertEqual([rule for rule in left if rule[-1] == "ACCEPT"], [rule for rule in right if rule[-1] == "ACCEPT"])
        dnat = lambda rules: [(rule[rule.index("-p") + 1], rule[rule.index("--dport") + 1], rule[-1])
                              for rule in rules if rule[-3:-1] == ["DNAT", "--to-destination"]]
        self.assertEqual(dnat(left), dnat(right))
        self.assertEqual(dnat(right), [("tcp", "5100", "203.0.113.20:5000"), ("udp", "5100", "203.0.113.20:5000")])

    def test_gre_ends_sync_and_prepare_cannot_admit_ingress(self):
        group = data([{"id": key(4), "node_id": key(5), "method": "gre", "service_ip": "203.0.113.20",
                       "outer_ip": "203.0.113.21"}])
        listener, = group["listeners"]
        member, = listener["members"]
        left, right = gre_link(key(3), listener, member), gre_link(key(3), listener, member, True)
        self.assertEqual(left["local_tun"], right["peer_tun"])
        self.assertEqual(left["key"], right["key"])
        self.assertEqual(participant_order(group, {key(3), key(5)}), [key(5), key(3)])
        config = {"settings": DEFAULTS, "connections": []}
        prepared = {"groups": {}, "operations": {key(8): {
            "phase": "prepared", "owner": key(3), "change": {"group": group},
        }}}
        ingress = topology_views(config, prepared, key(3))
        egress = topology_views(config, prepared, key(5))
        self.assertEqual(ingress["v2_devices"], [left])
        self.assertFalse(ingress["v2_listeners"])
        self.assertEqual(egress["connections"][0]["v2_ports"], {"tcp": [(5000, 5000)], "udp": [(5000, 5000)]})
        # A persisted P2 group did not have explicit outer endpoints or MTU.
        del listener["outer_ip"], member["outer_ip"], member["mtu"], member["draining"]
        migrated = topology_views(config, prepared, key(3))
        self.assertEqual(migrated["v2_devices"][0]["outer_local"], listener["ip"])
        self.assertEqual(migrated["v2_devices"][0]["outer_peer"], member["service_ip"])
        self.assertEqual(migrated["v2_devices"][0]["mtu"], 1280)

    def test_generated_member_policy_selects_only_the_best_active_priority(self):
        rng = random.Random(2305100)
        for case in range(128):
            members = [{"id": key(index + 10), "priority": rng.randrange(4), "enabled": rng.choice((True, False)),
                        "draining": rng.choice((True, False)), "weight": rng.randint(1, 1000)} for index in range(16)]
            candidates = [member for member in members if member["enabled"] and not member["draining"]]
            selected = active_members({"members": members}, "weighted")
            with self.subTest(case=case):
                self.assertCountEqual(selected, [item for item in candidates if not any(
                    other["priority"] < item["priority"] for other in candidates
                )])
                self.assertEqual(active_members({"members": members}, "failover"), selected[:1])

    def test_discovered_ssh_port_is_protected_in_reserve_apply_and_restore(self):
        ports = [23351, 34471, 65535]
        with tempfile.TemporaryDirectory() as root, patch("panel.engine.discovered_ssh_ports", return_value=ports):
            paths = Paths(root)
            store = Store(paths)
            engine = DemoEngine()
            participant = v2_participant(paths, engine)
            owner = participant.node_id
            group = normalize_group({"id": key(1), "name": "All ports", "listeners": [{
                "id": key(2), "node_id": owner, "ip": "192.0.2.10", "ports": "all",
                "members": [{"id": key(4), "node_id": key(5), "method": "direct", "service_ip": "203.0.113.20"}],
            }]})
            change = {"id": key(7), "owner": owner, "group_id": key(1), "expected_revision": 0,
                      "participants": [owner], "group": group}
            participant.request(owner, "prepare", change)
            participant.request(owner, "commit", change)
            restored = installed_topology(paths, store.config())
            for config in (engine.current, restored):
                self.assertTrue(set(ports).issubset(config["settings"]["ssh_ports"]))
                forwarded = set()
                for rule in build_rules(config, engine.interfaces())["nat"]["GMP_PRE"]:
                    if "DNAT" in rule:
                        bounds = list(map(int, rule[rule.index("--dport") + 1].split(":")))
                        forwarded.update(range(bounds[0], bounds[-1] + 1))
                self.assertIn(6111, forwarded)
                self.assertTrue(set(ports).isdisjoint(forwarded))
