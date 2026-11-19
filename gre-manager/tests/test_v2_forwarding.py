"""Properties and compatibility of the v2 forwarding compiler."""
import random
import unittest
import uuid

from panel.engine import build_rules
from panel.model import DEFAULTS, connection
from panel.v2_config import normalize_group, participant_order
from panel.v2_forwarding import active_members, gre_link, topology_views


def key(index):
    return uuid.UUID(int=index).hex


def data(members):
    return normalize_group({"id": key(1), "name": "Fixture", "listeners": [{
        "id": key(2), "node_id": key(3), "ip": "192.0.2.10", "outer_ip": "192.0.2.11",
        "ports": "5100", "port_map": {"5100": 5000}, "members": members,
    }]})


class ForwardingTests(unittest.TestCase):
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
