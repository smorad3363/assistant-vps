"""Resource policy, directionality and restart-safe rates."""
import copy
from pathlib import Path
import random
import tempfile
import unittest

from panel.engine import build_rules
from panel.model import DEFAULTS, PanelError
from panel.store import Paths
from panel.v2_config import normalize_group
from panel.v2_forwarding import gre_link, topology_views, traffic_caps
from panel.v2_resources import HostSampler, admission_pressure
from test_v2_forwarding import data, key


class PolicyTests(unittest.TestCase):
    def test_group_budget_is_shared_by_protocol_and_destination(self):
        group = data([{"id": key(i), "node_id": key(i + 10), "method": "direct", "service_ip": f"203.0.113.{i}"}
                      for i in (4, 5, 6, 7)])
        group["limits"] = {"up": 100, "down": 80}
        config = {"settings": DEFAULTS, "connections": []}
        state = {"groups": {group["id"]: {"active": True, "owner": key(3), "group": group}}, "operations": {}}
        view = topology_views(config, state, key(3))
        filters = build_rules(view, {"192.0.2.10": "eth0"})["filter"]["GMP_FWD"]
        for direction in ("ORIGINAL", "REPLY"):
            matches = [rule for rule in filters if "--hashlimit-name" in rule and direction in rule]
            self.assertEqual(len(matches), 8)
            self.assertEqual(len({rule[rule.index("--hashlimit-name") + 1] for rule in matches}), 1)
            expected = "12500000b/s" if direction == "ORIGINAL" else "10000000b/s"
            self.assertTrue(all(expected in rule for rule in matches))
            self.assertTrue(all(int(rule[rule.index("--hashlimit-burst") + 1][:-1]) > int(expected[:-3]) for rule in matches))
        self.assertNotEqual(filters[0][filters[0].index("--hashlimit-name") + 1],
                            filters[2][filters[2].index("--hashlimit-name") + 1])
        rng = random.Random(1035)
        listener = group["listeners"][0]
        for _ in range(50):
            hosts = rng.randint(1, 32)
            cap = rng.randint(1, 10000)
            group["limits"]["up"] = cap
            group["listeners"] = [dict(listener, node_id=key(i + 100)) for i in range(hosts)]
            speed = next(iter(traffic_caps(config, group, listener, listener["members"], "up", "5100")))[1]
            self.assertAlmostEqual(speed * hosts, cap)

    def test_per_side_mtu_and_mss_keep_the_link_identity(self):
        group = data([{"id": key(4), "node_id": key(5), "method": "gre", "service_ip": "203.0.113.20"}])
        listener = group["listeners"][0]
        original = gre_link(key(3), listener, listener["members"][0])
        listener["members"][0]["link_settings"] = {"ingress": {"mtu": 1240, "mss_mode": "manual", "mss": 1190},
                                                     "destination": {"mtu": 1300, "mss_mode": "pmtu"}}
        group = normalize_group(group)
        listener = group["listeners"][0]
        local, remote = (gre_link(key(3), listener, listener["members"][0], receiving=side) for side in (False, True))
        self.assertEqual(local["key"], remote["key"])
        self.assertEqual(local["tunnel"], original["tunnel"])
        self.assertEqual((local["mtu"], remote["mtu"]), (1240, 1300))
        state = {"groups": {group["id"]: {"active": True, "owner": key(3), "group": group}}, "operations": {}}
        config = {"settings": DEFAULTS, "connections": []}
        receiver = topology_views(config, state, key(5))
        output = build_rules(receiver, {"203.0.113.20": "eth0"})["mangle"]["GMP_MSS_LOCAL"]
        self.assertEqual(len(output), 1)
        self.assertIn("--clamp-mss-to-pmtu", output[0])
        second = copy.deepcopy(group)
        second["id"] = key(100)
        second["listeners"][0]["members"][0]["link_settings"]["ingress"]["mtu"] = 1270
        state["groups"][second["id"]] = {"active": True, "owner": key(3), "group": second}
        with self.assertRaisesRegex(PanelError, "agree on the local MTU and MSS"):
            topology_views(config, state, key(3))

    def test_pressure_drop_only_matches_unconfirmed_first_packets(self):
        group = data([{"id": key(4), "node_id": key(5), "method": "direct", "service_ip": "203.0.113.20"}])
        state = {"groups": {group["id"]: {"active": True, "owner": key(3), "group": group}}, "operations": {}}
        view = topology_views({"settings": DEFAULTS, "connections": [], "v2_conntrack_busy": True}, state, key(3))
        rules = build_rules(view, {"192.0.2.10": "eth0"})["filter"]["GMP_FWD"]
        blocked = [rule for rule in rules if rule[-1] == "DROP"]
        self.assertEqual(len(blocked), 2)
        self.assertTrue(all(rule[-7:-2] == ["--ctstate", "NEW", "!", "--ctstatus", "CONFIRMED"] for rule in blocked))

    def test_conntrack_rises_and_recovers_with_separate_thresholds(self):
        with tempfile.TemporaryDirectory() as root:
            proc = Path(root)
            table = proc / "sys/net/netfilter"
            table.mkdir(parents=True)
            (table / "nf_conntrack_max").write_text("100")
            counter = table / "nf_conntrack_count"
            settings = {"v2_conntrack_guard": {"high": 90, "low": 75}}
            busy = False
            for count, expected in ((89, False), (90, True), (82, True), (75, False), (91, True)):
                counter.write_text(str(count))
                busy = admission_pressure(settings, busy, proc)
                self.assertIs(busy, expected)
            counter.unlink()
            self.assertTrue(admission_pressure(settings, busy, proc))

    def test_interface_rates_reject_counter_resets_and_changes_of_boot(self):
        with tempfile.TemporaryDirectory() as root:
            root = Path(root)
            proc, network = root / "proc", root / "net"
            (proc / "sys/kernel/random").mkdir(parents=True)
            boot = proc / "sys/kernel/random/boot_id"
            boot.write_text("first")
            stats = network / "eth0/statistics"
            stats.mkdir(parents=True)
            (stats.parent / "ifindex").write_text("3")
            counter = stats / "rx_bytes"
            time = iter((10, 12, 14, 16))
            sampler = HostSampler(Paths(root / "panel"), proc, network, clock=lambda: next(time))
            counter.write_text("100")
            self.assertNotIn("rx_bytes_per_second", sampler.snapshot()["interfaces"]["eth0"])
            counter.write_text("500")
            self.assertEqual(sampler.snapshot()["interfaces"]["eth0"]["rx_bytes_per_second"], 200)
            counter.write_text("0")
            self.assertNotIn("rx_bytes_per_second", sampler.snapshot()["interfaces"]["eth0"])
            counter.write_text("1000")
            boot.write_text("next")
            self.assertNotIn("rx_bytes_per_second", sampler.snapshot()["interfaces"]["eth0"])
