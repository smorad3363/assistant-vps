import importlib.util
from pathlib import Path
import subprocess
import unittest
from unittest.mock import patch

spec = importlib.util.spec_from_file_location("pair_docker_test", Path(__file__).with_name("pair.py"))
pair = importlib.util.module_from_spec(spec)
spec.loader.exec_module(pair)


class DockerWireGuardTests(unittest.TestCase):
    def setUp(self):
        identity, tunnel, local, peer, key = pair.pair_values("198.51.100.1", "203.0.113.2")
        self.cfg = dict(id=identity, tunnel=tunnel, role="foreign",
                        outer_local="198.51.100.1", outer_peer="203.0.113.2",
                        service_ip="198.51.100.1", wan="eth0",
                        local_tun=local, peer_tun=peer, key=key,
                        mtu=1420, ports="all")

    def test_iran_never_changes_docker(self):
        self.cfg["role"] = "iran"
        with patch.object(pair, "run") as mocked:
            pair.sync_docker_wireguard(self.cfg)
            mocked.assert_not_called()

    def test_direct_rule_has_specific_source_destination_and_port(self):
        rule = pair.docker_wireguard_rule(self.cfg)
        joined = " ".join(rule)
        self.assertIn("-i " + self.cfg["tunnel"], joined)
        self.assertIn("-s " + self.cfg["peer_tun"] + "/32", joined)
        self.assertIn("-d " + self.cfg["local_tun"] + "/32", joined)
        self.assertIn("--dport 51820", joined)
        self.assertIn("-j DOCKER", joined)
        self.assertNotIn("--dport 10086", joined)

    def test_creates_rule_when_docker_udp_is_published(self):
        calls = []
        published = "-A DOCKER ! -i br-a -p udp -m udp --dport 51820 -j DNAT --to-destination 172.18.0.2:51820\n"
        def mock_run(*args, **kwargs):
            calls.append(args)
            if args[-2:] == ("-S", "DOCKER"):
                return subprocess.CompletedProcess(args, 0, published, "")
            if args[-2:] == ("-S", "PREROUTING"):
                return subprocess.CompletedProcess(args, 0, "-P PREROUTING ACCEPT\n-A PREROUTING -j ACCEPT\n", "")
            if "-C" in args:
                return subprocess.CompletedProcess(args, 1, "", "")
            return subprocess.CompletedProcess(args, 0, "", "")
        with patch.object(pair, "run", side_effect=mock_run):
            pair.sync_docker_wireguard(self.cfg)
        self.assertEqual(sum("-I" in c for c in calls), 1)
        self.assertTrue(any("-I" in c and c[-1] == "DOCKER" for c in calls))

    def test_no_rule_when_no_published_wireguard_udp(self):
        def mock_run(*args, **kwargs):
            if args[-2:] == ("-S", "DOCKER"):
                return subprocess.CompletedProcess(args, 0, "-A DOCKER -p tcp --dport 10086 -j DNAT --to-destination 172.18.0.2:10086\n", "")
            if "-C" in args:
                return subprocess.CompletedProcess(args, 1, "", "")
            return subprocess.CompletedProcess(args, 0, "", "")
        with patch.object(pair, "run", side_effect=mock_run) as mocked:
            pair.sync_docker_wireguard(self.cfg)
        self.assertFalse(any("-I" in call.args for call in mocked.call_args_list))


    def test_nondefault_public_port_tracks_real_wg0(self):
        published = "-A DOCKER ! -i br-a -p udp --dport 51822 -j DNAT --to-destination 172.18.0.2:51821\n"
        calls = []
        def mock_run(*args, **kwargs):
            calls.append(args)
            if args[-2:] == ("-S", "DOCKER"):
                return subprocess.CompletedProcess(args, 0, published, "")
            if args[-2:] == ("-S", "PREROUTING"):
                return subprocess.CompletedProcess(args, 0, "-P PREROUTING ACCEPT\n", "")
            if args[:2] == ("docker", "exec"):
                return subprocess.CompletedProcess(args, 0, "51821\n", "")
            return subprocess.CompletedProcess(args, 0, "", "")
        with patch.object(pair, "run", side_effect=mock_run):
            pair.sync_docker_wireguard(self.cfg)
        inserted = [x for x in calls if "-I" in x]
        self.assertEqual(len(inserted), 1)
        self.assertIn("51822", inserted[0])
        self.assertNotIn("51820", inserted[0])

    def test_mismatch_removes_owned_jump_and_defers_to_wireguard_sync(self):
        published = "-A DOCKER -p udp --dport 51820 -j DNAT --to-destination 172.18.0.2:51820\n"
        owned = "-A PREROUTING " + " ".join(pair.docker_wireguard_rule(self.cfg)) + "\n"
        calls = []
        def mock_run(*args, **kwargs):
            calls.append(args)
            if args[-2:] == ("-S", "DOCKER"):
                return subprocess.CompletedProcess(args, 0, published, "")
            if args[-2:] == ("-S", "PREROUTING"):
                return subprocess.CompletedProcess(args, 0, owned, "")
            if args[:2] == ("docker", "exec"):
                return subprocess.CompletedProcess(args, 0, "51821\n", "")
            return subprocess.CompletedProcess(args, 0, "", "")
        with patch.object(pair, "run", side_effect=mock_run):
            pair.sync_docker_wireguard(self.cfg)
        self.assertTrue(any("-D" in x for x in calls))
        self.assertFalse(any("-I" in x for x in calls))

    def test_change_from_old_port_removes_old_rule_and_adds_new(self):
        published = "-A DOCKER -p udp --dport 41821 -j DNAT --to-destination 172.18.0.2:51821\n"
        old = "-A PREROUTING " + " ".join(pair.docker_wireguard_rule(self.cfg)) + "\n"
        calls = []
        def mock_run(*args, **kwargs):
            calls.append(args)
            if args[-2:] == ("-S", "DOCKER"):
                return subprocess.CompletedProcess(args, 0, published, "")
            if args[-2:] == ("-S", "PREROUTING"):
                return subprocess.CompletedProcess(args, 0, old, "")
            if args[:2] == ("docker", "exec"):
                return subprocess.CompletedProcess(args, 0, "51821\n", "")
            return subprocess.CompletedProcess(args, 0, "", "")
        with patch.object(pair, "run", side_effect=mock_run):
            pair.sync_docker_wireguard(self.cfg)
        self.assertEqual(sum("-D" in x for x in calls), 1)
        self.assertEqual(sum("-I" in x for x in calls), 1)
        self.assertTrue(any("-I" in x and "41821" in x for x in calls))

    def test_ambiguous_udp_publications_cannot_hijack_other_service(self):
        published = (
            "-A DOCKER -p udp --dport 51820 -j DNAT --to-destination 172.18.0.2:51820\n"
            "-A DOCKER -p udp --dport 51822 -j DNAT --to-destination 172.18.0.9:51822\n"
        )
        calls = []
        def mock_run(*args, **kwargs):
            calls.append(args)
            if args[-2:] == ("-S", "DOCKER"):
                return subprocess.CompletedProcess(args, 0, published, "")
            return subprocess.CompletedProcess(args, 0, "", "")
        with patch.object(pair, "run", side_effect=mock_run):
            pair.sync_docker_wireguard(self.cfg)
        self.assertFalse(any("-I" in x for x in calls))

    def test_property_port_validation_and_differential_default(self):
        import random
        rng = random.Random(51821)
        self.assertEqual(pair.docker_wireguard_rule(self.cfg),
                         pair.docker_wireguard_rule(self.cfg, 51820))
        for _ in range(2000):
            p = rng.randrange(1, 65536)
            rule = pair.docker_wireguard_rule(self.cfg, p)
            self.assertIn(str(p), rule)
            self.assertEqual(rule[rule.index("--dport")+1], str(p))
        for bad in (0, -1, 65536, True, "51821;rm"):
            with self.assertRaises(ValueError):
                pair.docker_wireguard_rule(self.cfg, bad)

if __name__ == "__main__":
    unittest.main()