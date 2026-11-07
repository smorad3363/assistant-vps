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


if __name__ == "__main__":
    unittest.main()
