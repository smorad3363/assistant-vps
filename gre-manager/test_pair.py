import importlib.util
from pathlib import Path
import unittest
import json
import subprocess
import tempfile
from unittest.mock import patch

spec = importlib.util.spec_from_file_location("pair", Path(__file__).with_name("pair.py"))
pair = importlib.util.module_from_spec(spec)
spec.loader.exec_module(pair)


class PairTests(unittest.TestCase):
    def test_ports(self):
        self.assertEqual(pair.parse_ports(" 443, 8080 : 80 , 65535 "), [[443, 443], [8080, 80], [65535, 65535]])
        self.assertEqual(pair.parse_ports("all"), "all")
        for bad in ("", "22", "22:443", "0", "80:65536", "80,,443", "80,", "80,80:81", "80;id", "all,80", "1:2:3", "-1"):
            with self.subTest(bad=bad), self.assertRaises(ValueError):
                pair.parse_ports(bad)

    def test_symmetric_endpoints(self):
        first = pair.pair_values("94.184.22.49", "65.109.240.226")
        reverse = pair.pair_values("65.109.240.226", "94.184.22.49")
        self.assertEqual(first[:2], reverse[:2])
        self.assertEqual(first[2:4], reverse[2:4][::-1])
        self.assertEqual(first[4], reverse[4])
        self.assertLessEqual(len(first[1]), 15)

    def test_role_firewall(self):
        identity, tunnel, local, peer, key = pair.pair_values("192.0.2.1", "192.0.2.2")
        c = dict(id=identity, tunnel=tunnel, role="iran", outer_local="192.0.2.1", outer_peer="192.0.2.2", service_ip="192.0.2.1", wan="eth0", local_tun=local, peer_tun=peer, key=key, mtu=1400, ports=[[8080, 80]])
        pair.validate(c)
        rendered = [" ".join(rule[2]) for rule in pair.rules(c)]
        self.assertTrue(any("--dport 8080" in r and f"{peer}:80" in r for r in rendered))
        c["ports"] = "all"
        self.assertEqual(sum("! --dport 22" in r for _, _, args in pair.rules(c) for r in [" ".join(args)]), 2)
        c["role"] = "foreign"
        foreign = [" ".join(args) for _, _, args in pair.rules(c)]
        self.assertTrue(all("--dport" not in r for r in foreign))
        self.assertTrue(any(f"-i {tunnel}" in r and "--to-destination 192.0.2.1" in r for r in foreign))

    def test_failed_edit_restores_previous_configuration(self):
        identity, tunnel, local, peer, key = pair.pair_values("192.0.2.1", "192.0.2.2")
        old = dict(id=identity, tunnel=tunnel, role="iran", outer_local="192.0.2.1", outer_peer="192.0.2.2", service_ip="192.0.2.1", wan="eth0", local_tun=local, peer_tun=peer, key=key, mtu=1400, ports=[[80, 80]])
        calls = []
        def fake_run(*args, **kwargs):
            calls.append(args)
            stdout = ""
            if args[:5] == ("ip", "-j", "-4", "route", "get"):
                stdout = json.dumps([dict(prefsrc="192.0.2.1", dev="eth0")])
            elif args[:5] == ("ip", "-j", "-4", "addr", "show"):
                stdout = json.dumps([dict(ifname="eth0", addr_info=[dict(local="192.0.2.1")])])
            elif args[:3] == ("systemctl", "enable", "--now"):
                raise subprocess.CalledProcessError(1, args, stderr="simulated start failure")
            return subprocess.CompletedProcess(args, 0, stdout, "")
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp)
            pair.save(root / (identity + ".json"), old)
            answers = iter(["1", "192.0.2.1", "192.0.2.2", "192.0.2.1", "8080:80"])
            with patch.object(pair, "ROOT", root), patch.object(pair, "legacy_config", return_value=None), patch.object(pair, "run", side_effect=fake_run), patch.object(pair, "down"), patch.object(pair, "ask", side_effect=lambda *a: next(answers)):
                with self.assertRaises(subprocess.CalledProcessError):
                    pair.configure()
            self.assertEqual(json.loads((root / (identity + ".json")).read_text()), old)
            self.assertEqual(len(list((root / "backups").glob("*.json"))), 1)
            self.assertIn(("systemctl", "start", "gremgr-pair@" + identity + ".service"), calls)


if __name__ == "__main__":
    unittest.main()
