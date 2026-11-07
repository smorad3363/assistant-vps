import importlib.util
import json
from pathlib import Path
import subprocess
import tempfile
import unittest
from unittest.mock import patch

spec = importlib.util.spec_from_file_location("pair_mtu", Path(__file__).with_name("pair.py"))
pair = importlib.util.module_from_spec(spec)
spec.loader.exec_module(pair)


class MtuTests(unittest.TestCase):
    def setUp(self):
        identity, tunnel, local, peer, key = pair.pair_values("192.0.2.1", "192.0.2.2")
        self.c = dict(id=identity, tunnel=tunnel, role="iran",
                      outer_local="192.0.2.1", outer_peer="192.0.2.2",
                      service_ip="192.0.2.1", wan="eth0", local_tun=local,
                      peer_tun=peer, key=key, mtu=1450, ports="all")

    def test_live_mtu_updates_mss_and_saved_profile_without_restart(self):
        old_mss = {tuple(args) for table, chain, args in pair.rules(self.c) if table == "mangle"}
        active = set(old_mss)
        calls = []
        def fake_run(*args, **kwargs):
            calls.append(args)
            if args[:5] == ("ip", "-j", "-d", "link", "show"):
                return subprocess.CompletedProcess(args, 0, json.dumps([{
                    "linkinfo": {"info_kind": "gre", "info_data": {
                        "local": self.c["outer_local"], "remote": self.c["outer_peer"],
                        "ikey": self.c["key"]}}}]), "")
            if len(args) >= 8 and args[0] == "iptables":
                ix = next((i for i,x in enumerate(args) if x in ("-C", "-I", "-D")), None)
                if ix is not None:
                    cmd=args[ix]
                    if cmd=="-I":
                        active.add(tuple(args[ix+3:]))
                    else:
                        item=tuple(args[ix+2:])
                        if cmd=="-C":
                            return subprocess.CompletedProcess(args, 0 if item in active else 1, "", "")
                        if cmd=="-D":
                            active.remove(item)
            return subprocess.CompletedProcess(args, 0, "", "")
        with tempfile.TemporaryDirectory() as dirname:
            root=Path(dirname)
            pair.save(root / (self.c["id"] + ".json"),self.c)
            with patch.object(pair,"ROOT",root), patch.object(pair,"run",side_effect=fake_run):
                pair.set_mtu(self.c["id"],"1400")
            updated=json.loads((root / (self.c["id"] + ".json")).read_text())
            self.assertEqual(updated["mtu"],1400)
            self.assertEqual(len(list((root/"backups").glob("*.json"))),1)
        self.assertFalse(any(a[0]=="systemctl" for a in calls))
        self.assertTrue(any(a[:5]==("ip","link","set","dev",self.c["tunnel"]) and a[-2:]==("mtu",1400) for a in calls))
        self.assertFalse(any("--set-mss" in a and "1410" in a for a in active))
        self.assertEqual(sum(("--set-mss","1360") == a[-2:] for a in active),2)

    def test_invalid_mtu_rejected_unchanged(self):
        with tempfile.TemporaryDirectory() as dirname:
            root=Path(dirname)
            pair.save(root / (self.c["id"] + ".json"),self.c)
            with patch.object(pair,"ROOT",root):
                for invalid in ("0","12800","abc","1477","500"):
                    with self.subTest(invalid=invalid), self.assertRaises(ValueError):
                        pair.set_mtu(self.c["id"],invalid)
            self.assertEqual(json.loads((root / (self.c["id"] + ".json")).read_text()),self.c)

    def test_inactive_pair_only_updates_profile(self):
        def fake_run(*args,**kwargs):
            if args[:5]==("ip","-j","-d","link","show"):
                return subprocess.CompletedProcess(args,1,"","not found")
            return subprocess.CompletedProcess(args,0,"","")
        with tempfile.TemporaryDirectory() as dirname:
            root=Path(dirname)
            pair.save(root / (self.c["id"] + ".json"),self.c)
            with patch.object(pair,"ROOT",root),patch.object(pair,"run",side_effect=fake_run) as mock:
                pair.set_mtu(self.c["id"],"1400")
                self.assertFalse(any("-I" in x.args for x in mock.call_args_list))
                self.assertEqual(pair.load(self.c["id"])["mtu"],1400)

if __name__=="__main__":
    unittest.main()
