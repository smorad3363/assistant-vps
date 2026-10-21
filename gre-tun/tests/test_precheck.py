"""No real sockets, network changes, or external internet required."""
import io
import json
import socket
import struct
import sys
from pathlib import Path
import unittest
from unittest.mock import patch
from types import SimpleNamespace
sys.path.insert(0, str(Path(__file__).resolve().parents[1] / 'src'))
from gre_tun import cli, precheck

PEER='1.1.1.1'
TOKEN='aabbccdd11223344556677889900aabb'

class PrecheckTests(unittest.TestCase):
    def test_rejects_non_public_target(self):
        for ip in ('127.0.0.1', '10.0.0.1', '224.0.0.1', '0.0.0.0', 'nope'):
            with self.assertRaises(ValueError):precheck.validate_peer(ip)

    def test_rejects_bad_token(self):
        for v in ('x'*32, 'aa'*14, 'aa'*17, '\\x00'*32):
            with self.assertRaises(ValueError):precheck.validate_token(v)

    def test_protocol_frame_accepts_exact_ip_and_token(self):
        blob=precheck.packet(precheck.HELLO,bytes.fromhex(TOKEN))
        iphdr=bytearray(20)
        iphdr[0]=0x45
        iphdr[9]=socket.IPPROTO_GRE
        iphdr[12:16]=socket.inet_aton(PEER)
        self.assertEqual(precheck.unpack(bytes(iphdr)+blob,PEER,bytes.fromhex(TOKEN)),precheck.HELLO)
        self.assertIsNone(precheck.unpack(bytes(iphdr)+blob,'203.0.113.1',bytes.fromhex(TOKEN)))
        self.assertIsNone(precheck.unpack(bytes(iphdr)+blob,PEER,b'0'*16))
        iphdr[6]=0x20
        self.assertIsNone(precheck.unpack(bytes(iphdr)+blob,PEER,bytes.fromhex(TOKEN)))

    def test_passive_no_tunnel_config_or_network_writes(self):
        def fake_run(args,timeout=5):
            if args[:4]==['ip','-j','-4','route']:
                return SimpleNamespace(returncode=0,stdout=json.dumps([{'src':'192.0.2.20','dev':'ens18'}]))
            return SimpleNamespace(returncode=1,stdout='')
        with patch.object(precheck,'run',side_effect=fake_run) as run, patch.object(precheck.os,'geteuid',return_value=0):
            output=precheck.passive(PEER)
        self.assertEqual(output['gre_path'],'NOT_TESTED')
        self.assertTrue(any(c['name']=='Public IPv4 ICMP' and c['status']=='UNKNOWN' for c in output['checks']))
        self.assertTrue(all(call.args[0][0] in ('ip','ping') for call in run.call_args_list))

    def test_cli_peer_works_without_config(self):
        capture=io.StringIO()
        with patch.object(precheck,'run',return_value=None),patch('sys.stdout',capture):
            self.assertEqual(cli.main(['test','--peer',PEER]),6)
        self.assertIn('Pre-tunnel test',capture.getvalue())
        self.assertIn('NOT verified',capture.getvalue())

    def test_precheck_does_not_confuse_icmp_with_GRE_PASS(self):
        with patch.object(precheck,'run',side_effect=[SimpleNamespace(returncode=0,stdout='[{"src":"192.0.2.2","dev":"ens18"}]'),SimpleNamespace(returncode=0)]):
            r=precheck.passive(PEER)
        self.assertEqual(r['gre_path'],'NOT_TESTED')
        self.assertEqual(r['checks'][2]['status'],'UNKNOWN')

if __name__=='__main__':unittest.main()

class ActiveProbeSafetyTests(unittest.TestCase):
    def test_does_not_open_raw_socket_without_privilege(self):
        with patch.object(precheck.os,'geteuid',return_value=1000), patch.object(precheck.socket,'socket') as raw:
            with self.assertRaises(PermissionError):
                precheck.exchange(PEER,TOKEN,listen=True,seconds=1)
            raw.assert_not_called()

    def test_duration_never_exceeds_maximum(self):
        self.assertLessEqual(precheck.MAX_WAIT,120)
        self.assertGreaterEqual(precheck.MAX_WAIT,60)

    def test_active_requires_matching_peer_and_token(self):
        with self.assertRaises(ValueError):precheck.exchange('10.0.0.10',TOKEN)
        with self.assertRaises(ValueError):precheck.exchange(PEER,'not-an-acceptable-token')

class ZeroConfigInteractiveTests(unittest.TestCase):
    def test_test_menu_does_not_force_setup_or_save_config(self):
        fake={'peer_ip':PEER,'checks':[],'summary':'Protocol 47 NOT tested.'}
        buf=io.StringIO()
        with patch.object(cli.config,'read',return_value=None), \
             patch.object(cli.sys.stdin,'isatty',return_value=True), \
             patch.object(cli.os,'geteuid',return_value=0), \
             patch.object(cli,'menu',side_effect=['3','0']), \
             patch('builtins.input',side_effect=['1',PEER]), \
             patch.object(cli.precheck,'passive',return_value=fake), \
             patch.object(cli,'setup') as setup, \
             patch.object(cli.config,'save_if_changed') as save, \
             patch('sys.stdout',buf):
            self.assertEqual(cli.main([]),0)
        setup.assert_not_called()
        save.assert_not_called()
        self.assertIn('Pre-tunnel test',buf.getvalue())
