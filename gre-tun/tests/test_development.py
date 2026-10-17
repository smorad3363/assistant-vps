"""Offline-safe tests for pre-alpha code. No host networking changes."""
from __future__ import annotations
import copy
import io
import json
import os
from pathlib import Path
import sys
import tempfile
import unittest
from unittest.mock import patch

ROOT=Path(__file__).resolve().parents[1]
sys.path.insert(0,str(ROOT/'src'))
from gre_tun import cli, config, contract, diagnostics, peer


class ConfigTests(unittest.TestCase):
    def setUp(self):
        self.temp=tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.old_cfg=config.CONFIG_DIR,config.CONFIG_PATH,config.LOCK_PATH
        config.CONFIG_DIR=Path(self.temp.name)/'etc'
        config.CONFIG_PATH=config.CONFIG_DIR/'config.json'
        config.LOCK_PATH=Path(self.temp.name)/'run'/'app.lock'
        self.addCleanup(self.restore)

    def restore(self):
        config.CONFIG_DIR,config.CONFIG_PATH,config.LOCK_PATH=self.old_cfg

    def test_atomic_stored_config(self):
        c=config.empty_config('foreign')
        self.assertTrue(config.save_if_changed(c))
        self.assertEqual(config.CONFIG_PATH.stat().st_mode & 0o777,0o600)
        self.assertFalse(config.save_if_changed(c))
        self.assertEqual(config.read(),c)
        changed=copy.deepcopy(c)
        changed['next_tunnel_id']=2
        self.assertTrue(config.save_if_changed(changed))
        self.assertEqual(config.read()['config_revision'],2)

    def test_schema_examples(self):
        for x in ('config.empty.json','config.entry.json','config.peer.json'):
            config.validate(json.loads((ROOT/'examples'/x).read_text()))

    def test_reject_type_confusions_and_unknown_keys(self):
        c=config.empty_config();c['next_tunnel_id']=True
        with self.assertRaises(config.ConfigError):config.validate(c)
        c=config.empty_config();c['foreign_rule']='drop all'
        with self.assertRaises(config.ConfigError):config.validate(c)

    def test_disable_keeps_reserved_tuple(self):
        c=json.loads((ROOT/'examples/config.entry.json').read_text())
        f=copy.deepcopy(c['forwards'][0]);f['id']=4;f['listen_port']=5445
        c['forwards'][1]['enabled']=False
        c['forwards'].append(f);c['next_forward_id']=5
        with self.assertRaises(config.ConfigError):config.validate(c)

    def test_reject_identity_mismatch(self):
        c=json.loads((ROOT/'examples/config.entry.json').read_text())
        c['tunnels'][0]['key']+=1
        with self.assertRaises(config.ConfigError):config.validate(c)

    def test_status_is_read_only(self):
        self.assertEqual(diagnostics.status()['service'],'Unconfigured')
        self.assertFalse(config.CONFIG_PATH.exists())

class PeerTests(unittest.TestCase):
    def test_token_transfer_and_symmetric_pair(self):
        t=peer.make_tunnel(1,'192.0.2.10','198.51.100.20','eth0','Test Tunnel')
        code=peer.token_for(t)
        data=contract.decode_peer(code)
        remote=peer.tunnel_from_token(code,'198.51.100.20',1,'Remote','eth0')
        self.assertEqual(remote['pair_id'],t['pair_id'])
        self.assertEqual(remote['inside_cidr'],t['inside_cidr'])
        self.assertEqual(data['key'],t['key'])

    def test_wrong_receiver_fails_closed(self):
        t=peer.make_tunnel(1,'192.0.2.10','198.51.100.20','eth0','Test Tunnel')
        with self.assertRaises(config.ConfigError):
            peer.tunnel_from_token(peer.token_for(t),'203.0.113.5',1,'Wrong','eth0')

class CLITests(unittest.TestCase):
    def test_frozen_main_menu(self):
        self.assertEqual(contract.render_menu('main',root=ROOT),(ROOT/'fixtures/ui/main.txt').read_text())

    def test_one_port_two_different_endpoints(self):
        self.assertEqual(contract.parse_ports('5445:5454,443'),[{'listen_port':5445,'target_port':5454},{'listen_port':443,'target_port':443}])

    def test_cap_zero_is_unlimited_not_back(self):
        with patch('builtins.input',return_value='0'):
            self.assertEqual(cli.cap_prompt('Limit:'),0)

    def test_confirmation_defaults(self):
        with patch('builtins.input',return_value=''):
            self.assertTrue(cli.confirm())
        with patch('builtins.input',return_value=''):
            self.assertFalse(cli.confirm('Disable? [y/N]:',False))

    def test_readonly_cli(self):
        output=io.StringIO()
        with patch('sys.stdout',output):
            self.assertEqual(cli.main(['--version']),0)
        self.assertIn('0.2.0-dev',output.getvalue())

if __name__=='__main__':unittest.main()
