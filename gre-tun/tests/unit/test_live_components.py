"""Mocked and SQLite-only tests: do not count these as kernel integration."""
from __future__ import annotations
import copy
import json
import os
from pathlib import Path
import sys
import tempfile
import unittest
from unittest.mock import patch
ROOT=Path(__file__).resolve().parents[2]
sys.path.insert(0,str(ROOT/'src'))
from gre_tun import config, firewall, network, stats

class FirewallTests(unittest.TestCase):
    def setUp(self):self.c=json.loads((ROOT/'examples/config.entry.json').read_text())

    def test_mark_is_per_tunnel_and_forward(self):
        self.assertEqual(firewall.marker(1,1),0x47001001)
        self.assertNotEqual(firewall.marker(2,1),firewall.marker(1,1))

    def test_original_and_reply_accounted_separately(self):
        text=firewall.generate(self.c)
        self.assertIn('ct direction original ct mark 0x47001001 oifname "gtn1" counter name p0001u',text)
        self.assertIn('ct direction reply ct mark 0x47001001 iifname "gtn1" counter name p0001d',text)
        self.assertIn('tcp dport 5445',text)
        self.assertIn('dnat to',text)
        self.assertIn('snat to',text)

    def test_no_global_flush_or_wan_qdisc_change(self):
        text=firewall.generate(self.c)
        self.assertNotIn('flush ruleset',text)
        self.assertNotIn('table inet filter',text)
        self.assertNotIn('iptables',text)
        self.assertNotIn('tc qdisc',text)

    def test_disabled_port_has_no_rules(self):
        self.c['forwards'][0]['enabled']=False
        text=firewall.generate(self.c)
        self.assertNotIn('p0001u',text)
        self.assertIn('p0002u',text)

    def test_known_reply_precedes_source_guard(self):
        text=firewall.generate(self.c)
        reply='iifname "gtn1" ct direction reply ct mark 0x47001001 ct state established,related accept'
        drop='iifname "gtn1" ip saddr != '
        self.assertIn(reply,text)
        self.assertLess(text.index(reply),text.index('forward_guard '+drop))

    def test_no_transit_across_gre(self):
        text=firewall.generate(self.c)
        self.assertIn('oifname "gtn1" drop',text)
        self.assertIn('ip saddr != ',text)

    def test_invalid_listen_data_rejected_before_rules(self):
        self.c['forwards'][0]['listen_ip']='invalid; delete table'
        with self.assertRaises(config.ConfigError):firewall.generate(self.c)

    def test_nonowned_table_not_adopted(self):
        data={'nftables':[{'counter':{'name':'p0002u','bytes':124}},{'counter':{'name':'p0002d','bytes':120}}]}
        class Result:returncode=0;stdout=json.dumps(data);stderr=''
        self.assertEqual(firewall.counters(lambda *a,**k:Result()),{2:(124,120)})

    def test_foreign_drop_causes_refusal(self):
        data={'nftables':[{'rule':{'table':'filter','family':'ip','expr':[{'drop':None}]}}]}
        class Result:returncode=0;stdout=json.dumps(data);stderr=''
        self.assertIn('E_FOREIGN_FIREWALL_UNCLASSIFIED',firewall.conservative_foreign_conflicts(lambda *a,**k:Result()))

class StatsTests(unittest.TestCase):
    def setUp(self):
        self.temp=tempfile.TemporaryDirectory();self.addCleanup(self.temp.cleanup)
        self.db=stats.connect(Path(self.temp.name)/'s.sqlite3');self.addCleanup(self.db.close)
        self.c=json.loads((ROOT/'examples/config.entry.json').read_text())
        self.f=self.c['forwards'][0]

    def test_exact_idle_coverage(self):
        stats.observe(self.db,[self.f],{self.f['id']:(0,0)},100000,100000000000,'boot','epoch')
        stats.observe(self.db,[self.f],{self.f['id']:(0,0)},160000,160000000000,'boot','epoch')
        w=stats.window(self.db,[self.f['id']],160000,60)
        self.assertEqual(w['upload_bytes'],0)
        self.assertEqual(w['coverage_ms'],60000)
        self.assertEqual(w['status'],'complete')

    def test_one_hour_aggregate_and_gap(self):
        stats.observe(self.db,[self.f],{self.f['id']:(500,600)},100000,100000000000,'boot','e1')
        stats.observe(self.db,[self.f],{self.f['id']:(1500,2600)},160000,160000000000,'boot','e1')
        w=stats.window(self.db,[self.f['id']],160000,3600)
        self.assertEqual(w['upload_bytes'],1000)
        self.assertEqual(w['download_bytes'],2000)
        self.assertEqual(w['status'],'partial')

    def test_counter_reset_never_negative(self):
        ident=self.f['id']
        stats.observe(self.db,[self.f],{ident:(9999,100)},100000,100000000000,'boot','e1')
        stats.observe(self.db,[self.f],{ident:(1,0)},160000,160000000000,'boot','e1')
        self.assertEqual(self.db.execute('SELECT COUNT(*) FROM samples').fetchone()[0],0)
        self.assertEqual(self.db.execute('SELECT COUNT(*) FROM gaps').fetchone()[0],1)

    def test_missing_counter_is_unknown_not_idle(self):
        stats.observe(self.db,[self.f],{},100000,100000000000,'boot','e1')
        self.assertEqual(stats.window(self.db,[self.f['id']],100000,3600)['status'],'unavailable')

    def test_boot_change_never_backfills(self):
        ident=self.f['id']
        stats.observe(self.db,[self.f],{ident:(100,100)},100000,100000000000,'boot-a','e1')
        stats.observe(self.db,[self.f],{ident:(500,500)},160000,160000000000,'boot-b','e1')
        self.assertEqual(self.db.execute('SELECT COUNT(*) FROM samples').fetchone()[0],0)

    def test_history_survives_reopen(self):
        stats.observe(self.db,[self.f],{self.f['id']:(0,0)},100000,100000000000,'boot','e1')
        self.db.close()
        self.db=stats.connect(Path(self.temp.name)/'s.sqlite3')
        self.assertEqual(self.db.execute('SELECT COUNT(*) FROM forward_history').fetchone()[0],1)

    def test_port_status_without_samples_is_not_zero(self):
        report=stats.snapshot(self.db,self.c,'P0001',100000)
        self.assertIsNone(report['last_1h']['total_bytes'])
        self.assertIsNone(report['current']['download_mbps'])

class NetworkTests(unittest.TestCase):
    def test_no_qos_silent_fallback(self):
        c=json.loads((ROOT/'examples/config.entry.json').read_text())
        self.assertTrue(any(f['upload_mbps'] or f['download_mbps'] for f in c['forwards']))
        self.assertIn('E_QOS_UNSUPPORTED',network.preflight(c))

    def test_readonly_check_no_mutations_when_error(self):
        c=json.loads((ROOT/'examples/config.entry.json').read_text())
        with patch.object(network,'preflight',return_value=['E_REJECT']),patch.object(network,'_make_tunnel') as mutate:
            with self.assertRaises(config.ConfigError):network.apply(c,check_only=True)
            mutate.assert_not_called()

if __name__=='__main__':unittest.main()

class ReleaseSafetyTests(unittest.TestCase):
    def test_unmarked_host_refuses_live_mutation(self):
        c=json.loads((ROOT/'examples/config.entry.json').read_text())
        for f in c['forwards']:
            f['upload_mbps']=f['download_mbps']=0
        with patch.object(network,'preflight',return_value=[]), patch.dict(os.environ,{'GRE_TUN_EXPERIMENTAL_LAB':'1'}), patch.object(network.Path,'is_file',return_value=False), patch.object(network,'_make_tunnel') as dangerous:
            with self.assertRaisesRegex(config.ConfigError,'E_NOT_READY'):
                network.apply(c)
            dangerous.assert_not_called()

    def test_check_only_provides_no_live_write(self):
        c=config.empty_config()
        with patch.object(network,'preflight',return_value=[]),patch.object(network,'_install_firewall') as dangerous:
            msg=network.apply(c,check_only=True)
            self.assertIn('NOT RUN',msg)
            dangerous.assert_not_called()
