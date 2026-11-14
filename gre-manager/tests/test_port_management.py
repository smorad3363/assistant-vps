"""Regression coverage for mappings, live sampling and scoped peer removal."""
import copy
import ipaddress
import json
from pathlib import Path
import tempfile
import time
import unittest
from unittest.mock import patch

from panel.agent import action, other_managers, validate_peer
from panel.controller import Controller
from panel.demo import DemoEngine, DemoRemote
from panel.engine import build_rules, gre_for, monitored, pair_values
from panel.model import DEFAULTS, PanelError, connection
from panel.store import Paths, Store


class PortManagementTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.store = Store(Paths(self.temp.name))
        self.engine = DemoEngine()
        self.remote = DemoRemote(self.store.paths)
        self.controller = Controller(self.store, self.engine, self.remote)
        self.server = self.remote.connect({"host": "203.0.113.10"})
        cfg = self.store.config(); cfg["servers"] = [self.server]; self.store.save(cfg)

    def tearDown(self):
        self.controller.executor.shutdown(wait=True)
        self.temp.cleanup()

    def make(self, **values):
        payload = dict(kind="gre", listen_ip="192.0.2.10", target_host="203.0.113.10",
                       server_id=self.server["id"], ports="5100,3300")
        payload.update(values)
        return connection(payload, dict(DEFAULTS), resolver=lambda x:x)

    def test_independent_mappings_and_original_port_counters_on_both_methods(self):
        for kind in ("gre", "direct"):
            c = self.make(kind=kind, port_map="5100:5000,3300:3000")
            cfg = {"settings": dict(DEFAULTS), "connections": [c]}
            rules = build_rules(cfg, {c["listen_ip"]:"wan0"})
            lines = [" ".join(x) for x in rules["nat"]["GMP_PRE"]]
            for src, dst in ((5100,5000),(3300,3000)):
                self.assertEqual(sum(f"--dport {src} " in x and x.endswith(":"+str(dst)) for x in lines),2)
                count = [" ".join(x) for x in rules["filter"]["GMP_COUNT"]]
                self.assertTrue(any(f"--ctorigdstport {src} " in x and f":{src}:up" in x for x in count))

    def test_duplicate_input_mappings_are_rejected_in_text_and_object(self):
        for value in ("5100:5000,5100:3000", "05100:5000,5100:3000", {"05100":5000,"5100":3000}):
            with self.subTest(value=value), self.assertRaises(PanelError):
                self.make(port_map=value)

    def test_all_ports_automatically_monitor_only_explicit_mappings(self):
        c = self.make(ports="all", port_map={"5100":5000,"3300":3000})
        self.assertEqual(monitored(c,dict(DEFAULTS)),[3300,5100])

    def test_collision_selects_same_free_subnet_on_both_endpoints(self):
        c = self.make(); base = gre_for(c)
        subnet = lambda slot:str(ipaddress.ip_network(pair_values(c["listen_ip"],c["resolved_ip"],slot)["local_tun"]+"/30",strict=False))
        self.engine.routes = lambda:[{"dst":subnet(0),"dev":"existing-vpn"}]
        self.remote.call = lambda *args:{"routes":[{"dst":subnet(1),"dev":"foreign-vpn"}]}
        cfg = self.store.config(); cfg["connections"]=[c]
        self.controller.allocate_gre(cfg,self.store.config())
        self.assertEqual(c["gre_slot"],2)
        g = gre_for(c); reverse = pair_values(g["outer_peer"],g["outer_local"],2); reverse["mtu"]=c["mtu"]
        self.assertEqual(g["local_tun"],reverse["peer_tun"])
        self.assertEqual(g["tunnel"],base["tunnel"])
        self.assertEqual(validate_peer({"id":c["id"],"gre":reverse,"service_ip":c["service_ip"]})["gre"],reverse)

    def test_existing_gre_does_not_move_or_accept_a_changed_internal_slot(self):
        c=self.make(gre_slot=2);cfg=self.store.config();cfg["connections"]=[c]
        updated=copy.deepcopy(cfg);updated["connections"][0]["gre_slot"]=99
        self.controller.allocate_gre(updated,cfg)
        self.assertEqual(updated["connections"][0]["gre_slot"],2)

    def test_private_subnet_selection_skips_a_whole_existing_prefix(self):
        c=self.make();prefix=ipaddress.ip_network(gre_for(c)["local_tun"]+"/16",strict=False)
        self.engine.routes=lambda:[{"dst":str(prefix),"dev":"vpn-prefix"}]
        cfg=self.store.config();cfg["connections"]=[c]
        self.controller.allocate_gre(cfg,self.store.config())
        self.assertNotIn(ipaddress.ip_address(gre_for(c)["local_tun"]),prefix)

    def test_exhausted_private_pool_returns_conflict(self):
        self.engine.routes=lambda:[{"dst":"10.0.0.0/8","dev":"private-network"}]
        cfg=self.store.config();cfg["connections"]=[self.make()]
        with self.assertRaises(PanelError) as caught:self.controller.allocate_gre(cfg,self.store.config())
        self.assertEqual(caught.exception.code,"route_conflict")

    def test_reactivating_an_old_paused_profile_checks_current_routes_again(self):
        c=self.make(enabled=False);cfg=self.store.config();cfg["connections"]=[c]
        subnet=str(ipaddress.ip_network(gre_for(c)["local_tun"]+"/30",strict=False))
        self.engine.routes=lambda:[{"dst":subnet,"dev":"new-vpn"}]
        updated=copy.deepcopy(cfg);updated["connections"][0]["enabled"]=True
        self.controller.allocate_gre(updated,cfg)
        self.assertEqual(updated["connections"][0]["gre_slot"],1)

    def test_one_second_rates_do_not_write_history_each_second(self):
        identity="abcdef0123";key=(identity,"all");port=(identity,"5100")
        counters={key:[100,200],port:[50,100]}
        self.engine.counters=lambda:(counters,"epoch-one")
        with patch.object(self.store,"sample",wraps=self.store.sample) as save:
            with patch("panel.controller.time.time",return_value=100):self.controller.collect()
            counters[key]=[1100,2200];counters[port]=[550,1100]
            with patch("panel.controller.time.time",return_value=101):self.controller.collect(persist=False)
            self.assertEqual(self.controller.rates[port],{"up":4000,"down":8000})
            self.assertEqual(save.call_count,1)
            with patch("panel.controller.time.time",return_value=105):self.controller.collect()
            self.assertEqual(save.call_count,2)
        totals={x["port"]:x for x in self.store.stats()["totals"]}
        self.assertEqual((totals["all"]["up"],totals["5100"]["down"]),(1100,1100))

    def test_cleanup_failure_keeps_retryable_server_and_management_key(self):
        c=self.make();cfg=self.store.config();cfg["connections"]=[c];self.store.save(cfg)
        def disconnect(server,request):
            if request["action"]=="cleanup":raise PanelError("Injected SSH disconnect","ssh")
            return {}
        self.remote.call=disconnect
        with self.assertRaises(PanelError) as caught:
            self.controller.operation("connection.delete",{"id":c["id"]},lambda *args:None)
        self.assertEqual(caught.exception.code,"cleanup_pending")
        cfg=self.store.config();self.assertEqual(cfg["connections"],[])
        self.assertTrue(cfg["servers"][0]["cleanup_pending"])
        self.assertTrue((self.store.paths.ssh/self.server["id"]).exists())
        self.remote.call=lambda *args:{"purged":True}
        self.controller.operation("server.delete",{"id":self.server["id"]},lambda *args:None)
        self.assertEqual(self.store.config()["servers"],[])
        self.assertFalse((self.store.paths.ssh/self.server["id"]).exists())

    def test_other_paused_profile_keeps_the_shared_management_connection(self):
        c=self.make();other=self.make(ports="9999",enabled=False)
        cfg=self.store.config();cfg["connections"]=[c,other];self.store.save(cfg)
        with patch.object(self.controller,"cleanup_server") as cleanup:
            self.controller.operation("connection.delete",{"id":c["id"]},lambda *args:None)
        cleanup.assert_not_called()
        self.assertEqual(len(self.store.config()["servers"]),1)

    def test_live_endpoint_requires_login_and_exposes_port_rates_without_csrf(self):
        c=self.make();cfg=self.store.config();cfg["connections"]=[c];self.store.save(cfg)
        self.store.set_password("local-live-test-password")
        with self.assertRaises(PanelError):self.controller.request("live",{})
        login=self.store.login("admin","local-live-test-password","test")
        self.controller.rates={(c["id"],"all"):{"up":16000,"down":24000},(c["id"],"5100"):{"up":8000,"down":12000}}
        live=self.controller.request("live",{},login["token"])
        self.assertEqual(live["connections"][0]["port_rates"]["5100"]["up"],8000)
        self.assertNotIn("csrf",live)


class PeerCleanupTests(unittest.TestCase):
    def setUp(self):
        self.temp=tempfile.TemporaryDirectory();self.paths=Paths(self.temp.name)
        self.auth=Path(self.temp.name)/"authorized_keys"
        self.auth.write_text('restrict,command="/usr/local/sbin/gremgr-peer" ssh-ed25519 FIRST\nssh-ed25519 NORMAL-ADMIN\n')
        self.request={"action":"cleanup","username":"root","key":"ssh-ed25519 FIRST"}

    def tearDown(self):self.temp.cleanup()

    def cleanup(self):
        with patch("panel.agent.management_key",return_value=(self.auth,"FIRST")):
            return action(self.paths,self.request,DemoEngine())

    def test_last_unused_helper_is_removed_but_normal_ssh_key_survives(self):
        with patch("panel.agent.other_managers",return_value=False),patch("panel.agent.uninstall_peer") as uninstall:
            result=self.cleanup()
        self.assertTrue(result["purged"]);uninstall.assert_called_once()
        self.assertNotIn("FIRST",self.auth.read_text());self.assertIn("NORMAL-ADMIN",self.auth.read_text())

    def test_local_panel_or_foreign_peers_keep_the_shared_helper(self):
        for reason in ("panel","peers","managers"):
            self.auth.write_text('restrict,command="/usr/local/sbin/gremgr-peer" ssh-ed25519 FIRST\n')
            self.paths.config.unlink(missing_ok=True)
            (self.paths.etc/"peers.json").unlink(missing_ok=True)
            if reason=="panel":self.paths.config.write_text('{}')
            if reason=="peers":(self.paths.etc/"peers.json").write_text('[{"id":"other"}]')
            with patch("panel.agent.other_managers",return_value=reason=="managers"),patch("panel.agent.uninstall_peer") as uninstall:
                result=self.cleanup()
            self.assertFalse(result["purged"]);self.assertEqual(result["shared"],reason);uninstall.assert_not_called()

    def test_uncommitted_transaction_blocks_removal_without_revoking_the_key(self):
        directory=self.paths.etc/"transactions";directory.mkdir()
        (directory/"0123456789abcdef.json").write_text(json.dumps({"deadline":time.time()+120}))
        with self.assertRaises(PanelError) as caught:self.cleanup()
        self.assertEqual(caught.exception.code,"busy");self.assertIn("FIRST",self.auth.read_text())

    def test_failed_uninstall_keeps_the_key_for_recovery(self):
        with patch("panel.agent.other_managers",return_value=False),patch("panel.agent.uninstall_peer",side_effect=OSError("Injected failure")):
            with self.assertRaises(OSError):self.cleanup()
        self.assertIn("FIRST",self.auth.read_text())

    def test_legacy_management_key_in_another_unix_account_prevents_uninstall(self):
        from types import SimpleNamespace
        home=Path(self.temp.name)/"other-user";(home/".ssh").mkdir(parents=True)
        (home/".ssh/authorized_keys").write_text('restrict,command="sudo -n /usr/local/sbin/gremgr-peer" ssh-ed25519 SECOND\n')
        with patch("panel.agent.pwd.getpwall",return_value=[SimpleNamespace(pw_dir=str(home))]):
            self.assertTrue(other_managers(self.auth,"FIRST"))


if __name__=="__main__":unittest.main()
