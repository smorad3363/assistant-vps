import base64
import copy
import http.client
import io
import json
from pathlib import Path
import sqlite3
import tempfile
import threading
import time
import unittest
from unittest.mock import patch
import zipfile

from panel.agent import validate_peer, action as peer_action
from panel.controller import Controller
from panel.demo import DemoEngine, DemoRemote, LocalBackend
from panel.engine import Engine, build_rules, gre_for, pair_values
from panel.model import DEFAULTS, PanelError, connection, port_ranges, ranges_for, validate_conflicts
from panel.remote import BOOTSTRAP, Remote
from panel.store import Paths, Store
from panel.web import Handler, ThreadingHTTPServer


def make(**kwargs):
    data = {"kind": "direct", "listen_ip": "192.0.2.10", "target_host": "203.0.113.10", "ports": "443"}
    data.update(kwargs)
    return connection(data, dict(DEFAULTS), resolver=lambda value: value)


class ConfigurationTests(unittest.TestCase):
    def test_ranges_and_management_ports(self):
        c = make(ports="all")
        settings = dict(DEFAULTS, ssh_ports=[22, 6111], reserved_ports=[2096])
        ranges = ranges_for(c, settings)
        for p in (22, 6111, 8787, 2096):
            self.assertFalse(any(a <= p <= b for a, b in ranges))
        for p in (1, 23, 1000, 51821, 65535):
            self.assertTrue(any(a <= p <= b for a, b in ranges))
        for ports in ("22", "8787", "1-65535", "65536", "-1", "443,,80", "443;touch /tmp/oops"):
            with self.subTest(ports=ports), self.assertRaises(PanelError):
                make(ports=ports)

    def test_conflict_is_shared_between_methods(self):
        gre = make(kind="gre", ports="all", server_id="abcdef0123")
        direct = make(ports="443")
        with self.assertRaises(PanelError): validate_conflicts([gre, direct], dict(DEFAULTS))
        gre["exclude_ports"] = [443]
        validate_conflicts([gre, direct], dict(DEFAULTS))
        direct["protocols"] = ["udp"]
        gre["protocols"] = ["tcp"]
        gre["exclude_ports"] = []
        validate_conflicts([gre, direct], dict(DEFAULTS))

    def test_same_port_on_different_public_ips_is_allowed(self):
        validate_conflicts([make(), make(listen_ip="192.0.2.11")], dict(DEFAULTS))

    def test_unsafe_values_are_rejected(self):
        for value in ("https://example.com", "example.com:22", "--help", "0.0.0.0", "127.0.0.1", "999.1.1.1", "name;id"):
            with self.subTest(value=value), self.assertRaises(PanelError): make(target_host=value)
        for n in (float("nan"), float("inf"), -1):
            with self.assertRaises(PanelError): make(upload_mbps=n)

    def test_mapping_preserves_original_port_and_rate_names(self):
        c = make(ports="443,8080", port_map={"8080": 80}, upload_mbps=10, port_limits={"443": {"up": 2, "down": 3}})
        config = {"settings": dict(DEFAULTS), "connections": [c]}
        rules = build_rules(config, {"192.0.2.10": "wan0"})
        nat = [" ".join(x) for x in rules["nat"]["GMP_PRE"]]
        self.assertTrue(any("--dport 8080" in x and "203.0.113.10:80" in x for x in nat))
        self.assertTrue(all("-i wan0" in x and "-d 192.0.2.10" in x for x in nat))
        filtered = [" ".join(x) for x in rules["filter"]["GMP_FWD"]]
        self.assertTrue(any("--ctdir REPLY" in x and "--ctorigdstport 443" in x for x in filtered))
        self.assertTrue(any("--hashlimit-above 1250000b/s" in x for x in filtered))
        self.assertFalse(any("-P " in x or "-F " in x for x in filtered))

    def test_peer_identity_cannot_control_arbitrary_device(self):
        g = pair_values("203.0.113.10", "192.0.2.10")
        g["mtu"] = 1400
        peer = {"id": "abcdef0123", "gre": g, "service_ip": "203.0.113.10"}
        self.assertEqual(validate_peer(peer)["gre"], g)
        peer["gre"]["tunnel"] = "eth0"
        with self.assertRaises(PanelError): validate_peer(peer)

    def test_remote_bootstrap_is_valid_python(self):
        compile(BOOTSTRAP, "<bootstrap>", "exec")

    def test_peer_udp_reply_fix_preserves_ipsec_endpoint_and_decrypted_l2tp(self):
        g=pair_values("203.0.113.10","192.0.2.10");g["mtu"]=1380
        peer={"id":"abcdef0123","kind":"peer","enabled":True,"gre":g,"service_ip":"203.0.113.10"}
        rules=build_rules({"settings":dict(DEFAULTS),"connections":[peer]},{"203.0.113.10":"wan0"})
        local=[" ".join(r) for r in rules["nat"]["GMP_LOCAL"]]
        self.assertTrue(any("! --dports 500,4500" in r and "--pol none" in r and "-j SNAT" in r for r in local))
        self.assertTrue(any("--pol ipsec" in " ".join(r) and "--dport 1701" in " ".join(r) for r in rules["filter"]["GMP_INPUT"]))

    def test_restore_keeps_inversion_as_a_rules_file_token(self):
        import subprocess
        calls=[]
        with tempfile.TemporaryDirectory() as directory:
            engine=Engine(Paths(directory))
            def run(*args,**kw):
                calls.append((args,kw))
                return subprocess.CompletedProcess(args,0,"","")
            engine.run=run
            engine.restore_owned({"nat":{"GMP_LOCAL":[["-p","udp","-m","multiport","!","--dports","500,4500","-j","ACCEPT"]]}})
        payload=next(kw["input"] for args,kw in calls if args[0]=="iptables-restore")
        self.assertIn("multiport ! --dports",payload)
        self.assertNotIn("'!'",payload)


class StoreTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.store = Store(Paths(self.temp.name))
        self.store.set_password("a-strong-local-password")

    def tearDown(self): self.temp.cleanup()

    def test_password_sessions_and_rate_limit(self):
        login = self.store.login("admin", "a-strong-local-password", "client")
        self.store.session(login["token"], login["csrf"])
        with self.assertRaises(PanelError): self.store.session(login["token"], "wrong")
        self.store.logout(login["token"])
        with self.assertRaises(PanelError): self.store.session(login["token"])
        for i in range(8):
            with self.assertRaises(PanelError): self.store.login("admin", "wrong", "bad-client")
        with self.assertRaises(PanelError) as error: self.store.login("admin", "a-strong-local-password", "bad-client")
        self.assertEqual(error.exception.code, "rate_limit")

    def test_counter_restarts_do_not_reset_totals_or_count_twice(self):
        key = ("abcdef0123", "all")
        self.store.sample({key: [100, 500]}, "epoch-one", 1000)
        self.store.sample({key: [150, 700]}, "epoch-one", 1005)
        self.store.sample({key: [5, 10]}, "epoch-two", 1010)
        self.store.sample({key: [5, 10]}, "epoch-two", 1015)
        totals = self.store.stats()["totals"][0]
        self.assertEqual((totals["up"], totals["down"]), (155, 710))
        restarted = Store(self.store.paths)
        restarted.sample({key: [15, 30]}, "epoch-two", 1020)
        totals = restarted.stats()["totals"][0]
        self.assertEqual((totals["up"], totals["down"]), (165, 730))

    def test_backup_excludes_credentials_even_in_deleted_sqlite_pages(self):
        login = self.store.login("admin", "a-strong-local-password", "client")
        password_hash = self.store.secret("password")
        self.store.paths.ssh.joinpath("private").write_text("PRIVATE-KEY-MUST-NOT-LEAK")
        archive = self.store.backup()
        cfg, telemetry = Store.read_backup(archive)
        self.assertNotIn(password_hash.encode(), telemetry)
        self.assertNotIn(login["csrf"].encode(), telemetry)
        self.assertNotIn(b"PRIVATE-KEY-MUST-NOT-LEAK", archive)
        with zipfile.ZipFile(io.BytesIO(archive)) as z:
            self.assertEqual(set(z.namelist()), {"manifest.json", "config.json", "telemetry.sqlite3"})
        self.store.session(login["token"], login["csrf"])

    def test_malicious_archive_paths_are_not_extracted(self):
        buf = io.BytesIO()
        with zipfile.ZipFile(buf, "w") as z: z.writestr("../../outside", "bad")
        with self.assertRaises(PanelError): Store.read_backup(buf.getvalue())

    def test_bounded_backup_retention(self):
        cfg = self.store.config();cfg["settings"]["backup_keep"] = 2;self.store.save(cfg)
        for i in range(4):
            with patch("panel.store.time.strftime", return_value=f"backup-20261113-12000{i}"):
                self.store.automatic_backup()
        self.assertEqual(len(list(self.store.paths.backups.glob("*.zip"))), 2)


class TransactionTests(StoreTests):
    def setUp(self):
        super().setUp()
        self.engine = DemoEngine()
        self.remote = DemoRemote(self.store.paths)
        self.controller = Controller(self.store, self.engine, self.remote)

    def tearDown(self):
        self.controller.executor.shutdown(wait=True)
        super().tearDown()

    def test_failed_network_apply_rolls_back_and_keeps_the_original_profile(self):
        before = self.store.config()
        changed = copy.deepcopy(before);changed["connections"] = [make()]
        calls = 0
        original = self.engine.apply
        def fail_once(config, previous=None):
            nonlocal calls
            calls += 1
            if calls == 1: raise PanelError("Injected apply failure")
            return original(config, previous)
        self.engine.apply = fail_once
        with self.assertRaises(PanelError): self.controller.transaction(changed)
        self.assertEqual(self.store.config(), before)
        self.assertFalse(self.controller.pending.exists())

    def test_missing_csrf_never_reaches_a_network_job(self):
        login = self.store.login("admin", "a-strong-local-password", "client")
        for route in ("connection.delete", "connection.save", "settings.save", "update", "server.connect"):
            with self.subTest(route=route), self.assertRaises(PanelError):
                self.controller.request(route, {}, login["token"])
        with self.store.database() as db: self.assertEqual(db.execute("SELECT COUNT(*) FROM jobs").fetchone()[0], 0)

    def test_recovery_replays_a_durable_local_journal(self):
        from panel.store import atomic_json
        before = self.store.config();changed=copy.deepcopy(before);changed["connections"]=[make()]
        self.store.save(changed)
        atomic_json(self.controller.pending, {"previous":before,"updated":changed,"remote":[]})
        self.controller.recover()
        self.assertEqual(self.store.config(), before)
        self.assertFalse(self.controller.pending.exists())

    def test_peer_request_retries_expired_rollback_after_timer_failure(self):
        from panel.store import atomic_json
        pending=self.store.paths.etc/"transactions"/"0123456789abcdef.json"
        atomic_json(pending,{"previous":[],"deadline":time.time()-1})
        reply=peer_action(self.store.paths,{"action":"status"},self.engine)
        self.assertEqual(reply["peers"],0)
        self.assertFalse(pending.exists())

    def test_panel_can_return_to_previous_port_with_time_wait_connections(self):
        import socket
        with socket.socket() as listener:
            listener.setsockopt(socket.SOL_SOCKET,socket.SO_REUSEADDR,1)
            listener.bind(("127.0.0.1",0));port=listener.getsockname()[1];listener.listen()
            with socket.socket() as client:
                client.connect(("127.0.0.1",port));server,_=listener.accept()
                server.close();client.recv(1)
        self.controller.schedule_web_restart=lambda:None
        self.controller.operation("settings.save",{"port":port},lambda *args:None)
        self.assertEqual(self.store.config()["settings"]["port"],port)

    def test_panel_still_rejects_an_actively_listening_port(self):
        import socket
        with socket.socket() as listener:
            listener.setsockopt(socket.SOL_SOCKET,socket.SO_REUSEADDR,1)
            listener.bind(("127.0.0.1",0));port=listener.getsockname()[1];listener.listen()
            with self.assertRaises(PanelError) as caught:
                self.controller.operation("settings.save",{"port":port},lambda *args:None)
            self.assertEqual(caught.exception.code,"port_in_use")

    def test_gre_peer_failure_does_not_leave_a_half_created_connection(self):
        cfg=self.store.config();server=self.remote.connect({"host":"203.0.113.10"});cfg["servers"].append(server);self.store.save(cfg)
        changed=copy.deepcopy(cfg);changed["connections"]=[make(kind="gre", server_id=server["id"])]
        self.engine.probe=lambda c: {"gre":False}
        with self.assertRaises(PanelError): self.controller.transaction(changed)
        self.assertEqual(self.store.config(),cfg)

    def test_auto_mtu_starts_from_ceiling_and_restore_preserves_saved_mtu(self):
        cfg=self.store.config();server=self.remote.connect({"host":"203.0.113.10"});cfg["servers"].append(server);self.store.save(cfg)
        changed=copy.deepcopy(cfg)
        changed["connections"]=[make(kind="gre",server_id=server["id"],mtu=1280)]
        measurements=[]
        def measure(c,ceiling):
            self.assertEqual(c["mtu"],ceiling)
            measurements.append(c["mtu"])
            return ceiling-20
        self.engine.choose_mtu=measure
        self.controller.transaction(changed)
        saved=self.store.config()
        self.assertEqual(saved["connections"][0]["mtu"],cfg["settings"]["mtu"]-20)
        self.controller.transaction(dict(saved,connections=[]))
        self.controller.transaction(saved,measure_mtu=False)
        self.assertEqual(self.store.config()["connections"][0]["mtu"],saved["connections"][0]["mtu"])
        self.assertEqual(len(measurements),1)


class HTTPTests(unittest.TestCase):
    def setUp(self):
        self.temp=tempfile.TemporaryDirectory();store=Store(Paths(self.temp.name));store.set_password("web-test-password-2026")
        self.controller=Controller(store,DemoEngine(),DemoRemote(store.paths))
        self.server=ThreadingHTTPServer(("127.0.0.1",0),Handler);self.server.secure=False;self.server.backend=LocalBackend(self.controller)
        self.thread=threading.Thread(target=self.server.serve_forever,daemon=True);self.thread.start()
        self.cookie=None;self.csrf=None

    def tearDown(self):
        self.server.shutdown();self.server.server_close();self.controller.executor.shutdown(wait=True);self.temp.cleanup()

    def call(self,path,data=None,headers=None):
        conn=http.client.HTTPConnection("127.0.0.1",self.server.server_port)
        h={"Content-Type":"application/json"}
        if self.cookie:h["Cookie"]=self.cookie
        if self.csrf:h["X-Gremgr-CSRF"]=self.csrf
        h.update(headers or {})
        conn.request("GET" if data is None else "POST",path,None if data is None else json.dumps(data),h)
        r=conn.getresponse();body=r.read();status=r.status;rh=dict(r.getheaders());conn.close()
        return status,rh,body

    def login(self):
        status,headers,raw=self.call("/api/login",{"username":"admin","password":"web-test-password-2026"})
        self.assertEqual(status,200);self.cookie=headers["Set-Cookie"].split(";")[0];self.csrf=json.loads(raw)["csrf"]
        self.assertIn("HttpOnly",headers["Set-Cookie"]);self.assertIn("SameSite=Strict",headers["Set-Cookie"])

    def test_auth_csp_and_traversal(self):
        status,headers,body=self.call("/");self.assertEqual(status,200);self.assertIn("frame-ancestors 'none'",headers["Content-Security-Policy"])
        self.assertEqual(self.call("/api/state")[0],401)
        self.assertEqual(self.call("/../../etc/passwd")[0],404)
        self.assertEqual(self.call("/api/connection.save",{})[0],401)

    def test_login_create_edit_delete_without_a_shell(self):
        self.login()
        status,_,body=self.call("/api/connection.save",{"kind":"direct","name":"test","listen_ip":"192.0.2.10","target_host":"203.0.113.10","ports":"1000"})
        self.assertEqual(status,200,body)
        identity=json.loads(body)["job"]
        for _ in range(100):
            job=self.controller.store.job(identity)
            if job["status"] in ("done","failed"):break
            time.sleep(.01)
        self.assertEqual(job["status"],"done",job)
        c=self.controller.store.config()["connections"][0]
        self.assertEqual(c["name"],"test")
        self.assertEqual(self.call("/api/state")[0],200)
        status,_,body=self.call("/api/connection.delete",{"id":c["id"]})
        job_id=json.loads(body)["job"]
        for _ in range(100):
            if self.controller.store.job(job_id)["status"]=="done":break
            time.sleep(.01)
        self.assertEqual(self.controller.store.config()["connections"],[])

    def test_cross_origin_and_missing_csrf_are_rejected(self):
        self.login()
        self.assertEqual(self.call("/api/connection.delete",{}, {"Origin":"https://evil.example"})[0],403)
        self.csrf=None
        self.assertEqual(self.call("/api/connection.delete",{})[0],403)


if __name__ == "__main__": unittest.main()
