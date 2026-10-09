"""Time-window clsact police safety contract; root privileges mocked."""
import json
import tempfile
import unittest
from datetime import datetime, timezone
from pathlib import Path
from unittest import mock

from pm2 import shaping
from pm2.errors import PM2Error

TID = "c7145b99-5b6c-4b76-a88f-fd0da56095ca"


def config():
    return {"generation": 1, "schema_version": 1, "tunnels": [{
        "id": TID, "enabled": True, "name": "example",
        "mode": "ports", "interface": "relay0", "listen_ip": "192.0.2.2",
        "target_ip": "198.51.100.2", "protocols": ["tcp", "udp"],
        "mapping": [{"listen_port": 443, "target_port": 8443}], "exclude": []
    }]}


def plan():
    return {"schema_version": 1, "policies": [{
        "id": "evening", "port": 443, "protocol": "tcp,udp", "timezone": "UTC",
        "days": [0, 1, 2, 3, 4, 5, 6], "start": "18:00", "end": "22:00",
        "download_mbps": 20, "upload_mbps": 10, "enabled": True
    }]}


class ShapingTests(unittest.TestCase):
    def setUp(self):
        t = tempfile.TemporaryDirectory()
        self.addCleanup(t.cleanup)
        self.base = Path(t.name)
        for name, value in (("SCHEDULE", self.base / "schedule.json"),
                            ("STATE", self.base / "state.json"),
                            ("PENDING", self.base / "pending.json"),
                            ("_V1", self.base / "not-installed-v1")):
            p = mock.patch.object(shaping, name, value)
            p.start()
            self.addCleanup(p.stop)

    def test_timer_policy_chooses_exact_interface_and_direction(self):
        t = datetime(2026, 10, 9, 19, tzinfo=timezone.utc)
        rules = shaping.desired_filters(plan(), config()["tunnels"], t)
        self.assertEqual(len(rules), 4)
        self.assertEqual({r["iface"] for r in rules}, {"relay0"})
        self.assertEqual({r["mbps"] for r in rules if r["direction"] == "ingress"}, {10})
        self.assertEqual({r["mbps"] for r in rules if r["direction"] == "egress"}, {20})
        self.assertEqual(shaping.desired_filters(plan(), config()["tunnels"],
                         datetime(2026, 10, 9, 12, tzinfo=timezone.utc)), [])

    def test_conflicting_v1_install_prevents_persistent_new_limit(self):
        self.base.joinpath("not-installed-v1").write_text("legacy V1")
        source = self.base / "in.json"
        source.write_text(json.dumps(plan()))
        with mock.patch.object(shaping.os, "geteuid", return_value=0):
            with self.assertRaises(PM2Error) as err:
                shaping.install_schedule(source)
        self.assertEqual(err.exception.code, "E_CONFLICT")
        self.assertFalse(shaping.SCHEDULE.exists())

    def test_foreign_qdisc_rejected_without_writes(self):
        before = shaping.state_load()
        rule = {"iface": "relay0", "proto": "tcp", "port": 443,
                "direction": "ingress", "mbps": 10, "pref": 41000}
        with mock.patch.object(shaping, "_kernel", return_value=(True, {
            "ingress": [], "egress": []
        })):
            with self.assertRaises(PM2Error) as err:
                shaping.preflight(before, [rule])
        self.assertEqual(err.exception.code, "E_CONFLICT")

    def test_iproute2_json_flower_header_is_not_duplicate_filter(self):
        header = {"protocol": "ip", "pref": 41000, "kind": "flower"}
        concrete = {"protocol": "ip", "pref": 41000, "kind": "flower",
                    "options": {"keys": {"ip_proto": "tcp", "dst_port": 443},
                                "actions": [{"kind": "police"}]}}
        with mock.patch.object(shaping, "_tc_json", side_effect=[
                [{"kind": "clsact"}], [header, concrete], []]):
            has_clsact, rows = shaping._kernel("relay0")
        self.assertTrue(has_clsact)
        self.assertEqual(len(rows["ingress"]), 1)
        self.assertEqual(rows["ingress"][0]["options"]["keys"]["dst_port"], 443)

    def test_idempotent_reconcile_and_cleanup(self):
        with (mock.patch.object(shaping.os, "geteuid", return_value=0),
              mock.patch.object(shaping, "schedule_load", return_value=plan()),
              mock.patch.object(shaping.config, "load", return_value=config()),
              mock.patch.object(shaping, "_kernel",
                                return_value=(False, {"ingress": [], "egress": []})),
              mock.patch.object(shaping, "_tc") as tc):
            at = datetime(2026, 10, 9, 12, tzinfo=timezone.utc)
            out = shaping.reconcile(at=at)
            self.assertFalse(out["changed"])
            tc.assert_not_called()

    def test_pending_blocks_mutation(self):
        shaping.PENDING.write_text('{"product":"portmanager2"}')
        with self.assertRaises(PM2Error):
            shaping.preflight(shaping.state_load(), [{
                "iface": "relay0", "proto": "tcp", "port": 443,
                "direction": "ingress", "mbps": 10, "pref": 41000
            }])

    def test_symlink_owner_record_rejected(self):
        shaping.STATE.symlink_to(self.base / "nonexistent")
        with self.assertRaises(PM2Error):
            shaping.state_load()


if __name__ == "__main__":
    unittest.main()
