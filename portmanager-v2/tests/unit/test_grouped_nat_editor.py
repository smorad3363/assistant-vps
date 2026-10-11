"""Grouped NAT rules and guarded manual edits without real firewall mutation."""
import tempfile
import unittest
from pathlib import Path
from unittest import mock

from pm2 import nat_editor, system_rules
from pm2.errors import PM2Error


TCP = ("-A PREROUTING -p tcp -m tcp -j DNAT "
       "--to-destination 135.125.254.188")
UDP = TCP.replace("-p tcp -m tcp", "-p udp -m udp")


class GroupedNatTests(unittest.TestCase):
    def test_pair_same_destination_and_matches(self):
        rows = system_rules.parse_nat(TCP + "\n" + UDP + "\n")
        groups = system_rules.group_nat(rows)
        self.assertEqual(len(groups), 1)
        self.assertEqual(groups[0]["protocol"], "tcp+udp")
        self.assertEqual(len(groups[0]["members"]), 2)
        self.assertEqual([m["line_number"] for m in groups[0]["members"]], [1, 2])

    def test_different_match_or_ip_not_grouped(self):
        lines = (TCP + "\n" +
                 UDP.replace("135.125.254.188", "185.226.94.239") + "\n" +
                 UDP.replace("PREROUTING", "OUTPUT") + "\n")
        self.assertEqual(len(system_rules.group_nat(system_rules.parse_nat(lines))), 3)

    def test_duplicate_tcp_does_not_disappear(self):
        rows = system_rules.parse_nat(TCP + "\n" + TCP + "\n" + UDP + "\n")
        grouped = system_rules.group_nat(rows)
        self.assertEqual(len(grouped), 2)
        self.assertEqual(sorted(len(row["members"]) for row in grouped), [1, 2])

    def test_returned_group_does_not_merge_different_ports(self):
        raw = ("-A PREROUTING -p tcp --dport 8080 -j DNAT "
               "--to-destination 192.0.2.10:8080\n"
               "-A PREROUTING -p udp --dport 8081 -j DNAT "
               "--to-destination 192.0.2.10:8080\n")
        self.assertEqual(len(system_rules.group_nat(system_rules.parse_nat(raw))), 2)

    def test_line_number_counts_all_chain_rules(self):
        raw = ("-A PREROUTING -j ACCEPT\n" + TCP + "\n" + UDP + "\n")
        rows = system_rules.parse_nat(raw)
        self.assertEqual(rows[0]["line_number"], 2)
        self.assertEqual(rows[1]["line_number"], 3)

    def test_owned_rule_is_not_manual_editor_candidate(self):
        managed = system_rules.parse_nat(
            TCP.replace("PREROUTING", "PM2_NAT_PRE"))[0]
        self.assertTrue(managed["owned"])
        self.assertFalse(nat_editor.editable(managed))


class ForeignEditTests(unittest.TestCase):
    def test_validate_ipv4_and_port(self):
        self.assertEqual(nat_editor.parse_destination("135.125.254.188:8080"),
                         "135.125.254.188:8080")
        for bad in ("127.0.0.1", "1.2.3.4:99999", "example.com",
                    "255.255.255.256", "1.1.1.1;iptables -F"):
            with self.subTest(bad=bad), self.assertRaises(PM2Error):
                nat_editor.parse_destination(bad)

    def test_replace_keeps_source_port_interface_and_all_other_matches(self):
        old = system_rules.parse_nat(
            "-A PREROUTING -i eth0 -p tcp --dport 443 -j DNAT "
            "--to-destination 192.0.2.5:8443")[0]
        self.assertEqual(nat_editor.replacement(old, "198.51.100.2:9443"), [
            "-i", "eth0", "-p", "tcp", "--dport", "443", "-j", "DNAT",
            "--to-destination", "198.51.100.2:9443"])

    def test_foreign_managed_chains_are_not_edited(self):
        for chain in ("DOCKER", "ufw-user-input", "PM2_NAT_PRE"):
            rule = system_rules.parse_nat(TCP.replace("PREROUTING", chain))[0]
            self.assertFalse(nat_editor.editable(rule))

    def test_watchdog_must_be_armed_before_first_iptables_change(self):
        with tempfile.TemporaryDirectory() as root:
            path = Path(root) / "edit.json"
            original = system_rules.parse_nat(TCP)
            events = []
            with (mock.patch.object(nat_editor, "JOURNAL", path),
                  mock.patch.object(nat_editor, "_snapshot", return_value=original),
                  mock.patch.object(nat_editor.os, "geteuid", return_value=0),
                  mock.patch.object(nat_editor, "_schedule",
                                    side_effect=lambda ident: events.append("timer")),
                  mock.patch.object(nat_editor, "_replace",
                                    side_effect=lambda *args: events.append("replace"))):
                result = nat_editor.apply(original, "185.226.94.239")
                self.assertTrue(path.exists())
                self.assertEqual(events, ["timer", "replace"])
                self.assertTrue(result["pending_confirmation"])

    def test_partial_pair_failure_restores_first_rule_immediately(self):
        with tempfile.TemporaryDirectory() as root:
            path = Path(root) / "edit.json"
            initial = system_rules.parse_nat(TCP + "\n" + UDP + "\n")
            rows = [dict(item, argv=list(item["argv"])) for item in initial]
            events = []

            def snapshot():
                return rows

            def replace(entry, args):
                if (entry["line_number"] == 2 and
                        "185.226.94.239" in args):
                    raise PM2Error("E_APPLY", "mock second rule failure")
                item = next(row for row in rows
                            if row["line_number"] == entry["line_number"])
                item["argv"] = ["-A", entry["chain"], *args]
                events.append(("replace", entry["line_number"]))

            with (mock.patch.object(nat_editor, "JOURNAL", path),
                  mock.patch.object(nat_editor, "_snapshot", side_effect=snapshot),
                  mock.patch.object(nat_editor.os, "geteuid", return_value=0),
                  mock.patch.object(nat_editor, "_schedule",
                                    side_effect=lambda _: events.append(("timer", 0))),
                  mock.patch.object(nat_editor, "_replace", side_effect=replace)):
                with self.assertRaises(PM2Error):
                    nat_editor.apply(initial, "185.226.94.239")
                self.assertEqual(events, [("timer", 0), ("replace", 1),
                                          ("replace", 1)])
                self.assertEqual(rows[0]["argv"], initial[0]["argv"])
                self.assertFalse(path.exists())

    def test_schedule_error_never_replaces_foreign_rules(self):
        with tempfile.TemporaryDirectory() as root:
            path = Path(root) / "edit.json"
            original = system_rules.parse_nat(TCP)
            with (mock.patch.object(nat_editor, "JOURNAL", path),
                  mock.patch.object(nat_editor, "_snapshot", return_value=original),
                  mock.patch.object(nat_editor.os, "geteuid", return_value=0),
                  mock.patch.object(nat_editor, "_schedule",
                                    side_effect=PM2Error("E_APPLY", "test timer failed")),
                  mock.patch.object(nat_editor, "_replace") as modified):
                with self.assertRaises(PM2Error):
                    nat_editor.apply(original, "185.226.94.239")
                modified.assert_not_called()
                self.assertFalse(path.exists())


if __name__ == "__main__":
    unittest.main()
