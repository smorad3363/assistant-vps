"""All-table iptables browser includes foreign and manual entries read-only."""
import io
import unittest
from contextlib import redirect_stdout
from unittest import mock

from pm2 import iptables_ui, system_rules


class FullRulesTests(unittest.TestCase):
    def test_all_tables_visible_not_just_nat(self):
        source = ("*filter\n:INPUT DROP [0:0]\n-A INPUT -p tcp --dport 22 -j ACCEPT\nCOMMIT\n"
                  "*nat\n-A PREROUTING -p tcp --dport 8080 -j DNAT --to-destination 10.0.0.2\nCOMMIT\n"
                  "*mangle\n-A FORWARD -j MARK --set-mark 5\nCOMMIT\n")
        with mock.patch.object(system_rules, "run", return_value=source) as executed:
            rows, err = system_rules.detect_all()
        self.assertIsNone(err)
        self.assertTrue(any("INPUT DROP" in line for line in rows))
        self.assertTrue(any("DNAT" in line for line in rows))
        self.assertTrue(any("MARK" in line for line in rows))
        self.assertEqual(executed.call_args.args[0], ["iptables-save"])

    def test_ui_separates_pm2_from_other_rules(self):
        data = ["*nat", ":PREROUTING ACCEPT [0:0]",
                "-A PREROUTING -p tcp --dport 8080 -j DNAT --to-destination 10.0.0.1",
                "-A PM2_NAT_PRE -p tcp --dport 80 -j DNAT --to-destination 198.51.100.2",
                "COMMIT"]
        with (mock.patch.object(system_rules, "detect_all", return_value=(data, None)),
              mock.patch("pm2.simple_ui._title"),
              mock.patch("pm2.simple_ui._choose", return_value="0"),
              redirect_stdout(io.StringIO()) as output):
            iptables_ui.browse()
        rendered = output.getvalue()
        self.assertIn("PM2", rendered)
        self.assertIn("OTHER", rendered)
        self.assertIn("8080", rendered)

    def test_full_reset_screen_has_no_network_mutation(self):
        with (mock.patch("pm2.simple_ui._title"),
              mock.patch("pm2.simple_ui._choose", return_value="0"),
              redirect_stdout(io.StringIO()) as output):
            iptables_ui.full_reset_information()
        self.assertIn("DANGER", output.getvalue())
        self.assertIn("No firewall rules are changed", output.getvalue())


if __name__ == "__main__":
    unittest.main()
