"""Regression checks for requested simple UI, unknown traffic and NAT rule visibility."""
import io
import unittest
from contextlib import redirect_stdout
from unittest import mock

from pm2 import live_screen, simple_ui, system_rules
from pm2.errors import PM2Error


class FakeCurses:
    A_BOLD = 1
    def has_colors(self):
        return False
    class error(Exception):
        pass


class FakeScreen:
    def __init__(self):
        self.lines = []
        self.refreshes = 0
    def getmaxyx(self):
        return 28, 115
    def erase(self):
        self.lines.clear()
    def addnstr(self, y, x, text, maxlen, attr=0):
        self.lines.append((y, text[:maxlen]))
    def refresh(self):
        self.refreshes += 1


class NewThemeTest(unittest.TestCase):
    def test_two_cards_and_untracked_estimate_on_one_screen(self):
        screen = live_screen.LiveScreen(5)
        screen.window = FakeScreen()
        screen.curses = FakeCurses()
        row = {"protocol": "tcp", "listen_port": 8080, "now_up_mbps": 150,
               "now_down_mbps": 200, "avg10m_up_mbps": 150,
               "avg10m_down_mbps": 200, "averages": {},
               "graph_up": "▁▆█"}
        with redirect_stdout(io.StringIO()) as capture:
            screen.draw({"rows": [row], "interfaces": [{
                "interface": "eth0", "rx_mbps": 650, "tx_mbps": 640}]})
            screen.draw()
        display = "\n".join(s for _, s in screen.window.lines)
        self.assertEqual(capture.getvalue(), "")
        self.assertIn("DOWNLOAD", display)
        self.assertIn("UPLOAD", display)
        self.assertIn("TCP:8080", display)
        self.assertIn("OTHER / UNKNOWN", display)
        self.assertIn("450.0", display)
        self.assertIn("490.0", display)
        self.assertEqual(screen.window.refreshes, 2)

    def test_tracked_more_than_interface_never_negative(self):
        down, up = live_screen.LiveScreen.untracked_rates(
            {"rx_mbps": 100, "tx_mbps": 100},
            [{"now_down_mbps": 150, "now_up_mbps": 130}])
        self.assertEqual((down, up), (0, 0))

    def test_terminal_navigation_clears_previous_screen(self):
        with (mock.patch.object(simple_ui.os, "isatty", return_value=True),
              mock.patch.dict(simple_ui.os.environ, {"TERM": "xterm-256color"}),
              redirect_stdout(io.StringIO()) as output):
            simple_ui._clear_screen()
        self.assertEqual(output.getvalue(), chr(27) + "[2J" + chr(27) + "[H")

    def test_ports_menu_displays_nat_without_entering_config(self):
        old = {"chain": "PREROUTING", "protocol": "tcp", "port": "1001",
               "target": "DNAT", "destination": "203.0.113.1:4343"}
        with (mock.patch.object(simple_ui.config, "load",
                                return_value={"tunnels": []}),
              mock.patch.object(simple_ui.system_rules, "detect_nat",
                                return_value=([old], None)),
              mock.patch.object(simple_ui, "_ask", return_value="0"),
              redirect_stdout(io.StringIO()) as output):
            simple_ui._tunnel_page()
        self.assertIn("tcp:1001", output.getvalue())
        self.assertIn("203.0.113.1:4343", output.getvalue())
        self.assertIn("0 tunnels created here", output.getvalue())

    def test_iptables_nat_includes_old_rules_but_only_readonly(self):
        text = (
            "-A PREROUTING -p tcp -m tcp --dport 8080 -j DNAT "
            "--to-destination 203.0.113.1:80\n"
            "-A POSTROUTING -j MASQUERADE\n"
            "-A PREROUTING -p tcp --dport 22 -j ACCEPT\n")
        rules = system_rules.parse_nat(text)
        self.assertEqual(len(rules), 2)
        self.assertEqual(rules[0]["port"], "8080")
        self.assertEqual(rules[0]["destination"], "203.0.113.1:80")
        self.assertEqual(rules[1]["target"], "MASQUERADE")
        self.assertEqual(rules[0]["source"], "iptables (read-only)")

    def test_menu_lists_detected_rule_even_if_v2_has_no_configs(self):
        fake = {"tunnels": []}
        old_rule = {"chain": "PREROUTING", "protocol": "tcp", "port": "8080",
                    "target": "DNAT", "destination": "203.0.113.1:80"}
        with (mock.patch.object(simple_ui.config, "load", return_value=fake),
              mock.patch.object(simple_ui.system_rules, "detect_nat",
                                return_value=([old_rule], None)),
              redirect_stdout(io.StringIO()) as output):
            self.assertEqual(simple_ui._list_tunnels(), [])
        self.assertIn("203.0.113.1:80", output.getvalue())
        self.assertIn("read-only", output.getvalue())


if __name__ == "__main__":
    unittest.main()
