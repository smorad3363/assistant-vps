"""One-line port mappings and minimal Port Manager tunnel prompts."""
import io
import unittest
from contextlib import redirect_stdout
from unittest import mock

from pm2 import simple_ui, validation
from pm2.errors import PM2Error


class QuickTunnelTests(unittest.TestCase):
    def test_one_port_is_symmetric(self):
        self.assertEqual(validation.mappings("5555"), [
            {"listen_port": 5555, "target_port": 5555}])

    def test_mixed_comma_separated_pairs_are_sorted(self):
        self.assertEqual(validation.mappings("5555, 80:8080, 443"), [
            {"listen_port": 80, "target_port": 8080},
            {"listen_port": 443, "target_port": 443},
            {"listen_port": 5555, "target_port": 5555}])

    def test_invalid_or_duplicate_pairs_rejected(self):
        for pairs in ("", "5555,", ",5555", "5555:0", "0",
                      "5555:70000", "5555,5555:6666", "5555:6:7"):
            with self.subTest(pairs=pairs), self.assertRaises(PM2Error):
                validation.mappings(pairs)

    def test_single_name_is_generated_and_escaped_to_ascii(self):
        result = simple_ui._auto_tunnel_name(
            "2.29.39.22", "5555", [])
        self.assertEqual(result, "port-5555-to-2-29-39-22")
        self.assertRegex(result, r"^[A-Za-z0-9_-]{1,64}$")

    def test_duplicate_generated_name_gets_numeric_suffix(self):
        taken = [{"name": "PORT-5555-to-2-29-39-22"},
                 {"name": "port-5555-to-2-29-39-22-2"}]
        self.assertEqual(simple_ui._auto_tunnel_name(
            "2.29.39.22", "5555", taken),
            "port-5555-to-2-29-39-22-3")

    def test_shorthand_prefills_existing_unchanged_ports(self):
        self.assertEqual(simple_ui._compact_mapping([
            {"listen_port": 5555, "target_port": 5555},
            {"listen_port": 8080, "target_port": 9090}]),
            "5555,8080:9090")

    def test_new_tunnel_only_asks_target_and_ports(self):
        recorded = []
        def answer(label, default=None):
            recorded.append((label, default))
            return {"Destination IPv4": "2.29.39.22",
                    "Ports (5555,5555:6666,80:8080)": "5555,80:8080"}[label]
        with (mock.patch.object(simple_ui, "_network_defaults",
                                return_value=("eth0", "77.90.10.180")),
              mock.patch.object(simple_ui.config, "load",
                                return_value={"tunnels": []}),
              mock.patch.object(simple_ui, "_ask", side_effect=answer),
              mock.patch.object(simple_ui, "_mutate") as mutate,
              redirect_stdout(io.StringIO()) as output):
            simple_ui._tunnel_wizard()
        self.assertEqual(len(recorded), 2)
        self.assertIn("Source: eth0 / 77.90.10.180", output.getvalue())
        op, args = mutate.call_args.args
        self.assertEqual(op, "create")
        self.assertEqual(args[args.index("--name") + 1],
                         "port-5555-to-2-29-39-22")
        self.assertEqual(args[args.index("--mapping") + 1], "5555,80:8080")
        self.assertEqual(args[args.index("--listen-ip") + 1], "77.90.10.180")

    def test_edit_prefills_and_retains_old_name_source_without_discovery(self):
        old = {"id": "edited-id", "name": "legacy-safe-name",
               "target_ip": "2.29.39.22", "interface": "ens18",
               "listen_ip": "77.90.10.180", "mode": "ports",
               "protocols": ["tcp"], "mapping": [
                   {"listen_port": 5555, "target_port": 5555}]}
        seen = []
        def answer(label, default=None):
            seen.append((label, default))
            return default
        with (mock.patch.object(simple_ui, "_network_defaults") as discover,
              mock.patch.object(simple_ui, "_ask", side_effect=answer),
              mock.patch.object(simple_ui, "_mutate") as mutate,
              redirect_stdout(io.StringIO())):
            simple_ui._tunnel_wizard(old)
        discover.assert_not_called()
        self.assertEqual(seen, [
            ("Destination IPv4", "2.29.39.22"),
            ("Ports (5555,5555:6666,80:8080)", "5555")])
        operation, args = mutate.call_args.args
        self.assertEqual(operation, "update")
        self.assertEqual(args[args.index("--name") + 1], "legacy-safe-name")
        self.assertEqual(args[args.index("--interface") + 1], "ens18")

    def test_all_except_keeps_ssh_guard_with_two_user_fields(self):
        seen = []
        def answer(label, default=None):
            seen.append((label, default))
            return "2.29.39.22" if label == "Destination IPv4" else default
        with (mock.patch.object(simple_ui, "_network_defaults",
                                return_value=("eth0", "77.90.10.180")),
              mock.patch.object(simple_ui, "_protected_ssh_ports",
                                return_value="22,2222"),
              mock.patch.object(simple_ui.config, "load",
                                return_value={"tunnels": []}),
              mock.patch.object(simple_ui, "_ask", side_effect=answer),
              mock.patch.object(simple_ui, "_mutate") as mutate,
              redirect_stdout(io.StringIO())):
            simple_ui._tunnel_wizard(all_ports=True)
        self.assertEqual(len(seen), 2)
        args = mutate.call_args.args[1]
        self.assertEqual(args[args.index("--exclude") + 1], "22,2222")
        self.assertIn("--ack-all-ports", args)


if __name__ == "__main__":
    unittest.main()
