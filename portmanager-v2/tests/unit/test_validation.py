"""Strict immutable tunnel model, collision coverage, schema and validation."""
import unittest
from pm2.validation import make_tunnel, collides, validate_collection
from pm2.errors import PM2Error


class TunnelTests(unittest.TestCase):
    def t(self, **kwargs):
        args = dict(name="relayA", listen_ip="192.0.2.11", target_ip="192.0.2.80",
                    interface="eth0", mode="ports", protocol="tcp,udp",
                    mapping="443:8443")
        args.update(kwargs)
        return make_tunnel(**args)

    def test_tcp_udp_mapping(self):
        a = self.t()
        self.assertEqual(a["mapping"], [{"listen_port": 443, "target_port": 8443}])
        self.assertEqual(a["protocols"], ["tcp", "udp"])
        validate_collection([a])

    def test_reject_duplicate_mapping(self):
        with self.assertRaises(PM2Error):
            self.t(mapping="443:8443,443:443")

    def test_reject_invalid_ip_port(self):
        for change in (dict(listen_ip="127.0.0.1"), dict(target_ip="0.0.0.0"),
                       dict(target_ip="224.0.0.1"), dict(mapping="0:8443"),
                       dict(mapping="70000:1"), dict(mapping="443:443,"),
                       dict(name="bad name"), dict(protocol="udp,tcp")):
            with self.subTest(change=change), self.assertRaises(PM2Error):
                self.t(**change)

    def test_reject_ssh_capturing_all_except(self):
        with self.assertRaises(PM2Error):
            self.t(mode="all-except", mapping=None, exclude="2222",
                   ack_all_ports=True)

    def test_all_except_valid_and_collisions(self):
        all_ports = self.t(mode="all-except", mapping=None, exclude="22,443",
                           ack_all_ports=True)
        port443 = self.t(name="otherA", mapping="443:5443")
        port80 = self.t(name="otherB", mapping="80:80")
        self.assertFalse(collides(all_ports, port443))
        self.assertTrue(collides(all_ports, port80))

    def test_overlaps_fail_closed(self):
        a = self.t()
        b = self.t(name="otherA", mapping="443:9443")
        with self.assertRaises(PM2Error) as error:
            validate_collection([a, b])
        self.assertEqual(error.exception.code, "E_CONFLICT")

    def test_same_nic_secondary_anchor_no_longer_allows_duplicate_ports(self):
        # Runtime uses every actual IPv4 on eth0, regardless of which one
        # the legacy V2 configuration stored as its interface anchor.
        a = self.t()
        b = self.t(name="otherA", listen_ip="192.0.2.12",
                   mapping="443:9443")
        self.assertTrue(collides(a, b))
        with self.assertRaises(PM2Error):
            validate_collection([a, b])

    def test_distinct_nics_can_hold_same_port(self):
        a = self.t()
        b = self.t(name="otherA", interface="eth1",
                   listen_ip="192.0.2.12", mapping="443:9443")
        self.assertFalse(collides(a, b))

    def test_case_insensitive_names_unique(self):
        a = self.t()
        b = self.t(name="RELAYA", mapping="2222:2222")
        with self.assertRaises(PM2Error):
            validate_collection([a, b])

    def test_disabled_tunnels_may_overlap(self):
        a = self.t()
        b = self.t(name="second", enabled=False)
        validate_collection([a, b])

    def test_wrong_schema_fields_rejected(self):
        a = self.t()
        a["bogus"] = "extra"
        with self.assertRaises(PM2Error):
            validate_collection([a])


if __name__ == "__main__":
    unittest.main()
