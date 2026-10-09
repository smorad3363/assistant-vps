"""Live monitoring must release lock and temporary counters on exit/TERM."""
import os
from pathlib import Path
import signal
import tempfile
import unittest
from unittest import mock

from pm2 import auto_monitor, port_graph


class MonitorLifecycleTest(unittest.TestCase):
    def test_lock_is_exclusive_only_while_live_and_pid_hint_is_cleared(self):
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / "monitor.lock"
            with (mock.patch.object(auto_monitor, "LOCK_FILE", path),
                  mock.patch.object(auto_monitor.os, "geteuid", return_value=0),
                  mock.patch.object(auto_monitor, "discover", return_value=[]),
                  mock.patch.object(auto_monitor, "_clear_owned") as cleaned):
                with auto_monitor.AutoMonitor():
                    self.assertEqual(auto_monitor.lock_owner_pid(), os.getpid())
                    with self.assertRaises(BlockingIOError):
                        with auto_monitor.AutoMonitor():
                            pass
                self.assertIsNone(auto_monitor.lock_owner_pid())
                # The file is deliberately retained; an inactive file isn't
                # an active lock and must not be manually removed.
                self.assertTrue(path.exists())
                with auto_monitor.AutoMonitor():
                    self.assertEqual(auto_monitor.lock_owner_pid(), os.getpid())
                self.assertEqual(cleaned.call_count, 2)

    def test_sigterm_unwinds_instead_of_leaving_stale_counters(self):
        previous = signal.getsignal(signal.SIGTERM)
        with port_graph._graceful_sigterm():
            current = signal.getsignal(signal.SIGTERM)
            self.assertNotEqual(current, previous)
            with self.assertRaises(KeyboardInterrupt):
                current(signal.SIGTERM, None)
        self.assertEqual(signal.getsignal(signal.SIGTERM), previous)


if __name__ == "__main__":
    unittest.main()
