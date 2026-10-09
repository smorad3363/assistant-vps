"""Exercise ncurses with a REAL pseudo-terminal, not only mocks.

This is the regression for a Debian SSH session where full frames previously
flooded scrollback instead of painting one live screen.
"""
import errno
import os
import pty
import select
import subprocess
import sys
import time
import unittest


class FullscreenPtyTests(unittest.TestCase):
    def test_actual_terminal_uses_alternate_screen_and_restores_shell(self):
        script = """
import time
from pm2.live_screen import LiveScreen
with LiveScreen(2) as live:
    for rate in (15.0, 25.0, 35.0):
        live.draw({
            'rows': [{
                'listen_port':8080, 'protocol':'tcp',
                'now_up_mbps': rate, 'now_down_mbps':3.0,
                'avg10m_up_mbps':rate, 'avg10m_down_mbps':3.0,
                'averages': {name:{'up_mbps':rate,'down_mbps':3.0,
                                   'coverage_seconds':10}
                             for name in ('10m','1h','8h','24h')},
                'graph_up':'rising', 'graph_down':'___'
            }],
            'interfaces':[{'interface':'eth0','rx_mbps':510.0,'tx_mbps':480.0}],
            'port_coverage':'selected_ipv4_listening_ports'
        }, effective=2)
        time.sleep(.08)
"""
        master, slave = pty.openpty()
        env = dict(os.environ, TERM="xterm-256color", NO_COLOR="1")
        try:
            child = subprocess.Popen([sys.executable, "-u", "-c", script],
                                     stdin=slave, stdout=slave, stderr=slave,
                                     env=env, close_fds=True)
            os.close(slave)
            slave = -1
            output = bytearray()
            deadline = time.monotonic() + 10
            while time.monotonic() < deadline:
                if child.poll() is not None and not select.select([master], [], [], 0)[0]:
                    break
                if select.select([master], [], [], .1)[0]:
                    try:
                        chunk = os.read(master, 65536)
                    except OSError as exc:
                        if exc.errno == errno.EIO:
                            break
                        raise
                    if not chunk:
                        break
                    output.extend(chunk)
            if child.poll() is None:
                child.kill()
            code = child.wait(timeout=5)
            text = bytes(output)
            self.assertEqual(code, 0, text[-1600:].decode("utf-8", "replace"))
            # Real curses enters/exits alternate screen; one long repeated
            # print table has no such transitions and leaves scrollback dirty.
            self.assertIn(b"\x1b[?1049h", text)
            self.assertIn(b"\x1b[?1049l", text)
            self.assertIn(b"PORT MANAGER", text)
            self.assertIn(b"510.0", text)
        finally:
            if slave != -1:
                os.close(slave)
            os.close(master)


if __name__ == "__main__":
    unittest.main()
