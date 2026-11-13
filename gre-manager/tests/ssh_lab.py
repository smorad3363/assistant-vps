"""Real SSH bootstrap and restricted-command acceptance on a disposable CI VM."""
import json
import os
from pathlib import Path
import socket
import subprocess
import tempfile
import time

from panel.engine import run, gre_for
from panel.model import DEFAULTS, PanelError, connection
from panel.remote import Remote
from panel.store import Paths

if os.geteuid()!=0 or os.environ.get('GITHUB_ACTIONS')!='true':
    raise SystemExit('This test is restricted to disposable GitHub Actions runners.')
with tempfile.TemporaryDirectory(prefix='gremgr-ssh-lab-') as directory:
    root=Path(directory)
    address=json.loads(run('ip','-j','-4','route','get','1.1.1.1').stdout)[0]['prefsrc']
    port=44223
    for name in ('initial','host'):
        run('ssh-keygen','-q','-t','ed25519','-N','','-f',root/name)
    authorized=root/'authorized';authorized.write_text((root/'initial.pub').read_text());authorized.chmod(0o600)
    ssh_cfg=root/'sshd_config'
    ssh_cfg.write_text(f'Port {port}\nListenAddress {address}\nHostKey {root}/host\nPidFile {root}/sshd.pid\nAuthorizedKeysFile {authorized} /root/.ssh/authorized_keys\nPermitRootLogin prohibit-password\nPubkeyAuthentication yes\nPasswordAuthentication no\nUsePAM no\nStrictModes no\nLogLevel ERROR\n')
    Path('/run/sshd').mkdir(exist_ok=True,mode=0o755)
    server=subprocess.Popen(['/usr/sbin/sshd','-D','-e','-f',str(ssh_cfg)],stdout=subprocess.DEVNULL,stderr=subprocess.PIPE)
    try:
        for _ in range(30):
            try:
                with socket.create_connection((address,port),timeout=.5):break
            except OSError:time.sleep(.1)
        paths=Paths(root/'client');remote=Remote(paths)
        foreign=remote.connect({'host':address,'port':port,'username':'root','private_key':(root/'initial').read_text(),'name':'SSH lab'})
        status=remote.call(foreign,{'action':'status'})
        assert address in status['addresses'],status
        marker=root/'must-not-exist'
        opts=remote._options(foreign,paths.ssh/foreign['id'])
        forced=run(*opts,'touch '+str(marker),input=json.dumps({'action':'status'}),timeout=20)
        assert json.loads(forced.stdout)['ok'] and not marker.exists()
        c=connection({'kind':'gre','listen_ip':'192.0.2.99','target_host':address,'server_id':foreign['id'],'ports':'51821','mtu':1400,'mtu_mode':'manual'},dict(DEFAULTS))
        reply=remote.batch(foreign,[(c,False)])
        remote.call(foreign,{'action':'rollback','transaction':reply['transaction']})
        reply=remote.batch(foreign,[(c,False)])
        remote.call(foreign,{'action':'commit','transaction':reply['transaction']})
        run('/usr/local/sbin/gremgr-peer','--restore')
        assert remote.call(foreign,{'action':'status'})['peers']>=1
        reply=remote.batch(foreign,[(c,True)])
        remote.call(foreign,{'action':'commit','transaction':reply['transaction']})
        print('PASS: real SSH bootstrap, pinned host keys, forced command, peer prepare/rollback/commit/boot restore/removal.')
    finally:
        server.terminate()
        server.wait(timeout=5)
