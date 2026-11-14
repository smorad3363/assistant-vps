"""Real L2TP/IPsec payload test, only inside the disposable network lab."""
import json
import os
from pathlib import Path
import shlex
import signal
import subprocess
import sys
import time

assert os.geteuid() == 0
assert os.readlink('/proc/self/ns/net') != os.readlink('/proc/1/ns/net'), 'Refusing host network namespace'
lab = Path(sys.argv[1])
mode = sys.argv[2]
assert mode in ('gre', 'direct')
work = lab / ('ipsec-' + mode)
work.mkdir(mode=0o700)
service = '192.0.2.21' if mode == 'gre' else '192.0.2.20'
processes = []


def run(*args, check=True, timeout=20):
    p = subprocess.run(args, capture_output=True, text=True, timeout=timeout)
    if check and p.returncode:
        raise RuntimeError(' '.join(args[:5]) + ': ' + (p.stderr + p.stdout)[-2000:])
    return p


def spawn(label, args):
    out = open(work / (label + '.log'), 'wb')
    p = subprocess.Popen(args, stdin=subprocess.DEVNULL, stdout=out, stderr=out, start_new_session=True)
    processes.append(p)
    return p


def wait(test, label, seconds=35):
    for _ in range(seconds):
        if test():
            return
        time.sleep(1)
    raise RuntimeError('Timed out: ' + label)


def inside(process, *args, check=True):
    return run('nsenter', '-t', str(process.pid), '-m', '-n', *args, check=check)


charons = []
secrets = Path('/etc/ipsec.secrets')
chap = Path('/etc/ppp/chap-secrets')
old_secrets = secrets.read_bytes() if secrets.exists() else None
old_chap = chap.read_bytes() if chap.exists() else None
try:
    # Each fixture starts fresh. Scope conntrack removal to these three test
    # namespaces and only IKE/L2TP ports; no host/global conntrack flush.
    for namespace in ('gm-ir', 'gm-fo', 'gm-client'):
        for port in ('500', '4500', '1701'):
            run('ip', 'netns', 'exec', namespace, 'conntrack', '-D', '-p', 'udp', '--dport', port, check=False)
    secrets.write_text((old_secrets or b'').decode() + '\n' + service + ' gml-client : PSK "isolated-test-secret"\n')
    secrets.chmod(0o600)
    chap.write_text((old_chap or b'').decode() + '\ngmluser gml-l2tp isolated-ppp-secret *\n')
    chap.chmod(0o600)
    common = 'config setup\n uniqueids=no\nconn gml-l2tp\n keyexchange=ikev1\n authby=secret\n type=transport\n ike=aes128-sha256-modp2048!\n esp=aes128-sha256!\n forceencaps=yes\n fragmentation=yes\n'
    (work / 'server.conf').write_text(common + f' left={service}\n leftid={service}\n leftprotoport=17/1701\n right=%any\n rightid=gml-client\n rightprotoport=17/%any\n auto=add\n')
    (work / 'client.conf').write_text(common + f' left=192.0.2.30\n leftid=gml-client\n leftprotoport=17/1701\n right=192.0.2.10\n rightid={service}\n rightprotoport=17/1701\n auto=start\n')
    for role, namespace in [('server', 'gm-fo'), ('client', 'gm-client')]:
        command = 'mount -t tmpfs tmpfs /run; exec ipsec start --nofork --conf ' + shlex.quote(str(work / (role + '.conf')))
        p = spawn('ipsec-' + role, ['unshare', '--mount', '--propagation', 'private', 'ip', 'netns', 'exec', namespace, 'sh', '-c', command])
        charons.append(p)
        if role == 'server':
            wait(lambda: 'gml-l2tp' in inside(p, 'ipsec', 'statusall', check=False).stdout, 'IPsec server')
    server, client = charons
    wait(lambda: 'INSTALLED, TRANSPORT' in inside(client, 'ipsec', 'statusall', check=False).stdout, 'IPsec transport SA')
    (work / 'lns.options').write_text('auth\nname gml-l2tp\nrequire-mschap-v2\nmtu 1280\nmru 1280\n')
    (work / 'lac.options').write_text('noauth\nuser gmluser\npassword isolated-ppp-secret\nnoipdefault\nnodefaultroute\nmtu 1280\nmru 1280\n')
    (work / 'lns.conf').write_text(f'[global]\nport=1701\n[lns default]\nip range=10.254.0.2-10.254.0.5\nlocal ip=10.254.0.1\nrequire authentication=yes\nrequire chap=yes\nrefuse pap=yes\nname=gml-l2tp\npppoptfile={work}/lns.options\nlength bit=yes\n')
    (work / 'lac.conf').write_text(f'[global]\nport=1701\n[lac gml]\nlns=192.0.2.10\npppoptfile={work}/lac.options\nname=gmluser\nautodial=yes\nredial=yes\nredial timeout=3\nmax redials=3\nlength bit=yes\n')
    for role, process in [('lns', server), ('lac', client)]:
        spawn('l2tp-' + role, ['nsenter', '-t', str(process.pid), '-m', '-n', 'xl2tpd', '-D', '-c', str(work / (role + '.conf')), '-p', '/run/xl2tp-test.pid', '-C', '/run/xl2tp-test.control'])
    wait(lambda: inside(client, 'ping', '-c', '1', '-W', '1', '10.254.0.1', check=False).returncode == 0, 'L2TP/IPsec data')
    inside(client, 'ping', '-c', '10', '-i', '.1', '-s', '1000', '-W', '2', '10.254.0.1')
    status = inside(server, 'ipsec', 'statusall').stdout
    assert 'ESP in UDP' in status and 'INSTALLED, TRANSPORT' in status, status
    print('PASS: ' + mode + ' L2TP/IPsec NAT-T, PPP authentication, bidirectional 1000-byte payloads.')
    print('\n'.join(x for x in status.splitlines() if 'bytes_i' in x))
except Exception:
    for log in work.glob('*.log'):
        print(log.name, log.read_text(errors='replace')[-3500:])
    for p in charons:
        if p.poll() is None:
            print(inside(p, 'ipsec', 'statusall', check=False).stdout)
    raise
finally:
    for p in reversed(charons):
        if p.poll() is None:
            inside(p, 'ipsec', 'stop', check=False)
    for p in reversed(processes):
        if p.poll() is None:
            try:
                os.killpg(p.pid, signal.SIGTERM)
            except ProcessLookupError:
                pass
    for path, previous in ((secrets, old_secrets), (chap, old_chap)):
        if previous is None:
            path.unlink(missing_ok=True)
        else:
            path.write_bytes(previous)
