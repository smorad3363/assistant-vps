"""Opt-in management/recovery acceptance on the disposable panel VPS."""
import argparse
import base64
import hashlib
import json
import os
from pathlib import Path
import secrets
import subprocess
import sys
import time
from live_api import API, peer_script

parser=argparse.ArgumentParser()
parser.add_argument('action',choices=('domain','peers','ports','tls','restart','watchdog','ssh','auth'))
args=parser.parse_args()
a=API()
report=Path('/root/gremgr-operations-acceptance.json')
results=json.loads(report.read_text()) if report.exists() else []


def passed(name,detail=None):
    results.append({'test':name,'passed':True,'detail':detail})
    report.write_text(json.dumps(results,indent=2))
    print(json.dumps(results[-1]),flush=True)


def wait(test,label,seconds=35):
    deadline=time.monotonic()+seconds
    while time.monotonic()<deadline:
        try:
            value=test()
            if value:return value
        except (OSError,RuntimeError):pass
        time.sleep(1)
    raise TimeoutError(label)


def config():return json.loads(Path('/etc/gremgr/panel.json').read_text())
def totals():return sum(x['up']+x['down'] for x in a.request('stats')['totals'] if x['port']=='all')
def digest():return hashlib.sha256(Path('/etc/gremgr/tls/cert.pem').read_bytes()).hexdigest()


if args.action=='domain':
    c=next(x for x in a.request('state')['connections'] if x['enabled'])
    hosts=Path('/etc/hosts');marker=c['resolved_ip']+' gremgr-peer.test #gremgr-disposable-test\n'
    hosts.write_text(hosts.read_text().rstrip()+'\n'+marker)
    try:
        a.job('connection.save',dict(c,target_host='gremgr-peer.test'))
        saved=next(x for x in a.request('state')['connections'] if x['id']==c['id'])
        assert saved['target_host']=='gremgr-peer.test' and saved['resolved_ip']==c['resolved_ip']
        subprocess.run(['python3','/root/live_network_lab.py','echo'],check=True,stdout=subprocess.DEVNULL)
        passed('domain destination resolution and real TCP/UDP payloads')
    finally:
        a.job('connection.save',c)
        hosts.write_text(''.join(x for x in hosts.read_text().splitlines(True) if x!=marker))
elif args.action=='peers':
    code="import pathlib;print(sum('gremgr-peer' in x and 'command=' in x for x in pathlib.Path('/root/.ssh/authorized_keys').read_text().splitlines()))"
    before=int(peer_script(code))
    peer=a.request('state')['servers'][0]
    identity=a.job('server.connect',{'host':peer['host'],'port':peer['port'],'username':peer['username'],'password':os.environ['LAB_PEER_PASSWORD'],'name':'Disposable key test'})['server']
    assert int(peer_script(code))==before+1
    a.job('server.delete',{'id':identity})
    assert int(peer_script(code))==before
    assert not Path('/etc/gremgr/ssh',identity).exists()
    passed('unused SSH peer deletion revokes only its own restricted key')
elif args.action=='ports':
    original=config()['settings']['reserved_ports']
    for port in (8788,8787):
        a.job('settings.save',{'port':port})
        a=wait(lambda:API(port),'new panel port')
        a.request('web.confirm',{'port':port})
        assert not Path('/etc/gremgr/web-pending.json').exists()
        passed('HTTPS panel port change confirmed '+str(port))
    a.job('settings.save',{'port':8789})
    assert config()['settings']['port']==8789
    passed('unconfirmed port rollback timer armed')
    wait(lambda:config()['settings']['port']==8787,'automatic panel port rollback',145)
    a=wait(lambda:API(8787),'rolled back HTTPS panel')
    assert not Path('/etc/gremgr/web-pending.json').exists()
    a.job('settings.save',{'reserved_ports':original})
    passed('unconfirmed panel port automatically rolls back after 120 seconds')
elif args.action=='tls':
    before=digest()
    rejected=a.job('tls.save',{'certificate':'invalid','key':'invalid'},fail=True)
    assert rejected['result']['code']=='certificate' and digest()==before
    passed('invalid TLS material rejected without replacing trusted certificate')
    a.job('tls.save',{'certificate':Path('/etc/gremgr/tls/cert.pem').read_text(),'key':Path('/etc/gremgr/tls/key.pem').read_text()})
    assert not a.request('state')['certificate']['enabled']
    passed('manual certificate upload disables automatic replacement')
    time.sleep(3);a=wait(lambda:API(),'HTTPS after certificate reload')
    a.job('tls.auto',{})
    wait(lambda:a.request('state')['certificate']['status']=='ready','automatic certificate re-enabled',80)
    passed('automatic IP certificate re-enabled through panel API')
    with open('/root/gremgr-certificate-staging.log','w') as log:
        subprocess.run(['python3','-m','panel.certificates','renew','--staging','--force'],cwd='/opt/gremgr/current',stdout=log,stderr=subprocess.STDOUT,timeout=180,check=True)
    assert digest()==before
    state=a.request('state')['certificate']
    assert state['status']=='ready' and state.get('staging_verified_at')
    subprocess.run(['curl','-fsS','--connect-timeout','5','https://'+a.host+':8787/','-o','/dev/null'],check=True)
    subprocess.run(['python3','/root/live_network_lab.py','echo'],stdout=subprocess.DEVNULL,check=True)
    passed('real staging issuance/renewal, trusted certificate retained, port 80 forwarding restored')
elif args.action=='restart':
    before=totals()
    subprocess.run(['systemctl','kill','--kill-who=main','--signal=SIGKILL','gremgr-worker.service'],check=True)
    a=wait(lambda:API(),'worker and frontend automatic crash recovery',45)
    after=totals()
    assert before<=after<before+1000000,(before,after)
    subprocess.run(['python3','/root/live_network_lab.py','echo'],stdout=subprocess.DEVNULL,check=True)
    passed('worker/frontend crash recovery and monotonic persistent traffic totals',{'before':before,'after':after})
    print(peer_script("import subprocess;subprocess.run(['systemctl','restart','gremgr-peer.service'],check=True);print('peer boot restore service passed')"),flush=True)
    subprocess.run(['python3','/root/live_network_lab.py','echo'],stdout=subprocess.DEVNULL,check=True)
    passed('foreign boot restore service retains payload forwarding')
elif args.action=='watchdog':
    c=next(x for x in a.request('state')['connections'] if x['kind']=='gre' and x['enabled'])
    probe=a.job('connection.probe',{'id':c['id']});assert probe['gre'] is True
    sys.path.insert(0,'/opt/gremgr/current')
    from panel.engine import gre_for
    device=gre_for(c)['tunnel'];started=time.time()
    subprocess.run(['ip','link','set','dev',device,'down'],check=True)
    try:
        assert a.job('connection.probe',{'id':c['id']})['gre'] is False
        passed('watchdog fixture detects the owned GRE interface outage')
        def recovered():
            s=a.request('state')
            return next((e for e in s['events'] if e['at']>=started and 'refreshed after three failed checks' in e['message']),None)
        event=wait(recovered,'watchdog automatic repair',210)
        assert a.job('connection.probe',{'id':c['id']})['gre'] is True
        passed('watchdog restores the owned GRE state after three failed checks',{'seconds':round(time.time()-started),'event':event['message']})
    finally:subprocess.run(['ip','link','set','dev',device,'up'],check=True)
elif args.action=='ssh':
    initial=a.request('state');desired={c['id']:c['enabled'] for c in initial['connections']}
    peer=initial['servers'][0]['resolved_ip']
    body=r'''
import subprocess,pathlib,os,shutil
D=pathlib.Path('/root/gremgr-protocol-lab')
if not shutil.which('sshpass'):subprocess.run(['apt-get','install','-y','-qq','sshpass'],stdout=subprocess.DEVNULL,check=True)
pub=pathlib.Path('/etc/ssh/ssh_host_ed25519_key.pub').read_text().strip()
known=D/'ssh-known';known.write_text(PEER+' '+pub+'\n['+PEER+']:2222 '+pub+'\n')
fd,write=os.pipe();os.write(write,PASSWORD.encode()+b'\n');os.close(write)
try:
 p=subprocess.run(['ip','netns','exec','gml-client','sshpass','-d',str(fd),'ssh','-T','-p','2222','-o','StrictHostKeyChecking=yes','-o','UserKnownHostsFile='+str(known),'-o','GlobalKnownHostsFile=/dev/null','-o','HostKeyAlias='+PEER,'-o','HostKeyAlgorithms=ssh-ed25519','-o','PreferredAuthentications=password','-o','PubkeyAuthentication=no','-o','ConnectTimeout=7','root@'+FRONT,'printf gremgr-ssh-payload'],pass_fds=(fd,),stdin=subprocess.DEVNULL,capture_output=True,text=True,timeout=20)
finally:os.close(fd)
assert p.returncode==0 and p.stdout=='gremgr-ssh-payload',p.stderr
print('SSH password authentication and command payload passed')
'''
    try:
        for kind in ('gre','direct'):
            s=a.request('state');c=next(x for x in s['connections'] if x['kind']==kind)
            for other in s['connections']:
                if other['id']!=c['id'] and other['enabled']:a.job('connection.toggle',{'id':other['id']})
            if not c['enabled']:a.job('connection.toggle',{'id':c['id']})
            c=next(x for x in a.request('state')['connections'] if x['id']==c['id'])
            a.job('connection.save',dict(c,ports='2222',target_port=22,port_map={},protocols=['tcp'],monitor_ports=[2222],port_limits={}))
            try:
                code='PASSWORD='+repr(os.environ['LAB_PEER_PASSWORD'])+'\nFRONT='+repr(a.host)+'\nPEER='+repr(peer)+'\n'+body
                passed(kind+' SSH authentication, real command data and single input-to-target port mapping',peer_script(code).strip())
            finally:a.job('connection.save',c)
    finally:
        current=a.request('state')['connections']
        for c in current:
            if c['enabled'] and not desired[c['id']]:a.job('connection.toggle',{'id':c['id']})
        for c in a.request('state')['connections']:
            if not c['enabled'] and desired[c['id']]:a.job('connection.toggle',{'id':c['id']})
elif args.action=='auth':
    path=Path('/root/gremgr-test-login.json');old=json.loads(path.read_text())
    try:a.request('password',{'current':old['password'],'password':'short'})
    except RuntimeError as error:assert 'password' in str(error)
    else:raise AssertionError('weak password accepted')
    passed('weak password rejected')
    credentials={'username':'admin_'+secrets.token_hex(4),'password':secrets.token_urlsafe(24)}
    a.job('settings.save',{'username':credentials['username']})
    a.request('password',{'current':old['password'],'password':credentials['password']})
    try:a.request('state')
    except RuntimeError as error:assert 'HTTP 401' in str(error)
    else:raise AssertionError('password rotation retained old session')
    path.write_text(json.dumps(credentials));path.chmod(0o600)
    a=API();a.request('logout',{})
    try:a.request('state')
    except RuntimeError as error:assert 'HTTP 401' in str(error)
    else:raise AssertionError('logout retained session')
    a=API()
    passed('random username/password, old-session revocation, logout and new login')
    print('CREDENTIALS64='+base64.b64encode(json.dumps(credentials).encode()).decode(),flush=True)
