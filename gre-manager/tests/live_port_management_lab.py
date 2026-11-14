"""Opt-in port/rate/cleanup acceptance on the two disposable VPSs only."""
import base64
import hashlib
import ipaddress
import json
import os
from pathlib import Path
import shutil
import subprocess
import sys
import time

from live_api import API

api=API()
initial=api.request('state')
assert initial['version']=='1.2.0'
gre=next(c for c in initial['connections'] if c['kind']=='gre' and c['enabled'])
direct=next(c for c in initial['connections'] if c['kind']=='direct' and not c['enabled'])
server=next(s for s in initial['servers'] if s['id']==gre['server_id'])
assert api.host=='65.109.211.168' and server['resolved_ip']=='65.109.208.206','Wrong disposable targets'
known=Path('/root/gremgr-port-management.known')
shutil.copyfile('/etc/gremgr/ssh/'+server['id']+'.known',known);known.chmod(0o600)
results=[]
report=Path('/root/gremgr-v12-live-acceptance.json')


def passed(name,detail=None):
    results.append({'test':name,'passed':True,'detail':detail})
    report.write_text(json.dumps(results,indent=2));report.chmod(0o600)
    print(json.dumps(results[-1]),flush=True)


def foreign(code):
    read_fd,write_fd=os.pipe()
    os.write(write_fd,os.environ['LAB_PEER_PASSWORD'].encode()+b'\n');os.close(write_fd)
    try:
        p=subprocess.run(['sshpass','-d',str(read_fd),'ssh','-T','-p',str(server['port']),
                          '-o','StrictHostKeyChecking=yes','-o','UserKnownHostsFile='+str(known),
                          '-o','PubkeyAuthentication=no','root@'+server['resolved_ip'],'python3 -'],
                         input=code,text=True,capture_output=True,pass_fds=(read_fd,),timeout=90)
    finally:os.close(read_fd)
    if p.returncode:raise RuntimeError((p.stderr+p.stdout)[-3000:])
    return p.stdout


def backup():
    name=api.job('backup.create',{})['filename']
    raw=api.request('backup.download?filename='+name)
    path=Path('/root/gremgr-v12-test-restore.zip');path.write_bytes(raw);path.chmod(0o600)
    return raw


def restore():
    state=api.request('state')
    if not any(c['id']==gre['id'] for c in state['connections']):
        api.job('backup.restore',{'content':base64.b64encode(saved).decode()})
        state=api.request('state')
    peer=next(s for s in state['servers'] if s['id']==server['id'])
    installed=foreign("import pathlib;print(pathlib.Path('/usr/local/sbin/gremgr-peer').exists() and pathlib.Path('/opt/gremgr-peer/panel/agent.py').exists())").strip()=='True'
    if not peer['key_ready'] or not installed:
        api.job('server.connect',dict(server,password=os.environ['LAB_PEER_PASSWORD']))
    current=next(c for c in api.request('state')['connections'] if c['id']==gre['id'])
    if current['enabled'] and current.get('gre_slot',0)!=gre.get('gre_slot',0):
        api.job('connection.toggle',{'id':gre['id']})
    api.job('connection.save',direct)
    api.job('connection.save',dict(gre,gre_slot=gre.get('gre_slot',0)))
    assert api.job('connection.probe',{'id':gre['id']})['gre'] is True


def payloads(mapping):
    program='FRONT='+repr(api.host)+'\nMAPPING='+repr(mapping)+'\n'+r'''
import socket,json
answers=[]
for source,target in MAPPING.items():
 for udp in (False,True):
  with socket.socket(socket.AF_INET,socket.SOCK_DGRAM if udp else socket.SOCK_STREAM) as sock:
   sock.settimeout(3);data=b'gremgr-v12-payload-'+bytes(range(256))*3
   if udp:
    sock.sendto(data,(FRONT,source));reply,peer=sock.recvfrom(65535);assert peer==(FRONT,source),peer
   else:
    sock.connect((FRONT,source));sock.sendall(data);reply=sock.recv(65535)
   assert reply==str(target).encode()+b':'+data,reply[:40]
   answers.append(str(source)+'->'+str(target)+(' UDP' if udp else ' TCP'))
print(json.dumps(answers))
'''
    return json.loads(foreign('import subprocess\np=subprocess.run('+repr(['ip','netns','exec','gmlp-client','python3','-c',program])+',capture_output=True,text=True)\nassert p.returncode==0,p.stderr\nprint(p.stdout)'))


def traffic_and_rates(c):
    program='FRONT='+repr(api.host)+'\n'+r'''
import socket,time,threading
def run(port):
 with socket.socket(socket.AF_INET,socket.SOCK_DGRAM) as sock:
  sock.settimeout(1);deadline=time.monotonic()+9
  while time.monotonic()<deadline:
   sock.sendto(b'x'*1000,(FRONT,port));sock.recvfrom(65535);time.sleep(.002)
threads=[threading.Thread(target=run,args=(port,)) for port in (3300,5100)]
for t in threads:t.start()
for t in threads:t.join()
'''
    foreign('import subprocess\np=subprocess.Popen('+repr(['ip','netns','exec','gmlp-client','python3','-c',program])+',stdin=subprocess.DEVNULL,stdout=subprocess.DEVNULL,stderr=subprocess.DEVNULL,start_new_session=True)\nprint(p.pid)')
    readings=[]
    for _ in range(7):
        time.sleep(1)
        live=api.request('live');item=next(x for x in live['connections'] if x['id']==c['id'])
        if all(item['port_rates'].get(str(p),{}).get(d,0)>0 for p in (3300,5100) for d in ('up','down')):
            readings.append({'at':live['sampled_at'],'ports':item['port_rates']})
    assert len({x['at'] for x in readings})>=3,readings
    return readings


fixture=r'''
import pathlib,json,subprocess,time
D=pathlib.Path('/root/gremgr-port-management-lab');D.mkdir(mode=0o700,exist_ok=True)
def run(*args):subprocess.run(args,check=True,stdout=subprocess.DEVNULL)
run('ip','netns','add','gmlp-client');run('ip','link','add','gmlp-host','type','veth','peer','name','gmlp-uplink')
run('ip','link','set','gmlp-uplink','netns','gmlp-client');run('ip','addr','add','10.234.0.1/30','dev','gmlp-host');run('ip','link','set','gmlp-host','up')
for args in [('link','set','lo','up'),('addr','add','10.234.0.2/30','dev','gmlp-uplink'),('link','set','gmlp-uplink','up'),('route','add','default','via','10.234.0.1')]:run('ip','-n','gmlp-client',*args)
run('iptables','-t','nat','-I','POSTROUTING','1','-s','10.234.0.0/30','-o','eth0','-m','comment','--comment','gremgr-port-management-lab','-j','MASQUERADE')
code="""import socketserver,threading
class T(socketserver.BaseRequestHandler):
 def handle(self):
  while True:
   data=self.request.recv(65535)
   if not data:return
   self.request.sendall(str(self.server.server_address[1]).encode()+b':'+data)
class U(socketserver.BaseRequestHandler):
 def handle(self):
  data,sock=self.request;sock.sendto(str(self.server.server_address[1]).encode()+b':'+data,self.client_address)
class S(socketserver.ThreadingTCPServer):allow_reuse_address=True;daemon_threads=True
for port in (3000,5000):
 for cls,handler in ((S,T),(socketserver.ThreadingUDPServer,U)):
  server=cls(('0.0.0.0',port),handler);threading.Thread(target=server.serve_forever,daemon=True).start()
threading.Event().wait()
"""
(D/'echo.py').write_text(code)
p=subprocess.Popen(['python3',str(D/'echo.py')],stdin=subprocess.DEVNULL,stdout=open(D/'echo.log','ab'),stderr=subprocess.STDOUT,start_new_session=True)
(D/'process.json').write_text(json.dumps({'pid':p.pid,'start':pathlib.Path('/proc/'+str(p.pid)+'/stat').read_text().split()[21]}))
time.sleep(.5);assert p.poll() is None,(D/'echo.log').read_text();print('fixture ready')
'''
stop=r'''
import pathlib,json,subprocess,os,signal
D=pathlib.Path('/root/gremgr-port-management-lab')
if (D/'process.json').exists():
 row=json.loads((D/'process.json').read_text())
 try:
  if pathlib.Path('/proc/'+str(row['pid'])+'/stat').read_text().split()[21]==row['start']:os.killpg(row['pid'],signal.SIGTERM)
 except (OSError,ProcessLookupError):pass
for raw in subprocess.run(['ip','netns','pids','gmlp-client'],capture_output=True,text=True).stdout.split():
 try:os.kill(int(raw),signal.SIGTERM)
 except ProcessLookupError:pass
for args in (['ip','netns','del','gmlp-client'],['ip','link','del','gmlp-host'],['iptables','-t','nat','-D','POSTROUTING','-s','10.234.0.0/30','-o','eth0','-m','comment','--comment','gremgr-port-management-lab','-j','MASQUERADE']):subprocess.run(args,capture_output=True)
print('fixture removed')
'''

saved=backup()
try:
    foreign(fixture)
    for c in (gre,direct):
        if c['kind']=='direct':api.job('connection.toggle',{'id':gre['id']})
        api.job('connection.save',dict(c,enabled=True,ports='5100,3300',target_port=None,port_map={'5100':5000,'3300':3000},monitor_ports=[]))
        passed(c['kind']+' separate mappings carry real TCP and UDP payloads',payloads({5100:5000,3300:3000}))
        passed(c['kind']+' per-port live upload/download rates advance each second',traffic_and_rates(c))
        time.sleep(3)
        totals={x['port']:x for x in api.request('stats')['totals'] if x['identity']==c['id']}
        assert all(totals[str(p)]['up']>100000 and totals[str(p)]['down']>100000 for p in (3300,5100)),totals
        passed(c['kind']+' port history is stored under original input ports')
        if c['kind']=='direct':api.job('connection.save',direct)
    restore()
    duplicate=api.job('connection.save',dict(gre,id='',ports='9999'),fail=True)
    assert duplicate['result']['code']=='gre_exists',duplicate
    passed('a second GRE for the same endpoint pair is rejected clearly')
    extra=api.job('server.connect',dict(server,id='',name='Disposable shared-helper check',password=os.environ['LAB_PEER_PASSWORD']))['server']
    cleaned=api.job('server.delete',{'id':extra});assert not cleaned['purged'] and cleaned['shared']=='peers',cleaned
    assert api.job('connection.probe',{'id':gre['id']})['gre'] is True
    passed('deleting an unused management key preserves the active shared helper')
    api.job('connection.toggle',{'id':gre['id']})
    g=gre.get('gre_slot',0)
    sys.path.insert(0,'/opt/gremgr/current')
    from panel.engine import gre_for
    subnet=str(ipaddress.ip_network(gre_for(gre)['local_tun']+'/30',strict=False))
    foreign("import subprocess;subprocess.run(['ip','route','add','blackhole',"+repr(subnet)+",'proto','186','metric','42666'],check=True)")
    try:
        api.job('connection.save',dict(gre,gre_slot=g))
        changed=next(c for c in api.request('state')['connections'] if c['id']==gre['id'])
        assert changed.get('gre_slot',0)!=g,changed
        passed('an occupied foreign private subnet selects an alternative and still carries payloads',payloads({5000:5000,3000:3000}))
    finally:
        foreign("import subprocess;subprocess.run(['ip','route','del','blackhole',"+repr(subnet)+",'proto','186','metric','42666'],check=True)")
    restore()
    saved=backup()
    before=foreign("import pathlib,json;print(json.dumps([x for x in pathlib.Path('/root/.ssh/authorized_keys').read_text().splitlines() if 'gremgr-peer' not in x]))")
    deleted=api.job('connection.delete',{'id':gre['id']});assert deleted['cleanup']['purged'],deleted
    foreign("""import pathlib,subprocess
assert not pathlib.Path('/usr/local/sbin/gremgr-peer').exists()
assert not pathlib.Path('/etc/systemd/system/gremgr-peer.service').exists()
assert not pathlib.Path('/opt/gremgr-peer/panel/agent.py').exists()
assert 'GMP_' not in subprocess.run(['iptables-save'],check=True,capture_output=True,text=True).stdout
assert not any('gmp-' in x for x in subprocess.run(['ip','-o','link'],check=True,capture_output=True,text=True).stdout.splitlines())
assert 'gremgr-peer' not in pathlib.Path('/root/.ssh/authorized_keys').read_text()
print('full removal verified')
""")
    after=foreign("import pathlib,json;print(json.dumps([x for x in pathlib.Path('/root/.ssh/authorized_keys').read_text().splitlines() if 'gremgr-peer' not in x]))")
    assert before==after
    passed('last GRE deletion removes foreign helper, service, restricted key, routes and owned chains; normal SSH keys survive')
finally:
    try:
        restore()
        passed('real TCP/UDP payloads still pass after restoring and reprovisioning the peer',payloads({5000:5000,3000:3000}))
    finally:print(foreign(stop),flush=True)
current=api.request('state');assert current['settings']['username']==initial['settings']['username']
assert next(c for c in current['connections'] if c['id']==gre['id'])['enabled']
assert not next(c for c in current['connections'] if c['id']==direct['id'])['enabled']
passed('original profiles and traffic history restored; foreign reinstalled through the panel')
print(json.dumps({'result':'PASS','checks':len(results)}),flush=True)
