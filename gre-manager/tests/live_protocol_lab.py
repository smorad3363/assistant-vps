"""Opt-in acceptance fixtures on two explicitly disposable VPSs.

Run on the panel host AFTER adding the peer through the authenticated panel API.
The peer password is supplied in LAB_PEER_PASSWORD, never in this source file.
This installs VPN test services, not the foreign tunnel helper.
"""
import argparse
import base64
import json
import os
from pathlib import Path
import subprocess
import sys

PEER_CODE = r'''
import json,os,pathlib,subprocess,time,signal,socket
D=pathlib.Path('/root/gremgr-protocol-lab');D.mkdir(mode=0o700,exist_ok=True)
NS='gml-client';records=D/'processes.json'
def run(*args,check=True,timeout=60):
 p=subprocess.run(args,capture_output=True,text=True,timeout=timeout)
 if check and p.returncode:raise RuntimeError(' '.join(args[:4])+': '+(p.stderr+p.stdout)[-1800:])
 return p
def spawn(name,args):
 log=open(D/(name+'.log'),'ab',buffering=0)
 p=subprocess.Popen(args,stdin=subprocess.DEVNULL,stdout=log,stderr=log,start_new_session=True,close_fds=True)
 saved=json.loads(records.read_text()) if records.exists() else []
 saved.append({'pid':p.pid,'start':pathlib.Path('/proc/'+str(p.pid)+'/stat').read_text().split()[21],'name':name})
 records.write_text(json.dumps(saved));return p.pid
def wait(test,label,seconds=30):
 for _ in range(seconds):
  if test():return
  time.sleep(1)
 raise RuntimeError('Timed out: '+label)
def stop():
 for row in json.loads(records.read_text()) if records.exists() else []:
  if row['name']=='ipsec-client':run('nsenter','-t',str(row['pid']),'-m','-n','ipsec','stop',check=False)
 run('ipsec','stop',check=False)
 for row in reversed(json.loads(records.read_text()) if records.exists() else []):
  try:
   if pathlib.Path('/proc/'+str(row['pid'])+'/stat').read_text().split()[21]==row['start']:os.killpg(row['pid'],signal.SIGTERM)
  except (OSError,ProcessLookupError):pass
 time.sleep(1)
 records.write_text('[]')
 run('ip','netns','del',NS,check=False)
 for dev in ('gml-host','gml-wgs','gml-ovs','gml-ovts'):run('ip','link','del',dev,check=False)
 rule=['-s','10.233.0.0/30','-o','eth0','-m','comment','--comment','gremgr-disposable-test','-j','MASQUERADE']
 while run('iptables','-t','nat','-C','POSTROUTING',*rule,check=False).returncode==0:run('iptables','-t','nat','-D','POSTROUTING',*rule)
def prepare(front,l2tp=True):
 if records.exists():stop()
 run('apt-get','update','-qq',timeout=180)
 env=dict(os.environ,DEBIAN_FRONTEND='noninteractive')
 p=subprocess.run(['apt-get','install','-y','-qq','wireguard-tools','openvpn','iperf3','xl2tpd','ppp','strongswan','conntrack','tcpdump'],env=env,capture_output=True,text=True,timeout=240)
 if p.returncode:raise RuntimeError(p.stderr[-1500:])
 run('systemctl','stop','xl2tpd.service',check=False)
 run('ip','netns','add',NS);run('ip','link','add','gml-host','type','veth','peer','name','gml-uplink')
 run('ip','link','set','gml-uplink','netns',NS)
 run('ip','addr','add','10.233.0.1/30','dev','gml-host');run('ip','link','set','gml-host','up')
 for args in [('link','set','lo','up'),('addr','add','10.233.0.2/30','dev','gml-uplink'),('link','set','gml-uplink','up'),('route','add','default','via','10.233.0.1')]:run('ip','-n',NS,*args)
 run('sysctl','-w','net.ipv4.ip_forward=1')
 run('iptables','-t','nat','-I','POSTROUTING','1','-s','10.233.0.0/30','-o','eth0','-m','comment','--comment','gremgr-disposable-test','-j','MASQUERADE')
 # WireGuard: real separate namespace client, public frontend endpoint.
 sk=run('wg','genkey').stdout.strip();ck=run('wg','genkey').stdout.strip()
 def public(key):return subprocess.run(['wg','pubkey'],input=key,text=True,capture_output=True,check=True).stdout.strip()
 for name,key in [('server',sk),('client',ck)]: (D/(name+'.wgkey')).write_text(key);(D/(name+'.wgkey')).chmod(0o600)
 run('ip','link','add','gml-wgs','type','wireguard');run('ip','addr','add','10.62.0.1/30','dev','gml-wgs')
 run('wg','set','gml-wgs','private-key',str(D/'server.wgkey'),'listen-port','51820','peer',public(ck),'allowed-ips','10.62.0.2/32')
 run('ip','link','set','gml-wgs','mtu','1280','up')
 run('ip','-n',NS,'link','add','gml-wgc','type','wireguard')
 run('ip','netns','exec',NS,'wg','set','gml-wgc','private-key',str(D/'client.wgkey'),'peer',public(sk),'endpoint',front+':51820','allowed-ips','10.62.0.1/32','persistent-keepalive','5')
 run('ip','-n',NS,'addr','add','10.62.0.2/32','dev','gml-wgc');run('ip','-n',NS,'link','set','gml-wgc','mtu','1280','up');run('ip','-n',NS,'route','add','10.62.0.1/32','dev','gml-wgc')
 # Disposable EC CA and proper TLS server/client certificates.
 run('openssl','req','-x509','-newkey','ec','-pkeyopt','ec_paramgen_curve:prime256v1','-nodes','-keyout',str(D/'ca.key'),'-out',str(D/'ca.pem'),'-days','2','-subj','/CN=GRE Manager disposable CA')
 for name,usage in [('vpnserver','serverAuth'),('vpnclient','clientAuth')]:
  run('openssl','req','-new','-newkey','ec','-pkeyopt','ec_paramgen_curve:prime256v1','-nodes','-keyout',str(D/(name+'.key')),'-out',str(D/(name+'.csr')),'-subj','/CN='+name)
  (D/'extensions').write_text('extendedKeyUsage='+usage+'\n')
  run('openssl','x509','-req','-in',str(D/(name+'.csr')),'-CA',str(D/'ca.pem'),'-CAkey',str(D/'ca.key'),'-CAcreateserial','-out',str(D/(name+'.pem')),'-days','2','-extfile',str(D/'extensions'))
 for name,port,network,proto,serverdev,clientdev in [('udp',1000,'10.63.0','udp4','gml-ovs','gml-ovc'),('tcp',1443,'10.64.0','tcp4','gml-ovts','gml-ovtc')]:
  common=f'ca {D}/ca.pem\ndata-ciphers AES-256-GCM\nauth SHA256\ntls-version-min 1.2\nverb 3\n'
  server=common+f'port {port}\nproto '+('tcp4-server' if name=='tcp' else proto)+f'\ndev {serverdev}\ndev-type tun\ntopology subnet\nserver {network}.0 255.255.255.0\ncert {D}/vpnserver.pem\nkey {D}/vpnserver.key\ndh none\nkeepalive 5 30\n'
  client=common+f'client\nremote {front} {port}\nproto '+('tcp4-client' if name=='tcp' else proto)+f'\ndev {clientdev}\ndev-type tun\nnobind\ncert {D}/vpnclient.pem\nkey {D}/vpnclient.key\nremote-cert-tls server\nroute-nopull\nroute {network}.1 255.255.255.255\nconnect-retry 1\nconnect-retry-max 5\n'
  (D/(name+'-server.conf')).write_text(server);(D/(name+'-client.conf')).write_text(client)
  spawn(name+'-server',['openvpn','--config',str(D/(name+'-server.conf'))])
  spawn(name+'-client',['ip','netns','exec',NS,'openvpn','--config',str(D/(name+'-client.conf'))])
 # Plain L2TP/PPP is tested separately from IPsec NAT-T.
 secret='gmluser gml-l2tp lab-only-password *\n'
 chap=pathlib.Path('/etc/ppp/chap-secrets');old=chap.read_text() if chap.exists() else ''
 if secret not in old:chap.write_text(old+'\n'+secret);chap.chmod(0o600)
 (D/'lns.options').write_text('auth\nname gml-l2tp\nrequire-mschap-v2\nmtu 1280\nmru 1280\nms-dns 1.1.1.1\n')
 (D/'lac.options').write_text('noauth\nuser gmluser\npassword lab-only-password\nnoipdefault\nnodefaultroute\nusepeerdns\nmtu 1280\nmru 1280\n')
 (D/'lns.conf').write_text(f'[global]\nport = 1701\n[lns default]\nip range = 10.65.0.2-10.65.0.10\nlocal ip = 10.65.0.1\nrequire authentication = yes\nrequire chap = yes\nrefuse pap = yes\nname = gml-l2tp\npppoptfile = {D}/lns.options\nlength bit = yes\n')
 (D/'lac.conf').write_text(f'[global]\nport = 1701\n[lac gml]\nlns = {front}\npppoptfile = {D}/lac.options\nname = gmluser\nautodial = yes\nredial = yes\nredial timeout = 3\nmax redials = 5\nlength bit = yes\n')
 if l2tp:
  spawn('l2tp-server',['xl2tpd','-D','-c',str(D/'lns.conf'),'-p',str(D/'lns.pid'),'-C',str(D/'lns.control')])
  spawn('l2tp-client',['ip','netns','exec',NS,'xl2tpd','-D','-c',str(D/'lac.conf'),'-p',str(D/'lac.pid'),'-C',str(D/'lac.control')])
 return {'prepared':True,'frontend':front,'services':['WireGuard UDP/51820','OpenVPN UDP/1000','OpenVPN TCP/1443','L2TP PPP/1701']}
def ipsec(front):
 # IKEv1 transport mode plus mandatory NAT-T, as used by L2TP/IPsec clients.
 # A private /run mount gives the namespace client its own charon PID/socket.
 for row in json.loads(records.read_text()):
  if row['name'].startswith('l2tp-'):
   try:os.killpg(row['pid'],signal.SIGTERM)
   except ProcessLookupError:pass
 time.sleep(1)
 run('ipsec','stop',check=False)
 # Rule updates deliberately retain unrelated conntrack state. Reset only
 # this disposable IKE/L2TP fixture's old flows before changing its transport.
 owned=[a['local'] for i in json.loads(run('ip','-j','-4','addr').stdout) if i['ifname'].startswith('gmp-') for a in i.get('addr_info',[])]
 for destination in owned+[json.loads(run('ip','-j','-4','route','get',front).stdout)[0]['prefsrc']]:
  for port in ('500','4500','1701'):run('conntrack','-D','-p','udp','--orig-dst',destination,'--dport',port,check=False)
 secret=pathlib.Path('/etc/ipsec.secrets')
 peer=json.loads(run('ip','-j','-4','route','get',front).stdout)[0]['prefsrc']
 entry=peer+' gml-client : PSK "gremgr-disposable-ipsec-secret"\n'
 old=secret.read_text() if secret.exists() else ''
 if entry not in old:secret.write_text(old+'\n'+entry);secret.chmod(0o600)
 common='config setup\n uniqueids=no\nconn gml-l2tp\n keyexchange=ikev1\n authby=secret\n type=transport\n ike=aes128-sha256-modp2048!\n esp=aes128-sha256!\n forceencaps=yes\n fragmentation=yes\n dpdaction=clear\n'
 (D/'ipsec-server.conf').write_text(common+f' left={peer}\n leftid={peer}\n leftprotoport=17/1701\n right=%any\n rightid=gml-client\n rightprotoport=17/%any\n auto=add\n')
 (D/'ipsec-client.conf').write_text(common+f' left=10.233.0.2\n leftid=gml-client\n leftprotoport=17/1701\n right={front}\n rightid={peer}\n rightprotoport=17/1701\n auto=start\n')
 spawn('ipsec-server',['ipsec','start','--nofork','--conf',str(D/'ipsec-server.conf')]);time.sleep(2)
 pid=spawn('ipsec-client',['unshare','--mount','--propagation','private','ip','netns','exec',NS,'sh','-c','mount -t tmpfs tmpfs /run; exec ipsec start --nofork --conf '+str(D/'ipsec-client.conf')])
 wait(lambda:'INSTALLED, TRANSPORT' in run('nsenter','-t',str(pid),'-m','-n','ipsec','statusall',check=False).stdout,'IPsec transport SA',35)
 spawn('l2tp-server-ipsec',['xl2tpd','-D','-c',str(D/'lns.conf'),'-p',str(D/'lns.pid'),'-C',str(D/'lns.control')])
 spawn('l2tp-client-ipsec',['ip','netns','exec',NS,'xl2tpd','-D','-c',str(D/'lac.conf'),'-p',str(D/'lac.pid'),'-C',str(D/'lac.control')])
 wait(lambda:run('ip','netns','exec',NS,'ping','-c','1','-W','1','10.65.0.1',check=False).returncode==0,'L2TP/IPsec data',35)
 stats=run('ipsec','statusall').stdout
 return {'passed':True,'nat_t': 'ESP in UDP' in stats or '4500' in stats,'sa': '\n'.join(x for x in stats.splitlines() if any(s in x for s in ['ESTABLISHED','INSTALLED, TRANSPORT','bytes_i','bytes_o']))}
def verify():
 results={}
 for name,ip,port in [('wireguard','10.62.0.1',5203),('openvpn-udp','10.63.0.1',5204),('openvpn-tcp','10.64.0.1',5205),('l2tp-ppp','10.65.0.1',5206)]:
  try:
   wait(lambda:run('ip','netns','exec',NS,'ping','-c','1','-W','1',ip,check=False).returncode==0,name,35)
   spawn(name+'-iperf',['iperf3','-s','-B',ip,'-p',str(port)])
   time.sleep(.3)
   up=json.loads(run('ip','netns','exec',NS,'iperf3','-c',ip,'-p',str(port),'-t','2','-b','10M','-J',timeout=15).stdout)
   down=json.loads(run('ip','netns','exec',NS,'iperf3','-c',ip,'-p',str(port),'-t','2','-b','10M','-R','-J',timeout=15).stdout)
   results[name]={'passed':True,'up_bytes':up['end']['sum_received']['bytes'],'down_bytes':down['end']['sum_received']['bytes']}
  except Exception as error:results[name]={'passed':False,'error':str(error)}
 results['wg_handshake']=run('wg','show','gml-wgs','latest-handshakes',check=False).stdout.strip().split('\t')[-1]
 return results
if ACTION=='prepare':answer=prepare(FRONT)
elif ACTION=='prepare-ipsec':prepare(FRONT,False);answer=ipsec(FRONT)
elif ACTION=='verify':answer=verify()
elif ACTION=='stop':stop();answer={'stopped':True}
elif ACTION=='ipsec':answer=ipsec(FRONT)
else:answer={'logs':{p.name:p.read_text(errors='replace')[-2500:] for p in D.glob('*.log') if 'iperf' not in p.name}}
print(json.dumps(answer))
'''


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("action", choices=("prepare", "prepare-ipsec", "verify", "ipsec", "logs", "stop"))
    parser.add_argument("--frontend", required=True)
    args = parser.parse_args()
    config = json.loads(Path("/etc/gremgr/panel.json").read_text())
    server = config["servers"][0]
    read_fd, write_fd = os.pipe()
    os.write(write_fd, os.environ["LAB_PEER_PASSWORD"].encode() + b"\n"); os.close(write_fd)
    script = "ACTION=" + repr(args.action) + "\nFRONT=" + repr(args.frontend) + "\n" + PEER_CODE
    try:
        result = subprocess.run(["sshpass", "-d", str(read_fd), "ssh", "-T", "-p", str(server["port"]),
                                 "-o", "StrictHostKeyChecking=yes", "-o", "UserKnownHostsFile=/etc/gremgr/ssh/" + server["id"] + ".known",
                                 "-o", "PubkeyAuthentication=no", "root@" + server["resolved_ip"], "python3 -"],
                                pass_fds=(read_fd,), input=script, text=True, capture_output=True, timeout=480)
    finally:
        os.close(read_fd)
    print(result.stdout)
    if result.returncode:
        print(result.stderr[-5000:], file=sys.stderr)
        raise SystemExit(result.returncode)


if __name__ == "__main__":
    main()
