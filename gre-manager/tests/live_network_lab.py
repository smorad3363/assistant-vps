"""Actual public TCP/UDP forwarding, translations, and rate-cap acceptance."""
import argparse
import json
import os
from pathlib import Path
import time
from live_api import API, peer_script

parser=argparse.ArgumentParser()
parser.add_argument('action',choices=('echo','caps','mappings'))
args=parser.parse_args()
a=API();state=a.request('state');active=next(c for c in state['connections'] if c['enabled'])
results=[]
def passed(name,data=None):
 results.append({'test':name,'passed':True,'detail':data});print(json.dumps(results[-1]),flush=True)
 Path('/root/gremgr-network-'+active['kind']+'-'+args.action+'.json').write_text(json.dumps(results,indent=2))

def fixture():
 return peer_script(r'''
import pathlib,subprocess,time,json
D=pathlib.Path('/root/gremgr-protocol-lab')
code="""import socketserver,threading
class T(socketserver.BaseRequestHandler):
 def handle(self):
  data=self.request.recv(65535);self.request.sendall(str(self.server.server_address[1]).encode()+b':'+data)
class U(socketserver.BaseRequestHandler):
 def handle(self):
  data,s=self.request;s.sendto(str(self.server.server_address[1]).encode()+b':'+data,self.client_address)
class S(socketserver.ThreadingTCPServer):allow_reuse_address=True;daemon_threads=True
servers=[]
for port in (80,443,5311,5312,65535,30000,30001):
 for cls,handler in [(S,T),(socketserver.ThreadingUDPServer,U)]:
  s=cls(('0.0.0.0',port),handler);servers.append(s);threading.Thread(target=s.serve_forever,daemon=True).start()
threading.Event().wait()
"""
(D/'echo.py').write_text(code)
saved=json.loads((D/'processes.json').read_text())
def spawn(name,cmd):
 if any(r['name']==name and pathlib.Path('/proc/'+str(r['pid'])).exists() for r in saved):return
 p=subprocess.Popen(cmd,stdin=subprocess.DEVNULL,stdout=open(D/(name+'.log'),'ab'),stderr=subprocess.STDOUT,start_new_session=True)
 saved.append({'name':name,'pid':p.pid,'start':pathlib.Path('/proc/'+str(p.pid)+'/stat').read_text().split()[21]})
spawn('public-echo',['python3',str(D/'echo.py')])
for port in (5201,5202):spawn('public-iperf-'+str(port),['iperf3','-s','-p',str(port)])
(D/'processes.json').write_text(json.dumps(saved));time.sleep(1);print('ready')
''')

def echo(port,target=None,udp=True,tcp=True,expect=True):
 code='HOST='+repr(a.host)+'\nPORT='+str(port)+'\nTARGET='+str(target or port)+'\nUDP='+repr(udp)+'\nTCP='+repr(tcp)+'\nEXPECT='+repr(expect)+'\n'+r'''
import socket,subprocess,json
program="""import socket,json
answers=[]
for udp in ([False] if TCP else [])+([True] if UDP else []):
 s=socket.socket(socket.AF_INET,socket.SOCK_DGRAM if udp else socket.SOCK_STREAM);s.settimeout(2)
 try:
  payload=b'gremgr-real-payload-'+bytes(range(256))*3
  if udp:s.sendto(payload,(HOST,PORT));data,peer=s.recvfrom(65535);assert peer==(HOST,PORT),peer
  else:s.connect((HOST,PORT));s.sendall(payload);data=s.recv(65535)
  assert data==str(TARGET).encode()+b':'+payload
  assert EXPECT
  answers.append('UDP' if udp else 'TCP')
 except (TimeoutError,ConnectionRefusedError):
  assert not EXPECT
  answers.append('blocked as expected')
 finally:s.close()
print(json.dumps(answers))
"""
prefix='HOST='+repr(HOST)+'\nPORT='+str(PORT)+'\nTARGET='+str(TARGET)+'\nTCP='+repr(TCP)+'\nUDP='+repr(UDP)+'\nEXPECT='+repr(EXPECT)+'\n'
p=subprocess.run(['ip','netns','exec','gml-client','python3','-c',prefix+program],capture_output=True,text=True)
assert p.returncode==0,p.stderr
print(p.stdout)
'''
 return json.loads(peer_script(code))

def measure(ports=(5201,),reverse=False):
 code='HOST='+repr(a.host)+'\nPORTS='+repr(tuple(ports))+'\nREVERSE='+repr(reverse)+'\n'+r'''
import subprocess,json,concurrent.futures
def run(port):
 cmd=['ip','netns','exec','gml-client','iperf3','-c',HOST,'-p',str(port),'-u','-b','8M','-l','1000','-O','3','-t','4','-J','--get-server-output']
 if REVERSE:cmd.append('-R')
 p=subprocess.run(cmd,capture_output=True,text=True,timeout=25);d=json.loads(p.stdout)
 assert p.returncode==0 and not d.get('error'),d
 end=d['end'];received=end.get('sum_received',end.get('sum',{}))
 return {'port':port,'mbps':received['bits_per_second']/1e6,'bytes':received['bytes']}
with concurrent.futures.ThreadPoolExecutor() as pool:print(json.dumps(list(pool.map(run,PORTS))))
'''
 return json.loads(peer_script(code))

fixture()
if args.action=='echo':
 for port in (80,443,5311,65535):passed('real TCP/UDP source and payload '+str(port),echo(port))
elif args.action=='caps':
 original=dict(active)
 try:
  baseline=measure();assert baseline[0]['mbps']>5,baseline;passed('unlimited UDP baseline',baseline)
  for reverse in (False,True):
   c=dict(active,upload_mbps=0 if reverse else 2,download_mbps=2 if reverse else 0,port_limits={})
   a.job('connection.save',c)
   measured=measure((5201,5202),reverse);total=sum(r['mbps'] for r in measured)
   assert .7<total<2.5,measured
   passed('aggregate cap shared by two flows '+('download' if reverse else 'upload'),measured)
   c['port_limits']={'5201':{'up':0 if reverse else 1,'down':1 if reverse else 0}}
   a.job('connection.save',c);measured=measure((5201,),reverse)
   assert .3<measured[0]['mbps']<1.4,measured
   passed('per-port cap '+('download' if reverse else 'upload'),measured)
  a.job('connection.save',dict(active,upload_mbps=0,download_mbps=0,port_limits={'5201':{'up':1,'down':1}}))
  measured=measure((5201,5202));assert measured[0]['mbps']<1.4 and measured[1]['mbps']>5,measured
  passed('per-port isolation and unlimited other port',measured)
 finally:a.job('connection.save',original)
elif args.action=='mappings':
 original=dict(active);direct=None
 try:
  c=dict(active,exclude_ports=sorted(set(active['exclude_ports']+[5311,65535])))
  a.job('connection.save',c)
  direct=a.job('connection.save',{'kind':'direct','name':'Mapping test','listen_ip':a.host,'target_host':active['target_host'],'ports':'5311,65535','port_map':{'5311':5312,'65535':80}})['id']
  passed('GRE/direct coexistence and input-to-target maps',{'5311':echo(5311,5312),'65535':echo(65535,80)})
  a.job('connection.toggle',{'id':direct});passed('paused direct forwarding blocks payload',echo(5311,5312,expect=False))
  a.job('connection.toggle',{'id':direct});passed('direct resume',echo(5311,5312))
  a.job('connection.delete',{'id':direct});direct=None
  a.job('connection.save',dict(active,protocols=['tcp']))
  passed('TCP-only forwards TCP',echo(5312,udp=False));passed('TCP-only does not forward UDP',echo(5312,tcp=False,expect=False))
  a.job('connection.save',dict(active,ports='30000-30001',protocols=['udp']))
  passed('UDP range endpoints forward',{'30000':echo(30000,tcp=False),'30001':echo(30001,tcp=False)})
  passed('UDP-only does not forward TCP',echo(30000,udp=False,expect=False))
 finally:
  if direct:a.job('connection.delete',{'id':direct})
  a.job('connection.save',original)
print(json.dumps({'result':'PASS','checks':len(results)}),flush=True)
