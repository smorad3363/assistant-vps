"""Conservative native GRE planner and guarded local reconciler.

IMPORTANT: Live end-to-end acceptance has not been performed. User must not
interpret a successful local apply as proven remote throughput or QoS support.
"""
from __future__ import annotations
import hashlib
import ipaddress
import json
import os
from pathlib import Path
import platform
import re
import subprocess
import tempfile
from . import firewall
from .config import ConfigError, validate

STATE_DIR=Path(os.environ.get('GRE_TUN_STATE_DIR','/var/lib/gre-tun/state'))
STATE_PATH=STATE_DIR/'owned.json'


def run(argv,check=True,timeout=8,input=None):
    try:
        p=subprocess.run(argv,check=False,capture_output=True,text=True,timeout=timeout,input=input)
    except (FileNotFoundError,subprocess.TimeoutExpired) as exc:
        raise ConfigError('E_COMMAND: '+repr(exc)) from None
    if check and p.returncode:
        raise ConfigError(f'E_COMMAND: {" ".join(argv[:3])}: {(p.stderr or p.stdout)[:350].strip()}')
    return p


def _json(argv):
    try:return json.loads(run(argv).stdout)
    except ValueError:raise ConfigError('E_JSON') from None


def _current_ipv4():
    return {(a['local'],x['ifname']) for x in _json(['ip','-j','-4','addr','show']) for a in x.get('addr_info',[]) if 'local' in a}


def _link(dev):
    p=run(['ip','-d','-j','link','show','dev',dev],check=False)
    if p.returncode:return None
    try:return json.loads(p.stdout)[0]
    except (ValueError,IndexError):raise ConfigError('E_LINK_QUERY') from None


def read_state():
    if not STATE_PATH.exists():return None
    data=json.loads(STATE_PATH.read_text(encoding='utf-8'))
    if data.get('owner')!='gre-tun/1':raise ConfigError('E_OWNERSHIP_INVALID')
    if type(data.get('tunnels')) is not list:raise ConfigError('E_OWNERSHIP_INVALID')
    return data


def _save_state(data):
    STATE_DIR.mkdir(parents=True,exist_ok=True,mode=0o700)
    fd,path=tempfile.mkstemp(prefix='.owned-',dir=STATE_DIR)
    try:
        with os.fdopen(fd,'w',encoding='utf-8') as f:
            os.fchmod(f.fileno(),0o600)
            json.dump(data,f,sort_keys=True,indent=2);f.write('\n');f.flush();os.fsync(f.fileno())
        os.replace(path,STATE_PATH)
    finally:
        if os.path.exists(path):os.unlink(path)


def _digest(c):
    return hashlib.sha256(json.dumps(c,sort_keys=True,separators=(',',':')).encode()).hexdigest()


def preflight(c):
    validate(c)
    issues=[]
    if os.geteuid()!=0:issues.append('E_ROOT')
    if platform.system()!='Linux':issues.append('E_LINUX')
    if not Path('/run/systemd/system').exists():issues.append('E_SYSTEMD')
    if any(f['enabled'] and (f['upload_mbps'] or f['download_mbps']) for f in c['forwards']):
        issues.append('E_QOS_UNSUPPORTED')
    try:
        actual=_current_ipv4()
        for name,argv in [('nft',['nft','--version']),('tc',['tc','-V']),('conntrack',['conntrack','-V'])]:
            if run(argv,check=False).returncode:issues.append('E_DEPENDENCY_'+name.upper())
        issues.extend(firewall.conservative_foreign_conflicts(run))
        state=read_state()
        known={t['id']:t for t in (state or {}).get('tunnels',[])}
        for t in c['tunnels']:
            if (t['local_ip'],t['wan_if']) not in actual:issues.append(f'E_LOCAL_IP:T{t["id"]:04d}')
            remote=ipaddress.IPv4Address(t['peer_ip'])
            route=_json(['ip','-j','-4','route','get',str(remote)])[0]
            if route.get('dev')!=t['wan_if'] or route.get('src',route.get('prefsrc'))!=t['local_ip']:
                issues.append(f'E_PEER_ROUTE:T{t["id"]:04d}')
            if t['mtu']>1400:issues.append('E_MTU')
            current=_link('gtn'+str(t['id']))
            if current and t['id'] not in known:issues.append(f'E_FOREIGN_INTERFACE:T{t["id"]:04d}')
            if current and t['id'] in known:
                previous=known[t['id']]
                if any(previous[k]!=t[k] for k in ('local_ip','peer_ip','inside_cidr','key')):
                    issues.append(f'E_TUNNEL_REBUILD_REQUIRES_EXPLICIT_REMOVE:T{t["id"]:04d}')
        table=firewall.read_existing(run)
        if table and not (state or {}).get('nft_owned'):
            issues.append('E_FOREIGN_NFT_TABLE')
        # Do not adopt a routing table or priority already used by a foreign rule.
        observed=run(['ip','-j','-4','rule','show'],check=False)
        rules=json.loads(observed.stdout) if observed.returncode==0 else []
        for t in c['tunnels']:
            table=45000+t['id'];prio=30000+t['id']
            if any(int(x.get('priority',-1))==prio and t['id'] not in known for x in rules):
                issues.append('E_FOREIGN_POLICY_PRIORITY')
            rt=run(['ip','-j','-4','route','show','table',str(table)],check=False)
            if rt.returncode==0 and rt.stdout.strip() not in ('','[]') and t['id'] not in known:
                issues.append('E_FOREIGN_ROUTE_TABLE')
        # If port is bound locally, it will not necessarily be visible to the
        # forwarded flow, but fail closed until explicit socket-scoped lab tests.
        ss=run(['ss','-H','-lntup'],check=False)
        if ss.returncode==0:
            listeners=ss.stdout.splitlines()
            for f in c['forwards']:
                if not f['enabled']:continue
                ptn=re.compile(r'(?<!\d):'+str(f['listen_port'])+r'(?!\d)')
                for line in listeners:
                    if ptn.search(line) and (f['listen_ip'] in line or '0.0.0.0:' in line or '*:' in line or '[::]:' in line):
                        issues.append(f'E_LOCAL_LISTENER:P{f["id"]:04d}');break
    except (ConfigError,OSError,KeyError,ValueError,IndexError) as exc:
        issues.append(f'E_PREFLIGHT:{str(exc)[:180]}')
    return list(dict.fromkeys(issues))


def _one_inner(t):
    return firewall.address_pair(t)


def _ip_rule(t, action):
    m=0x47000000|(t['id']<<12)
    return ['ip','-4','rule',action,'priority',str(30000+t['id']), 'iif',t['wan_if'],
            'fwmark',f'{m:#x}/0xfffff000','lookup',str(45000+t['id'])]


def _make_tunnel(t):
    tid=t['id'];dev='gtn'+str(tid)
    local,peer=_one_inner(t)
    run(['ip','tunnel','add',dev,'mode','gre','local',t['local_ip'],'remote',t['peer_ip'],
         'key',str(t['key']),'ttl','64'])
    run(['ip','addr','add',f'{local}/30','dev',dev])
    run(['ip','link','set','dev',dev,'mtu',str(t['mtu']),'up'])
    run(['ip','-4','route','replace','table',str(45000+tid),'default','via',peer,'dev',dev])
    run(_ip_rule(t,'add'))


def _remove_tunnel(t):
    tid=t['id'];dev='gtn'+str(tid)
    run(_ip_rule(t,'del'),check=False)
    run(['ip','-4','route','flush','table',str(45000+tid)],check=False)
    if _link(dev):run(['ip','link','del',dev])


def _install_firewall(c,table_exists):
    script=firewall.generate(c,table_exists)
    run(['nft','-c','-f','-'],input=script,timeout=10)
    run(['nft','-f','-'],input=script,timeout=10)


def apply(c,check_only=False):
    """Validate before touching owned kernel objects.

    This preproduction reconciler intentionally refuses capped forwarding and
    ambiguous firewalls instead of bypassing requested security properties.
    """
    issues=preflight(c)
    if issues:raise ConfigError('; '.join(issues))
    if check_only:return 'Preflight passed (kernel integration NOT RUN).'
    # This guard is deliberately independent of privilege level. The full
    # transaction/rollback, tc IFB and remote-path acceptance gates have not
    # been certified; never alter a production host via this dev CLI.
    if os.environ.get('GRE_TUN_EXPERIMENTAL_LAB')!='1' or not Path('/etc/gre-tun-test-disposable-vm').is_file():
        raise ConfigError('E_NOT_READY: Live changes require an explicitly marked disposable lab.')
    old=read_state() or {'owner':'gre-tun/1','tunnels':[],'nft_owned':False}
    active=[t for t in c['tunnels'] if t['enabled']]
    desired={t['id']:t for t in active}
    before={t['id']:t for t in old['tunnels']}
    if old.get('digest')==_digest(c) and all(_link('gtn'+str(tid)) for tid in desired):
        return 'Already configured.'
    # Only provision new tunnels before changing nft. On any failure remove
    # exactly newly created tunnels, never a pre-existing foreign resource.
    new=[]
    try:
        for tid,t in desired.items():
            if tid not in before:
                _make_tunnel(t);new.append(t)
        _install_firewall(c,old.get('nft_owned',False))
    except (ConfigError,OSError):
        for t in reversed(new):_remove_tunnel(t)
        raise
    for tid,t in before.items():
        if tid not in desired:_remove_tunnel(t)
    _save_state({'owner':'gre-tun/1','digest':_digest(c),'tunnels':active,'nft_owned':True,'counter_epoch':old.get('counter_epoch',0)+1})
    return 'Local structures applied. Peer traffic and QoS have not been end-to-end certified.'


def uninstall_owned():
    previous=read_state()
    if not previous:return 'No owned runtime objects recorded.'
    if previous.get('nft_owned'):
        if firewall.read_existing(run) is not None:
            run(['nft','delete','table','ip','gre_tun'])
    for t in previous['tunnels']:_remove_tunnel(t)
    STATE_PATH.unlink(missing_ok=True)
    return 'Recorded owned network resources removed locally.'
