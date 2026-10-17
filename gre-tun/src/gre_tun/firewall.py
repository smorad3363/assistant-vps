"""Scoped nftables renderer; never manipulate external nft tables.

Activation is intentionally gated by network preflight. Generated rules are
validated with nft -c before a single nft -f batch is submitted.
"""
from __future__ import annotations
import ipaddress
import json
import re
import subprocess
from .config import ConfigError, validate
from .contract import inside_addresses

TABLE='gre_tun'
CHAIN_SPEC={
 'classify':'type filter hook prerouting priority -150; policy accept;',
 'dnat':'type nat hook prerouting priority -90; policy accept;',
 'forward_guard':'type filter hook forward priority 10; policy accept;',
 'account':'type filter hook postrouting priority 90; policy accept;',
 'snat':'type nat hook postrouting priority 110; policy accept;',
 'input_guard':'type filter hook input priority 10; policy accept;',
}

def address_pair(t):
    pair=inside_addresses(t['inside_cidr'],t['local_ip'],t['peer_ip'])
    return pair['local_inner'],pair['peer_inner']

def marker(tid,fid):
    return 0x47000000 | (tid<<12) | fid

def generate(c, table_exists=False):
    validate(c)
    lines=[]
    if table_exists: lines.append('delete table ip gre_tun')
    lines.extend(['add table ip gre_tun']+[f'add chain ip gre_tun {name} {{ {spec} }}' for name,spec in CHAIN_SPEC.items()])
    active={t['id']:t for t in c['tunnels'] if t['enabled']}
    managed=[f for f in c['forwards'] if f['enabled'] and f['tunnel_id'] in active]
    for f in managed:
        lines.append(f'add counter ip gre_tun p{f["id"]:04d}u')
        lines.append(f'add counter ip gre_tun p{f["id"]:04d}d')
    for t in active.values():
        tid=t['id']; iface=f'gtn{tid}'
        local,remote=address_pair(t)
        # A gateway may have many GRE tunnels. Only the expected /30 peer
        # source is allowed to access the kernel from this owned tunnel.
        lines.append(f'add rule ip gre_tun input_guard iifname "{iface}" ip saddr != {remote} drop comment "gt:t{tid}:bad-peer"')
        lines.append(f'add rule ip gre_tun forward_guard iifname "{iface}" ip saddr != {remote} drop comment "gt:t{tid}:bad-peer"')
        for other in active.values():
            lines.append(f'add rule ip gre_tun forward_guard iifname "{iface}" oifname "gtn{other["id"]}" drop comment "gt:t{tid}:no-transit"')
        # Transit toward real physical WAN; peer-side masquerading is only for
        # this specific expected inner source and selected underlay interface.
        lines.append(f'add rule ip gre_tun forward_guard iifname "{iface}" ip saddr {remote} oifname "{t["wan_if"]}" accept comment "gt:t{tid}:peer-out"')
        lines.append(f'add rule ip gre_tun snat iifname "{iface}" ip saddr {remote} oifname "{t["wan_if"]}" masquerade comment "gt:t{tid}:peer-snat"')
    for f in managed:
        t=active[f['tunnel_id']];tid=t['id'];fid=f['id'];iface=f'gtn{tid}'
        own,peer=address_pair(t)
        m=f'0x{marker(tid,fid):08x}'
        for proto in (('tcp','udp') if f['protocol']=='both' else (f['protocol'],)):
            match=f'iifname "{t["wan_if"]}" ip daddr {f["listen_ip"]} {proto} dport {f["listen_port"]}'
            lines.append(f'add rule ip gre_tun classify {match} ct state new ct mark 0 ct mark set {m} comment "gt:p{fid}:classify-{proto}"')
            lines.append(f'add rule ip gre_tun dnat {match} ct mark {m} dnat to {f["target_ip"]}:{f["target_port"]} comment "gt:p{fid}:dnat-{proto}"')
        # Subsequent packets of an already NATted connection retain ct mark.
        lines.append(f'add rule ip gre_tun classify iifname "{t["wan_if"]}" ct direction original ct mark {m} meta mark set ct mark comment "gt:p{fid}:route"')
        lines.append(f'add rule ip gre_tun forward_guard iifname "{t["wan_if"]}" oifname "{iface}" ct direction original ct mark {m} accept comment "gt:p{fid}:original"')
        lines.append(f'add rule ip gre_tun forward_guard iifname "{iface}" ct direction reply ct mark {m} ct state established,related accept comment "gt:p{fid}:reply"')
        lines.append(f'add rule ip gre_tun account ct direction original ct mark {m} oifname "{iface}" counter name p{fid:04d}u comment "gt:p{fid}:up"')
        lines.append(f'add rule ip gre_tun account ct direction reply ct mark {m} iifname "{iface}" counter name p{fid:04d}d comment "gt:p{fid}:down"')
        lines.append(f'add rule ip gre_tun snat ct direction original ct mark {m} oifname "{iface}" snat to {own} comment "gt:p{fid}:entry-snat"')
    for t in active.values():
        iface=f'gtn{t["id"]}'
        # This rule must be last among owned forward hooks, after explicit
        # reverse/original exceptions; foreign firewall drops still apply.
        lines.append(f'add rule ip gre_tun forward_guard oifname "{iface}" drop comment "gt:t{t["id"]}:egress-deny"')
        lines.append(f'add rule ip gre_tun forward_guard iifname "{iface}" ct state new oifname != "{t["wan_if"]}" drop comment "gt:t{t["id"]}:ingress-deny"')
    return '\n'.join(lines)+'\n'


def read_existing(run):
    proc=run(['nft','-j','list','table','ip',TABLE],check=False)
    if proc.returncode==0:
        try:return json.loads(proc.stdout)
        except ValueError:raise ConfigError('E_NFT_INVALID') from None
    if 'No such file or directory' in (proc.stderr or '') or 'does not exist' in (proc.stderr or ''):
        return None
    raise ConfigError('E_NFT_QUERY: '+(proc.stderr or '')[:300])


def counters(run):
    table=read_existing(run)
    result={}
    if not table:return result
    for item in table.get('nftables',[]):
        obj=item.get('counter')
        if not obj:continue
        m=re.fullmatch(r'p(\d{4})(u|d)',obj.get('name',''))
        if not m:continue
        fid=int(m.group(1));direction=m.group(2)
        result.setdefault(fid,{'u':None,'d':None})[direction]=obj.get('bytes')
    return {fid:(x['u'],x['d']) for fid,x in result.items() if type(x['u']) is int and type(x['d']) is int}


def conservative_foreign_conflicts(run):
    """Fail closed for firewall operations that may mask or bypass ours.

    This rejects some harmless complex firewalls, intentionally, until a
    supported firewall-coexistence kernel test exists.
    """
    p=run(['nft','-j','list','ruleset'],check=False)
    if p.returncode:return ['E_FOREIGN_FIREWALL_UNREADABLE']
    try:tables=json.loads(p.stdout).get('nftables',[])
    except (ValueError,AttributeError):return ['E_FOREIGN_FIREWALL_UNREADABLE']
    errors=[]
    for x in tables:
        if 'flowtable' in x:
            errors.append('E_FOREIGN_FLOWTABLE');continue
        if 'rule' not in x:continue
        rule=x['rule']
        if rule.get('table')==TABLE and rule.get('family')=='ip':continue
        expr=json.dumps(rule.get('expr',[]),sort_keys=True).lower()
        # Fast conservative scan: fail rather than imply coexistence with
        # unknown filtering, translational NAT or conntrack manipulation.
        if any(k in expr for k in ('"drop"','"reject"','"dnat"','"redirect"','"tproxy"','"notrack"','"ct zone"')):
            errors.append('E_FOREIGN_FIREWALL_UNCLASSIFIED');break
    return errors
