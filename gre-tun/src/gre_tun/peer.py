"""Peer tokens and host discovery; no remote commands."""
import ipaddress
import json
import subprocess
from .contract import pair_identity, candidate_cidrs, inside_addresses, encode_peer, decode_peer
from .config import ConfigError

def run(*args):
    return subprocess.run(args,check=True,capture_output=True,text=True,timeout=8)

def local_sources():
    info=json.loads(run("ip","-j","-4","addr","show","scope","global").stdout)
    return [(addr["local"],dev["ifname"]) for dev in info for addr in dev.get("addr_info",[]) if addr.get("family")=="inet" and addr.get("scope")=="global"]

def route_source(peer):
    routes=json.loads(run("ip","-j","-4","route","get",peer).stdout)
    if not routes:return None
    route=routes[0]
    return route.get("prefsrc") or route.get("src"),route.get("dev")

def occupied_cidrs():
    links=json.loads(run("ip","-j","-4","addr","show").stdout)
    routes=json.loads(run("ip","-j","-4","route","show","table","main").stdout)
    n=[x.get("local")+"/"+str(x.get("prefixlen")) for l in links for x in l.get("addr_info",[]) if x.get("family")=="inet"]
    n.extend(x["dst"] for x in routes if "/" in x.get("dst", "") or x.get("dst") not in (None,"default"))
    return n

def make_tunnel(tid,local,remote,interface,name,occupied=()):
    identity=pair_identity(local,remote)
    options=candidate_cidrs(local,remote,occupied)
    return {"id":tid,"name":name,"pair_id":identity["pair_id"],"local_ip":local,
            "peer_ip":remote,"wan_if":interface,"inside_cidr":options[0],
            "key":identity["key"],"mtu":1400,"enabled":True,"setup_revision":1}

def token_for(tunnel,occupied=()):
    t=tunnel
    identity=pair_identity(t["local_ip"],t["peer_ip"])
    options=[t["inside_cidr"]]
    for x in candidate_cidrs(t["local_ip"],t["peer_ip"],occupied):
        if x not in options: options.append(x)
        if len(options)==16:break
    return encode_peer({"schema_version":1,"kind":"setup","pair_id":identity["pair_id"],
                        "outer_a":identity["outer_a"],"outer_b":identity["outer_b"],
                        "key":identity["key"],"mtu":t["mtu"],"candidates":options,
                        "selected_index":0,"revision":t["setup_revision"],"rejected_cidrs":[]})

def tunnel_from_token(code,local,tid,name,interface,occupied=()):
    payload=decode_peer(code)
    if payload["kind"]!="setup":raise ConfigError("E_CODE_KIND")
    if local not in (payload["outer_a"],payload["outer_b"]):raise ConfigError("E_CODE_RECEIVER")
    peer=payload["outer_b"] if local==payload["outer_a"] else payload["outer_a"]
    existing=[ipaddress.IPv4Network(x,strict=False) for x in occupied if x!="default"]
    choices=payload["candidates"]
    viable=[x for x in choices if not any(ipaddress.IPv4Network(x).overlaps(y) for y in existing)]
    if not viable: raise ConfigError("E_ADDRESS_CONFLICT")
    chosen=viable[0]
    return {"id":tid,"name":name,"pair_id":payload["pair_id"],"local_ip":local,
            "peer_ip":peer,"wan_if":interface,"inside_cidr":chosen,
            "key":payload["key"],"mtu":payload["mtu"],"enabled":True,
            "setup_revision":payload["revision"]+(1 if chosen!=choices[payload["selected_index"]] else 0)}
