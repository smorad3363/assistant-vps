"""Operator CLI. Unverified development features never activate networking."""
import argparse
import copy
from datetime import datetime, timezone
import json
import os
from pathlib import Path
import sys
from . import __version__
from . import config, contract, diagnostics, network, peer

ROOT = Path(__file__).resolve().parents[2]
MENU = json.loads((ROOT / "contracts/menus.json").read_text())
MESSAGES = json.loads((ROOT / "contracts/ui.en.json").read_text())

class Cancel(Exception): pass

def prompt(label, default=None, required=True):
    while True:
        try: value=input(label+"\n").strip()
        except (KeyboardInterrupt,EOFError):raise Cancel()
        if value=="0":raise Cancel()
        if not value and default is not None:return default
        if value or not required:return value
        print("Error [E_REQUIRED]: Value is required.")

def cap_prompt(label):
    try: value=input(label+"\n").strip()
    except (KeyboardInterrupt,EOFError):raise Cancel()
    if value.lower()=="b":raise Cancel()
    return contract.parse_limit(value,0)

def confirm(label="Apply changes? [Y/n]:",yes_default=True):
    while True:
        try: answer=input(label+"\n").strip().lower()
        except (KeyboardInterrupt,EOFError):raise Cancel()
        if answer in ("", "y", "yes") if yes_default else answer in ("y", "yes"): return True
        if answer in ("n", "no") or (not answer and not yes_default):return False
        print("Error [E_YES_NO]: Enter yes or no.")

def menu(which,enabled=True):
    print(contract.render_menu(which,enabled,ROOT),end="")
    try: return input().strip()
    except (EOFError,KeyboardInterrupt):raise Cancel()

def select_id(records,prefix,label):
    if not records:return None
    value=prompt(label)
    if value.upper().startswith(prefix):value=value[1:]
    try: ident=int(value)
    except ValueError:return None
    return next((t for t in records if t["id"]==ident),None)

def setup():
    print(MESSAGES["setup_title"])
    role=prompt(MESSAGES["role_prompt"])
    if role not in ("1","2"):raise config.ConfigError("E_ROLE")
    c=config.empty_config("iran" if role=="1" else "foreign")
    if config.save_if_changed(c):print("Setup saved.")
    return c

def new_tunnel(c):
    remote=prompt(MESSAGES["peer_ip_prompt"])
    sources=peer.local_sources()
    if not sources:raise config.ConfigError("E_LOCAL_IP")
    preferred=peer.route_source(remote)
    if preferred in sources: local,wan=preferred
    elif len(sources)==1:local,wan=sources[0]
    else:
        print("Available local addresses:")
        for i,(addr,dev) in enumerate(sources,1):print(f"{i}) {addr} | {dev}")
        index=prompt(MESSAGES["local_ip_prompt"])
        if not index.isdecimal() or not 1<=int(index)<=len(sources):raise config.ConfigError("E_LOCAL_IP")
        local,wan=sources[int(index)-1]
    tid=c["next_tunnel_id"]
    if tid>4095:raise config.ConfigError("E_CAPACITY")
    name=prompt(MESSAGES["name_prompt"].format(value=f"Tunnel {tid}"),f"Tunnel {tid}")
    occupied=peer.occupied_cidrs()+[x["inside_cidr"] for x in c["tunnels"]]
    t=peer.make_tunnel(tid,local,remote,wan,name,occupied)
    if any(old["pair_id"]==t["pair_id"] for old in c["tunnels"]):
        print(MESSAGES["unchanged"]);return
    print(f"Peer: {remote}\nLocal: {local}\nName: {name}\nInside: {t['inside_cidr']}")
    if not confirm():return
    next_config=copy.deepcopy(c)
    next_config["tunnels"].append(t);next_config["next_tunnel_id"]+=1
    config.save_if_changed(next_config)
    print("Tunnel configuration saved but NOT activated (development release).")
    print(MESSAGES["code_notice"])
    print(peer.token_for(t,occupied))
    print(MESSAGES["waiting_peer"])

def import_tunnel(c):
    token=prompt(MESSAGES["setup_code_prompt"])
    sources=peer.local_sources()
    payload=contract.decode_peer(token)
    local_candidates=[(ip,iface) for ip,iface in sources if ip in (payload["outer_a"],payload["outer_b"])]
    if len(local_candidates)!=1:raise config.ConfigError("E_CODE_RECEIVER")
    ip,iface=local_candidates[0]
    existing=next((x for x in c["tunnels"] if x["pair_id"]==payload["pair_id"]),None)
    tid=existing["id"] if existing else c["next_tunnel_id"]
    if tid>4095:raise config.ConfigError("E_CAPACITY")
    occupied=peer.occupied_cidrs()+[t["inside_cidr"] for t in c["tunnels"] if t["id"]!=tid]
    tunnel=peer.tunnel_from_token(token,ip,tid,existing["name"] if existing else f"Tunnel {tid}",iface,occupied)
    if existing==tunnel:print(MESSAGES["unchanged"]);return
    if existing and tunnel["setup_revision"]<existing["setup_revision"]:raise config.ConfigError("E_STALE_CODE")
    print(f"Peer: {tunnel['peer_ip']}\nLocal: {ip}\nInside: {tunnel['inside_cidr']}")
    if not confirm():return
    d=copy.deepcopy(c)
    if existing:d["tunnels"]=[tunnel if x["id"]==tid else x for x in d["tunnels"]]
    else:d["tunnels"].append(tunnel);d["next_tunnel_id"]+=1
    config.save_if_changed(d)
    print("Peer configuration saved but NOT activated (development release).")
    if tunnel["setup_revision"]>payload["revision"]:
        print(MESSAGES["updated_code_notice"])
        print(peer.token_for(tunnel,occupied))

def create_menu():
    while True:
        choice=menu("create")
        if choice=="0":return
        c=config.read()
        if choice=="1":new_tunnel(c)
        elif choice=="2":import_tunnel(c)

def show_tunnel(c,t):
    while True:
        print(f"T{t['id']:04d} | {t['name']}\nPeer: {t['peer_ip']}\nState: {'Enabled' if t['enabled'] else 'Disabled'} | Health: Unverified")
        choice=menu("tunnel",t["enabled"])
        if choice=="0":return
        if choice=="1":ports_menu(t)
        elif choice=="2":print("Network-aware edits are not available in this development release.")
        elif choice=="3":
            desired=not t["enabled"]
            if confirm("Enable this tunnel? [y/N]:" if desired else MESSAGES["disable_tunnel_confirm"],not desired):
                d=copy.deepcopy(config.read())
                for x in d["tunnels"]:
                    if x["id"]==t["id"]:x["enabled"]=desired
                config.save_if_changed(d)
                t["enabled"]=desired
                print("Saved (not applied to the network).")
        elif choice=="4":print(peer.token_for(t,[x["inside_cidr"] for x in c["tunnels"] if x["id"]!=t["id"]]))
        elif choice=="5":
            if confirm(MESSAGES["delete_tunnel_confirm"],False):
                d=copy.deepcopy(config.read())
                d["tunnels"]=[x for x in d["tunnels"] if x["id"]!=t["id"]]
                d["forwards"]=[x for x in d["forwards"] if x["tunnel_id"]!=t["id"]]
                config.save_if_changed(d);print(MESSAGES["deleted"]);return

def add_ports(t):
    parsed=contract.parse_ports(prompt(MESSAGES["ports_prompt"]))
    protocol={"1":"tcp","2":"udp","3":"both"}.get(prompt(MESSAGES["protocol_prompt"],"3"))
    if not protocol:raise config.ConfigError("E_PROTOCOL")
    listen=prompt(MESSAGES["listen_ip_prompt"].format(value=t["local_ip"]),t["local_ip"])
    target=prompt(MESSAGES["target_ip_prompt"].format(value=t["peer_ip"]),t["peer_ip"])
    up=cap_prompt(MESSAGES["upload_limit_prompt"].format(value=0))
    down=cap_prompt(MESSAGES["download_limit_prompt"].format(value=0))
    d=copy.deepcopy(config.read())
    now=datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")
    for ports in parsed:
        idx=d["next_forward_id"]
        if idx>4095:raise config.ConfigError("E_CAPACITY")
        d["forwards"].append({"id":idx,"tunnel_id":t["id"],"listen_ip":listen,
                              "listen_port":ports["listen_port"],"target_ip":target,
                              "target_port":ports["target_port"],"protocol":protocol,
                              "enabled":True,"upload_mbps":up,"download_mbps":down,
                              "generation":1,"created_at":now})
        d["next_forward_id"]+=1
    config.validate(d)
    print("\n".join(f"{x['listen_port']} -> {x['target_port']}" for x in parsed))
    if not confirm():return
    config.save_if_changed(d)
    print("Port mappings saved but NOT activated (development release).")

def ports_menu(t):
    while True:
        c=config.read();forwards=[f for f in c["forwards"] if f["tunnel_id"]==t["id"]]
        print("\n".join(f"P{f['id']:04d} | {f['listen_ip']}:{f['listen_port']} -> {f['target_ip']}:{f['target_port']} | {f['protocol']}" for f in forwards) or MESSAGES["no_ports"])
        choice=menu("ports")
        if choice=="0":return
        if choice=="1":add_ports(t)
        elif choice=="2":
            f=select_id(forwards,"P",MESSAGES["port_id_prompt"])
            if not f:continue
            print("Forward edits require the network transaction implementation.")
        elif choice=="3": print("Traffic counters are not yet collected (NOT RUN).")

def manage_menu():
    while True:
        c=config.read()
        if not c["tunnels"]:
            print(MESSAGES["no_tunnels"]);return
        for t in sorted(c["tunnels"],key=lambda x:x["id"]):
            print(f"T{t['id']:04d} | {t['name']} | {t['peer_ip']} | Unverified")
        t=select_id(c["tunnels"],"T",MESSAGES["tunnel_id_prompt"])
        if t is None:return
        show_tunnel(c,t)

def uninstall_prompt():
    print(MESSAGES["uninstall_title"])
    print(MESSAGES["uninstall_warning"])
    answer=prompt(MESSAGES["uninstall_confirm"],"y").lower()
    if answer not in ("y","yes","n","no"):raise config.ConfigError("E_YES_NO")
    # The installer must be removed separately; do not delete user data in a pre-alpha build.
    print("Not available: this development build does not own active network objects.")
    print("No data was deleted. No network objects were changed.")

def main(argv=None):
    p=argparse.ArgumentParser(prog="gre-tun",description="GRE Tunnel Manager development build")
    p.add_argument("--version",action="store_true")
    sub=p.add_subparsers(dest="command")
    s=sub.add_parser("status");s.add_argument("--json",action="store_true")
    a=sub.add_parser("apply");a.add_argument("--check",action="store_true")
    t=sub.add_parser("test");t.add_argument("tunnel",nargs="?",default="all");t.add_argument("--json",action="store_true")
    v=sub.add_parser("config");v.add_argument("verb",choices=["validate"]);v.add_argument("--file",required=True)
    e=sub.add_parser("peer");e.add_argument("verb",choices=["export","import","regenerate"]);e.add_argument("value",nargs="?");e.add_argument("--code")
    args=p.parse_args(argv)
    if args.version:print(__version__);return 0
    try:
        if args.command=="status":
            info=diagnostics.status()
            print(json.dumps(info,indent=2) if args.json else f"Revision: {info['config_revision']} | Tunnels: {len(info['tunnels'])} | Forwards: {len(info['forwards'])} | State: {info['service']}")
            return 0
        if args.command=="config":
            config.validate(json.loads(Path(args.file).read_text()))
            print("Configuration is valid.");return 0
        if args.command=="apply":
            print(network.apply(config.read() or config.empty_config(),args.check));return 0
        if args.command=="test":
            idx=None if args.tunnel=="all" else int(args.tunnel.lstrip("Tt"))
            reports=diagnostics.test(idx)
            print(json.dumps(reports,indent=2) if args.json else "\n".join(f"{t['tunnel_id']}: UNVERIFIED (NOT RUN)" for t in reports))
            return 7 if reports else 0
        if args.command=="peer":
            if args.verb=="export":
                c=config.read();idx=int(args.value.lstrip("Tt"));t=next(t for t in c["tunnels"] if t["id"]==idx)
                print(peer.token_for(t));return 0
            if args.verb=="import":
                if not args.code:raise config.ConfigError("E_CODE_REQUIRED")
                import_tunnel_token(args.code);return 0
            print("E_NOT_READY: Regeneration is not available in this development release.");return 3
        if os.geteuid()!=0:
            print(MESSAGES["root_required"]);return 3
        if config.read() is None:setup()
        while True:
            selection=menu("main")
            if selection=="0":return 0
            if selection=="1":create_menu()
            elif selection=="2":manage_menu()
            elif selection=="3":
                print("\n".join(f"{x['tunnel_id']}: UNVERIFIED (NOT RUN)" for x in diagnostics.test()))
            elif selection=="4":uninstall_prompt()
    except Cancel:
        print(MESSAGES["cancelled"]);return 0
    except (config.ConfigError, contract.ContractError, ValueError, KeyError, OSError) as exc:
        print(f"Error [E_VALIDATION]: {exc}",file=sys.stderr);return 3

def import_tunnel_token(code):
    c=config.read()
    if c is None:raise config.ConfigError("E_SETUP_REQUIRED")
    sources=peer.local_sources();data=contract.decode_peer(code)
    matched=[(a,b) for a,b in sources if a in (data["outer_a"],data["outer_b"])]
    if len(matched)!=1:raise config.ConfigError("E_CODE_RECEIVER")
    local,wan=matched[0]
    old=next((t for t in c["tunnels"] if t["pair_id"]==data["pair_id"]),None)
    ident=old["id"] if old else c["next_tunnel_id"]
    other=[t["inside_cidr"] for t in c["tunnels"] if t["id"]!=ident]
    t=peer.tunnel_from_token(code,local,ident,old["name"] if old else f"Tunnel {ident}",wan,peer.occupied_cidrs()+other)
    if old==t:print(MESSAGES["unchanged"]);return
    print(f"Peer: {t['peer_ip']}\nInside: {t['inside_cidr']}")
    if not confirm():return
    d=copy.deepcopy(c)
    if old:d["tunnels"]=[t if x["id"]==ident else x for x in d["tunnels"]]
    else:d["tunnels"].append(t);d["next_tunnel_id"]+=1
    config.save_if_changed(d);print("Saved but NOT applied to network.")

if __name__=="__main__":sys.exit(main())
