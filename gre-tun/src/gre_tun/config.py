"""Validated atomic configuration storage. No host network writes."""
import contextlib
import copy
import fcntl
import ipaddress
import json
import os
from pathlib import Path
import tempfile

CONFIG_DIR = Path(os.environ.get("GRE_TUN_CONFIG_DIR", "/etc/gre-tun"))
CONFIG_PATH = CONFIG_DIR / "config.json"
LOCK_PATH = Path(os.environ.get("GRE_TUN_LOCK_PATH", "/run/gre-tun/app.lock"))
VERSION = "1.0.0"

class ConfigError(ValueError):
    pass

def empty_config(role="iran"):
    if role not in ("iran", "foreign"):
        raise ConfigError("E_ROLE")
    return dict(schema_version=1, contract_version=VERSION, config_revision=1,
                role=role, next_tunnel_id=1, next_forward_id=1, tunnels=[], forwards=[])

def _positive(x, low=1, high=4095):
    return type(x) is int and low <= x <= high

def _ip(x):
    try:
        return isinstance(x, str) and str(ipaddress.IPv4Address(x)) == x
    except ipaddress.AddressValueError:
        return False

def validate(value):
    if type(value) is not dict or set(value) != set(empty_config()):
        raise ConfigError("E_CONFIG_SHAPE")
    if value["schema_version"] != 1 or type(value["schema_version"]) is not int:
        raise ConfigError("E_SCHEMA")
    if value["contract_version"] != VERSION or value["role"] not in ("iran","foreign"):
        raise ConfigError("E_VERSION_OR_ROLE")
    if not _positive(value["config_revision"], 1, 2147483647):
        raise ConfigError("E_REVISION")
    if not _positive(value["next_tunnel_id"], 1, 4096) or not _positive(value["next_forward_id"], 1, 4096):
        raise ConfigError("E_ALLOCATOR")
    if type(value["tunnels"]) is not list or type(value["forwards"]) is not list:
        raise ConfigError("E_LIST")
    tkeys={"id","name","pair_id","local_ip","peer_ip","wan_if","inside_cidr","key","mtu","enabled","setup_revision"}
    fkeys={"id","tunnel_id","listen_ip","protocol","listen_port","target_ip","target_port","enabled","upload_mbps","download_mbps","generation","created_at"}
    tids=set(); pairs=set(); fids=set(); tuples=set(); nets=[]
    for t in value["tunnels"]:
        if type(t) is not dict or set(t)!=tkeys or not _positive(t["id"]):
            raise ConfigError("E_TUNNEL_SHAPE")
        if t["id"] in tids or t["pair_id"] in pairs:
            raise ConfigError("E_TUNNEL_DUPLICATE")
        tids.add(t["id"]);pairs.add(t["pair_id"])
        if not all(_ip(t[x]) for x in ("local_ip","peer_ip")) or t["local_ip"]==t["peer_ip"]:
            raise ConfigError("E_IP")
        if not isinstance(t["name"],str) or not 1<=len(t["name"])<=32 or not all(c.isascii() and (c.isalnum() or c in "_. -") for c in t["name"]):
            raise ConfigError("E_NAME")
        if not isinstance(t["wan_if"],str) or not 1<=len(t["wan_if"])<=15 or not all(c.isascii() and (c.isalnum() or c in "_.-") for c in t["wan_if"]):
            raise ConfigError("E_INTERFACE")
        try: n=ipaddress.IPv4Network(t["inside_cidr"],strict=True)
        except (ValueError,TypeError): raise ConfigError("E_CIDR") from None
        if not n.subnet_of(ipaddress.IPv4Network("10.240.0.0/12")) or n.prefixlen!=30 or any(n.overlaps(x) for x in nets):
            raise ConfigError("E_CIDR")
        nets.append(n)
        from .contract import pair_identity
        expected=pair_identity(t["local_ip"],t["peer_ip"])
        if t["key"]!=expected["key"] or t["pair_id"]!=expected["pair_id"]:
            raise ConfigError("E_IDENTITY")
        if type(t["enabled"]) is not bool or not _positive(t["mtu"],1280,1400) or not _positive(t["setup_revision"],1,2147483647):
            raise ConfigError("E_TUNNEL_DATA")
    for f in value["forwards"]:
        if type(f) is not dict or set(f)!=fkeys or not _positive(f["id"]) or f["id"] in fids or f["tunnel_id"] not in tids:
            raise ConfigError("E_FORWARD_SHAPE")
        fids.add(f["id"])
        if not _ip(f["listen_ip"]) or not _ip(f["target_ip"]) or f["protocol"] not in ("tcp","udp","both") or type(f["enabled"]) is not bool:
            raise ConfigError("E_FORWARD_DATA")
        if not all(_positive(f[k],1,65535) for k in ("listen_port","target_port")) or not all(_positive(f[k],0,100000) for k in ("upload_mbps","download_mbps")) or not _positive(f["generation"],1,2147483647):
            raise ConfigError("E_FORWARD_VALUE")
        if not isinstance(f["created_at"],str) or len(f["created_at"])!=20 or not f["created_at"].endswith("Z"):
            raise ConfigError("E_TIMESTAMP")
        for protocol in (("tcp","udp") if f["protocol"]=="both" else (f["protocol"],)):
            key=(protocol,f["listen_ip"],f["listen_port"])
            if key in tuples: raise ConfigError("E_FORWARD_COLLISION")
            tuples.add(key)
    if tids and max(tids)>=value["next_tunnel_id"] or fids and max(fids)>=value["next_forward_id"]:
        raise ConfigError("E_ALLOCATOR_REUSED")
    return value

def read():
    if not CONFIG_PATH.exists(): return None
    return validate(json.loads(CONFIG_PATH.read_text(encoding="utf-8")))

def atomic_write(value):
    validate(value)
    CONFIG_DIR.mkdir(parents=True,exist_ok=True,mode=0o700)
    text=json.dumps(value,sort_keys=True,indent=2,ensure_ascii=True)+"\n"
    fd,name=tempfile.mkstemp(prefix=".config-",dir=CONFIG_DIR)
    try:
        with os.fdopen(fd,"w",encoding="utf-8") as f:
            os.fchmod(f.fileno(),0o600)
            f.write(text);f.flush();os.fsync(f.fileno())
        os.replace(name,CONFIG_PATH)
        dfd=os.open(CONFIG_DIR,os.O_DIRECTORY)
        try:os.fsync(dfd)
        finally:os.close(dfd)
    finally:
        if os.path.exists(name):os.unlink(name)

@contextlib.contextmanager
def locked():
    LOCK_PATH.parent.mkdir(parents=True,exist_ok=True)
    fd=os.open(LOCK_PATH,os.O_CREAT|os.O_RDWR,0o600)
    try:
        fcntl.flock(fd,fcntl.LOCK_EX|fcntl.LOCK_NB)
        yield
    except BlockingIOError:
        raise ConfigError("E_BUSY") from None
    finally:
        os.close(fd)

def save_if_changed(new):
    with locked():
        old=read()
        if old==new: return False
        proposed=copy.deepcopy(new)
        if old:
            if proposed["role"]!=old["role"]:raise ConfigError("E_ROLE_IMMUTABLE")
            proposed["config_revision"]=old["config_revision"]+1
        atomic_write(proposed)
        return True
