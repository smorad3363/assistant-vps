"""Network preflight. Mutations are deliberately disabled in this development build.

Never print a successful apply if forwarding, return routing, QoS and rollback have
not been proven by isolated network-namespace integration tests.
"""
import json
import os
import platform
import subprocess
from .config import ConfigError

def command(*args):
    return subprocess.run(args,capture_output=True,text=True,timeout=8,check=True)

def preflight(config):
    checks=[]
    if os.geteuid()!=0:checks.append("E_ROOT")
    if platform.system()!="Linux":checks.append("E_LINUX")
    try:
        for t in config["tunnels"]:
            info=json.loads(command("ip","-j","-4","route","get",t["peer_ip"]).stdout)
            if not info or info[0].get("dev")!=t["wan_if"]:checks.append("E_PEER_ROUTE")
        command("nft","--version")
        command("tc","-V")
    except (subprocess.CalledProcessError,FileNotFoundError,subprocess.TimeoutExpired,ValueError):
        checks.append("E_CAPABILITY")
    return checks

def apply(config, check_only=False):
    issues=preflight(config)
    if issues:raise ConfigError(",".join(issues))
    if config["tunnels"] or config["forwards"]:
        raise ConfigError("E_NOT_READY: Live GRE/NAT/QoS transactions are not available in 0.1.0-dev")
    return "Already configured."
