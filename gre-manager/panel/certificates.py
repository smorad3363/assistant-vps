"""Automatic short-lived IP certificates, with scoped HTTP-01 interception."""
import argparse
import fcntl
import ipaddress
import json
import os
import shutil
import socket
import ssl
import subprocess
import time

from .store import Store, atomic_json

CERTBOT = "/opt/gremgr/acme-venv/bin/certbot"
CHAINS = (("nat", "PREROUTING", "GMP_ACME_NAT"), ("filter", "INPUT", "GMP_ACME_IN"))


def command(*args, check=True, timeout=30):
    result = subprocess.run(args, capture_output=True, text=True, timeout=timeout)
    if check and result.returncode:
        raise RuntimeError((result.stderr or result.stdout or "Command failed")[-1200:])
    return result


def status(paths):
    try:
        return json.loads((paths.tls / "automation.json").read_text())
    except (OSError, ValueError):
        return {"enabled": False, "status": "manual"}


def save(paths, data):
    atomic_json(paths.tls / "automation.json", data)


def configure(store):
    saved = status(store.paths)
    if saved.get("address"):
        return saved
    route = json.loads(command("ip", "-j", "-4", "route", "get", "1.1.1.1").stdout)[0]
    address = route.get("prefsrc", "")
    if not ipaddress.IPv4Address(address).is_global:
        raise ValueError("Automatic IP certificates require a directly assigned public IPv4.")
    saved = {"enabled": True, "address": address, "status": "pending"}
    save(store.paths, saved)
    return saved


def firewall(address=None, port=None):
    # Separate owned chains survive normal panel rule transactions. The service's
    # ExecStopPost removes interception even after timeout, failure or SIGKILL.
    for table, parent, chain in CHAINS:
        while command("iptables", "-w", "5", "-t", table, "-C", parent, "-j", chain, check=False).returncode == 0:
            command("iptables", "-w", "5", "-t", table, "-D", parent, "-j", chain)
        command("iptables", "-w", "5", "-t", table, "-F", chain, check=False)
        command("iptables", "-w", "5", "-t", table, "-X", chain, check=False)
    if address is None:
        return
    try:
        for table, parent, chain in CHAINS:
            command("iptables", "-w", "5", "-t", table, "-N", chain)
        command("iptables", "-w", "5", "-t", "nat", "-A", "GMP_ACME_NAT", "-d", address,
                "-p", "tcp", "--dport", "80", "-j", "REDIRECT", "--to-ports", str(port))
        command("iptables", "-w", "5", "-t", "filter", "-A", "GMP_ACME_IN", "-d", address,
                "-p", "tcp", "--dport", str(port), "-m", "conntrack", "--ctstate", "DNAT",
                "--ctorigdst", address, "--ctorigdstport", "80", "-j", "ACCEPT")
        # Accept before enabling redirection; no other destination or port changes.
        for table, parent, chain in reversed(CHAINS):
            command("iptables", "-w", "5", "-t", table, "-I", parent, "1", "-j", chain)
    except Exception:
        firewall()
        raise


def renew(store, staging=False, force=False):
    paths = store.paths
    saved = status(paths)
    if not saved.get("enabled"):
        return
    if not (staging or force) and saved.get("status") == "ready" and saved.get("expires_at", 0) - time.time() > 60 * 3600:
        if (paths.tls / "cert.pem").is_file() and (paths.tls / "key.pem").is_file():
            return
    address = str(ipaddress.IPv4Address(saved["address"]))
    previous_status, previous_error = saved.get("status", "pending"), saved.get("error", "")
    saved.update(status="renewing", last_attempt=time.time(), error="")
    save(paths, saved)
    try:
        assigned = {a["local"] for i in json.loads(command("ip", "-j", "-4", "address").stdout)
                    for a in i.get("addr_info", [])}
        if address not in assigned:
            raise ValueError("The certificate IPv4 is no longer assigned to this server.")
        name = "gremgr-staging" if staging else "gremgr-ip"
        acme = paths.etc / ("acme-staging" if staging else "acme")
        with socket.socket() as probe:
            probe.bind(("0.0.0.0", 0))
            port = probe.getsockname()[1]
        args = [CERTBOT, "certonly", "--standalone", "--non-interactive", "--agree-tos",
                "--register-unsafely-without-email", "--preferred-profile", "shortlived",
                "--ip-address", address, "--cert-name", name, "--http-01-port", str(port),
                "--http-01-address", "0.0.0.0", "--config-dir", str(acme),
                "--work-dir", str(paths.var / "acme-work"), "--logs-dir", str(paths.var / "acme-logs"),
                "--no-directory-hooks"]
        if staging:
            args.append("--staging")
        if force:
            args.append("--force-renewal")
        # Serialize temporary validation rules with the panel's network jobs.
        with open(paths.etc / "network.lock", "a") as lock:
            fcntl.flock(lock, fcntl.LOCK_EX)
            try:
                firewall(address, port)
                command(*args, timeout=150)
            finally:
                firewall()
            live = acme / "live" / name
            cert, key = live / "fullchain.pem", live / "privkey.pem"
            ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER).load_cert_chain(cert, key)
            command("openssl", "x509", "-in", str(cert), "-noout", "-checkip", address)
            info = ssl._ssl._test_decode_cert(str(cert))
            if staging:
                print("Staging issuance/renewal passed; the trusted panel certificate was retained.")
                saved.update(status=previous_status, error=previous_error, staging_verified_at=time.time())
            else:
                changed = not (paths.tls / "cert.pem").exists() or (paths.tls / "cert.pem").read_bytes() != cert.read_bytes()
                for source, target in ((cert, "cert.pem"), (key, "key.pem")):
                    temporary = paths.tls / (target + ".new")
                    shutil.copyfile(source, temporary)
                    temporary.chmod(0o600)
                    temporary.replace(paths.tls / target)
                # Publish the new certificate to the unprivileged web service.
                from .controller import Controller
                Controller(store).publish_web_config()
                if changed:
                    command("systemctl", "try-restart", "gremgr-web.service")
                saved.update(status="ready", last_success=time.time(), expires_at=ssl.cert_time_to_seconds(info["notAfter"]))
                print("Trusted IP certificate installed; automatic renewal is enabled.")
        save(paths, saved)
    except Exception as error:
        saved.update(status="error", error=str(error)[-1200:])
        save(paths, saved)
        raise


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("action", choices=("configure", "renew", "cleanup"))
    parser.add_argument("--staging", action="store_true")
    parser.add_argument("--force", action="store_true")
    args = parser.parse_args()
    if args.action == "cleanup":
        firewall()
        if os.environ.get("SERVICE_RESULT", "success") != "success":
            store = Store()
            saved = status(store.paths)
            if saved.get("status") == "renewing":
                saved.update(status="error", error="Certificate renewal was interrupted; the previous certificate is retained and renewal will retry.")
                save(store.paths, saved)
        return
    store = Store()
    if args.action == "configure":
        configure(store)
    else:
        renew(store, args.staging, args.force)


if __name__ == "__main__":
    main()
