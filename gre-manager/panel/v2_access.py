"""Expiring HTTPS pairing and transport-specific participant authorization."""
import hashlib
import hmac
import http.client
import json
import re
import secrets
import ssl
import time

from .model import PanelError, hostname, integer
from .transactions import Journal, identity

AUTH_ROUTES = {"v2/agent.exchange", "v2/agent.request"}


def digest(value):
    return hashlib.sha256(value.encode()).hexdigest()


def token(value):
    if not isinstance(value, str) or not re.fullmatch(r"[A-Za-z0-9_-]{43}", value):
        raise PanelError("Invalid or expired peer credential.", "auth")
    return value


def pin(value):
    if not isinstance(value, str) or not re.fullmatch(r"[0-9a-f]{64}", value):
        raise PanelError("Invalid peer fingerprint.", "fingerprint")
    return value


def https_request(peer, route, payload):
    # The invite carries an explicitly verified leaf certificate pin.
    # Pin before sending an invitation code, authorization, or topology.
    context = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
    context.minimum_version = ssl.TLSVersion.TLSv1_2
    context.check_hostname = False
    context.verify_mode = ssl.CERT_NONE
    connection = http.client.HTTPSConnection(peer["host"], peer["port"], timeout=8, context=context)
    try:
        connection.connect()
        observed = hashlib.sha256(connection.sock.getpeercert(binary_form=True)).hexdigest()
        if not hmac.compare_digest(observed, peer["fingerprint"]):
            raise PanelError("The peer HTTPS certificate no longer matches its pin.", "fingerprint")
        connection.request("POST", "/api/" + route, json.dumps(payload), {"Content-Type": "application/json"})
        reply = connection.getresponse()
        raw = reply.read(262145)
        if len(raw) > 262144:
            raise PanelError("The remote response is too large.", "transport")
        decoded = json.loads(raw)
        if reply.status != 200 or not isinstance(decoded, dict):
            code = decoded.get("code") if isinstance(decoded, dict) else None
            if not isinstance(code, str) or not re.fullmatch(r"[a-z_]{1,30}", code):
                code = "transport"
            raise PanelError("The remote panel rejected this request.", code)
        return decoded
    except (OSError, http.client.HTTPException, json.JSONDecodeError) as error:
        raise PanelError("The paired HTTPS endpoint could not be reached.", "transport") from error
    finally:
        connection.close()


class Access:
    def __init__(self, paths, node_id, clock=time.time):
        self.paths = paths
        self.node_id = node_id
        self.clock = clock
        self.journal = Journal(paths.etc / "v2-access.json", {"invites": {}, "trusted": {}, "paired": {}, "ssh_keys": {}})

    def invite(self, host, port, owner):
        host = hostname(host)
        port = integer(port, 1, 65535, "port")
        owner = identity(owner)
        if owner == self.node_id:
            raise PanelError("A panel cannot pair with itself.", "identity")
        try:
            leaf, delimiter, _ = (self.paths.run / "cert.pem").read_text().partition("-----END CERTIFICATE-----")
            certificate = ssl.PEM_cert_to_DER_cert(leaf + delimiter)
        except (ValueError, OSError) as error:
            raise PanelError("A working HTTPS certificate is required to pair a panel.", "certificate") from error
        fingerprint = hashlib.sha256(certificate).hexdigest()
        code = secrets.token_urlsafe(32)
        expires = int(self.clock()) + 300
        with self.journal.edit() as state:
            state["invites"] = {key: invite for key, invite in state["invites"].items()
                                if invite["expires_at"] > self.clock()}
            if "https:" + owner in state["trusted"]:
                raise PanelError("Revoke the existing pairing before authorizing a new key.", "paired")
            if len(state["invites"]) >= 32:
                raise PanelError("Too many active pairing codes.", "rate_limit")
            state["invites"][digest(code)] = {"owner": owner, "expires_at": expires}
        return {"node_id": self.node_id, "host": host, "port": port, "fingerprint": fingerprint,
                "code": code, "expires_at": expires}

    def exchange(self, payload):
        peer_id = identity(payload.get("owner"))
        if peer_id == self.node_id or payload.get("target") != self.node_id:
            raise PanelError("Pairing addresses the wrong panel.", "identity")
        invitation = digest(token(payload.get("code")))
        secret = secrets.token_urlsafe(32)
        with self.journal.edit() as state:
            current = state["invites"].get(invitation)
            if not current or current["owner"] != peer_id or current["expires_at"] <= self.clock():
                raise PanelError("The pairing code has expired or already been used.", "auth")
            if "https:" + peer_id in state["trusted"]:
                raise PanelError("Revoke the existing pairing before authorizing a new key.", "paired")
            state["invites"].pop(invitation)
            state["trusted"]["https:" + peer_id] = digest(secret)
        return {"node_id": self.node_id, "token": secret}

    def pair(self, invitation):
        peer_id = identity(invitation.get("node_id"))
        if peer_id == self.node_id:
            raise PanelError("A panel cannot pair with itself.", "identity")
        peer = {"host": hostname(invitation.get("host", "")),
                "port": integer(invitation.get("port"), 1, 65535, "port"),
                "fingerprint": pin(invitation.get("fingerprint"))}
        response = https_request(peer, "v2/agent.exchange",
                                 {"owner": self.node_id, "target": peer_id, "code": token(invitation.get("code"))})
        if response.get("node_id") != peer_id:
            raise PanelError("The remote node identity did not match the invite.", "identity")
        with self.journal.edit() as state:
            state["paired"][peer_id] = dict(peer, token=token(response.get("token")))
        return {"node_id": peer_id}

    def trusted_owner(self, payload, transport):
        owner = identity(payload.get("owner"))
        current = self.journal.read()
        if transport == "ssh":
            credentials = [record["credential"] for record in current["ssh_keys"].values() if record["owner"] == owner]
        else:
            credentials = [current["trusted"].get("https:" + owner, "")]
        supplied = digest(token(payload.get("token")))
        if not any(hmac.compare_digest(value, supplied) for value in credentials):
            raise PanelError("The peer is not authorized.", "auth")
        return owner

    def trust_ssh(self, owner, credential_hash, public_blob):
        with self.journal.edit() as state:
            owner = identity(owner)
            state["ssh_keys"][digest(public_blob)] = {"owner": owner, "credential": pin(credential_hash)}

    def ssh_owner(self, public_blob):
        return self.journal.read()["ssh_keys"].get(digest(public_blob), {}).get("owner")

    def forget_ssh(self, public_blob):
        with self.journal.edit() as state:
            state["ssh_keys"].pop(digest(public_blob), None)

    def revoke(self, peer_id):
        peer_id = identity(peer_id)
        with self.journal.edit() as state:
            state["paired"].pop(peer_id, None)
            state["trusted"].pop("https:" + peer_id, None)
            state["ssh_keys"] = {key: record for key, record in state["ssh_keys"].items() if record["owner"] != peer_id}

    def paired(self):
        return [{"id": identity, "access": "paired", "hostname": peer["host"], "management_port": peer["port"]}
                for identity, peer in sorted(self.journal.read()["paired"].items())]

    def peers(self):
        result = {row["id"]: dict(row, inbound=[], outbound=True) for row in self.paired()}
        for key in sorted(self.journal.read()["trusted"]):
            transport, peer_id = key.split(":", 1)
            result.setdefault(peer_id, {"id": peer_id, "inbound": [], "outbound": False})["inbound"].append(transport)
        for peer_id in sorted({record["owner"] for record in self.journal.read()["ssh_keys"].values()}):
            result.setdefault(peer_id, {"id": peer_id, "inbound": [], "outbound": False})["inbound"].append("ssh")
        return {"node_id": self.node_id, "peers": sorted(result.values(), key=lambda row: row["id"])}

    def call(self, peer_id, action, change):
        peer = self.journal.read()["paired"].get(peer_id)
        if not peer:
            raise PanelError("The node has no paired HTTPS connection.", "participant")
        return https_request(peer, "v2/agent.request",
                             {"owner": self.node_id, "token": peer["token"], "action": action, "change": change})
