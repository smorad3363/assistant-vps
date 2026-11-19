"""Durable v2 reservations and revision-checked configuration decisions."""
from contextlib import contextmanager
import copy
import fcntl
import hashlib
import json
import re
import time

from .model import PanelError
from .store import atomic_json


def identity(value, group=False):
    pattern = r"(?:[0-9a-f]{10}|[0-9a-f]{32})" if group else r"[0-9a-f]{32}"
    if not isinstance(value, str) or not re.fullmatch(pattern, value):
        raise PanelError("Invalid topology identity.", "identity")
    return value


def fingerprint(data):
    return hashlib.sha256(json.dumps(data, sort_keys=True, separators=(",", ":"), allow_nan=False).encode()).hexdigest()


def validate_change(change):
    if not isinstance(change, dict):
        raise PanelError("Invalid topology operation.")
    for field in ("id", "owner", "group_id"):
        identity(change.get(field), group=field == "group_id")
    revision = change.get("expected_revision")
    if type(revision) is not int or not 0 <= revision < 2**53:
        raise PanelError("Invalid expected revision.", "revision")
    participants = change.get("participants")
    if not isinstance(participants, list) or not 1 <= len(participants) <= 128:
        raise PanelError("Invalid participant list.")
    for participant in participants:
        identity(participant)
    if change["owner"] not in participants or len(set(participants)) != len(participants):
        raise PanelError("Invalid participant list.")
    membership = []
    for field in ("joining", "departing"):
        values = change.get(field, [])
        if not isinstance(values, list) or any(node not in participants or node == change["owner"] for node in values):
            raise PanelError("Invalid participant membership change.")
        membership.extend(values)
    if len(set(membership)) != len(membership):
        raise PanelError("Invalid participant membership change.")
    if change.get("group") is not None and not isinstance(change["group"], dict):
        raise PanelError("Invalid topology group.")
    return fingerprint(change)


class Journal:
    def __init__(self, path, defaults=None):
        self.path = path
        self.lock = path.with_suffix(".lock")
        self.defaults = {"operations": {}, "groups": {}} if defaults is None else defaults

    def read(self):
        try:
            return json.loads(self.path.read_text())
        except FileNotFoundError:
            return copy.deepcopy(self.defaults)

    @contextmanager
    def edit(self):
        with self.lock.open("a") as lock:
            fcntl.flock(lock, fcntl.LOCK_EX)
            state = self.read()
            previous = copy.deepcopy(state)
            yield state
            if state != previous:
                atomic_json(self.path, state)


def overlaps(left, right):
    return any(
        ip == other_ip and proto == other_proto and max(lo, other_lo) <= min(hi, other_hi)
        for ip, proto, lo, hi in left
        for other_ip, other_proto, other_lo, other_hi in right
    )


class Participant:
    def __init__(self, paths, node_id, claims, clock=time.time, materialize=None):
        self.journal = Journal(paths.var / "v2-participant.json")
        self.network_lock = paths.etc / "network.lock"
        self.node_id = node_id
        self.claims = claims
        self.clock = clock
        self.materialize = materialize

    def receipt(self, change, digest, operation, *, preview=False):
        phase = operation["phase"] if operation else "unknown"
        if phase == "prepared" and self.clock() >= operation["expires_at"]:
            phase = "expired"
        elif phase == "prepared" and not preview and self.materialize and not operation.get("network_ready"):
            phase = "unknown"
        return {
            "id": change["id"], "digest": digest, "node_id": self.node_id, "phase": phase,
            "revision": change["expected_revision"] + (phase == "committed"),
            "expires_at": operation.get("expires_at") if phase in ("prepared", "expired") else None,
        }

    def request(self, owner, action, change):
        digest = validate_change(change)
        if owner != change["owner"] or self.node_id not in change["participants"]:
            raise PanelError("This node cannot act for that owner or operation.", "owner")
        with self.journal.edit() as state:
            operations, groups = state["operations"], state["groups"]
            operation = operations.get(change["id"])
            if operation and operation["digest"] != digest:
                raise PanelError("Operation ID is already in use.", "idempotency")
            if action == "status":
                receipt = self.receipt(change, digest, operation)
                record = groups.get(change["group_id"], {})
                if receipt["phase"] == "committed" and record.get("revision") == receipt["revision"]:
                    prefix = change["group_id"] + ":"
                    receipt["health"] = {key[len(prefix):]: sample for key, sample in state.get("health", {}).items()
                                         if key.startswith(prefix) and sample.get("revision") == record["revision"]}
                return receipt
            if action not in ("plan", "prepare", "commit", "abort"):
                raise PanelError("Unknown transaction operation.")
            if action == "abort":
                if not operation or operation["phase"] == "prepared":
                    previous = copy.deepcopy(state) if self.materialize and operation else None
                    operation = operations[change["id"]] = {"digest": digest, "phase": "aborted"}
                    if previous is not None:
                        self.materialize(state, previous)
                return self.receipt(change, digest, operation)
            if operation and operation["phase"] != "prepared":
                return self.receipt(change, digest, operation)

            group_id = change["group_id"]
            current = groups.get(group_id)
            if current and current["owner"] != owner:
                raise PanelError("This group belongs to another owner.", "owner")
            revision = current["revision"] if current else 0
            joining = self.node_id in change.get("joining", []) and (not current or not current["active"])
            if revision != change["expected_revision"] and not (joining and revision < change["expected_revision"]):
                raise PanelError("The group revision changed.", "revision")

            if action == "commit":
                if not operation:
                    raise PanelError("This operation was never prepared.", "unknown_operation")
                if self.materialize and not operation.get("network_ready"):
                    self.prepare_network(state, operation, change)
                # Expiry stops a prepare from authorizing a new decision. The
                # reservation stays fenced until the original owner commits or aborts.
                previous = copy.deepcopy(state) if self.materialize else None
                groups[group_id] = {
                    "owner": owner, "revision": change["expected_revision"] + 1,
                    "group": change["group"], "claims": operation["claims"],
                    "active": change["group"] is not None and self.node_id not in change.get("departing", []),
                }
                operation["phase"] = "committed"
                if self.materialize:
                    self.materialize(state, previous)
                return self.receipt(change, digest, operation)
            if operation:
                if action == "prepare" and self.materialize and not operation.get("network_ready"):
                    self.prepare_network(state, operation, change)
                return self.receipt(change, digest, operation, preview=action == "plan")

            claims = self.claims(change)
            for reserved_id, reservation in groups.items():
                if reserved_id != group_id and overlaps(claims, reservation["claims"]):
                    raise PanelError("Listener overlaps group " + reserved_id + ".", "overlap")
            for reservation in operations.values():
                if reservation["phase"] != "prepared":
                    continue
                if reservation["group_id"] == group_id or overlaps(claims, reservation["claims"]):
                    raise PanelError("A matching change is still reserved.", "reserved")
            operation = {"digest": digest, "phase": "prepared", "group_id": group_id, "owner": owner,
                         "claims": claims, "expires_at": self.clock() + 120}
            if action == "prepare":
                operations[change["id"]] = operation
                if self.materialize:
                    self.prepare_network(state, operation, change)
            return self.receipt(change, digest, operation, preview=action == "plan")

    def prepare_network(self, state, operation, change):
        operation["change"] = change
        operation["network_ready"] = False
        previous = copy.deepcopy(state)
        previous["operations"].pop(change["id"])
        # Keep the intent on disk even if the process dies during kernel setup.
        atomic_json(self.journal.path, state)
        self.materialize(state, previous)
        operation["network_ready"] = True


class Coordinator:
    def __init__(self, paths, dispatch):
        self.journal = Journal(paths.var / "v2-coordinator.json")
        self.dispatch = dispatch

    def _response(self, node, action, change, digest):
        receipt = self.dispatch(node, action, change)
        if (not isinstance(receipt, dict)
                or (receipt.get("id"), receipt.get("digest"), receipt.get("node_id")) != (change["id"], digest, node)
                or receipt.get("phase") not in ("prepared", "expired", "committed", "aborted", "unknown")
                or type(receipt.get("revision")) is not int):
            raise PanelError("The participant did not confirm the requested operation.", "receipt")
        return receipt

    def plan(self, change):
        digest = validate_change(change)
        for node in change["participants"]:
            receipt = self._response(node, "plan", change, digest)
            if receipt["phase"] != "prepared":
                raise PanelError("A participant cannot reserve the planned change.", "reserved")
        return {"id": change["id"], "digest": digest, "participants": change["participants"]}

    def enqueue(self, change):
        digest = validate_change(change)
        with self.journal.edit() as state:
            operation = state["operations"].get(change["id"])
            if operation:
                if operation["digest"] != digest:
                    raise PanelError("Operation ID is already in use.", "idempotency")
                return self.public(operation)
            operation = {"change": change, "digest": digest, "decision": None,
                         "phase": "pending", "participants": {}}
            state["operations"][change["id"]] = operation
            return self.public(operation)

    @staticmethod
    def public(operation):
        return {
            "id": operation["change"]["id"], "group_id": operation["change"]["group_id"],
            "phase": operation["phase"], "digest": operation["digest"], "decision": operation["decision"],
            "participants": operation["participants"], "total": len(operation["change"]["participants"]),
        }

    def job(self, operation_id):
        operation = self.journal.read()["operations"].get(identity(operation_id))
        if not operation:
            raise PanelError("Unknown topology operation.", "not_found")
        return self.public(operation)

    def pending(self):
        return [key for key, value in self.journal.read()["operations"].items()
                if value["phase"] in ("pending", "committing", "aborting")]

    def advance(self, operation_id):
        # A separate lock serializes coordinator attempts without holding any
        # participant's reservation lock across a remote call.
        lock_path = self.journal.path.with_suffix(".advance")
        with lock_path.open("a") as lock:
            fcntl.flock(lock, fcntl.LOCK_EX)
            operation = self.journal.read()["operations"][operation_id]
            if operation["phase"] in ("committed", "aborted"):
                return self.public(operation)
            change, digest = operation["change"], operation["digest"]
            if operation["decision"] is None:
                self._decide(operation)
            self._deliver(operation, change, digest)
            return self.public(self.journal.read()["operations"][operation_id])

    def _decide(self, operation):
        change, digest = operation["change"], operation["digest"]
        decision, results = "commit", {}
        deadlines = []
        for node in change["participants"]:
            try:
                receipt = self._response(node, "prepare", change, digest)
                if receipt["phase"] != "prepared" or receipt["revision"] != change["expected_revision"]:
                    raise PanelError("A participant did not prepare this revision.", "receipt")
                if type(receipt.get("expires_at")) not in (float, int):
                    raise PanelError("The participant did not provide a reservation deadline.", "receipt")
                deadlines.append(receipt["expires_at"])
                results[node] = {"phase": "prepared"}
            except (PanelError, OSError) as error:
                decision = "abort"
                results[node] = {"phase": "unconfirmed", "error": getattr(error, "code", "transport")}
                break
        if decision == "commit" and min(deadlines) <= time.time():
            decision = "abort"
        with self.journal.edit() as state:
            state["operations"][change["id"]].update(
                decision=decision, phase="committing" if decision == "commit" else "aborting",
                participants=results,
            )
        operation["decision"] = decision
        operation["participants"] = results

    def _deliver(self, operation, change, digest):
        decision = operation["decision"]
        terminal = "committed" if decision == "commit" else "aborted"
        results = copy.deepcopy(operation["participants"])
        for node in change["participants"]:
            if results.get(node, {}).get("phase") == terminal:
                continue
            try:
                receipt = self._response(node, "status", change, digest)
                if receipt["phase"] != terminal:
                    receipt = self._response(node, decision, change, digest)
                revision = change["expected_revision"] + (decision == "commit")
                if receipt["phase"] != terminal or receipt["revision"] != revision:
                    raise PanelError("The participant did not confirm the decision.", "receipt")
                results[node] = {"phase": terminal}
            except (PanelError, OSError) as error:
                results[node] = {"phase": "unconfirmed", "error": getattr(error, "code", "transport")}
            with self.journal.edit() as state:
                state["operations"][change["id"]]["participants"] = results
            if decision == "commit" and results[node]["phase"] != terminal:
                # Later ingress participants depend on this verified commit.
                break
        if all(results.get(node, {}).get("phase") == terminal for node in change["participants"]):
            with self.journal.edit() as state:
                state["operations"][change["id"]]["phase"] = terminal
