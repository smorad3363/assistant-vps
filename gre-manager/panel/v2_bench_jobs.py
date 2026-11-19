"""Durable benchmark coordination over already authorized management channels."""
from concurrent.futures import ThreadPoolExecutor
from contextlib import suppress
import threading
import time

from .model import PanelError, address
from .transactions import Journal, fingerprint, identity
from .v2_bench_agent import ACTIVE, METHODS, key_for
from .v2_benchmark import SECOND, direction_lengths, report


def request_values(payload):
    if not isinstance(payload, dict):
        raise PanelError("Provide benchmark settings.")
    nodes = payload.get("nodes")
    methods = payload.get("methods")
    parallel = payload.get("parallel", False)
    if not isinstance(nodes, list) or len(nodes) != 2 or nodes[0] == nodes[1]:
        raise PanelError("Choose two different benchmark nodes.", "participant")
    if not isinstance(methods, list) or not 1 <= len(methods) <= len(METHODS) or type(parallel) is not bool:
        raise PanelError("Choose at least one supported test method.", "method")
    nodes = [identity(node) for node in nodes]
    first, second = address(payload.get("first")), address(payload.get("second"))
    if first == second:
        raise PanelError("The two endpoints need different IPv4 addresses.", "participant")
    selection = {}
    for item in methods:
        if not isinstance(item, dict) or item.get("method") not in METHODS or item["method"] in selection:
            raise PanelError("Choose each benchmark method once.", "method")
        seconds = item.get("duration_s", payload.get("duration_s", 30))
        direction_lengths(seconds)
        selection[item["method"]] = seconds
    return {"nodes": nodes, "methods": [{"method": method, "duration_s": seconds} for method, seconds in selection.items()],
            "parallel": parallel and len(selection) > 1, "first": first, "second": second}


def receiver_receipt(value, seconds, budget):
    if not isinstance(value, dict):
        raise PanelError("The endpoint returned an invalid benchmark receipt.", "receipt")
    elapsed, count, full, peak, reason = (value.get(field) for field in
                                          ("elapsed_ns", "received_bytes", "complete_seconds", "peak_second_bytes", "reason"))
    if (type(elapsed) is not int or type(count) is not int or type(full) is not int or not 0 <= elapsed <= seconds * SECOND
            or not 0 <= count <= budget or full != elapsed // SECOND or (full == 0 and peak is not None)
            or (full > 0 and (type(peak) is not int or not 0 <= peak <= count))
            or reason not in ("finished", "active", "cancelled", "byte_budget", "connection_lost")
            or reason == "finished" and elapsed != seconds * SECOND):
        raise PanelError("The endpoint receipt did not match the benchmark lease.", "receipt")
    return {"elapsed_ns": elapsed, "received_bytes": count, "complete_seconds": full, "peak_second_bytes": peak, "reason": reason}


class Benchmarks:
    def __init__(self, paths, dispatch):
        self.dispatch = dispatch
        self.journal = Journal(paths.var / "v2-bench-jobs.json", {"jobs": {}})
        self.stopping = threading.Event()
        self.queue = ThreadPoolExecutor(max_workers=1, thread_name_prefix="benchmark")
        with self.journal.edit() as state:
            for item in state["jobs"].values():
                if item["phase"] in ("queued", "running", "cancelling"):
                    item["phase"] = "interrupted"

    def capabilities(self, node):
        result = self.dispatch(identity(node), "benchmark/capabilities", {})
        if result.get("node_id") != node:
            raise PanelError("The benchmark node identity did not match.", "identity")
        return result

    def plan(self, payload):
        request = request_values(payload)
        with ThreadPoolExecutor(max_workers=2) as workers:
            left, right = workers.map(self.capabilities, request["nodes"])
        if request["first"] not in left["addresses"] or request["second"] not in right["addresses"]:
            raise PanelError("Choose an IPv4 address that belongs to each paired node.", "local_ip")
        available = set(left["methods"]) & set(right["methods"])
        maximum = min(left["max_seconds"], right["max_seconds"])
        rate = min(left["rate"], right["rate"])
        budget = min(left["bytes"], right["bytes"])
        durations = [item["duration_s"] for item in request["methods"]]
        total_seconds = sum(durations)
        parallel = request["parallel"]
        share = rate // len(durations) if parallel else rate
        if share < 1:
            raise PanelError("The shared host rate is too low for concurrent tests.", "rate_limit")
        rows = []
        for item in request["methods"]:
            method = item["method"]
            if method not in available:
                raise PanelError(f"{method.upper()} is unavailable on one of the selected hosts.", "method")
            lengths = direction_lengths(item["duration_s"], maximum)
            volumes = [min(share * seconds, budget * seconds // total_seconds) for seconds in lengths]
            if min(volumes) < 1:
                raise PanelError("The shared host byte budget is too low for these tests.", "rate_limit")
            rows.append(dict(item, directions=list(lengths), budgets=volumes, rate=share))
        preview = {"request": request, "max_seconds": maximum, "rate": rate,
                   "estimated_bytes": sum(sum(row["budgets"]) for row in rows),
                   "transfer_seconds": max(durations) if parallel else total_seconds, "methods": rows}
        return dict(preview, digest=fingerprint(preview))

    def start(self, payload):
        job_id = identity(payload.get("id"))
        digest = fingerprint(request_values(payload))
        existing = self.journal.read()["jobs"].get(job_id)
        if existing:
            if existing["request_digest"] != digest:
                raise PanelError("The benchmark ID already has other settings.", "idempotency")
            return existing
        plan = self.plan(payload)
        if payload.get("digest") != plan["digest"]:
            raise PanelError("The limits or benchmark settings changed. Create a fresh preview.", "plan_changed")
        with self.journal.edit() as state:
            jobs = state["jobs"]
            existing = jobs.get(job_id)
            if existing:
                if existing["request_digest"] != digest:
                    raise PanelError("The benchmark ID already has other settings.", "idempotency")
                return existing
            if sum(item["phase"] in ("queued", "running", "cancelling") for item in jobs.values()) >= 4:
                raise PanelError("The benchmark queue is full.", "busy")
            for old, _ in sorted(jobs.items(), key=lambda row: row[1]["created_at"])[:max(0, len(jobs) - 95)]:
                jobs.pop(old)
            job = {"id": job_id, "request_digest": digest, "plan": plan, "phase": "queued", "created_at": time.time(), "results": {}}
            jobs[job_id] = job
        self.queue.submit(self.run, job_id)
        return job

    def change(self, job_id, **values):
        with self.journal.edit() as state:
            item = state["jobs"][job_id]
            item.update(values)
            return item

    def status(self, job_id):
        job = self.journal.read()["jobs"].get(identity(job_id))
        if not job:
            raise PanelError("Benchmark not found.", "missing")
        return job

    def cancel(self, job_id):
        with self.journal.edit() as state:
            item = state["jobs"].get(identity(job_id))
            if not item:
                raise PanelError("Benchmark not found.", "missing")
            if item["phase"] in ("queued", "running"):
                item["phase"] = "cancelling"
            return item

    def stopped(self, job_id):
        return self.stopping.is_set() or self.status(job_id)["phase"] == "cancelling"

    def observed(self, node, task):
        status = self.dispatch(node, "benchmark/status", task)
        if status.get("node_id") != node or status.get("task_key") != key_for(task):
            raise PanelError("The benchmark status addressed another job or endpoint.", "receipt")
        return status

    def wait(self, job_id, node, task, max_wait, update, ready=False):
        deadline = time.monotonic() + max_wait
        latest = {"phase": "unknown"}
        while not self.stopped(job_id) and time.monotonic() < deadline:
            try:
                latest = self.observed(node, task)
            except (PanelError, OSError):
                self.stopping.wait(.8)
                continue
            if latest.get("receipt") is not None:
                update(latest["receipt"])
            phase = latest.get("phase")
            if (ready and phase == "ready") or (phase not in ACTIVE and phase != "unknown"):
                break
            self.stopping.wait(.25 if ready else 1)
        return latest

    def release(self, nodes, task):
        for node in nodes:
            with suppress(PanelError, OSError):
                self.dispatch(node, "benchmark/cancel", task)
        pending = set(nodes)
        deadline = time.monotonic() + 12
        while pending and time.monotonic() < deadline:
            for node in list(pending):
                with suppress(PanelError, OSError):
                    status = self.observed(node, task)
                    if status.get("phase") not in ACTIVE and status.get("cleaned") is True:
                        pending.remove(node)
            if pending:
                time.sleep(.3)
        return not pending

    def directional(self, job_id, request, method, direction, update):
        nodes = request["nodes"]
        receiver, sender = nodes[1 - direction], nodes[direction]
        seconds = method["directions"][direction]
        budget = method["budgets"][direction]
        key = {"job_id": job_id, "method": method["method"], "direction": direction}
        shared = dict(key, **{k: request[k] for k in ("nodes", "first", "second")}, seconds=seconds,
                      rate=method["rate"], budget=budget)
        result, reason = None, None
        try:
            approvals = []
            for node in nodes:
                candidate = self.dispatch(node, "benchmark/offer", shared)
                approval = candidate.get("approval", {})
                if approval.get("node_id") != node or approval.get("task_key") != key_for(key):
                    raise PanelError("One benchmark endpoint did not confirm its own offer.", "auth")
                approvals.append(approval)
            launch = dict(shared, approvals=approvals)
            if self.stopped(job_id):
                raise PanelError("The benchmark was cancelled.", "cancelled")
            self.dispatch(receiver, "benchmark/start", launch)
            valid_sample = lambda value: update(receiver_receipt(value, seconds, budget))
            ready = self.wait(job_id, receiver, key, 18, valid_sample, ready=True)
            if ready.get("phase") != "ready" or self.stopped(job_id):
                reason = ready.get("error") or "receiver_unavailable"
            else:
                self.dispatch(sender, "benchmark/start", dict(launch, port=ready["port"]))
                receipt = self.wait(job_id, receiver, key, seconds + 36, valid_sample)
                if value := receipt.get("receipt"):
                    result = receiver_receipt(value, seconds, budget)
                reason = receipt.get("error") or receipt.get("phase")
        except (PanelError, OSError) as error:
            reason = getattr(error, "code", "transport")
        finally:
            cleaned = self.release(nodes, key)
        if not cleaned:
            return result, "cleanup_pending"
        return result, reason

    def method(self, job_id, request, method):
        results = [None, None]
        errors = [None, None]

        def save(direction, received):
            results[direction] = received
            snapshot = report(*results)
            snapshot["finished"] = snapshot["finished"] and all(value == "done" for value in errors)
            with self.journal.edit() as state:
                state["jobs"][job_id]["results"][method["method"]] = dict(snapshot, reasons=errors[:])

        for direction in (0, 1):
            if self.stopped(job_id):
                break
            receipt, errors[direction] = self.directional(job_id, request, method, direction,
                                                          lambda result: save(direction, result))
            save(direction, receipt if receipt is not None else results[direction])
            if errors[direction] == "cleanup_pending":
                break

    def run(self, job_id):
        with self.journal.edit() as state:
            item = state["jobs"][job_id]
            if self.stopping.is_set() or item["phase"] == "cancelling":
                item["phase"] = "cancelled"
                return
            item["phase"] = "running"
            plan = item["plan"]
        try:
            if plan["request"]["parallel"]:
                with ThreadPoolExecutor(max_workers=len(plan["methods"])) as workers:
                    for future in [workers.submit(self.method, job_id, plan["request"], row) for row in plan["methods"]]:
                        future.result()
            else:
                for row in plan["methods"]:
                    self.method(job_id, plan["request"], row)
            results = self.status(job_id)["results"]
            complete = len(results) == len(plan["methods"]) and all(row["finished"] for row in results.values())
            with self.journal.edit() as state:
                item = state["jobs"][job_id]
                item["phase"] = ("interrupted" if self.stopping.is_set() else "cancelled" if item["phase"] == "cancelling"
                                 else "done" if complete else "partial")
        except (PanelError, OSError, KeyError, TypeError) as error:
            self.change(job_id, phase="partial", error=getattr(error, "code", "benchmark"))

    def close(self):
        self.stopping.set()
        self.queue.shutdown(wait=True, cancel_futures=True)
