"""IPv4 iptables backend. Only owns PM2_* chains, never flushes global tables.

Phase 2 pre-release. Network changes require exclusive V2 lock and VM gates.
"""
import shlex
from .discovery import run, backend
from .errors import PM2Error

CHAINS = {
    "nat": ("PM2_NAT_PRE", "PM2_NAT_POST"),
    "filter": ("PM2_FORWARD",),
    "mangle": ("PM2_ACCOUNT",)
}
ORDER = [(table, chain) for table, names in CHAINS.items() for chain in names]
HOOKS = {"PM2_NAT_PRE": "PREROUTING", "PM2_NAT_POST": "POSTROUTING",
         "PM2_FORWARD": "FORWARD", "PM2_ACCOUNT": "FORWARD"}
COMMENT = "pm2:owned-hook"


def ipt(table, *arguments):
    return run(["iptables", "-w", "3", "-t", table, *arguments],
               timeout=12)


def compile_rules(config, interface_ips=None):
    """Pure V2-owned rules. Optionally expand a NIC to its assigned IPv4s.

    Production apply supplies verified interface addresses from discovery.audit.
    When omitted (e.g. offline unit previews), keep the per-anchor projection.
    Every expanded DNAT has its own conntrack original-destination match in
    FORWARD and POSTROUTING, so no broad MASQUERADE rewrites foreign traffic.
    """
    rules = {chain: [] for _, chain in ORDER}
    active = sorted((t for t in config["tunnels"] if t["enabled"]),
                    key=lambda t: (t["mode"] != "ports", t["id"]))
    for t in active:
        tid, anchor, target, iface = (t[k] for k in (
            "id", "listen_ip", "target_ip", "interface"))
        if interface_ips is None:
            bound_addresses = [anchor]
        else:
            bound_addresses = interface_ips.get(iface, [])
            if anchor not in bound_addresses or not bound_addresses:
                raise PM2Error("E_CONFLICT", "Assigned ingress IPv4s changed during apply",
                               {"interface": iface, "ip": anchor})
        for listen in bound_addresses:
            for proto in t["protocols"]:
                prefix = ["-i", iface, "-d", listen, "-p", proto]
                if t["mode"] == "ports":
                    targets = [(m["listen_port"], m["target_port"])
                               for m in t["mapping"]]
                else:
                    for exclude in t["exclude"]:
                        rules["PM2_NAT_PRE"].append([
                            *prefix, "--dport", str(exclude), "-m", "comment",
                            "--comment", f"pm2:{tid}:exclude", "-j", "RETURN"
                        ])
                    targets = [(None, None)]
                for listenport, targetport in targets:
                    to = target if targetport is None else f"{target}:{targetport}"
                    orig = ["-m", "conntrack", "--ctorigdst", listen]
                    if listenport is not None:
                        orig.extend(["--ctorigdstport", str(listenport)])
                    dnat = list(prefix)
                    if listenport is not None:
                        dnat += ["--dport", str(listenport)]
                    rules["PM2_NAT_PRE"].append([
                        *dnat, "-m", "comment", "--comment",
                        f"pm2:{tid}:dnat", "-j", "DNAT", "--to-destination", to
                    ])
                    rules["PM2_NAT_POST"].append([
                        "-d", target, "-p", proto, *orig, "--ctdir", "ORIGINAL",
                        "-m", "comment", "--comment", f"pm2:{tid}:snat",
                        "-j", "MASQUERADE"
                    ])
                    rules["PM2_FORWARD"].append([
                        "-d", target, "-p", proto, *orig, "--ctdir", "ORIGINAL",
                        "-m", "comment", "--comment", f"pm2:{tid}:forward",
                        "-j", "ACCEPT"
                    ])
                    rules["PM2_FORWARD"].append([
                        "-s", target, "-p", proto, *orig, "--ctdir", "REPLY",
                        "-m", "comment", "--comment", f"pm2:{tid}:reply",
                        "-j", "ACCEPT"
                    ])
                    for direction in ("ORIGINAL", "REPLY"):
                        rules["PM2_ACCOUNT"].append([
                            "-p", proto, *orig, "--ctdir", direction,
                            "-m", "comment", "--comment",
                            f"pm2:{tid}:{'up' if direction == 'ORIGINAL' else 'down'}"
                        ])
    return rules

def _kernel_signature(args):
    """Compare V2 intent despite iptables -S normalizing /32 and -m tcp."""
    flags = ("-i", "-o", "-d", "-s", "-p", "--dport", "--ctorigdst",
             "--ctorigdstport", "--ctdir", "--to-destination",
             "--comment", "-j")
    result = []
    for key in flags:
        if key not in args:
            continue
        position = args.index(key)
        if position + 1 >= len(args):
            return None
        value = args[position + 1]
        if key in ("-d", "-s", "--ctorigdst") and value.endswith("/32"):
            value = value[:-3]
        result.append((key, value))
    return tuple(result)


def matches_compiled_inventory(compiled, inventory):
    """No-op when every owned chain already has the expected actual rules."""
    for table, chain in ORDER:
        rows = inventory.get(table, {}).get(chain, [])
        prepared = compiled[chain]
        if len(rows) != len(prepared):
            return False
        if [_kernel_signature(row) for row in rows] != [
                _kernel_signature(row) for row in prepared]:
            return False
    return True


def snapshot():
    return {table: [shlex.split(line) for line in ipt(table, "-S").splitlines()
                    if line.startswith(("-N ", "-A ", "-P "))]
            for table in CHAINS}


def _hook(chain):
    return ["-A", HOOKS[chain], "-m", "comment", "--comment", COMMENT,
            "-j", chain]


def _saved_inventory_exists(inventory):
    return any(chain in inventory.get(table, {}) for table, chain in ORDER)


def owned_footprint_present(snapshot_rules):
    """Whether any PM2-owned chain/hook/comment is still present in kernel."""
    owned = set(HOOKS)
    for table in CHAINS:
        for row in snapshot_rules.get(table, []):
            if len(row) >= 2 and row[0] == "-N" and row[1] in owned:
                return True
            if len(row) >= 2 and row[0] == "-A" and row[1] in owned:
                return True
            if "-j" in row:
                pos = row.index("-j")
                if pos + 1 < len(row) and row[pos + 1] in owned:
                    return True
            if "--comment" in row:
                pos = row.index("--comment")
                if pos + 1 < len(row):
                    value = row[pos + 1]
                    if value == COMMENT or value.startswith("pm2:"):
                        return True
    return False


def inventory_completely_missing(snapshot_rules, inventory):
    """True only when state expects PM2 and the kernel has zero PM2 footprint."""
    return _saved_inventory_exists(inventory) and not owned_footprint_present(snapshot_rules)


def repairable_inventory(snapshot_rules, inventory):
    """Validate what remains and return the exact safe kernel baseline.

    An expected chain may be completely absent. Any chain/hook that remains
    must exactly match the persisted inventory. Partial chains, duplicate
    hooks, changed rules, or stray PM2 comments outside owned locations fail
    closed and are never auto-repaired.
    """
    actual_inventory = {table: {} for table in CHAINS}
    missing = []
    owned = set(HOOKS)

    for table, chain in ORDER:
        lines = snapshot_rules.get(table, [])
        exists = ["-N", chain] in lines
        saved = inventory.get(table, {}).get(chain)
        links = [row for row in lines if "-j" in row and
                 row[row.index("-j") + 1] == chain]
        if saved is None:
            if exists or links:
                raise PM2Error("E_CONFLICT", "Unowned V2-like chain or hook exists",
                               {"table": table, "chain": chain})
            continue
        if not exists and not links:
            missing.append((table, chain))
            continue
        if not exists or links != [_hook(chain)]:
            raise PM2Error("E_CONFLICT", "V2 chain or hook modified externally",
                           {"table": table, "chain": chain})
        actual = [row[2:] for row in lines if row[:2] == ["-A", chain]]
        if actual != saved:
            raise PM2Error("E_CONFLICT", "Owned rule inventory drift",
                           {"table": table, "chain": chain})
        actual_inventory[table][chain] = actual

    # Reject orphaned PM2-looking comments in foreign chains. Valid PM2 rule
    # comments live in a PM2_* chain; the one valid foreign comment is the
    # exact owned hook that jumps to that chain.
    for table in CHAINS:
        for row in snapshot_rules.get(table, []):
            if "--comment" not in row:
                continue
            pos = row.index("--comment")
            if pos + 1 >= len(row):
                continue
            value = row[pos + 1]
            if value != COMMENT and not value.startswith("pm2:"):
                continue
            chain_name = row[1] if len(row) > 1 and row[0] == "-A" else None
            jump = None
            if "-j" in row:
                jump_pos = row.index("-j")
                if jump_pos + 1 < len(row):
                    jump = row[jump_pos + 1]
            if chain_name in owned:
                continue
            if value == COMMENT and jump in owned and row == _hook(jump):
                continue
            raise PM2Error("E_CONFLICT", "Orphaned V2-like firewall rule exists",
                           {"table": table, "rule": " ".join(row)[:500]})

    return actual_inventory, missing


def check_inventory(snapshot_rules, inventory):
    """Reject any unknown owner/collision/modified/missing PM2 rule."""
    _, missing = repairable_inventory(snapshot_rules, inventory)
    if missing:
        table, chain = missing[0]
        raise PM2Error("E_CONFLICT", "V2 chain or hook missing externally",
                       {"table": table, "chain": chain})


def _remove(inventory):
    for table, chain in reversed(ORDER):
        if chain not in inventory.get(table, {}):
            continue
        ipt(table, "-D", HOOKS[chain], "-m", "comment",
            "--comment", COMMENT, "-j", chain)
        ipt(table, "-F", chain)  # exclusively owned chain, never global flush
        ipt(table, "-X", chain)


def _install(rules):
    if not any(rules.values()):
        return {table: {} for table in CHAINS}
    result = {table: {} for table in CHAINS}
    for table, chain in ORDER:
        ipt(table, "-N", chain)
        for args in rules[chain]:
            ipt(table, "-A", chain, *args)
        ipt(table, "-I", HOOKS[chain], "1", "-m", "comment",
            "--comment", COMMENT, "-j", chain)
        actual = snapshot()[table]
        result[table][chain] = [row[2:] for row in actual if row[:2] == ["-A", chain]]
    return result


def _cleanup_partial():
    """Best-effort cleanup of only unambiguously-owned partial chains."""
    current = snapshot()
    for table, chain in reversed(ORDER):
        lines = current[table]
        if ["-N", chain] not in lines:
            continue
        links = [row for row in lines if "-j" in row and
                 row[row.index("-j") + 1] == chain]
        if any(row != _hook(chain) for row in links) or len(links) > 1:
            raise PM2Error("E_CONFLICT", "Foreign reference to V2 chain during rollback")
        if links:
            ipt(table, "-D", HOOKS[chain], "-m", "comment", "--comment",
                COMMENT, "-j", chain)
        ipt(table, "-F", chain)
        ipt(table, "-X", chain)


def reconcile(desired, prior):
    before = snapshot()
    check_inventory(before, prior)
    previous = {chain: list(prior.get(table, {}).get(chain, []))
                for table, chain in ORDER}
    if (not any(desired.values())) and not any(prior.get(t) for t in CHAINS):
        return prior
    # Returning early when matching inventory avoids resetting live counters.
    if all(desired[chain] == previous[chain] for _, chain in ORDER):
        return prior
    try:
        _remove(prior)
        return _install(desired)
    except PM2Error as failure:
        try:
            _cleanup_partial()
            _install(previous)
        except Exception as rollback_exc:
            raise PM2Error("E_ROLLBACK", "Could not restore previous owned rules",
                           {"cause": failure.message,
                            "rollback": str(rollback_exc)}) from rollback_exc
        raise failure
