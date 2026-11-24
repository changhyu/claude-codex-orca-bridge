"""Signed, local-only configuration operations for the Secure Bridge."""
import argparse
import fcntl
import os
import runpy
import subprocess
import time
import uuid
from pathlib import Path

from bridge import put
from agent_mesh import directory
from mcp_server import session_id, result_tool
from secure_bridge import ALIAS, BASE, REQUEST_ID, ROOT, ensure_state, load, mac, secret_file, verify

TTL = 120
ACTIONS = {
    "list": set(),
    "sync_orca": set(),
    "list_orca": set(),
    "diagnose_orca": {"identifier"},
    "add_orca": {"identifier"},
    "disable_orca": {"identifier"},
    "add_claude": {"alias", "session_id"},
    "disable": {"alias"},
    "enable_orca": {"alias"},
}
ADMIN_TOOL = {
    "name": "bridge_manage",
    "description": "List bridge destinations or perform a user-authorized local enrollment, sync, or removal.",
    "inputSchema": {
        "type": "object",
        "properties": {"action": {"enum": list(ACTIONS)}, "alias": {"type": "string"}, "session_id": {"type": "string"}, "identifier": {"type": "string", "maxLength": 240}},
        "required": ["action"],
        "additionalProperties": False,
    },
    "annotations": {"readOnlyHint": False},
}
RESULT_TOOL = result_tool("bridge_manage_result", "Get the result of this client's local management request.")


READ_ACTIONS = {"list", "list_orca", "diagnose_orca"}


def admin_path(kind, request_id):
    if not isinstance(request_id, str) or not REQUEST_ID.fullmatch(request_id):
        raise ValueError("Invalid management request ID.")
    return ROOT / ("admin-" + kind) / (request_id + ".json")


def validate(arguments):
    if not isinstance(arguments, dict):
        raise ValueError("Management arguments must be an object.")
    action = arguments.get("action")
    if not isinstance(action, str) or action not in ACTIONS or set(arguments) != ACTIONS[action] | {"action"}:
        raise ValueError("Invalid management action or arguments.")
    alias = arguments.get("alias")
    if "alias" in arguments and (not isinstance(alias, str) or not ALIAS.fullmatch(alias)):
        raise ValueError("Invalid destination alias.")
    if action == "add_claude":
        session_id(arguments["session_id"])
    if "identifier" in arguments:
        identifier = arguments["identifier"]
        if not isinstance(identifier, str) or not identifier.strip() or len(identifier) > 240:
            raise ValueError("Invalid Orca identifier.")


def result(request_id, client):
    request = verify(load(admin_path("requests", request_id)), client["key"])
    if request["client"] != client["id"] or request["request_id"] != request_id:
        raise ValueError("Management request is unavailable for this client.")
    path = admin_path("results", request_id)
    if not path.is_file():
        return {"request_id": request_id, "state": "pending_mac"}
    data = verify(load(path), client["key"])
    if data["request_id"] != request_id or data["client"] != client["id"]:
        raise ValueError("Management result does not match this request.")
    return {k: v for k, v in data.items() if k != "client"}


def queue(arguments, client):
    validate(arguments)
    rid = uuid.uuid4().hex
    data = {"request_id": rid, "client": client["id"], "created": time.time(), "arguments": arguments}
    put(admin_path("requests", rid), {"data": data, "signature": mac(client["key"], data)})
    deadline = time.monotonic() + 5
    while time.monotonic() < deadline:
        current = result(rid, client)
        if current["state"] != "pending_mac":
            return current
        time.sleep(0.25)
    return {"request_id": rid, "state": "pending_mac"}


def changes(worker, client, arguments, orca_commands=None):
    validate(arguments)
    action, alias = arguments["action"], arguments.get("alias")
    targets = worker["targets"]
    policy = worker["clients"][client["id"]]
    if action == "list":
        return {
            "recipients": directory(worker, set(policy["allow"]) & set(client["allow"])),
            "targets": [{"alias": name, "transport": target["transport"], "destination": target["id"],
                         "allowed": name in policy["allow"],
                         **({"display_name": target["display_name"]} if target.get("display_name") else {})} for name, target in sorted(targets.items())],
            "orca_excluded_handles": worker.get("orca_excluded_handles", []),
        }
    if action == "add_claude":
        destination = {"transport": "claude", "id": session_id(arguments["session_id"])}
        if alias in targets and targets[alias] != destination:
            raise ValueError("Alias already points to another destination.")
        targets[alias] = destination
        for config in (policy, client):
            if alias not in config["allow"]:
                config["allow"].append(alias)
        return {"alias": alias, "transport": "claude"}
    if action == "disable":
        removed = targets.pop(alias, None)
        if removed and removed.get("source") in {"codex-bridge-environment", "codex-bridge-local-project"}:
            worker["codex_discovery_exclusions"] = sorted(set(worker.get("codex_discovery_exclusions", [])) | {alias})
        if removed and removed.get("source") in {"bridge-roster", "bridge-claude-created"}:
            worker["roster_exclusions"] = sorted(set(worker.get("roster_exclusions", [])) | {alias})
        if removed and removed["transport"] == "orca":
            excluded = set(worker.get("orca_excluded_handles", []))
            excluded.add(removed["id"])
            worker["orca_excluded_handles"] = sorted(excluded)
        for config in (*worker["clients"].values(), client):
            config["allow"] = [name for name in config["allow"] if name != alias]
        return {"alias": alias, "registered": False}

    commands = orca_commands if orca_commands is not None else runpy.run_path(str(BASE / "register_orca_adapter.py"))
    try:
        rows = commands["terminals"]()
    except (OSError, RuntimeError, subprocess.TimeoutExpired):
        if action != "disable_orca":
            raise
        rows = []
    selector = arguments.get("identifier", alias)
    if selector in targets and targets[selector].get("transport") == "orca":
        selector = targets[selector]["id"]
    elif selector and selector.startswith("orca-"):
        selector = "term_" + selector[5:]

    if action in {"list_orca", "diagnose_orca"}:
        registered = {target["id"]: name for name, target in targets.items() if target.get("transport") == "orca"}
        excluded = set(worker.get("orca_excluded_handles", []))
        inventory = []
        for row in rows:
            if action == "diagnose_orca" and not commands["matches"](row, selector):
                continue
            handle = row.get("handle")
            info = commands["describe_terminal"](row) if row.get("agentIdentity") and handle else {}
            blockers = commands["blockers"](row)
            item = {"handle": handle, "alias": registered.get(handle), "excluded": handle in excluded,
                    "blockers": blockers, "connected": row.get("connected"), "writable": row.get("writable"),
                    "orphaned": row.get("orphaned"), "exit_cause": row.get("exitCause")}
            for key in ("name", "agent", "branch", "worktree"):
                value = info.get(key)
                if isinstance(value, str):
                    item[key] = "".join(char for char in value[:200] if char.isprintable())
            inventory.append(item)
        present = {row.get("handle") for row in rows}
        return {"terminals": inventory[:100], "total_matches": len(inventory), "registered_not_visible": [
            name for handle, name in registered.items() if handle not in present
            and (action == "list_orca" or handle == selector)]}

    operation = {"sync_orca": "sync", "disable_orca": "disable"}.get(action, "enable")
    updated, excluded = commands["update"](worker, client, rows, operation, selector)
    return {"orca_aliases": sorted(updated), "excluded_count": len(excluded)}


def run_pending(worker_path):
    for path in sorted((ROOT / "admin-requests").glob("*.json")):
        rid = path.stem
        if not REQUEST_ID.fullmatch(rid) or admin_path("results", rid).is_file():
            continue
        try:
            envelope = load(path)
            client_id = envelope["data"]["client"]
            with (ROOT / "enrollment.lock").open("a") as lock:
                fcntl.flock(lock, fcntl.LOCK_EX)
                worker = secret_file(worker_path)
                policy = worker["clients"][client_id]
                data = verify(envelope, policy["key"])
                if data["request_id"] != rid or not 0 <= time.time() - data["created"] <= TTL:
                    continue
                client_path = worker_path.with_name("client.json")
                client = secret_file(client_path)
                response = {"request_id": rid, "client": client_id, "state": "denied"}
                if policy.get("manage_destinations") is True and client["id"] == client_id and client["key"] == policy["key"]:
                    try:
                        payload = changes(worker, client, data["arguments"])
                        if data["arguments"]["action"] not in READ_ACTIONS:
                            put(worker_path, worker)
                            put(client_path, client)
                        response.update(state="done", result=payload)
                    except (ValueError, RuntimeError) as exc:
                        response.update(state="error", error=str(exc))
                    except (OSError, KeyError, TypeError, subprocess.TimeoutExpired):
                        response.update(state="error", error="Local configuration or Orca runtime is unavailable.")
                put(admin_path("results", rid), {"data": response, "signature": mac(policy["key"], response)})
        except (OSError, ValueError, KeyError, TypeError, AttributeError):
            continue

    cutoff = time.time() - 3600
    for kind in ("requests", "results"):
        for path in (ROOT / ("admin-" + kind)).glob("*.json"):
            try:
                if path.lstat().st_mtime < cutoff:
                    path.unlink()
            except OSError:
                pass


def grant(worker_path, enabled):
    ensure_state()
    with (ROOT / "enrollment.lock").open("a") as lock:
        fcntl.flock(lock, fcntl.LOCK_EX)
        worker = secret_file(worker_path)
        client = secret_file(worker_path.with_name("client.json"))
        policy = worker["clients"][client["id"]]
        if policy["key"] != client["key"]:
            raise ValueError("MCP and worker client keys differ.")
        policy["manage_destinations"] = enabled
        put(worker_path, worker)


if __name__ == "__main__":
    os.umask(0o077)
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("mode", choices=("enable", "disable"))
    parser.add_argument("worker_config", type=Path)
    args = parser.parse_args()
    grant(args.worker_config, args.mode == "enable")
    print("Local bridge management " + ("enabled" if args.mode == "enable" else "disabled"))
