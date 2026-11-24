"""Agent mesh routing and Orca discovery for the authenticated local bridge."""

from contextlib import closing
import hashlib
import hmac
import json
from pathlib import Path, PurePosixPath, PureWindowsPath
import re
import sqlite3
import subprocess
import time

from bridge_message import connector_forward_proof, normalize_message
from bridge_settings import CODEX_CLOUD_ALIAS, CODEX_CLOUD_THREAD, ORCA_REPOSITORY, PROJECT_DIR
from cloud_roster import CONNECTOR_CLIENT, sync_connector_targets


PROJECT = PROJECT_DIR
VICE_ALIAS = CODEX_CLOUD_ALIAS
VICE_THREAD = CODEX_CLOUD_THREAD
DESTINATION = {"transport": "codex-desktop", "id": VICE_THREAD, "host": "durable"}
RELAY_CLIENT = "claude_callback"
LOCAL_CLIENT = "workspace_agent"
SCAN_SECONDS = 30


def discover_orca(orca, valid, invoke):
    response = subprocess.run(
        [str(orca), "worktree", "list", "--repo", f"path:{PROJECT}", "--limit", "1000",
         "--environment", "local", "--json"], capture_output=True, text=True, check=True, timeout=15,
    )
    worktrees = json.loads(response.stdout)["result"]
    if worktrees.get("truncated"):
        raise ValueError("Truncated Orca worktree list.")
    paths = {str(Path(row["path"]).resolve()) for row in worktrees["worktrees"]
             if row.get("hostId") in (None, "local") and not row.get("isArchived")}
    inventory = invoke("list", "--limit", "1000")
    if inventory.get("truncated"):
        raise ValueError("Truncated Orca terminal list.")
    found = {}
    for row in inventory["terminals"]:
        if valid(row) or not row.get("worktreePath"):
            continue
        if str(Path(row["worktreePath"]).resolve()) not in paths:
            continue
        handle = row["handle"]
        title = "".join(ch for ch in (row.get("title") or "") if ch.isprintable()).strip()
        found[f"orca-{handle.removeprefix('term_').lower()}"] = {
            "transport": "orca", "id": handle, "incarnation": row["incarnationId"],
            "auto_discovered": True,
            **({"display_name": title[:100]} if title else {}),
        }
    return found


def remote_path(path):
    windows = PureWindowsPath(path)
    return windows if windows.drive else PurePosixPath(path)


def paired_inventory(invoke_on, blockers):
    if not ORCA_REPOSITORY:
        return {}
    discovered = {}
    for environment in invoke_on(None, "environment", "list")["environments"]:
        host = environment.get("id")
        if not isinstance(host, str) or not re.fullmatch(r"[a-f0-9-]{36}", host):
            continue
        try:
            repos = invoke_on(host, "repo", "list")["repos"]
            for repo in repos:
                if ((repo.get("gitRemoteIdentity") or {}).get("canonicalKey", "").lower() != ORCA_REPOSITORY
                        or repo.get("executionHostId") not in (None, "local")):
                    continue
                worktrees = invoke_on(host, "worktree", "list", "--repo", "id:" + repo["id"], "--limit", "1000")
                if worktrees.get("truncated"):
                    continue
                directories = {remote_path(row["path"]): "identity:" + row["identity"]["key"]
                               for row in worktrees["worktrees"]
                               if row.get("hostId") in (None, "local") and not row.get("isArchived")
                               and row.get("identity", {}).get("key") and not row.get("isBare")}
                terminals = invoke_on(host, "terminal", "list", "--limit", "1000")
                if terminals.get("truncated"):
                    continue
                for terminal in terminals["terminals"]:
                    workspace = directories.get(remote_path(terminal.get("worktreePath") or ""))
                    if not workspace or blockers(terminal):
                        continue
                    handle = terminal["handle"]
                    digest = hashlib.sha256(f"{host}:{handle}".encode()).hexdigest()[:24]
                    title = "".join(char for char in (terminal.get("title") or "") if char.isprintable()).strip()
                    pane = {}
                    if terminal.get("tabId") and terminal.get("leafId"):
                        pane["pane_key"] = f"{terminal['tabId']}:{terminal['leafId']}"
                    discovered["orca-remote-" + digest] = {
                        "transport": "orca", "host": host, "id": handle, "worktree": workspace,
                        "incarnation": terminal["incarnationId"], "auto_discovered": True,
                        "display_name": title[:100] or handle, **pane,
                    }
        except (OSError, RuntimeError, KeyError, TypeError, ValueError, subprocess.SubprocessError):
            continue
    return discovered


def merge_inventory(config, clients, discovered):
    targets = config["targets"]
    previous = {name for name, dest in targets.items() if dest.get("auto_discovered") is True}
    excluded = set(config.get("orca_excluded_handles", ()))
    next_targets = {name: dest for name, dest in targets.items() if name not in previous}
    live = {(dest.get("host"), dest["id"], dest["incarnation"]): dest for dest in discovered.values() if dest["id"] not in excluded}
    for dest in next_targets.values():
        if dest["transport"] != "orca":
            continue
        verified = live.get((dest.get("host"), dest["id"], dest.get("incarnation")))
        dest.pop("project_live_orca", None)
        if verified:
            dest["project_live_orca"] = True
            if verified.get("display_name") and not dest.get("display_name"):
                dest["display_name"] = verified["display_name"]
    for name, dest in discovered.items():
        if dest["id"] not in excluded and name not in next_targets:
            next_targets[name] = dest
    config["targets"] = next_targets
    for client_id, policy in config["clients"].items():
        kept = [alias for alias in policy["allow"] if alias not in previous]
        if client_id in {"codex", LOCAL_CLIENT, RELAY_CLIENT}:
            kept.extend(name for name, dest in next_targets.items() if dest.get("auto_discovered"))
        policy["allow"] = list(dict.fromkeys(kept))
        if client_id in clients:
            clients[client_id]["allow"] = policy["allow"]
    sync_connector_targets(config)


def directory(config, allowed, *, include_host=False):
    roster_names = config.get("claude_connector_roster_names", {})
    return [
        {"alias": alias, "transport": item["transport"],
         **({"host": item["host"]} if include_host and item.get("host") else {}),
         **({"display_name": title} if (title := item.get("display_name") or roster_names.get(alias)) else {})}
        for alias, item in sorted(config["targets"].items()) if alias in allowed
    ]


def queue_claude_dispatch(bridge, parent, token, data, *, via_connector=False):
    """Allow a single idempotent forward using the existing Claude reply lease."""
    if not bridge.REQUEST_ID.fullmatch(parent) or not bridge.TOKEN.fullmatch(token):
        raise ValueError("Invalid dispatch authorization.")
    if not isinstance(data, dict) or set(data) != {"target", "message"}:
        raise ValueError("Invalid dispatch body.")
    target, message = data["target"], normalize_message(data["message"])
    if not isinstance(target, str) or not bridge.ALIAS.fullmatch(target):
        raise ValueError("Invalid target alias.")
    bridge.validate_message(message)
    config = bridge.secret_file(bridge.BASE / "worker.json")
    client_id = CONNECTOR_CLIENT if via_connector else RELAY_CLIENT
    client = config["clients"][client_id]
    if target not in client["allow"] or target not in config["targets"]:
        raise PermissionError("Target is unavailable.")
    with bridge.database("worker") as con:
        entry = con.execute("SELECT client,target FROM audit WHERE id=?", (parent,)).fetchone()
    if not entry:
        raise PermissionError("The parent request cannot dispatch to that target.")
    original_client, source_alias = entry
    source = config["targets"].get(source_alias, {})
    destination = config["targets"][target]
    if source.get("transport") != "claude" or (
        destination["transport"] == "claude" and destination["id"] == source["id"]
    ):
        raise PermissionError("The parent request cannot dispatch to that target.")
    with bridge.database("callback") as con:
        lease = con.execute(
            "SELECT token FROM replies WHERE id=? AND transport='claude' AND expires>?",
            (parent, time.time()),
        ).fetchone()
    if not lease:
        raise PermissionError("The dispatch lease is invalid or expired.")
    actual = token if via_connector else bridge.token_hash(token)
    expected = connector_forward_proof(parent, lease[0]) if via_connector else lease[0]
    if not hmac.compare_digest(actual, expected):
        raise PermissionError("The dispatch lease is invalid or expired.")
    signed_parent = bridge.verify(bridge.load(bridge.location("requests", parent)),
                                  config["clients"][original_client]["key"])
    origin = bridge.destination_identity(source)
    if (signed_parent["request_id"] != parent or signed_parent["client"] != original_client
            or signed_parent["target"] != source_alias or signed_parent.get("destination") != origin):
        raise PermissionError("The Claude source no longer matches the original request.")
    rid = hashlib.sha256(("claude-dispatch:" + parent).encode()).hexdigest()[:32]
    data = {"request_id": rid, "client": client_id, "target": target,
            "created": time.time(), "message": f"[Bridge from {source_alias}]\n{message}",
            "destination": bridge.destination_identity(destination),
            "claude_return_alias": source_alias, "claude_return_to": origin}
    if via_connector:
        data["destination_id"] = destination["id"]
    with closing(sqlite3.connect(bridge.ROOT / "dispatch.sqlite3", timeout=5)) as con, con:
        con.execute("CREATE TABLE IF NOT EXISTS dispatch (parent TEXT PRIMARY KEY, payload TEXT, created REAL)")
        con.execute("BEGIN IMMEDIATE")
        con.execute("DELETE FROM dispatch WHERE created<?", (time.time() - bridge.DAY,))
        existing = con.execute("SELECT payload FROM dispatch WHERE parent=?", (parent,)).fetchone()
        if existing:
            stored = json.loads(existing[0])
            if (stored["target"], stored["message"], stored.get("destination")) != (
                target, data["message"], data["destination"]
            ):
                raise PermissionError("The dispatch lease has already been used.")
            return rid
        con.execute("INSERT INTO dispatch VALUES (?, ?, ?)", (parent, json.dumps(data), time.time()))
        bridge.put(bridge.location("requests", rid), {"data": data, "signature": bridge.mac(client["key"], data)})
    return rid
