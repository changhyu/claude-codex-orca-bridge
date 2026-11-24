"""Discover project chats from Codex Desktop and its local thread index (experimental IPC)."""

from collections import deque
from contextlib import contextmanager
import fcntl
import hashlib
import json
import os
from pathlib import Path
import re
from select import select
import socket
import sqlite3
import stat
import struct
import subprocess
import sys
from threading import Thread
import time

import secure_bridge as bridge
from agent_mesh import LOCAL_CLIENT, PROJECT
from bridge_settings import CODEX_ENVIRONMENTS, GIT_CLI
from cloud_roster import sync_connector_targets
from codex_desktop_delivery import DesktopUnavailable, read_exact, request
from codex_turn_reply import IPC_LIMIT, broadcast


HOST = "durable"
ENVIRONMENTS = CODEX_ENVIRONMENTS
SCAN_INTERVAL = 60
THREAD_ID = re.compile(r"[0-9a-f]{8}(?:-[0-9a-f]{4}){3}-[0-9a-f]{12}")
SOURCE = "codex-bridge-environment"
LOCAL_SOURCE = "codex-bridge-local-project"
LOCAL_CLIENTS = {"codex", LOCAL_CLIENT}
DISCOVERY_EVENTS = {
    "thread-read-state-changed": None,
    "thread-archived": True,
    "thread-unarchived": False,
}


@contextmanager
def ipc(timeout):
    path = Path.home() / ".codex/ipc/ipc.sock"
    info = path.lstat()
    if not stat.S_ISSOCK(info.st_mode) or info.st_uid != os.getuid() or info.st_mode & 0o077:
        raise DesktopUnavailable("Unexpected owner or mode for Codex IPC.")
    with socket.socket(socket.AF_UNIX) as conn:
        conn.settimeout(timeout)
        conn.connect(str(path))
        identity = request(conn, "initializing-client", "initialize", 0,
                           {"clientType": "agent-bridge-discovery"})["result"]["clientId"]
        yield conn, identity


def read_frame(conn):
    size, = struct.unpack("<I", read_exact(conn, 4))
    if not 0 < size <= IPC_LIMIT:
        raise DesktopUnavailable("Oversized desktop event.")
    return json.loads(read_exact(conn, size))


def git_directory(path):
    result = subprocess.run([GIT_CLI, "-C", str(path), "rev-parse", "--path-format=absolute",
                             "--git-common-dir"], check=True, capture_output=True, text=True, timeout=4)
    return Path(result.stdout.strip()).resolve()


def in_target_project(cwd):
    if not isinstance(cwd, str) or not Path(cwd).is_absolute():
        return False
    try:
        return git_directory(cwd).samefile(git_directory(PROJECT))
    except (OSError, subprocess.SubprocessError):
        return False


def source_for(host):
    return LOCAL_SOURCE if host == "local" else SOURCE


def destination(state, thread, host=HOST):
    if state.get("id") != thread or state.get("hostId") != host:
        return None
    if host == HOST:
        if ENVIRONMENTS and state.get("environmentConfigId") not in ENVIRONMENTS:
            return None
    elif (host != "local" or state.get("workspaceKind") != "project" or state.get("threadSource") != "user"
          or state.get("attachedThreadParentId") or not in_target_project(state.get("cwd"))):
        return None
    title = "".join(ch for ch in (state.get("title") or "") if ch.isprintable()).strip()
    return {"id": thread, "host": host, "transport": "codex-desktop",
            "display_name": title[:100] or ("Codex Cloud" if host == HOST else "Codex"), "source": source_for(host)}


class ThreadOwnerUnavailable(DesktopUnavailable):
    """The desktop did not find a responsive owner for the selected thread."""


def inspect(thread, host=HOST):
    with ipc(4) as (conn, client):
        try:
            owner = request(conn, client, "thread-owner-discovery", 1, {
                "hostId": host, "conversationId": thread,
            })["handledByClientId"]
        except TimeoutError as error:
            raise ThreadOwnerUnavailable("Codex thread owner did not respond.") from error
        except DesktopUnavailable as error:
            if str(error) != "no-client-found":
                raise
            raise ThreadOwnerUnavailable(str(error)) from error
        broadcast(conn, client, owner, thread, host, True)
        try:
            deadline = time.monotonic() + 5
            while time.monotonic() < deadline:
                conn.settimeout(max(.1, deadline - time.monotonic()))
                item = read_frame(conn)
                params = item.get("params", {})
                change = params.get("change", {})
                if (item.get("sourceClientId") == owner and item.get("method") == "thread-stream-state-changed"
                        and params.get("conversationId") == thread and params.get("hostId") == host
                        and change.get("type") == "snapshot"):
                    return destination(change.get("conversationState", {}), thread, host)
        finally:
            try:
                broadcast(conn, client, owner, thread, host, False)
            except OSError:
                pass
    return None


def alias_for(thread, host=HOST):
    return ("codex-cloud-" if host == HOST else "codex-local-") + hashlib.sha256(thread.encode()).hexdigest()[:12]


def reconcile(config, thread, row=None, archived=None, host=HOST):
    alias = alias_for(thread, host)
    suppressed = set(config.get("codex_discovery_archived", []))
    if archived is True:
        suppressed.add(thread)
    elif archived is False:
        suppressed.discard(thread)
    targets = config["targets"]
    prior = targets.get(alias)
    managed = prior and prior.get("source") == source_for(host) and prior.get("id") == thread
    if prior and not managed:
        raise ValueError("The generated Codex alias is already in use.")
    pinned = [entry for name, entry in targets.items() if entry["transport"] == "codex-desktop"
              and entry.get("host", "local") == host and entry["id"] == thread and name != alias]
    if row and thread not in suppressed:
        for entry in pinned:
            entry.setdefault("display_name", row.get("display_name", "Codex"))
    if thread in suppressed or pinned:
        if managed:
            targets.pop(alias)
    elif row is not None and alias not in config.get("codex_discovery_exclusions", []):
        targets[alias] = row
    config["codex_discovery_archived"] = sorted(suppressed)
    for client_name, policy in config["clients"].items():
        if client_name not in LOCAL_CLIENTS:
            continue
        allowed = [name for name in policy["allow"] if name != alias]
        if alias in targets:
            allowed.append(alias)
        policy["allow"] = list(dict.fromkeys(allowed))
    sync_connector_targets(config)


def write_registry(thread, row=None, archived=None, host=HOST, *, quiet=False):
    with (bridge.ROOT / "enrollment.lock").open("a") as lock:
        fcntl.flock(lock, fcntl.LOCK_EX)
        path = bridge.BASE / "worker.json"
        config = bridge.secret_file(path)
        before = json.dumps(config, sort_keys=True)
        reconcile(config, thread, row, archived, host)
        if json.dumps(config, sort_keys=True) == before:
            return
        bridge.put(path, config)
        for filename in ("client.json", "agent-client.json"):
            client_path = bridge.BASE / filename
            client = bridge.secret_file(client_path)
            client["allow"] = config["clients"][client["id"]]["allow"]
            bridge.put(client_path, client)
    if not quiet:
        print("Codex registry updated.", flush=True)


def inspect_candidate(thread, archived=None, host=HOST):
    if archived is True:
        alias = alias_for(thread, host)
        if bridge.secret_file(bridge.BASE / "worker.json")["targets"].get(alias, {}).get("source") == source_for(host):
            write_registry(thread, archived=True, host=host)
        return
    if archived is False:
        config = bridge.secret_file(bridge.BASE / "worker.json")
        if thread in config.get("codex_discovery_archived", []):
            write_registry(thread, archived=False, host=host)
    try:
        row = inspect(thread, host)
    except (OSError, RuntimeError, KeyError, ValueError, TypeError):
        return
    if row:
        write_registry(thread, row, archived, host)


def candidates(argv):
    found = deque()
    for thread in argv:
        if not THREAD_ID.fullmatch(thread):
            raise ValueError("Expected a Codex thread ID.")
        found.append(thread)
    return found


def discover_local_history():
    home = Path.home() / ".codex"
    indexes = [path for path in home.glob("state_*.sqlite")
               if re.fullmatch(r"state_\d+\.sqlite", path.name) and not path.is_symlink()]
    if not indexes:
        return
    index = max(indexes, key=lambda path: int(path.stem.split("_")[1]))
    if index.stat().st_uid != os.getuid():
        return
    with sqlite3.connect(index.as_uri() + "?mode=ro", uri=True, timeout=3) as conn:
        rows = conn.execute("""
            SELECT id, cwd, title, archived FROM threads
            WHERE source='vscode' AND thread_source='user' AND originator='Codex Desktop'
              AND attached_thread_parent_id IS NULL
        """).fetchall()
    for thread, cwd, title, archived in rows:
        if not THREAD_ID.fullmatch(thread):
            continue
        if archived:
            inspect_candidate(thread, archived=True, host="local")
            continue
        row = destination({"id": thread, "hostId": "local", "workspaceKind": "project", "cwd": cwd,
                           "title": title, "threadSource": "user"}, thread, "local")
        if row:
            write_registry(thread, row, host="local")


def allowed_alias(config, thread, host):
    if thread in config.get("codex_discovery_archived", []):
        return None
    allowed = config["clients"][LOCAL_CLIENT]["allow"]
    return next((alias for alias, route in config["targets"].items()
                 if alias in allowed and route["transport"] == "codex-desktop"
                 and route["id"] == thread and route.get("host", "local") == host), None)


def inspect_for_send(thread, host):
    try:
        return inspect(thread, host)
    except ThreadOwnerUnavailable:
        pass
    subprocess.run(["/usr/bin/open", "-g", f"codex://threads/{thread}?hostId={host}"],
                   check=True, capture_output=True, timeout=5)
    deadline = time.monotonic() + 8
    while True:
        try:
            return inspect(thread, host)
        except ThreadOwnerUnavailable:
            if time.monotonic() >= deadline:
                raise
        time.sleep(.5)


def resolve(thread, host, *, open_for_send=False):
    if not THREAD_ID.fullmatch(thread) or host not in {"local", HOST}:
        raise ValueError("Invalid Codex chat link.")
    path = bridge.BASE / "worker.json"
    config = bridge.secret_file(path)
    alias = allowed_alias(config, thread, host)
    if alias:
        return alias
    if (thread in config.get("codex_discovery_archived", [])
            or alias_for(thread, host) in config.get("codex_discovery_exclusions", [])):
        raise ValueError("This Codex chat is archived or excluded.")
    try:
        route = (inspect_for_send if open_for_send else inspect)(thread, host)
    except (OSError, RuntimeError, subprocess.SubprocessError) as error:
        raise ValueError("Open this Codex chat once so its project can be verified.") from error
    if not route:
        raise ValueError("This Codex chat could not be verified for the configured project.")
    write_registry(thread, route, host=host, quiet=True)
    alias = allowed_alias(bridge.secret_file(path), thread, host)
    if not alias:
        raise ValueError("This Codex chat is not available for messaging.")
    return alias


def event_candidate(event):
    if not isinstance(event, dict) or event.get("type") != "broadcast":
        return None
    params = event.get("params", {})
    if not isinstance(params, dict):
        return None
    method = event.get("method")
    host = params.get("hostId")
    thread = params.get("conversationId") or params.get("threadId") or ""
    if (host not in ("local", HOST) or not isinstance(method, str) or method not in DISCOVERY_EVENTS
            or not isinstance(thread, str) or not THREAD_ID.fullmatch(thread)):
        return None
    return host, thread, DISCOVERY_EVENTS[method]


def unread_candidates(state):
    identities = state.get("electron-thread-read-state-v1", {}).get("unreadByIdentity", {})
    if not isinstance(identities, dict) or len(identities) != 1:
        return set()
    hosts = next(iter(identities.values()))
    if not isinstance(hosts, dict):
        return set()
    found = set()
    for scope, ids in hosts.items():
        host = scope.split(":", 1)[0]
        if host == HOST and isinstance(ids, list):
            found.update((host, tid) for tid in ids if isinstance(tid, str) and THREAD_ID.fullmatch(tid))
    return found


def staged_desktop_candidates():
    path = Path.home() / ".codex/.codex-global-state.json"
    if not path.is_file() or path.is_symlink() or path.stat().st_uid != os.getuid():
        return set()
    return unread_candidates(bridge.load(path, max_bytes=4 * 1024 * 1024))


def scan_candidates(seed):
    try:
        found = staged_desktop_candidates()
    except (OSError, ValueError, KeyError, TypeError, AttributeError):
        found = set()
    found.update((HOST, thread) for thread in seed)
    config = bridge.secret_file(bridge.BASE / "worker.json")
    for host, thread in sorted(found):
        if (thread not in config.get("codex_discovery_archived", [])
                and alias_for(thread, host) not in config.get("codex_discovery_exclusions", [])
                and not allowed_alias(config, thread, host)):
            inspect_candidate(thread, host=host)


def watch(seed):
    import codex_outbound

    Thread(target=codex_outbound.watch, args=(bridge, ipc, read_frame, request, broadcast),
           name="codex-outbound", daemon=True).start()
    recently_seen = {}
    next_scan = 0
    with ipc(8) as (conn, _):
        conn.settimeout(8)
        while True:
            now = time.monotonic()
            if now >= next_scan:
                try:
                    discover_local_history()
                except (OSError, ValueError, sqlite3.Error) as error:
                    print(f"Local Codex discovery unavailable: {type(error).__name__}", flush=True)
                scan_candidates(seed)
                next_scan = time.monotonic() + SCAN_INTERVAL
            if not select([conn], [], [], max(0, next_scan - time.monotonic()))[0]:
                continue
            candidate = event_candidate(read_frame(conn))
            if candidate is None:
                continue
            host, thread, archived = candidate
            identity = (host, thread)
            now = time.monotonic()
            if archived is None and now - recently_seen.get(identity, -60) < 10:
                continue
            recently_seen = {key: stamp for key, stamp in recently_seen.items() if now - stamp < 600}
            recently_seen[identity] = now
            if archived is None:
                config = bridge.secret_file(bridge.BASE / "worker.json")
                if allowed_alias(config, thread, host):
                    continue
            inspect_candidate(thread, archived, host)


if __name__ == "__main__":
    os.umask(0o077)
    bridge.ensure_state()
    args = sys.argv[1:]
    if len(args) == 3 and args[0] in {"--resolve", "--open-for-send"}:
        try:
            alias = resolve(args[1], args[2], open_for_send=args[0] == "--open-for-send")
        except (KeyError, TypeError, ValueError, OSError) as error:
            print(json.dumps({"state": "unavailable", "error": str(error)}))
            raise SystemExit(1)
        print(json.dumps({"state": "resolved", "alias": alias}))
    elif args == ["--local-history"]:
        discover_local_history()
    elif args[:1] == ["--once"]:
        for item in candidates(args[1:]):
            inspect_candidate(item)
    else:
        watch(candidates(args))
