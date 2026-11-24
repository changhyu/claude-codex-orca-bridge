"""Collect the final answer to a specific bridge request from Codex Desktop."""

import json
from pathlib import Path
import socket
import sqlite3
import stat
import struct
import os
import time
import subprocess
import uuid
from concurrent.futures import ThreadPoolExecutor

from codex_desktop_delivery import ADMIN_ALIAS, CHAT_PRESENTATION, DesktopUnavailable, read_exact, request


FINAL_STATES = {"completed", "interrupted", "failed", "cancelled"}
IPC_LIMIT = 32 * 1024 * 1024
REPLY_LIMIT = 23000
MAX_WATCHERS = 4
_watchers = {}
_checked_at = {}
_executor = ThreadPoolExecutor(max_workers=MAX_WATCHERS, thread_name_prefix="codex-reply")


def track(bridge, request_id, destination, expires):
    thread = destination["id"]
    host = destination.get("host", "local")
    with bridge.database("callback") as conn:
        conn.execute("""CREATE TABLE IF NOT EXISTS desktop_replies (
            id TEXT PRIMARY KEY, thread TEXT NOT NULL, host TEXT NOT NULL, expires REAL NOT NULL
        )""")
        conn.execute("INSERT OR IGNORE INTO desktop_replies VALUES (?,?,?,?)", (request_id, thread, host, expires))
        row = conn.execute("SELECT thread,host FROM desktop_replies WHERE id=?", (request_id,)).fetchone()
    return row == (thread, host)


def extend_cloud_reply(bridge, rid, thread, now, *, mailbox=False):
    expires = now + bridge.CLOUD_REPLY_TTL
    with bridge.database("callback") as conn:
        conn.execute("UPDATE desktop_replies SET expires=MAX(expires,?) WHERE id=? AND thread=? AND host='durable'",
                     (expires, rid, thread))
        if mailbox:
            conn.execute("UPDATE desktop_mailbox SET expires=MAX(expires,?) WHERE id=? AND thread=?",
                         (expires, rid, thread))
            if conn.execute("SELECT 1 FROM sqlite_master WHERE name='cloud_turn_leases' AND type='table'").fetchone():
                conn.execute("UPDATE cloud_turn_leases SET expires=MAX(expires,?) WHERE id=? AND thread=?",
                             (expires, rid, thread))
    return expires


def wake_once(bridge, request_id, destination):
    """Load an authenticated request's registered chat if it has no desktop owner."""
    thread = destination["id"]
    host = destination.get("host", "local")
    if str(uuid.UUID(thread)) != thread or host not in {"local", "durable"}:
        return False
    with bridge.database("callback") as conn:
        conn.execute("CREATE TABLE IF NOT EXISTS desktop_wake (id TEXT PRIMARY KEY, created REAL NOT NULL)")
        conn.execute("DELETE FROM desktop_wake WHERE created < ?", (time.time() - bridge.DAY,))
        claimed = conn.execute("INSERT OR IGNORE INTO desktop_wake VALUES (?,?)",
                               (request_id, time.time())).rowcount
    if not claimed:
        return False
    result = subprocess.run(
        ["/usr/bin/open", "-g", f"codex://threads/{thread}?hostId={host}"],
        capture_output=True, timeout=8,
    )
    return result.returncode == 0


def collect(bridge, config, mailbox_requests=()):
    now = time.time()
    with bridge.database("worker") as conn:
        active = {rid: (client, target) for rid, client, target in conn.execute(
            "SELECT id,client,target FROM audit WHERE state IN ('delivered','input_accepted','delivery_unknown')"
        )}
    with bridge.database("callback") as conn:
        conn.execute("""CREATE TABLE IF NOT EXISTS desktop_replies (
            id TEXT PRIMARY KEY, thread TEXT NOT NULL, host TEXT NOT NULL, expires REAL NOT NULL
        )""")
        rows = conn.execute("SELECT id,thread,host,expires FROM desktop_replies").fetchall()
        conn.execute("DELETE FROM desktop_replies WHERE expires < ?", (now - bridge.DAY,))
    tracked = {rid for rid, _, _, _ in rows}
    for rid in _checked_at.keys() - active.keys():
        del _checked_at[rid]
    candidates = []
    for rid, thread, host, expires in rows:
        mailbox = rid in mailbox_requests
        if rid not in active or (mailbox and host != "durable"):
            continue
        client, target = active[rid]
        policy = config["clients"].get(client)
        if not policy:
            continue
        observer = _watchers.get(rid)
        if observer and observer.done():
            try:
                receipt = observer.result()
            except (OSError, ValueError, RuntimeError, TypeError, KeyError, sqlite3.Error):
                receipt = None
            del _watchers[rid]
            if receipt:
                state = receipt.pop("state")
                if state == "running":
                    expires = max(expires, extend_cloud_reply(bridge, rid, thread, now, mailbox=mailbox))
                else:
                    bridge.publish(rid, client, target, state, policy["key"], **receipt)
                    continue
        if expires <= now:
            if not mailbox and rid not in _watchers:
                bridge.publish(rid, client, target, "reply_expired", policy["key"])
            continue
        if rid not in _watchers:
            candidates.append((rid, thread, host, mailbox))
    for rid, future in tuple(_watchers.items()):
        if rid not in active and future.done():
            del _watchers[rid]
    for rid, thread, host, mailbox in sorted(candidates, key=lambda row: _checked_at.get(row[0], 0)):
        if len(_watchers) >= MAX_WATCHERS:
            break
        _checked_at[rid] = now
        _watchers[rid] = _executor.submit(observe, thread, host, rid, mailbox=mailbox)
    return tracked


def tagged_request(item, request_id):
    message_id = item.get("clientUserMessageId") or ""
    if not isinstance(message_id, str) or message_id.replace("-", "") != request_id:
        return False
    return tagged_input(item.get("input", []), request_id)


def tagged_input(inputs, request_id):
    prefix = "codex-untrusted-app-input:"
    for content in inputs:
        for element in content.get("text_elements", []):
            placeholder = element.get("placeholder") or ""
            if not isinstance(placeholder, str) or not placeholder.startswith(prefix):
                continue
            try:
                record = json.loads(placeholder.removeprefix(prefix))["message"]
                if (record["source"] == "mcp_app" and record["sourceId"] == ADMIN_ALIAS
                        and record["structuredContent"]["bridge_request_id"] == request_id):
                    return True
            except (ValueError, TypeError, KeyError):
                continue
    return False


def mailbox_request(item, request_id):
    message_id = item.get("clientUserMessageId") or item.get("clientId") or ""
    if not isinstance(message_id, str) or message_id.replace("-", "") != request_id:
        return False
    return any(str(content.get("text", "")).startswith(f"브릿지 수신 {request_id}.")
               for content in item.get("input", item.get("content", [])))


def result_from_snapshot(state, request_id, *, report_running=False, mailbox=False):
    history = state.get("turnHistory", {}).get("history", {}).get("entitiesByKey", {})
    turns = [*state.get("turns", []), *history.values()]
    for turn in reversed(turns):
        params = turn.get("params", {}) or {}
        message_id = params.get("clientUserMessageId") or ""
        items = turn.get("items", [])
        if mailbox:
            if turn.get("status") == "inProgress" and any(
                item.get("type") in {"userMessage", "steeringUserMessage"} and mailbox_request(item, request_id)
                for item in items
            ):
                return {"state": "running"}
            continue
        if message_id.replace("-", "") != request_id:
            # Hydrated Cloud turns can lose the outer client ID while retaining the app payload.
            steering = next((item for item in reversed(items) if item.get("type") == "steeringUserMessage"), {})
            admitted = tagged_input(params.get("input", []), request_id) or any(
                item.get("type") == "userMessage" and tagged_input(item.get("content", []), request_id)
                for item in items
            ) or tagged_request(steering, request_id)
            if not admitted:
                continue
        status = turn.get("status")
        if report_running and status == "inProgress":
            return {"state": "running"}
        if status not in FINAL_STATES:
            continue
        if status != "completed":
            return {"state": "reply_failed", "turn_state": status}
        for item in reversed(items):
            if item.get("type") == "agentMessage" and item.get("phase") == "final_answer":
                text = item.get("text")
                if isinstance(text, str) and text.strip():
                    inputs = params.get("input") or [
                        content for user in items if user.get("type") == "userMessage"
                        for content in user.get("content", [])
                    ]
                    text = reply_without_displayed_request(text, inputs)
                    data = text.encode()
                    if len(data) > REPLY_LIMIT:
                        text = data[:REPLY_LIMIT].decode(errors="ignore") + "\n[Remaining text is in the Codex chat.]"
                    return {"state": "replied", "reply": text}
    return None


def reply_without_displayed_request(text, inputs):
    """Keep the answer for the callback when the chat displays the original request above it."""
    for item in inputs:
        for element in item.get("text_elements", []):
            placeholder = element.get("placeholder") or ""
            prefix = "codex-untrusted-app-input:"
            if not isinstance(placeholder, str) or not placeholder.startswith(prefix):
                continue
            try:
                message = json.loads(placeholder[len(prefix):])["message"]
                presentation = message["structuredContent"]["bridge_chat_presentation"]
                if presentation != CHAT_PRESENTATION["request"] or message["sourceId"] != ADMIN_ALIAS:
                    continue
                displayed = f"브릿지 수신\n\n{message['text']}\n\n브릿지 답변\n\n"
                if text.startswith(displayed) and text[len(displayed):].strip():
                    return text[len(displayed):]
            except (ValueError, TypeError, KeyError):
                continue
    return text


def broadcast(conn, client, owner, thread, host, following):
    frame = {
        "type": "broadcast", "method": "thread-stream-following-changed", "version": 1,
        "sourceClientId": client, "targetClientIds": [owner],
        "params": {"conversationId": thread, "hostId": host, "following": following},
    }
    data = json.dumps(frame).encode()
    conn.sendall(struct.pack("<I", len(data)) + data)


def final_update(change):
    for patch in change.get("patches", []):
        value = patch.get("value")
        if isinstance(value, str) and value in FINAL_STATES:
            return True
        if isinstance(value, dict) and value.get("status") in FINAL_STATES:
            return True
    return False


def observe(thread, host, request_id, timeout=25, *, mailbox=False):
    path = Path.home() / ".codex/ipc/ipc.sock"
    info = path.lstat()
    if not stat.S_ISSOCK(info.st_mode) or info.st_uid != os.getuid() or info.st_mode & 0o077:
        raise DesktopUnavailable("Desktop IPC socket ownership or permissions changed.")
    with socket.socket(socket.AF_UNIX) as conn:
        conn.settimeout(8)
        conn.connect(str(path))
        client = request(conn, "initializing-client", "initialize", 0,
                         {"clientType": "agent-bridge-reply"})["result"]["clientId"]
        owner = request(conn, client, "thread-owner-discovery", 1,
                        {"hostId": host, "conversationId": thread})["handledByClientId"]
        broadcast(conn, client, owner, thread, host, True)
        end = time.monotonic() + timeout
        running = None
        try:
            while time.monotonic() < end:
                conn.settimeout(max(0.1, end - time.monotonic()))
                size, = struct.unpack("<I", read_exact(conn, 4))
                if not 0 < size <= IPC_LIMIT:
                    return None
                frame = json.loads(read_exact(conn, size))
                if frame.get("sourceClientId") != owner or frame.get("method") != "thread-stream-state-changed":
                    continue
                params = frame.get("params", {})
                if params.get("conversationId") != thread or params.get("hostId") != host:
                    continue
                change = params.get("change", {})
                if change.get("type") == "snapshot":
                    receipt = result_from_snapshot(change.get("conversationState", {}), request_id,
                                                   report_running=host == "durable", mailbox=mailbox)
                    if receipt and receipt["state"] != "running":
                        return receipt
                    running = receipt
                elif final_update(change):
                    broadcast(conn, client, owner, thread, host, False)
                    broadcast(conn, client, owner, thread, host, True)
        except TimeoutError:
            return running
        finally:
            try:
                broadcast(conn, client, owner, thread, host, False)
            except OSError:
                pass
    return running
