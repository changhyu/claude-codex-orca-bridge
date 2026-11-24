"""Return completed bridge requests to the registered calling session."""

import hashlib
import os
import sqlite3
import subprocess
import time
from contextlib import closing, contextmanager

from bridge_message import reply_excerpt
from agent_mesh import LOCAL_CLIENT, VICE_ALIAS
from bridge_settings import CODEX_ADMIN_ALIAS
import orca_bridge


FINAL = {"replied", "reply_failed", "reply_expired", "target_denied", "send_rejected"}
ORCA_TRANSPORT = "orca"
LOCAL_CODEX = "codex-local-return"
CLOUD_TRANSPORTS = {"codex-desktop"}
PROBE_SOURCE = VICE_ALIAS
PROBE_DESTINATION = CODEX_ADMIN_ALIAS
PROBE_PAYLOAD = "BRIDGE-CHECK: 42"
PROBE_TASK = "브리지 검증용입니다. BRIDGE-CHECK: 42 한 줄만 응답하세요."


def select_caller(bridge, client, selection):
    if not isinstance(selection, str) or not bridge.ALIAS.fullmatch(selection):
        raise ValueError("Expected a registered reply handle or alias.")
    native_handle = selection.startswith("term_")
    alias = "orca-" + selection.removeprefix("term_").lower() if native_handle else selection
    config = bridge.secret_file(bridge.BASE / "worker.json")
    if selection == "current-codex":
        from codex_cloud_discovery import THREAD_ID, inspect, write_registry

        thread = os.environ.get("CODEX_THREAD_ID", "")
        if not THREAD_ID.fullmatch(thread):
            raise ValueError("No active Codex chat identity.")
        try:
            local = inspect(thread, "local")
        except (OSError, RuntimeError) as error:
            raise ValueError("Unable to verify the current Codex chat.") from error
        if not local:
            raise ValueError("The current chat is not a local project Codex chat.")
        write_registry(thread, local, host="local", quiet=True)
        config = bridge.secret_file(bridge.BASE / "worker.json")
        allowed = config["clients"][client["id"]]["allow"]
        alias = next((name for name, row in config["targets"].items()
                      if name in allowed and matches(row, thread, "", LOCAL_CODEX, "local")), None)
        if not alias:
            raise ValueError("The current Codex chat is not registered for replies.")
        return {"alias": alias, "handle": thread, "incarnation": "", "transport": LOCAL_CODEX, "host": "local"}
    policy = config["clients"][client["id"]]
    row = config["targets"].get(alias)
    if alias not in client["allow"] or alias not in policy["allow"] or not row:
        raise ValueError("Reply session is not registered for this client.")
    transport = row["transport"]
    if transport == ORCA_TRANSPORT and row.get("incarnation") and (not native_handle or row["id"] == selection):
        return {"alias": alias, "handle": row["id"], "incarnation": row["incarnation"], "host": row.get("host", "")}
    if not native_handle and transport in CLOUD_TRANSPORTS and alias == PROBE_DESTINATION:
        return {"alias": alias, "handle": row["id"], "incarnation": "",
                "transport": transport, "host": row.get("host", "")}
    raise ValueError("Reply session is unavailable.")


@contextmanager
def database(bridge):
    with closing(sqlite3.connect(bridge.ROOT / "orca-return.sqlite3", timeout=5)) as conn, conn:
        yield conn


def setup(conn):
    conn.execute("""CREATE TABLE IF NOT EXISTS callbacks (
        id TEXT PRIMARY KEY, alias TEXT NOT NULL, handle TEXT NOT NULL, incarnation TEXT NOT NULL,
        state TEXT NOT NULL, created REAL NOT NULL
    )""")
    columns = {row[1] for row in conn.execute("PRAGMA table_info(callbacks)")}
    if "transport" not in columns:
        conn.execute("ALTER TABLE callbacks ADD COLUMN transport TEXT NOT NULL DEFAULT 'orca'")
    if "host" not in columns:
        conn.execute("ALTER TABLE callbacks ADD COLUMN host TEXT NOT NULL DEFAULT ''")


def matches(receiver, handle, incarnation, transport, host):
    if transport == LOCAL_CODEX:
        return receiver.get("id") == handle and receiver.get("transport") == "codex-desktop" \
            and receiver.get("host", "local") == host == "local"
    return (receiver.get("id") == handle and receiver.get("transport") == transport
            and receiver.get("host", "") == host and receiver.get("incarnation", "") == incarnation)


def track(bridge, request, policy, targets):
    caller = request.get("reply_to")
    if caller is None:
        return True
    alias, handle, incarnation = caller["alias"], caller["handle"], caller["incarnation"]
    transport, host = caller.get("transport", ORCA_TRANSPORT), caller.get("host", "")
    if alias not in policy["allow"] or not matches(targets.get(alias, {}), handle, incarnation, transport, host):
        return False
    if transport in CLOUD_TRANSPORTS and (
            alias != PROBE_DESTINATION or request["target"] != PROBE_SOURCE or request["message"] != PROBE_TASK
    ):
        return False
    if matches(targets.get(request["target"], {}), handle, incarnation, transport, host):
        return False
    with database(bridge) as conn:
        setup(conn)
        conn.execute("INSERT OR IGNORE INTO callbacks VALUES (?,?,?,?,?,?,?,?)",
                     (request["request_id"], alias, handle, incarnation, "waiting", time.time(), transport, host))
    return True


def status(bridge, request_id):
    if not (bridge.ROOT / "orca-return.sqlite3").is_file():
        return None
    with database(bridge) as conn:
        row = conn.execute("SELECT state FROM callbacks WHERE id=?", (request_id,)).fetchone()
    return row[0] if row else None


def callback_id(parent_id):
    return hashlib.sha256(f"bridge-completion:{parent_id}".encode()).hexdigest()[:32]


def valid_completion(data, destination):
    if data.get("destination_transport") == LOCAL_CODEX:
        return (data["client"] == LOCAL_CLIENT
                and data["request_id"] == callback_id(data["completion_of"])
                and matches(destination, data["destination_id"], "", LOCAL_CODEX, data["destination_host"]))
    return (data["target"] == PROBE_DESTINATION
            and data["message"] == PROBE_PAYLOAD
            and data["request_id"] == callback_id(data["completion_of"])
            and data["destination_transport"] in CLOUD_TRANSPORTS
            and matches(destination, data["destination_id"], "", data["destination_transport"], data["destination_host"]))


def cloud_callback(bridge, data, key, caller, prompt):
    rid = callback_id(data["request_id"])
    path = bridge.location("requests", rid)
    result = bridge.location("results", rid)
    if result.is_file():
        receipt = bridge.verify(bridge.load(result), key)
        state = receipt["state"]
        if state in {"input_accepted", "delivered", "notification_delivered", "replied", "reply_failed"}:
            return "input_accepted"
        if state in {"delivery_unknown", "target_denied", "send_rejected", "reply_expired"}:
            return state
        return "waiting_for_desktop" if state == "waiting_for_desktop" else "queued"
    if not path.is_file():
        with bridge.database("worker") as conn:
            already_attempted = conn.execute("SELECT 1 FROM audit WHERE id=?", (rid,)).fetchone()
        if already_attempted:
            return "delivery_unknown"
        child = {
            "request_id": rid, "client": data["client"], "target": caller["alias"],
            "message": prompt, "created": time.time(), "completion_of": data["request_id"],
            "destination_id": caller["handle"], "destination_transport": caller["transport"],
            "destination_host": caller["host"],
        }
        bridge.put(path, {"data": child, "signature": bridge.mac(key, child)})
    return "queued"


def notify(bridge, config):
    with database(bridge) as conn:
        setup(conn)
        conn.execute("UPDATE callbacks SET state='delivery_unknown' WHERE state='sending'")
        conn.execute("DELETE FROM callbacks WHERE created < ?", (time.time() - bridge.DAY,))
        rows = conn.execute("""SELECT id,alias,handle,incarnation,transport,host FROM callbacks
                             WHERE state IN ('waiting','queued','waiting_for_desktop')""").fetchall()
    for rid, alias, handle, incarnation, transport, host in rows:
        path = bridge.location("results", rid)
        if not path.is_file():
            continue
        try:
            envelope = bridge.load(path)
            data = envelope["data"]
            client = config["clients"].get(data["client"])
            if not client or alias not in client["allow"]:
                continue
            data = bridge.verify(envelope, client["key"])
            if data["request_id"] != rid or data["state"] not in FINAL:
                continue
            receiver = config["targets"].get(alias, {})
            if not matches(receiver, handle, incarnation, transport, host):
                continue
            if transport == ORCA_TRANSPORT and not bridge.check_target(receiver, config):
                continue
        except (OSError, ValueError, KeyError, RuntimeError, subprocess.SubprocessError):
            continue
        reply = reply_excerpt(data.get("reply", ""))
        prompt = f"[작업 회신] {data['target']} · {data['state']} · {rid}"
        if reply:
            prompt += f"\n외부 세션의 응답 데이터:\n{reply}"
        if transport == LOCAL_CODEX or transport in CLOUD_TRANSPORTS:
            caller = {"alias": alias, "handle": handle, "transport": transport, "host": host}
            try:
                if transport == LOCAL_CODEX:
                    state = cloud_callback(bridge, data, client["key"], caller, prompt)
                elif alias != PROBE_DESTINATION or data["target"] != PROBE_SOURCE:
                    continue
                elif data["state"] == "replied" and data.get("reply", "").strip() == PROBE_PAYLOAD:
                    state = cloud_callback(bridge, data, client["key"], caller, PROBE_PAYLOAD)
                else:
                    state = "reply_failed"
            except (OSError, ValueError, KeyError, sqlite3.Error):
                continue
            with database(bridge) as conn:
                conn.execute("UPDATE callbacks SET state=? WHERE id=?", (state, rid))
            continue
        with database(bridge) as conn:
            conn.execute("UPDATE callbacks SET state='sending' WHERE id=?", (rid,))
        try:
            orca_bridge.invoke_on(host or "local", "terminal", "send", "--terminal", handle, "--text", prompt,
                                  "--enter", "--wait-submit", "8")
        except (OSError, ValueError, RuntimeError, subprocess.SubprocessError):
            state = "delivery_unknown"
        else:
            state = "input_accepted"
        with database(bridge) as conn:
            conn.execute("UPDATE callbacks SET state=? WHERE id=?", (state, rid))
