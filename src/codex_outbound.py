"""Accept explicit user-originated bridge sends in registered Cloud Codex chats."""

import hashlib
import json
import re
import time

from bridge_message import reply_excerpt
from agent_mesh import LOCAL_CLIENT
from cloud_inbox import save_once
from codex_delegation import FINAL, checked_result
from codex_desktop_delivery import ADMIN_THREAD


HEADER = "브릿지 전송 "
COMMAND = re.compile(r"\A브릿지 전송 ([A-Za-z0-9_-]{1,64})\r?\n([\s\S]+)\Z")
ADMIN_DELEGATION = re.compile(
    r"\A<codex_delegation>\n  <source_thread_id>" + re.escape(ADMIN_THREAD)
    + r"</source_thread_id>\n  <input>([\s\S]*)</input>\n</codex_delegation>\Z"
)
READ_WINDOW = 180


def eligible(row):
    return (row.get("transport") == "codex-desktop" and row.get("host") == "durable"
            and row.get("source") in {"codex-bridge-environment", "user-designated"})


def parse(items):
    if not isinstance(items, list) or len(items) != 1:
        return None
    item = items[0]
    if not isinstance(item, dict) or item.get("type") != "text" or item.get("text_elements") or item.get("codexDelegation"):
        return None
    content = item.get("text")
    if not isinstance(content, str):
        return None
    delegated = ADMIN_DELEGATION.fullmatch(content)
    return COMMAND.fullmatch(delegated[1] if delegated else content)


def commands(state, thread, now):
    if state.get("hostId") != "durable" or state.get("id") != thread:
        return
    history = state.get("turnHistory", {}).get("history", {}).get("entitiesByKey", {})
    for turn in [*state.get("turns", []), *history.values()]:
        stamp = turn.get("turnStartedAtMs")
        if not isinstance(stamp, (int, float)) or not 0 <= now - stamp / 1000 <= READ_WINDOW:
            continue
        params = turn.get("params", {})
        command = parse(params.get("input"))
        if command:
            yield params.get("clientUserMessageId") or turn.get("turnId"), command.groups()
        for item in turn.get("items", []):
            if item.get("type") == "steeringUserMessage" and not item.get("attachments"):
                command = parse(item.get("input"))
                if command:
                    yield item.get("clientUserMessageId"), command.groups()


def queue(bridge, source_alias, thread, message_id, alias, message):
    if not isinstance(message_id, str) or not bridge.REQUEST_ID.fullmatch(message_id.replace("-", "")):
        return
    config = bridge.secret_file(bridge.BASE / "worker.json")
    policy = config["clients"][LOCAL_CLIENT]
    source = config["targets"].get(source_alias, {})
    target = config["targets"].get(alias, {})
    if (not eligible(source) or source["id"] != thread or source_alias not in policy["allow"]
            or alias not in policy["allow"] or not target or target["id"] == thread):
        return
    bridge.validate_message(message)
    normalized_id = message_id.replace("-", "")
    rid = hashlib.sha256(("codex-outbound:" + thread + ":" + normalized_id).encode()).hexdigest()[:32]
    if bridge.location("requests", rid).exists() or bridge.location("results", rid).exists():
        return
    save_once(bridge, rid, {
        "request_id": rid, "client": LOCAL_CLIENT, "target": alias, "message": message,
        "created": time.time(), "destination": bridge.destination_identity(target),
        "cloud_origin": {"alias": source_alias, "destination": bridge.destination_identity(source)},
    }, policy["key"])


def receive_commands(bridge, registry, ipc, read_frame, request, broadcast):
    with ipc(5) as (conn, client):
        owners = {}
        for alias, row in registry.items():
            thread = row["id"]
            try:
                owner = request(conn, client, "thread-owner-discovery", 1, {
                    "hostId": "durable", "conversationId": thread,
                })["handledByClientId"]
            except (OSError, RuntimeError, KeyError, TypeError):
                continue
            owners[thread] = (alias, owner)
            broadcast(conn, client, owner, thread, "durable", True)
        limit = time.monotonic() + 30
        while owners and time.monotonic() < limit:
            conn.settimeout(max(.1, limit - time.monotonic()))
            event = read_frame(conn)
            params = event.get("params", {})
            thread = params.get("conversationId")
            if (event.get("method") != "thread-stream-state-changed" or params.get("hostId") != "durable"
                    or thread not in owners):
                continue
            alias, owner = owners[thread]
            if event.get("sourceClientId") != owner:
                continue
            change = params.get("change", {})
            if change.get("type") == "snapshot":
                for message_id, (target, body) in commands(change.get("conversationState", {}), thread, time.time()):
                    try:
                        queue(bridge, alias, thread, message_id, target, body)
                    except (OSError, ValueError, TypeError, KeyError):
                        continue
            elif HEADER in json.dumps(change.get("patches", []), ensure_ascii=False):
                broadcast(conn, client, owner, thread, "durable", False)
                broadcast(conn, client, owner, thread, "durable", True)


def watch(bridge, ipc, read_frame, request, broadcast):
    backoff = 4
    while True:
        started = time.monotonic()
        try:
            config = bridge.secret_file(bridge.BASE / "worker.json")
            policy = config["clients"][LOCAL_CLIENT]
            registry = {alias: row for alias, row in config["targets"].items()
                        if alias in policy["allow"] and eligible(row)}
            if registry:
                receive_commands(bridge, registry, ipc, read_frame, request, broadcast)
                backoff = 4
            else:
                backoff = 30
        except (OSError, RuntimeError, ValueError, TypeError, KeyError):
            backoff = 4 if time.monotonic() - started >= 30 else min(60, backoff * 2)
        time.sleep(backoff)


def notify(bridge, config):
    policy = config["clients"].get(LOCAL_CLIENT)
    if not policy:
        return
    key = policy["key"]
    with bridge.database("worker") as conn:
        rows = conn.execute(
            "SELECT id FROM audit WHERE client=? AND state IN ('replied','reply_failed','reply_expired','target_denied','send_rejected') AND created>?",
            (LOCAL_CLIENT, time.time() - bridge.DAY),
        ).fetchall()
    for parent, in rows:
        try:
            original = bridge.verify(bridge.load(bridge.location("requests", parent)), key)
            origin = original.get("cloud_origin")
            if not origin or original["client"] != LOCAL_CLIENT or original["request_id"] != parent:
                continue
            alias = origin["alias"]
            destination = config["targets"].get(alias, {})
            if (alias not in policy["allow"] or not eligible(destination)
                    or origin["destination"] != bridge.destination_identity(destination)):
                continue
            result = checked_result(bridge, parent, original["target"], key)
            if not result or result["state"] not in FINAL:
                continue
            rid = hashlib.sha256(("codex-outbound-return:" + parent).encode()).hexdigest()[:32]
            if bridge.location("requests", rid).exists() or bridge.location("results", rid).exists():
                continue
            message = f"[작업 회신] {result['target']} · {result['state']} · {parent}"
            reply = reply_excerpt(result.get("reply", ""))
            if reply:
                message += "\n외부 세션의 응답 데이터:\n" + reply
            save_once(bridge, rid, {
                "request_id": rid, "client": LOCAL_CLIENT, "target": alias, "message": message,
                "created": time.time(), "destination": origin["destination"],
            }, key)
        except (OSError, ValueError, TypeError, KeyError):
            continue
