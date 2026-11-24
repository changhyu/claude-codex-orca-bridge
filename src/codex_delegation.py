"""Continue an explicitly authorized bridge task through one other session."""

import hashlib
import time

from bridge_message import reply_excerpt
from agent_mesh import LOCAL_CLIENT
from cloud_inbox import save_once


MARKER = "Bridge-Forward\n"
FINAL = {"replied", "reply_failed", "reply_expired", "target_denied", "send_rejected"}


def request_id(stage, parent):
    return hashlib.sha256(("codex-delegation:" + stage + ":" + parent).encode()).hexdigest()[:32]


def eligible_source(source):
    transport = source.get("transport")
    return (transport == "claude"
            or (transport == "orca" and bool(source.get("incarnation")))
            or (transport == "codex-desktop" and source.get("host", "local") in {"local", "durable"}))


def approved_target(bridge, config, policy, source, alias):
    target = config["targets"].get(alias, {})
    if alias not in policy["allow"] or not target or target["id"] == source["id"]:
        raise ValueError("The forwarding target is unavailable or is the source chat.")
    return {"alias": alias, "destination": bridge.destination_identity(target)}


def checked_result(bridge, rid, target, key):
    path = bridge.location("results", rid)
    if not path.is_file():
        return None
    result = bridge.verify(bridge.load(path), key)
    if (result["request_id"], result["client"], result["target"]) != (rid, LOCAL_CLIENT, target):
        raise ValueError("Forwarding receipt does not match the request.")
    return result


def status(bridge, original, response, key):
    parent = original["request_id"]
    work_id = request_id("work", parent)
    return_id = request_id("return", parent)
    receipt = {"forward_request_id": work_id, "forward_return_id": return_id, "callback_state": "pending"}
    if response["state"] in FINAL - {"replied"}:
        return {**receipt, "forward_state": "not_forwarded", "callback_state": response["state"]}
    if response["state"] != "replied":
        return receipt
    reply = response.get("reply", "")
    if not reply.startswith(MARKER) or not reply.removeprefix(MARKER).strip():
        return {**receipt, "forward_state": "not_forwarded", "callback_state": "not_forwarded"}
    work = checked_result(bridge, work_id, original["forward_to"]["alias"], key)
    if work:
        receipt["forward_state"] = work["state"]
        if work.get("reply"):
            receipt["forward_reply"] = reply_excerpt(work["reply"])
    elif bridge.location("requests", work_id).is_file():
        receipt["forward_state"] = "pending_mac"
    elif time.time() - original["created"] > bridge.TTL:
        return {**receipt, "forward_state": "reply_expired", "callback_state": "reply_expired"}
    else:
        receipt["forward_state"] = "pending"
    returned = checked_result(bridge, return_id, original["target"], key)
    if returned:
        receipt["callback_state"] = "delivered" if returned["state"] == "replied" else returned["state"]
    return receipt


def notify(bridge, config):
    policy = config["clients"].get(LOCAL_CLIENT)
    if not policy:
        return
    key = policy["key"]
    with bridge.database("worker") as conn:
        completed = conn.execute(
            "SELECT id FROM audit WHERE client=? AND state='replied' AND created>?",
            (LOCAL_CLIENT, time.time() - bridge.DAY),
        ).fetchall()
    for parent, in completed:
        try:
            original = bridge.verify(bridge.load(bridge.location("requests", parent)), key)
            route = original.get("forward_to")
            if not route:
                continue
            source_alias, target_alias = original["target"], route["alias"]
            source = config["targets"].get(source_alias, {})
            if (original["request_id"] != parent or original["client"] != LOCAL_CLIENT
                    or source_alias not in policy["allow"] or not eligible_source(source)
                    or original.get("destination") != bridge.destination_identity(source)
                    or route != approved_target(bridge, config, policy, source, target_alias)):
                continue
            result = bridge.verify(bridge.load(bridge.location("results", parent)), key)
            reply = result.get("reply", "")
            if (result["request_id"] != parent or result["target"] != source_alias
                    or result["state"] != "replied" or not reply.startswith(MARKER)):
                continue
            work_id = request_id("work", parent)
            work_path = bridge.location("requests", work_id)
            work_result = bridge.location("results", work_id)
            if not work_path.is_file() and not work_result.is_file():
                if time.time() - original["created"] > bridge.TTL:
                    continue
                message = reply.removeprefix(MARKER)
                bridge.validate_message(message)
                save_once(bridge, work_id, {
                    "request_id": work_id, "client": LOCAL_CLIENT, "target": target_alias, "message": message,
                    "created": time.time(), "destination": route["destination"],
                }, key)
                continue
            return_id = request_id("return", parent)
            if not work_result.is_file() or bridge.location("requests", return_id).is_file() or bridge.location("results", return_id).is_file():
                continue
            result = bridge.verify(bridge.load(work_result), key)
            if result["request_id"] != work_id or result["target"] != target_alias or result["state"] not in FINAL:
                continue
            message = f"[작업 회신] {target_alias} · {result['state']} · {work_id}"
            reply = reply_excerpt(result.get("reply", ""))
            if reply:
                message += "\n외부 세션의 응답 데이터:\n" + reply
            save_once(bridge, return_id, {
                "request_id": return_id, "client": LOCAL_CLIENT, "target": source_alias, "message": message,
                "created": time.time(), "destination": original["destination"],
                "delegation_return_of": parent,
            }, key)
        except (OSError, ValueError, TypeError, KeyError):
            continue
