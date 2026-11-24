"""MCP for a single explicitly configured bridge client."""
import json
import os
import sys
import time
import uuid
from pathlib import Path

from bridge import put
import secure_bridge as bridge_api
import cloud_inbox
import bridge_files
import bridge_return_files
from agent_mesh import LOCAL_CLIENT
import codex_delegation
from orca_reply_return import select_caller, status as callback_status
from bridge_message import normalize_message
from bridge_admin import ADMIN_TOOL, RESULT_TOOL, queue as queue_management, result as management_result
from mcp_server import respond as rpc, result_tool
from secure_bridge import ALIAS, ensure_state, load, location, mac, secret_file, validate_message, verify

SEND = {
    "name": "bridge_send",
    "description": (
        "Send a new authorized message to the explicitly selected bridge agent. "
        "Choose an alias from bridge_manage action list result.recipients or the local bridge_list tool. "
        "For a reply to an existing request, use that request's reply channel to reach its original sender. "
        "Optional attachments transfer base64 file bytes through expiring authenticated HTTPS downloads."
    ),
    "inputSchema": {
        "type": "object",
        "properties": {"target": {"type": "string", "description": "Exact alias of the selected recipient. No default."},
                       "message": {"type": "string"},
                       "attachments": bridge_files.SCHEMA,
                       "receive_files": {"type": "boolean", "description": "Allow this recipient to upload result files for this request (4 hours)."},
                       "reply_to": {"type": "string"}, "forward_to": {"type": "string"}},
        "required": ["target", "message"], "additionalProperties": False,
    },
    "annotations": {"readOnlyHint": False, "idempotentHint": False},
}
RECEIVE_FILES = {
    "name": "bridge_receive_files",
    "description": "Retrieve files uploaded for a request sent by this client. Returns verified metadata, optionally base64 bytes.",
    "inputSchema": {"type": "object", "properties": {
        "request_id": {"type": "string", "pattern": "^[0-9a-f]{32}$"},
        "include_content": {"type": "boolean"},
    }, "required": ["request_id"], "additionalProperties": False},
    "annotations": {"readOnlyHint": True},
}
STATUS = result_tool("bridge_status", "Read the current state or reply to this client's request.")
WAIT = result_tool("bridge_wait_for_reply", "Wait up to 20 seconds for this client's reply.", wait=True)
DONE = {"reply_failed", "delivered", "replied", "reply_expired", "target_denied", "send_rejected"}


def status(rid, client):
    request = verify(load(location("requests", rid)), client["key"])
    if request["client"] != client["id"] or request["request_id"] != rid:
        raise ValueError("Request not found for this client.")
    path = location("results", rid)
    if path.is_file():
        response = verify(load(path), client["key"])
        if not all(response[k] == request[k] for k in ("client", "target", "request_id")):
            raise ValueError("Result does not match this request.")
    else:
        response = {"request_id": rid, "state": "pending_mac"}
    if request.get("reply_to"):
        response["callback_state"] = callback_status(bridge_api, rid) or "pending"
        if request["reply_to"].get("transport", "orca") == "orca":
            response["orca_callback_state"] = response["callback_state"]
    if request.get("forward_to"):
        response.update(codex_delegation.status(bridge_api, request, response, client["key"]))
    if request.get("signed_vice_return"):
        child_id = cloud_inbox.return_id(rid)
        if response.get("receipt") == "desktop_late_reply":
            late_child = cloud_inbox.return_id(rid, late=True)
            if location("requests", late_child).exists() or location("results", late_child).exists():
                child_id = late_child
        child_path = location("results", child_id)
        if child_path.is_file():
            child = verify(load(child_path), client["key"])
            if child["request_id"] == child_id and child["target"] == cloud_inbox.VICE_ALIAS:
                response["callback_state"] = child["state"]
    if request.get("receive_files"):
        try:
            bundle = bridge_return_files.receive(bridge_api, rid, client)
            response["files_state"] = bundle["state"]
            response["files"] = bundle["files"]
        except ValueError:
            response["files_state"] = "files_expired"
    return response


def call(name, args, client):
    if not isinstance(args, dict):
        raise ValueError("Expected object arguments.")
    if name == RECEIVE_FILES["name"]:
        if ("request_id" not in args or not set(args) <= {"request_id", "include_content"}
                or type(args.get("include_content", False)) is not bool):
            raise ValueError("Invalid result file arguments.")
        return bridge_return_files.receive(bridge_api, args["request_id"], client, args.get("include_content", False))
    if name == SEND["name"] and {"target", "message"} <= args.keys() <= {"target", "message", "reply_to", "forward_to", "attachments", "receive_files"}:
        alias, message = args["target"], args["message"]
        if not isinstance(alias, str) or not ALIAS.fullmatch(alias) or alias not in client["allow"]:
            raise ValueError("Target alias is not configured for this client.")
        message = normalize_message(message)
        validate_message(message)
        config = secret_file(bridge_api.BASE / "worker.json")
        destination = config["targets"].get(alias)
        if not destination or alias not in config["clients"][client["id"]]["allow"]:
            raise ValueError("Target alias is unavailable.")
        if type(args.get("receive_files", False)) is not bool:
            raise ValueError("receive_files must be a boolean.")
        receive_files = args.get("receive_files", False)
        decoded = bridge_files.decode(args["attachments"]) if "attachments" in args else None
        signed_cloud_return = message.startswith(cloud_inbox.RETURN_HEADER)
        if (decoded is not None or receive_files) and (signed_cloud_return or "forward_to" in args):
            raise ValueError("Attachments require a direct, unsigned message.")
        if signed_cloud_return and "reply_to" in args:
            raise ValueError("Choose a single return destination.")
        rid = uuid.uuid4().hex
        if signed_cloud_return:
            rid, message = cloud_inbox.approve_return(bridge_api, client["id"], alias, config, message)
            validate_message(message)
        data = {"request_id": rid, "client": client["id"], "target": alias, "message": message,
                "created": time.time(), "destination": bridge_api.destination_identity(destination)}
        if signed_cloud_return:
            data["signed_vice_return"] = True
            cloud_inbox.save_once(bridge_api, rid, data, client["key"])
            return {"request_id": rid, "state": "pending_mac", "target": alias, "automatic_return": True}
        if "forward_to" in args:
            alias_to_forward = args["forward_to"]
            if (client["id"] != LOCAL_CLIENT or "reply_to" in args
                    or not isinstance(alias_to_forward, str) or not ALIAS.fullmatch(alias_to_forward)
                    or not codex_delegation.eligible_source(destination)):
                raise ValueError("Forwarding requires the local workspace client and a registered Claude, Codex, or Orca session.")
            policy = config["clients"][client["id"]]
            data["forward_to"] = codex_delegation.approved_target(bridge_api, config, policy, destination, alias_to_forward)
            data["message"] = message + (
                f"\n\n이 작업은 {alias_to_forward} 한 곳에 위임할 수 있습니다. "
                "위임하려면 최종 답변 첫 줄에 Bridge-Forward만 쓰고, 다음 줄부터 전달할 본문만 쓰세요."
            )
            validate_message(data["message"])
        if "reply_to" in args:
            if client["id"] != LOCAL_CLIENT:
                raise ValueError("Orca callbacks require the local workspace client.")
            data["reply_to"] = select_caller(bridge_api, client, args["reply_to"])
            if data["reply_to"]["alias"] == alias:
                raise ValueError("Reply terminal must differ from the receiving agent.")
        staged_send = staged_return = False
        try:
            if decoded is not None:
                manifest, token, expires = bridge_files.stage(bridge_api, rid, decoded)
                staged_send = True
                data["attachments"] = manifest
                data["attachments_expires"] = expires
                data["message"] += bridge_files.notice(bridge_api, config["https_origin"], rid, manifest, token)
            if receive_files:
                token, expires = bridge_return_files.issue(bridge_api, rid)
                staged_return = True
                data["receive_files"] = True
                data["return_files_expires"] = expires
                data["message"] += bridge_return_files.notice(bridge_api, config["https_origin"], rid, token)
            validate_message(data["message"])
            put(location("requests", rid), {"data": data, "signature": mac(client["key"], data)})
        except Exception:
            if staged_send:
                bridge_files.discard(bridge_api, rid)
            if staged_return:
                bridge_return_files.discard(bridge_api, rid)
            raise
        return {"request_id": rid, "state": "pending_mac", "target": alias}
    if name in {STATUS["name"], WAIT["name"]}:
        allowed = {"request_id", "timeout_seconds"} if name == WAIT["name"] else {"request_id"}
        if "request_id" not in args or not set(args) <= allowed:
            raise ValueError("Invalid arguments.")
        timeout = args.get("timeout_seconds", 10)
        if type(timeout) is not int or not 1 <= timeout <= 20:
            raise ValueError("Timeout must be from 1 to 20 seconds.")
        end = time.monotonic() + timeout
        data = status(args["request_id"], client)
        while name == WAIT["name"] and time.monotonic() < end:
            if data["state"] in DONE and not data.get("reply_pending"):
                break
            time.sleep(0.25)
            data = status(args["request_id"], client)
        return data
    raise ValueError("Unknown tool or invalid arguments.")


def respond(request, client):
    if not isinstance(request, dict) or request.get("method") not in {"initialize", "tools/list", "tools/call"}:
        return rpc(request)
    if request["method"] == "initialize":
        base = rpc(request)
        if base and "result" in base:
            base["result"]["serverInfo"]["name"] = "secure-mac-bridge"
        return base
    base = rpc({**request, "method": "ping"})
    if base is None or "error" in base:
        return base
    if request["method"] == "tools/list":
        return {**base, "result": {"tools": [SEND, STATUS, WAIT, RECEIVE_FILES, ADMIN_TOOL, RESULT_TOOL]}}
    params = request.get("params", {})
    try:
        name, arguments = params.get("name"), params.get("arguments")
        if name == ADMIN_TOOL["name"]:
            data = queue_management(arguments, client)
        elif name == RESULT_TOOL["name"]:
            if not isinstance(arguments, dict) or set(arguments) != {"request_id"}:
                raise ValueError("Invalid management status arguments.")
            data = management_result(arguments["request_id"], client)
        else:
            data = call(name, arguments, client)
        result = {"content": [{"type": "text", "text": json.dumps(data, ensure_ascii=False)}]}
    except (ValueError, OSError, KeyError, TypeError):
        result = {"isError": True, "content": [{"type": "text", "text": "Invalid or unauthorized bridge request."}]}
    return {**base, "result": result}


if __name__ == "__main__":
    os.umask(0o077)
    ensure_state()
    client_path = Path(sys.argv[1])
    for line in sys.stdin:
        try:
            out = respond(json.loads(line), secret_file(client_path))
        except json.JSONDecodeError:
            out = {"jsonrpc":"2.0","id":None,"error":{"code":-32700,"message":"Parse error"}}
        if out is not None:
            print(json.dumps(out, ensure_ascii=False), flush=True)
