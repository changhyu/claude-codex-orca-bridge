#!/usr/bin/env python3
"""Stdio MCP server for Claude Code cloud follow-ups."""
import json
import os
import re
import sys
import time

from bridge import LIMIT, enqueue, status
from urllib.parse import urlsplit

SESSION_ID = re.compile(r"(?:session|cse)_[A-Za-z0-9]{1,128}")
TOOL = {
    "name": "claude_cloud_send",
    "description": "Queue a message for the Mac worker to send to an existing Claude Code cloud session.",
    "inputSchema": {
        "type": "object",
        "properties": {
            "session": {"type": "string", "description": "Claude Code cloud session ID or claude.ai/code session URL"},
            "message": {"type": "string", "minLength": 1, "maxLength": LIMIT},
        },
        "required": ["session", "message"],
        "additionalProperties": False,
    },
    "annotations": {"readOnlyHint": False, "idempotentHint": False, "openWorldHint": True},
}


def session_id(value):
    if not isinstance(value, str) or len(value) > 4096:
        raise ValueError("Provide a Claude Code cloud session ID or URL.")
    value = value.strip()
    if value.startswith("claude.ai/"):
        value = "https://" + value
    if value.startswith("https://"):
        url = urlsplit(value)
        if url.netloc != "claude.ai" or not url.path.startswith("/code/"):
            raise ValueError("Use a https://claude.ai/code/ session URL.")
        value = url.path.removeprefix("/code/").rstrip("/")
    if not SESSION_ID.fullmatch(value):
        raise ValueError("Expected a session_… or cse_… cloud session ID.")
    return value


def send(arguments):
    if not isinstance(arguments, dict) or set(arguments) != {"session", "message"}:
        raise ValueError("Provide exactly session and message.")
    message = arguments["message"]
    if not isinstance(message, str) or not message.strip() or len(message) > LIMIT:
        raise ValueError("Provide a nonblank message of up to 24,000 characters.")
    return enqueue(session_id(arguments["session"]), message)


def result_tool(name, description, wait=False):
    properties = {"request_id": {"type": "string", "pattern": "^[0-9a-f]{32}$"}}
    if wait:
        properties["timeout_seconds"] = {"type": "integer", "minimum": 1, "maximum": 20}
    return {
        "name": name, "description": description,
        "inputSchema": {"type": "object", "properties": properties,
                        "required": ["request_id"], "additionalProperties": False},
        "annotations": {"readOnlyHint": True},
    }


STATUS = result_tool("claude_cloud_status", "Read the send or reply status for a request.")
WAIT = result_tool("claude_cloud_wait_for_reply", "Wait briefly for the same request to receive a reply.", wait=True)
TERMINAL = {"replied", "send_rejected", "reply_expired"}


def call(params):
    arguments = params.get("arguments")
    name = params["name"]
    if not isinstance(arguments, dict):
        raise ValueError("Expected object arguments.")
    if name == TOOL["name"]:
        return send(arguments)
    allowed = {"request_id", "timeout_seconds"} if name == WAIT["name"] else {"request_id"}
    if not set(arguments) <= allowed:
        raise ValueError("Unexpected arguments.")
    timeout = arguments.get("timeout_seconds", 10)
    if type(timeout) is not int or not 1 <= timeout <= 20:
        raise ValueError("timeout_seconds must be an integer from 1 to 20.")
    result = status(arguments.get("request_id"))
    if name == WAIT["name"]:
        deadline = time.monotonic() + timeout
        while result["state"] not in TERMINAL and time.monotonic() < deadline:
            time.sleep(min(0.25, max(0, deadline - time.monotonic())))
            result = status(arguments["request_id"])
    return result


def respond(request):
    if not isinstance(request, dict) or request.get("jsonrpc") != "2.0" or not isinstance(request.get("method"), str):
        return {"jsonrpc": "2.0", "id": None, "error": {"code": -32600, "message": "Invalid request"}}
    if "id" not in request:
        return None
    response = {"jsonrpc": "2.0", "id": request["id"]}
    method = request["method"]
    params = request.get("params", {})
    if not isinstance(params, dict):
        return {**response, "error": {"code": -32602, "message": "Expected object params"}}
    if method == "initialize":
        version = params.get("protocolVersion")
        if version not in ("2024-11-05", "2025-03-26", "2025-06-18", "2025-11-25"):
            version = "2025-11-25"
        result = {
            "protocolVersion": version,
            "capabilities": {"tools": {}},
            "serverInfo": {"name": "claude-cloud-mcp", "version": "1.0.0"},
        }
    elif method == "ping":
        result = {}
    elif method == "tools/list":
        result = {"tools": [TOOL, STATUS, WAIT]}
    elif method == "tools/call" and params.get("name") in (TOOL["name"], STATUS["name"], WAIT["name"]):
        try:
            payload = call(params)
            result = {"content": [{"type": "text", "text": json.dumps(payload)}]}
        except (ValueError, OSError) as exc:
            message = str(exc) if type(exc) is ValueError else "The shared queue could not be read or written."
            result = {"isError": True, "content": [{"type": "text", "text": message}]}
    else:
        return {**response, "error": {"code": -32602 if method == "tools/call" else -32601, "message": "Unknown tool or method"}}
    return {**response, "result": result}


def main():
    os.umask(0o077)
    for line in sys.stdin:
        try:
            response = respond(json.loads(line))
        except json.JSONDecodeError:
            response = {"jsonrpc": "2.0", "id": None, "error": {"code": -32700, "message": "Parse error"}}
        if response is not None:
            print(json.dumps(response), flush=True)


if __name__ == "__main__":
    main()
