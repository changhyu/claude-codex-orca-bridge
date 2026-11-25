"""Remote MCP transport for the approved Claude-to-Codex/Orca bridge connector."""

import json
import uuid

import claude_peer
from agent_mesh import queue_claude_dispatch
from bridge_message import CONNECTOR_FORWARD, normalize_message
from bridge_settings import CLAUDE_MCP_PATH, CLAUDE_PEER_ALIAS
from cloud_roster import CONNECTOR_CLIENT


PATH = CLAUDE_MCP_PATH
HEADER = "x-api-key"
TOOLS = [
    {
        "name": "send_to_codex_peer",
        "description": "Send one authorized message to the registered Codex Cloud peer.",
        "inputSchema": {
            "type": "object", "properties": {
                "message": {"type": "string"},
                "nonce": {"type": "string", "pattern": "^[0-9a-f]{32}$",
                          "description": "Optional idempotency key. Reuse it if retrying the same send."},
                "return_to_sender": {"type": "boolean",
                                     "description": "Return the outcome to the registered Claude peer chat."},
            }, "required": ["message"], "additionalProperties": False,
        },
        "annotations": {"readOnlyHint": False, "destructiveHint": False, "openWorldHint": False},
    },
    {
        "name": "codex_peer_delivery_status",
        "description": "Check delivery of a message previously sent through this connector.",
        "inputSchema": {
            "type": "object", "properties": {"request_id": {"type": "string"}},
            "required": ["request_id"], "additionalProperties": False,
        },
        "annotations": {"readOnlyHint": True, "openWorldHint": False},
    },
    {
        "name": "list_agents",
        "description": "List the sendable aliases confirmed in the published agent roster.",
        "inputSchema": {"type": "object", "additionalProperties": False},
        "annotations": {"readOnlyHint": True, "openWorldHint": False},
    },
    {
        "name": "send_to_agent",
        "description": (
            "Send one authorized message to an alias returned by list_agents. "
            "Plain message body is delivered by default to Claude sessions; "
            f"start the message with Bridge-Reply-To: {CLAUDE_PEER_ALIAS} on its own line "
            "to post the result to the registered Claude peer chat, "
            "or pass no_reply: true for one-way notifications."
        ),
        "inputSchema": {
            "type": "object", "properties": {
                "target": {"type": "string"}, "message": {"type": "string"},
                "nonce": {"type": "string", "pattern": "^[0-9a-f]{32}$"},
                "no_reply": {"type": "boolean", "description": "Deliver plain body without allocating a reply lease."},
                "expect_reply": {"type": "boolean", "description": "Attach the compact reply callback envelope when targeting a Claude session."},
            }, "required": ["target", "message"], "additionalProperties": False,
        },
        "annotations": {"readOnlyHint": False, "destructiveHint": False, "openWorldHint": False},
    },
]


def directory(bridge):
    config = bridge.secret_file(bridge.BASE / "worker.json")
    names = config.get("claude_connector_roster_names", {})
    return [{"alias": alias, "transport": destination["transport"],
             **({"display_name": title} if (title := names.get(alias) or destination.get("display_name")) else {})}
            for alias, destination in sorted(config["targets"].items())
            if alias in config["clients"][CONNECTOR_CLIENT]["allow"]]


def handle(bridge, bearer, raw):
    with claude_peer.database(bridge) as conn:
        claude_peer.authenticate(bridge, conn, bearer)
    request = json.loads(raw)
    if not isinstance(request, dict) or request.get("jsonrpc") != "2.0":
        raise ValueError("Invalid MCP request.")
    response = {"jsonrpc": "2.0", "id": request.get("id")}
    method = request.get("method", "")
    params = request.get("params", {})
    if not isinstance(params, dict):
        raise ValueError("Invalid MCP parameters.")
    if isinstance(method, str) and method.startswith("notifications/") and "id" not in request:
        return 202, None
    if method == "initialize":
        version = params.get("protocolVersion")
        result = {
            "protocolVersion": version if version in {"2025-06-18", "2025-11-25"} else "2025-11-25",
            "capabilities": {"tools": {}},
            "serverInfo": {"name": "claude-codex-bridge", "version": "1.0.0"},
        }
    elif method == "tools/list":
        result = {"tools": TOOLS}
    elif method == "tools/call":
        args = params.get("arguments", {})
        if not isinstance(args, dict):
            raise ValueError("Invalid MCP tool arguments.")
        try:
            if params.get("name") == "send_to_codex_peer":
                data = claude_peer.send(bridge, bearer, {"nonce": uuid.uuid4().hex, **args})
            elif params.get("name") == "codex_peer_delivery_status":
                data = claude_peer.status(bridge, bearer, args)
            elif params.get("name") == "list_agents":
                if args:
                    raise ValueError("list_agents accepts no arguments.")
                data = {"agents": directory(bridge)}
            elif params.get("name") == "send_to_agent":
                if not {"target", "message"} <= set(args) <= {"target", "message", "nonce", "no_reply", "expect_reply"}:
                    raise ValueError("Invalid send_to_agent arguments.")
                for flag in ("no_reply", "expect_reply"):
                    if type(args.get(flag, False)) is not bool:
                        raise ValueError(f"{flag} must be a boolean.")
                no_reply = args.get("no_reply", False)
                expect_reply = args.get("expect_reply", False)
                if no_reply and expect_reply:
                    raise ValueError("no_reply and expect_reply cannot both be true.")
                text = args["message"]
                forwarded = CONNECTOR_FORWARD.match(text) if isinstance(text, str) else None
                if forwarded:
                    if "nonce" in args or no_reply:
                        raise ValueError("Do not combine nonce or no_reply with Bridge-Forward.")
                    request_id = queue_claude_dispatch(
                        bridge, forwarded[1], forwarded[2],
                        {"target": args["target"], "message": normalize_message(text[forwarded.end():])},
                        via_connector=True,
                    )
                    data = {"state": "queued", "request_id": request_id}
                else:
                    data = claude_peer.queue_message(
                        bridge, bearer, args.get("nonce", uuid.uuid4().hex),
                        text, args["target"], roster=True, no_reply=no_reply, expect_reply=expect_reply,
                    )
            else:
                raise ValueError("Unknown MCP tool.")
            result = {"content": [{"type": "text", "text": json.dumps(data, ensure_ascii=False)}],
                      "structuredContent": data}
        except (PermissionError, ValueError, BlockingIOError) as exc:
            result = {"isError": True, "content": [{"type": "text", "text": str(exc)}]}
    else:
        return 200, {**response, "error": {"code": -32601, "message": "Method not found."}}
    return 200, {**response, "result": result}
