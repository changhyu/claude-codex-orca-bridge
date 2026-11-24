"""Common list, send, and status MCP for local workspace agents."""

import json
import os
import re
from pathlib import Path
import subprocess
import sys

from agent_mesh import LOCAL_CLIENT, PROJECT, directory
from secure_bridge import BASE, ensure_state, refresh_agents, secret_file
from secure_mcp import SEND, STATUS, WAIT, RECEIVE_FILES, respond


ORCA_ALIAS = re.compile(r"orca-[0-9a-f-]{1,54}")
ORCA_HANDLE = re.compile(r"term_[0-9a-fA-F-]{1,54}")

LIST = {
    "name": "bridge_list",
    "description": "List allowed workspace agent destinations and their bridge aliases.",
    "inputSchema": {"type": "object", "additionalProperties": False},
    "annotations": {"readOnlyHint": True},
}


def handle(request, client):
    response = {"jsonrpc": "2.0", "id": request.get("id")}
    if request.get("method") == "tools/list":
        return {**response, "result": {"tools": [LIST, SEND, STATUS, WAIT, RECEIVE_FILES]}}
    if request.get("method") != "tools/call":
        return respond(request, client)
    name = request.get("params", {}).get("name")
    if name == LIST["name"]:
        config = secret_file(BASE / "worker.json")
        allowed = set(client["allow"]) & set(config["clients"][LOCAL_CLIENT]["allow"])
        targets = directory(config, allowed, include_host=True)
        return {**response, "result": {"content": [{"type": "text", "text": json.dumps(targets)}]}}
    if name == SEND["name"]:
        arguments = request["params"].get("arguments")
        if isinstance(arguments, dict):
            target = arguments.get("target")
            caller = arguments.get("reply_to")
            aliases = set()
            if isinstance(target, str) and ORCA_ALIAS.fullmatch(target):
                aliases.add(target)
            if isinstance(caller, str) and ORCA_HANDLE.fullmatch(caller):
                aliases.add("orca-" + caller.removeprefix("term_").lower())
            if aliases.difference(client["allow"]):
                try:
                    refresh_agents(BASE / "worker.json")
                    client = secret_file(BASE / "agent-client.json")
                except (OSError, ValueError, RuntimeError, subprocess.SubprocessError):
                    pass
        return respond(request, client)
    if name in {STATUS["name"], WAIT["name"], RECEIVE_FILES["name"]}:
        return respond(request, client)
    return {**response, "error": {"code": -32602, "message": "Unsupported messaging tool."}}


def main():
    os.umask(0o077)
    common = ["git", "rev-parse", "--path-format=absolute", "--git-common-dir"]
    expected = subprocess.run(common, cwd=PROJECT, capture_output=True, text=True, timeout=5)
    current = subprocess.run(common, cwd=Path.cwd(), capture_output=True, text=True, timeout=5)
    if expected.returncode or current.returncode or expected.stdout.strip() != current.stdout.strip():
        return
    ensure_state()
    for line in sys.stdin:
        try:
            result = handle(json.loads(line), secret_file(BASE / "agent-client.json"))
        except (ValueError, OSError, KeyError, TypeError, AttributeError):
            result = {"jsonrpc": "2.0", "id": None, "error": {"code": -32600, "message": "Invalid bridge request."}}
        if result is not None:
            print(json.dumps(result, ensure_ascii=False), flush=True)


if __name__ == "__main__":
    main()
