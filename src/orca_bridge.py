"""Local Orca worker and request-scoped reply helper."""
import argparse
import fcntl
import hmac
import json
import os
import secrets
import subprocess
import sys
import time
import uuid
from pathlib import Path

import shlex
from bridge import LIMIT, REQUEST_ID, put, read
from bridge_settings import ORCA_CLI

ROOT = Path(os.environ.get("ORCA_BRIDGE_QUEUE", "/tmp/codex-claude-bridge/orca-queue"))
ORCA = Path(ORCA_CLI)
# Only admit agent identities that Orca reports for supported agent CLIs.
AGENTS = {
    "agy", "antigravity", "claude", "claude-code", "codex", "devin",
    "gemini", "grok", "omp", "opencode", "pi",
}
TTL = 900


def file(bucket, request_id):
    if not isinstance(request_id, str) or not REQUEST_ID.fullmatch(request_id):
        raise ValueError("Invalid request ID.")
    return ROOT / bucket / (request_id + ".json")


def queue(handle, message):
    if not isinstance(handle, str) or not handle.strip() or len(handle) > 512 or any(ord(c) < 33 for c in handle):
        raise ValueError("Invalid Orca terminal handle.")
    if not isinstance(message, str) or not message.strip() or len(message.encode()) > LIMIT:
        raise ValueError("Invalid message.")
    request_id = uuid.uuid4().hex
    put(file("requests", request_id), {"handle": handle, "message": message})
    return {"request_id": request_id, "state": "pending_mac"}


def result(request_id):
    path = file("results", request_id)
    if file("replies", request_id).is_file():
        return {"request_id": request_id, "state": "replied", "reply": read(file("replies", request_id))["reply"]}
    if path.is_file():
        receipt = read(path)
        if receipt.get("expires", float("inf")) <= time.time():
            return {"request_id": request_id, "state": "reply_expired"}
        return {"request_id": request_id, "state": receipt["state"]}
    if file("requests", request_id).is_file():
        return {"request_id": request_id, "state": "pending_mac"}
    raise ValueError("Request not found.")


def invoke(*args):
    return invoke_on("local", "terminal", *args)


def invoke_on(environment, *args, timeout=18):
    selector = ["--environment", environment] if environment is not None else []
    process = subprocess.run([str(ORCA), *args, *selector, "--json"],
                             capture_output=True, text=True, timeout=timeout)
    try:
        response = json.loads(process.stdout)
    except ValueError:
        raise RuntimeError("Orca returned no valid receipt.") from None
    if process.returncode != 0 or response.get("ok") is not True:
        code = response.get("error", {}).get("code", "unknown")
        raise RuntimeError(f"Orca command failed ({code}).")
    return response["result"]


def terminals(worktree):
    args = ("list", "--worktree", worktree) if worktree else ("list",)
    try:
        return invoke(*args)["terminals"]
    except RuntimeError as exc:
        if worktree in {"active", "current"} and str(exc) == "Orca command failed (selector_not_found).":
            return invoke("list")["terminals"]
        raise


def is_agent(terminal):
    return terminal.get("agentIdentity") in AGENTS


def describe_terminal(terminal):
    worktree = terminal.get("worktree")
    worktree = worktree if isinstance(worktree, dict) else {}
    workspace = terminal.get("workspace")
    workspace = workspace if isinstance(workspace, dict) else {}
    entry = {
        "name": terminal.get("paneTitle") or terminal.get("title") or terminal.get("tabTitle") or terminal.get("name"),
        "agent": terminal.get("agentIdentity"),
        "handle": terminal["handle"],
    }
    context = {
        "tab": terminal.get("tabTitle"),
        "worktree": terminal.get("worktreeName") or worktree.get("name") or worktree.get("displayName") or workspace.get("name"),
        "branch": terminal.get("branch") or worktree.get("branch"),
        "path": terminal.get("worktreePath") or worktree.get("path") or terminal.get("cwd"),
    }
    entry.update({key: value for key, value in context.items() if isinstance(value, str) and value.strip()})
    return entry


def ticket(request_id, token):
    data = read(file("tickets", request_id))
    if data["expires"] <= time.time() or not hmac.compare_digest(data["token"], token):
        raise ValueError("Invalid or expired reply ticket.")
    return data


def reply(request_id, token, payload):
    ticket(request_id, token)
    if not payload.strip() or len(payload.encode()) > LIMIT:
        raise ValueError("Reply must contain 1–24000 UTF-8 bytes.")
    destination = file("replies", request_id)
    destination.parent.mkdir(mode=0o700, parents=True, exist_ok=True)
    temporary = destination.with_name("." + uuid.uuid4().hex)
    try:
        put(temporary, {"reply": payload})
        os.link(temporary, destination)
    except FileExistsError:
        raise ValueError("Reply already received.") from None
    finally:
        temporary.unlink(missing_ok=True)


def step(worktree, allowed):
    for path in sorted((ROOT / "requests").glob("*.json")):
        request_id = path.stem
        if not REQUEST_ID.fullmatch(request_id):
            continue
        destination = file("results", request_id)
        if destination.exists():
            receipt = read(destination)
            if receipt["state"] == "sending":
                put(destination, {**receipt, "state": "delivery_unknown"})
            continue
        try:
            handle = read(path)["handle"]
        except (OSError, ValueError, KeyError, TypeError):
            put(destination, {"state": "target_denied"})
            continue
        if not isinstance(handle, str) or handle not in allowed:
            put(destination, {"state": "target_denied"})
            continue
        try:
            targets = terminals(worktree)
        except (RuntimeError, OSError, subprocess.TimeoutExpired):
            continue
        if not any(target.get("handle") == handle and is_agent(target) for target in targets):
            put(destination, {"state": "target_denied"})
            continue
        token = secrets.token_hex(24)
        expiry = time.time() + TTL
        put(file("tickets", request_id), {"token": token, "expires": expiry})
        receipt = {"state": "sending", "expires": expiry}
        put(destination, receipt)
        helper = shlex.quote(str(Path(__file__).resolve()))
        # Keep the terminal input to one line with a shell-inert character set.
        prompt = (
            f"CODEX-ORCA-{request_id} is a Codex bridge request. Read the user message using python3 {helper} read {request_id} {token} . "
            f"After answering post only the final answer through standard input to python3 {helper} reply {request_id} {token} ."
        )
        try:
            invoke("send", "--terminal", handle, "--text", prompt, "--enter", "--wait-submit", "8")
        except (RuntimeError, OSError, subprocess.TimeoutExpired):
            state = "delivery_unknown"
        else:
            state = "input_accepted"
        put(destination, {**receipt, "state": state})


def main():
    os.umask(0o077)
    parser = argparse.ArgumentParser()
    commands = parser.add_subparsers(dest="command", required=True)
    listing = commands.add_parser("list")
    listing.add_argument("--worktree", help="Optional Orca worktree selector")
    worker = commands.add_parser("worker")
    worker.add_argument("--worktree", help="Optional Orca worktree selector")
    worker.add_argument("--allow", action="append", required=True)
    for name in ("read", "reply"):
        command = commands.add_parser(name)
        command.add_argument("id")
        command.add_argument("token")
    args = parser.parse_args()
    try:
        if args.command == "list":
            print(json.dumps([describe_terminal(t) for t in terminals(args.worktree) if is_agent(t)],
                             ensure_ascii=False, indent=2))
        elif args.command == "read":
            ticket(args.id, args.token)
            print(read(file("requests", args.id))["message"])
        elif args.command == "reply":
            reply(args.id, args.token, sys.stdin.read(LIMIT + 1))
        else:
            initial = {t["handle"] for t in terminals(args.worktree) if is_agent(t)}
            allowed = set(args.allow)
            if not allowed <= initial:
                raise ValueError("An allowed handle is absent or not a recognized agent.")
            ROOT.mkdir(mode=0o700, parents=True, exist_ok=True)
            with (ROOT / "worker.lock").open("a") as lock:
                fcntl.flock(lock, fcntl.LOCK_EX | fcntl.LOCK_NB)
                print("Orca worker ready", flush=True)
                while True:
                    step(args.worktree, allowed)
                    time.sleep(2)
    except (ValueError, OSError, RuntimeError, subprocess.TimeoutExpired) as exc:
        raise SystemExit(str(exc)) from None


if __name__ == "__main__":
    main()
