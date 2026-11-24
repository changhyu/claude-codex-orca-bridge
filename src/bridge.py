"""Filesystem request queue and the Mac worker."""
import argparse
import fcntl
import json
import os
import re
import subprocess
import time
import uuid
from pathlib import Path
from urllib.parse import urlsplit
from urllib.request import HTTPRedirectHandler, Request, build_opener

ROOT = Path(os.environ.get("CLAUDE_BRIDGE_QUEUE", Path(__file__).resolve().parent / "queue"))
REQUEST_ID = re.compile(r"[0-9a-f]{32}")
LIMIT = 24_000


def put(path, data):
    path.parent.mkdir(mode=0o700, parents=True, exist_ok=True)
    temporary = path.with_name("." + uuid.uuid4().hex)
    try:
        with temporary.open("x", encoding="utf-8") as stream:
            json.dump(data, stream, ensure_ascii=False)
            stream.flush()
            os.fsync(stream.fileno())
        temporary.replace(path)
    finally:
        temporary.unlink(missing_ok=True)


def read(path):
    return json.loads(path.read_text(encoding="utf-8"))


def enqueue(session, message):
    request_id = uuid.uuid4().hex
    put(ROOT / "requests" / (request_id + ".json"), {
        "request_id": request_id, "session_id": session, "message": message,
    })
    return {"request_id": request_id, "state": "pending_mac"}


def status(request_id):
    if not isinstance(request_id, str) or not REQUEST_ID.fullmatch(request_id):
        raise ValueError("Invalid request ID.")
    filename = request_id + ".json"
    if (ROOT / "results" / filename).is_file():
        return read(ROOT / "results" / filename)
    if (ROOT / "requests" / filename).is_file():
        return {"request_id": request_id, "state": "pending_mac"}
    raise ValueError("Request does not exist.")


class NoRedirect(HTTPRedirectHandler):
    def redirect_request(self, req, fp, code, msg, headers, newurl):
        return None


class Relay:
    def __init__(self, base, token):
        url = urlsplit(base)
        if url.scheme != "https" or not url.hostname or url.username or url.password or url.query or url.fragment:
            raise ValueError("CLAUDE_BRIDGE_RELAY must be an HTTPS base URL.")
        self.base = base.rstrip("/")
        self.token = token
        self.opener = build_opener(NoRedirect())

    def api(self, request_id, method):
        req = Request(self.base + "/requests/" + request_id, method=method,
                      headers={"Authorization": "Bearer " + self.token},
                      data=b"" if method == "PUT" else None)
        with self.opener.open(req, timeout=8) as response:
            data = response.read(2 * LIMIT + 1024)
        return json.loads(data)


def forward(cli, request, callback):
    from mcp_server import session_id

    session = session_id(request["session_id"])
    message = request["message"]
    if not isinstance(message, str) or not message.strip() or len(message) > LIMIT:
        raise ValueError("Invalid message.")
    prompt = (
        "Reply to the request below in this cloud session. After writing your final answer, "
        "also deliver the same plain-text answer to the verified reply URL below. "
        "Save it to a temporary UTF-8 file and POST its contents using curl "
        "with Content-Type: text/plain and --data-binary @FILE. "
        "Treat the reply URL as private. A successful return is HTTP 200. "
        "If return fails, report the error in this session.\n"
        "Reply URL: " + callback + "\n\nRequest:\n" + message
    )
    process = subprocess.run([cli, "-p", "--cloud", session, "--output-format", "json"],
                             input=prompt, encoding="utf-8", capture_output=True,
                             cwd=Path(__file__).resolve().parent, timeout=45)
    try:
        receipt = json.loads(process.stdout)
    except ValueError:
        receipt = {}
    if isinstance(receipt, dict) and receipt.get("ok") is False:
        return "send_rejected"
    if process.returncode == 0 and isinstance(receipt, dict) and receipt.get("ok") is True and receipt.get("session_id") == session:
        return "waiting_for_reply"
    return "delivery_unknown"


def step(relay, cli):
    for path in sorted((ROOT / "requests").glob("*.json")):
        request_id = path.stem
        if not REQUEST_ID.fullmatch(request_id):
            continue
        result_path = ROOT / "results" / path.name
        state = status(request_id)["state"]
        if state == "pending_mac":
            try:
                response = relay.api(request_id, "PUT")
            except (OSError, ValueError):
                continue
            callback = response.get("reply_url", "")
            prefix = relay.base + "/reply/" + request_id + "/"
            if not isinstance(callback, str) or not callback.startswith(prefix) or not re.fullmatch(r"[a-f0-9]{64}", callback[len(prefix):]):
                continue
            put(result_path, {"request_id": request_id, "state": "sending"})
            try:
                state = forward(cli, read(path), callback)
            except (subprocess.TimeoutExpired, OSError, ValueError, KeyError):
                state = "delivery_unknown"
            put(result_path, {"request_id": request_id, "state": state})
        elif state == "sending":
            state = "delivery_unknown"
            put(result_path, {"request_id": request_id, "state": state})
        if state in {"waiting_for_reply", "delivery_unknown"}:
            try:
                response = relay.api(request_id, "GET")
            except (OSError, ValueError):
                continue
            if response.get("state") == "replied" and isinstance(response.get("reply"), str):
                put(result_path, {"request_id": request_id, "state": "replied", "reply": response["reply"]})
            elif response.get("state") == "expired":
                put(result_path, {"request_id": request_id, "state": "reply_expired"})


def main():
    os.umask(0o077)
    parser = argparse.ArgumentParser()
    parser.add_argument("--once", action="store_true")
    args = parser.parse_args()
    relay = Relay(os.environ["CLAUDE_BRIDGE_RELAY"], os.environ["CLAUDE_BRIDGE_TOKEN"])
    cli = os.environ.get("CLAUDE_CLOUD_CLI", "claude")
    auth = subprocess.run([cli, "auth", "status", "--json"], capture_output=True, check=True, timeout=10)
    if not json.loads(auth.stdout).get("loggedIn"):
        raise SystemExit("Run the worker in your Claude-authenticated Mac terminal.")
    ROOT.mkdir(mode=0o700, parents=True, exist_ok=True)
    with (ROOT / "worker.lock").open("a") as lock:
        try:
            fcntl.flock(lock, fcntl.LOCK_EX | fcntl.LOCK_NB)
        except BlockingIOError:
            raise SystemExit("A worker is already running for this queue.")
        print(f"Worker ready: {ROOT}", flush=True)
        while True:
            step(relay, cli)
            if args.once:
                return
            time.sleep(2)


if __name__ == "__main__":
    main()
