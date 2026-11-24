"""Authenticated Mac queue with a separate callback-only HTTPS origin."""
import argparse
import contextlib
import fcntl
import hashlib
import hmac
import json
import os
import re
import select
import secrets
import sqlite3
import subprocess
import sys
import threading
import shlex
import time
from concurrent.futures import ThreadPoolExecutor
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from urllib.parse import urlsplit

import orca_bridge
import codex_turn_reply
import orca_reply_return
import desktop_mailbox
import cloud_inbox
import bridge_files
import bridge_return_files
import agent_mesh
import claude_peer
import claude_connector
from cloud_roster import CONNECTOR_CLIENT
import secure_bridge as bridge_api
from codex_desktop_delivery import ADMIN_ALIAS, ADMIN_THREAD, DesktopUnavailable, deliver, confirmed_in_history, mailbox_notice
from bridge_usage import claude_usage, gpt_usage
from bridge_message import claude_prompt, normalize_message
from bridge import LIMIT, REQUEST_ID, put
from bridge_settings import CLAUDE_CLI
from mcp_server import session_id

BASE = Path(__file__).resolve().parent
_legacy_state = Path("/tmp/codex-claude-bridge-secure-state")
_state_override = Path(os.environ.get("SECURE_BRIDGE_STATE", str(_legacy_state))).absolute()
ROOT = BASE / "state" if _state_override == _legacy_state else _state_override
TTL = 900
CLOUD_REPLY_TTL = 4 * 3600
DAY = 86400
WEEK = DAY * 7
MAX_CONCURRENT_DESTINATIONS = 6
ALIAS = re.compile(r"[A-Za-z0-9_-]{1,64}")
TOKEN = re.compile(r"[a-f0-9]{64}")


def load(path, max_bytes=160_000):
    if path.is_symlink():
        raise ValueError("Symbolic links are not accepted.")
    with path.open("rb") as stream:
        raw = stream.read(max_bytes + 1)
    if len(raw) > max_bytes:
        raise ValueError("File exceeds size limit.")
    return json.loads(raw)


def secret_file(path):
    if path.stat().st_uid != os.getuid() or path.stat().st_mode & 0o077:
        raise ValueError("Configuration must be owned by the current user with mode 0600.")
    return load(path)


def mac(key, payload):
    if not TOKEN.fullmatch(key):
        raise ValueError("Invalid signing key.")
    body = json.dumps(payload, sort_keys=True, separators=(",", ":"), ensure_ascii=True).encode()
    return hmac.new(bytes.fromhex(key), body, hashlib.sha256).hexdigest()


def token_hash(value):
    return hashlib.sha256(value.encode()).hexdigest()


def validate_message(message):
    if not isinstance(message, str) or not message.strip() or len(message.encode()) > LIMIT:
        raise ValueError("Expected a nonblank UTF-8 message of at most 24000 bytes.")


def location(bucket, rid):
    if not isinstance(rid, str) or not REQUEST_ID.fullmatch(rid):
        raise ValueError("Invalid request ID.")
    return ROOT / bucket / (rid + ".json")


def ensure_state():
    ROOT.mkdir(mode=0o700, parents=True, exist_ok=True)
    info = ROOT.lstat()
    if ROOT.is_symlink() or not ROOT.is_dir() or info.st_uid != os.getuid() or info.st_mode & 0o077:
        raise ValueError("The state directory must be private and owned by the current user.")
    for folder in ("requests", "results"):
        path = ROOT / folder
        if path.exists() and (path.is_symlink() or not path.is_dir() or path.stat().st_uid != os.getuid() or path.stat().st_mode & 0o077):
            raise ValueError("Queue directories must be private and owned by the current user.")


@contextlib.contextmanager
def database(which):
    ensure_state()
    with contextlib.closing(sqlite3.connect(ROOT / (which + ".sqlite3"), timeout=5)) as con, con:
        if which == "worker":
            con.execute("CREATE TABLE IF NOT EXISTS audit (id TEXT PRIMARY KEY, client TEXT, target TEXT, state TEXT, created REAL)")
        else:
            con.execute("CREATE TABLE IF NOT EXISTS replies (id TEXT PRIMARY KEY, token TEXT, transport TEXT, expires REAL, request TEXT, reply TEXT)")
        yield con


def audit(rid, client, target, state):
    with database("worker") as con:
        con.execute("INSERT INTO audit VALUES (?,?,?,?,?) ON CONFLICT(id) DO UPDATE SET state=excluded.state",
                    (rid, client, target, state, time.time()))


def publish(rid, client, target, state, key, **extras):
    data = {"request_id": rid, "client": client, "target": target, "state": state, **extras}
    put(location("results", rid), {"data": data, "signature": mac(key, data)})
    audit(rid, client, target, state)


def destination_identity(destination):
    return {"transport": destination["transport"], "id": destination["id"],
            "host": destination.get("host", "local"), "incarnation": destination.get("incarnation")}


def verify(envelope, key):
    data = envelope["data"]
    signature = envelope["signature"]
    if not isinstance(signature, str) or not hmac.compare_digest(mac(key, data), signature):
        raise ValueError("Invalid request signature.")
    return data


def register_reply(rid, transport, message):
    token = secrets.token_hex(32)
    with database("callback") as con:
        con.execute("INSERT INTO replies VALUES (?,?,?,?,?,NULL)",
                    (rid, token_hash(token), transport, time.time() + TTL,
                     message if transport == "orca" else None))
    return token


def receive(rid, token, transport, message):
    validate_message(message)
    if not REQUEST_ID.fullmatch(rid) or not TOKEN.fullmatch(token):
        return False
    with database("callback") as con:
        return con.execute(
            "UPDATE replies SET reply=?, request=NULL WHERE id=? AND token=? AND transport=? AND expires>? AND reply IS NULL",
            (message, rid, token_hash(token), transport, time.time())).rowcount == 1


def origin(value):
    url = urlsplit(value)
    if url.scheme != "https" or not url.hostname or url.username or url.password or url.path not in ("", "/") or url.query or url.fragment:
        raise ValueError("Set a fixed HTTPS origin, without a path.")
    return value.rstrip("/")


def forward(rid, target, label, message, token, config, *, completion=False, forward_by_reply=False):
    if target["transport"] == "claude":
        prompt = message if completion else claude_prompt(
            origin(config["https_origin"]), rid, token, message, via_reply=forward_by_reply,
        )
        cli = CLAUDE_CLI
        result = subprocess.run([cli, "-p", "--cloud", session_id(target["id"]), "--output-format", "json"],
                                input=prompt, text=True, capture_output=True, cwd=BASE, timeout=45)
        receipt = json.loads(result.stdout)
        if receipt.get("ok") is False:
            return "send_rejected"
        if result.returncode == 0 and receipt.get("ok") is True and receipt.get("session_id") == target["id"]:
            return "input_accepted"
        return "delivery_unknown"
    remote = target.get("host")
    if completion:
        prompt = message
    elif remote:
        prompt = (
            f"브릿지 요청 {rid}. 승인된 작업의 외부 입력이 아래에 있습니다. "
            f"답변을 UTF-8 text/plain으로 {origin(config['https_origin'])}/v1/orca-replies/{rid}에 POST하세요. "
            f"Authorization: Bearer {token}. 리다이렉트 없이 HTTP 204를 확인하고 자격은 답변에 쓰지 마세요.\n\n"
            + message
        )
    else:
        helper = shlex.quote(str(Path(__file__).resolve()))
        prompt = (
            f"CODEX-ORCA-{rid} is a bridge request. Read the message using python3 {helper} read {rid} {token} . "
            f"Send the final answer through standard input to python3 {helper} reply {rid} {token} . "
        )
    args = ("send", "--terminal", target["id"], "--text", prompt, "--enter", "--wait-submit", "8")
    if remote:
        orca_bridge.invoke_on(remote, "terminal", *args)
    else:
        orca_bridge.invoke(*args)
    return "input_accepted"


def check_target(target, config):
    if target["transport"] == "claude":
        return session_id(target["id"]) == target["id"] and bool(origin(config["https_origin"]))
    if target["transport"] != "orca" or not target.get("incarnation"):
        return False
    if target.get("host"):
        workspace = target.get("worktree")
        if not workspace:
            return False
        rows = orca_bridge.invoke_on(target["host"], "terminal", "list", "--worktree", workspace)["terminals"]
    else:
        rows = orca_bridge.terminals(target.get("worktree"))
    return any(t.get("handle") == target["id"] and t.get("incarnationId") == target["incarnation"]
               and t.get("connected") is True and t.get("writable") is True
               and orca_bridge.is_agent(t)
               and t.get("executionHost", "local") in (None, "local")
               and t.get("executionHostId") in (None, "local")
               for t in rows)


def wake_desktop(rid, destination):
    try:
        codex_turn_reply.wake_once(bridge_api, rid, destination)
    except (OSError, ValueError, subprocess.SubprocessError):
        pass


def dispatch_desktop(rid, client, target, key, message, created, destination, cloud_ready=False, return_only=False,
                     *, direct_notification=False, continuation=False):
    if time.time() - created > TTL:
        publish(rid, client, target, "reply_expired", key)
        return
    host = destination.get("host", "local")
    expires = time.time() + CLOUD_REPLY_TTL if host == "durable" else created + TTL
    if return_only and host == "local":
        tracked = desktop_mailbox.prepare(bridge_api, rid, destination["id"], created + TTL)
        message = mailbox_notice(rid, host, return_only=True)
    else:
        tracked = return_only or direct_notification or codex_turn_reply.track(
            bridge_api, rid, destination, expires)
    if not tracked:
        publish(rid, client, target, "target_denied", key)
        return
    audit(rid, client, target, "sending")
    try:
        options = {}
        if cloud_ready:
            presentation = "report" if return_only or direct_notification else "request"
            options["presentation"] = "continuation" if continuation else presentation
        deliver(rid, message, destination["id"], host, **options)
    except DesktopUnavailable as exc:
        # These responses come from the owner before admission. Other failures
        # may have happened after admission and must never be resent.
        if str(exc) == "no-client-found":
            wake_desktop(rid, destination)
        elif str(exc) == "App context must wait until the current turn finishes":
            from codex_outbound import eligible

            if host == "local" or cloud_ready or eligible(destination):
                return dispatch_mailbox(rid, client, target, key, destination["id"], created, host,
                                        return_only or direct_notification,
                                        cloud_ticket=host == "durable" and not cloud_ready,
                                        continuation=continuation)
        else:
            publish(rid, client, target, "delivery_unknown", key)
            return
        publish(rid, client, target, "waiting_for_desktop", key)
        return "waiting_for_desktop"
    except FileNotFoundError:
        wake_desktop(rid, destination)
        publish(rid, client, target, "waiting_for_desktop", key)
        return "waiting_for_desktop"
    except (OSError, ValueError, KeyError, TypeError):
        publish(rid, client, target, "delivery_unknown", key)
    else:
        notification = return_only or direct_notification
        publish(rid, client, target, "notification_delivered" if notification else "delivered", key,
                receipt="desktop_turn_accepted", reply_pending=not notification)


def dispatch_mailbox(rid, client, target, key, thread, created, host, return_only=False,
                     *, cloud_ticket=False, continuation=False):
    expires = time.time() + CLOUD_REPLY_TTL if host == "durable" else created + TTL
    if not desktop_mailbox.prepare(bridge_api, rid, thread, expires):
        publish(rid, client, target, "target_denied", key)
        return
    try:
        options = {"return_only": True} if return_only else {}
        if cloud_ticket:
            options["cloud_ticket"] = cloud_inbox.issue_turn_lease(
                bridge_api, rid, thread, expires, can_reply=not return_only)
        if continuation:
            options["continuation"] = True
        deliver(rid, "", thread, host, wake_only=True, **options)
    except DesktopUnavailable as error:
        if str(error) in {
            "no-client-found", f"Conversation {thread} is not being streamed.",
            f"Cannot steer conversation {thread} because its active turn already ended",
        }:
            desktop_mailbox.discard(bridge_api, rid)
            publish(rid, client, target, "waiting_for_desktop", key)
            return "waiting_for_desktop"
        publish(rid, client, target, "delivery_unknown", key)
    except (OSError, ValueError, KeyError, TypeError):
        publish(rid, client, target, "delivery_unknown", key)
    else:
        publish(rid, client, target, "notification_delivered" if return_only else "delivered", key,
                receipt="desktop_steer_accepted", reply_pending=not return_only)


def process(path, config, envelope=None):
    rid = path.stem
    if not REQUEST_ID.fullmatch(rid):
        return
    with database("worker") as con:
        previous = con.execute("SELECT client,target,state FROM audit WHERE id=?", (rid,)).fetchone()
    if previous and previous[2] != "waiting_for_desktop":
        client, target, state = previous
        key = config["clients"].get(client, {}).get("key")
        if key and state == "sending":
            publish(rid, client, target, "delivery_unknown", key)
        return
    try:
        if envelope is None:
            envelope = load(path)
        client = envelope["data"]["client"]
        client_config = config["clients"][client]
        key = client_config["key"]
        data = verify(envelope, key)
        if data["request_id"] != rid or not 0 <= time.time() - data["created"] or (not previous and time.time() - data["created"] > TTL):
            raise ValueError("Expired or mismatched request.")
        target = data["target"]
        data["message"] = normalize_message(data["message"])
        raw_return = data["message"].startswith(cloud_inbox.RETURN_HEADER)
        cloud_inbox.authorize_queued_return(bridge_api, data, config)
        validate_message(data["message"])
        if raw_return:
            put(path, {"data": data, "signature": mac(key, data)})
    except (ValueError, KeyError, TypeError, OSError, AttributeError):
        audit(rid, None, None, "invalid_request")
        return
    try:
        destination = config["targets"].get(target) if target in client_config["allow"] else None
        if not orca_reply_return.track(bridge_api, data, client_config, config["targets"]):
            publish(rid, client, target, "target_denied", key)
            return
        if client == CONNECTOR_CLIENT and (not destination or data.get("destination_id") != destination["id"]):
            destination = None
        if "destination" in data and (not destination or data["destination"] != destination_identity(destination)):
            destination = None
        if data.get("completion_of") and not orca_reply_return.valid_completion(data, destination or {}):
            destination = None
        if data.get("paired_directory_of"):
            from remote_orca_mail import valid_directory

            if not destination or not valid_directory(data, destination):
                destination = None
        if data.get("delegation_return_of"):
            from codex_delegation import eligible_source, request_id as delegation_id

            if (client != agent_mesh.LOCAL_CLIENT or not destination or not eligible_source(destination)
                    or rid != delegation_id("return", data["delegation_return_of"])):
                destination = None
        if data.get("claude_return_of") and (
                client != "codex"
                or rid != claude_peer.return_id(data["claude_return_of"])
                or not destination or destination["transport"] != "claude"):
            destination = None
        if destination and destination["transport"] == "codex-desktop":
            cloud_ready = bool(cloud_inbox.key_for(config, target, destination))
            vice_return = data.get("vice_return_of")
            if vice_return and (client != "codex" or not cloud_ready or not isinstance(vice_return, str)
                                or not REQUEST_ID.fullmatch(vice_return)
                                or rid != cloud_inbox.return_id(vice_return, late=data.get("vice_late_reply") is True)):
                publish(rid, client, target, "target_denied", key)
                return
            return_only = bool(vice_return or (data.get("completion_of")
                               and data.get("destination_transport") == orca_reply_return.LOCAL_CODEX))
            return dispatch_desktop(rid, client, target, key, data["message"], data["created"], destination,
                                    cloud_ready, return_only, direct_notification=bool(data.get("delegation_return_of")),
                                    continuation=bool(vice_return))
        allowed = destination is not None and check_target(destination, config)
    except (ValueError, KeyError, RuntimeError, OSError, subprocess.TimeoutExpired):
        allowed = False
    if not allowed:
        publish(rid, client, target, "target_denied", key)
        return
    # Persist the dispatch intent first. A crash after this point never auto-resends.
    audit(rid, client, target, "sending")
    try:
        completion = bool(data.get("completion_of") or data.get("claude_return_of")
                          or data.get("delegation_return_of") or data.get("paired_directory_of"))
        transport = destination["transport"]
        if transport == "orca" and destination.get("host"):
            transport = "orca-remote"
        token = None if completion else register_reply(rid, transport, data["message"])
        state = forward(rid, destination, client_config["label"], data["message"], token, config,
                        completion=completion, forward_by_reply=bool(data.get("forward_to")))
        if completion and state == "input_accepted":
            state = "delivered"
    except (RuntimeError, ValueError, OSError, subprocess.TimeoutExpired):
        state = "delivery_unknown"
    publish(rid, client, target, state, key)


def destination_key(envelope, config):
    target = envelope["data"]["target"]
    destination = config["targets"].get(target, {})
    return (destination.get("transport"), destination.get("host", "local"),
            destination.get("id", target))


def dispatch_pending(config, executor, inflight, deferred, notify_ready):
    # Only schedule work that can start now, so it uses the current routing policy.
    now = time.monotonic()
    for key, retry_at in list(deferred.items()):
        if retry_at <= now:
            del deferred[key]
    for key, (_, future) in list(inflight.items()):
        if future.done():
            if future.result() == "waiting_for_desktop":
                deferred[key] = now + 2
            del inflight[key]
    if len(inflight) >= MAX_CONCURRENT_DESTINATIONS:
        return
    active_ids = {rid for rid, _ in inflight.values()}
    with database("worker") as con:
        states = dict(con.execute("SELECT id,state FROM audit"))
    queued = []
    for path in (ROOT / "requests").glob("*.json"):
        if (path.stem in active_ids or not REQUEST_ID.fullmatch(path.stem)
                or states.get(path.stem) not in (None, "sending", "waiting_for_desktop")):
            continue
        try:
            queued.append((path.stat().st_mtime_ns, path))
        except FileNotFoundError:
            continue
    for _, path in sorted(queued):
        try:
            envelope = load(path)
            key = destination_key(envelope, config)
        except (OSError, ValueError, KeyError, TypeError):
            audit(path.stem, None, None, "invalid_request")
            continue
        if key in inflight or key in deferred:
            continue
        future = executor.submit(process, path, config, envelope)
        inflight[key] = (path.stem, future)
        future.add_done_callback(notify_ready)
        if len(inflight) >= MAX_CONCURRENT_DESTINATIONS:
            break


def collect(config):
    mailbox_requests = desktop_mailbox.collect(bridge_api, config)
    desktop_requests = mailbox_requests | codex_turn_reply.collect(bridge_api, config, mailbox_requests)
    with database("worker") as con:
        waiting = con.execute("SELECT id,client,target FROM audit WHERE state IN ('input_accepted','delivery_unknown')").fetchall()
    quotas = None
    with database("callback") as con:
        for rid, client, target in waiting:
            if rid in desktop_requests:
                continue
            if target == ADMIN_ALIAS:
                try:
                    confirmed = confirmed_in_history(rid)
                except OSError:
                    confirmed = False
                policy = config["clients"].get(client)
                if confirmed and policy:
                    publish(rid, client, target, "delivered", policy["key"], receipt="desktop_history_confirmed")
                continue
            if config["targets"].get(target, {}).get("transport") == "codex-desktop":
                continue
            row = con.execute("SELECT expires,reply FROM replies WHERE id=?", (rid,)).fetchone()
            client_config = config["clients"].get(client)
            if not client_config:
                continue
            if row and row[1] is not None:
                if quotas is None:
                    quotas = gpt_usage()
                usage = dict(quotas)
                if config["targets"].get(target, {}).get("transport") == "claude":
                    usage.update({
                        "usage": {"provider": "claude", "scope": "cloud_account", "status": "unavailable"},
                        "local_cli_usage": {**claude_usage(ROOT), "scope": "local_cli_account"},
                    })
                publish(rid, client, target, "replied", client_config["key"], reply=row[1], **usage)
                con.execute("DELETE FROM replies WHERE id=?", (rid,))
            elif not row or row[0] <= time.time():
                publish(rid, client, target, "reply_expired", client_config["key"])
        con.execute("DELETE FROM replies WHERE expires < ?", (time.time() - DAY,))


def purge():
    bridge_files.purge(bridge_api)
    bridge_return_files.purge(bridge_api)
    now = time.time()
    with database("worker") as con:
        for rid, client, target, state in con.execute("SELECT id,client,target,state FROM audit WHERE created < ?", (now - DAY,)):
            for bucket in ("requests", "results"):
                location(bucket, rid).unlink(missing_ok=True)
        con.execute("DELETE FROM audit WHERE created < ?", (now - WEEK,))
    # Expire files without audit rows too (for instance, while the worker was offline).
    for bucket in ("requests", "results"):
        for path in (ROOT / bucket).glob("*.json"):
            try:
                if path.lstat().st_mtime < now - DAY:
                    path.unlink()
            except FileNotFoundError:
                pass


@contextlib.contextmanager
def request_wakeup():
    """Wake on an atomic queue write and maintain existing timed retries."""
    if not hasattr(select, "kqueue"):
        yield time.sleep, lambda future: None
        return
    queue = ROOT / "requests"
    queue.mkdir(mode=0o700, exist_ok=True)
    fd = os.open(queue, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
    try:
        with contextlib.closing(select.kqueue()) as events, contextlib.ExitStack() as stack:
            read_fd, write_fd = os.pipe()
            stack.callback(os.close, read_fd)
            stack.callback(os.close, write_fd)
            os.set_blocking(read_fd, False)
            os.set_blocking(write_fd, False)
            subscription = select.kevent(
                fd, filter=select.KQ_FILTER_VNODE,
                flags=select.KQ_EV_ADD | select.KQ_EV_CLEAR,
                fflags=select.KQ_NOTE_WRITE,
            )
            ready = select.kevent(read_fd, filter=select.KQ_FILTER_READ, flags=select.KQ_EV_ADD)
            events.control([subscription, ready], 0)

            def wake(_future):
                with contextlib.suppress(BlockingIOError):
                    os.write(write_fd, b"\x01")

            def wait(seconds):
                events.control(None, 2, seconds)
                with contextlib.suppress(BlockingIOError):
                    os.read(read_fd, 4096)

            yield wait, wake
    finally:
        os.close(fd)


class Callback(BaseHTTPRequestHandler):
    def setup(self):
        self.request.settimeout(5)
        super().setup()

    def log_message(self, *_):
        pass

    def end_headers(self):
        self.send_header("X-Bridge-Origin", "callback-v1")
        super().end_headers()

    def do_POST(self):
        self.close_connection = True
        if not self.server.allow_post():
            self.send_error(429)
            return
        if bridge_return_files.PATH.fullmatch(self.path):
            return self.handle_return_file_upload()
        if cloud_inbox.PATH.fullmatch(self.path):
            return self.handle_cloud_inbox()
        match = re.fullmatch(r"/v1/(replies|orca-replies|dispatch)/([a-f0-9]{32})", self.path)
        peer = self.path in {claude_peer.ROUTE + "/" + action for action in ("enroll", "send", "status")}
        mcp = self.path == claude_connector.PATH
        if not match and not peer and not mcp:
            self.send_error(404)
            return
        headers = self.headers.get_all(claude_connector.HEADER if mcp else "Authorization", [])
        credential = headers[0] if len(headers) == 1 else ""
        if not mcp:
            credential = credential.removeprefix("Bearer ") if credential.startswith("Bearer ") else ""
        if not TOKEN.fullmatch(credential):
            self.send_error(403)
            return
        try:
            if self.headers.get("Transfer-Encoding") or len(self.headers.get_all("Content-Length", [])) != 1:
                raise ValueError
            count = int(self.headers["Content-Length"])
            if not 0 < count <= LIMIT:
                raise ValueError
            raw = self.rfile.read(count)
            if len(raw) != count:
                raise ValueError
            if mcp:
                status_code, payload = claude_connector.handle(bridge_api, credential, raw)
                body = json.dumps(payload).encode() if payload is not None else b""
                self.send_response(status_code)
                if body:
                    self.send_header("Content-Type", "application/json")
                self.send_header("Content-Length", str(len(body)))
                self.send_header("Cache-Control", "no-store")
                self.end_headers()
                if body:
                    self.wfile.write(body)
                return
            if peer:
                status_code, payload = claude_peer.handle(bridge_api, self.path, credential, raw)
                body = json.dumps(payload).encode()
                self.send_response(status_code)
                self.send_header("Content-Type", "application/json")
                self.send_header("Content-Length", str(len(body)))
                self.send_header("Cache-Control", "no-store")
                self.end_headers()
                self.wfile.write(body)
                return
            if match[1] == "dispatch":
                request_id = agent_mesh.queue_claude_dispatch(bridge_api, match[2], credential, json.loads(raw))
                body = json.dumps({"request_id": request_id, "state": "queued"}).encode()
                self.send_response(202)
                self.send_header("Content-Type", "application/json")
                self.send_header("Content-Length", str(len(body)))
                self.send_header("Cache-Control", "no-store")
                self.end_headers()
                self.wfile.write(body)
                return
            transport = "orca-remote" if match[1] == "orca-replies" else "claude"
            ok = receive(match[2], credential, transport, raw.decode("utf-8"))
        except BlockingIOError:
            self.send_error(429)
            return
        except PermissionError:
            self.send_error(403)
            return
        except (ValueError, TimeoutError):
            self.send_error(400)
            return
        self.send_response(204 if ok else 403)
        self.send_header("Cache-Control", "no-store")
        self.end_headers()

    def handle_return_file_upload(self):
        headers = self.headers.get_all("Authorization", [])
        try:
            if len(headers) != 1:
                raise PermissionError("Upload authorization required.")
            # Reject unauthorized clients before reading the multi-megabyte body.
            bridge_return_files.authorize(bridge_api, self.path, headers[0])
            if (self.headers.get("Transfer-Encoding") or self.headers.get_content_type() != "application/json"
                    or len(self.headers.get_all("Content-Length", [])) != 1):
                raise ValueError("Invalid upload framing.")
            count = int(self.headers["Content-Length"])
            if not 0 < count <= bridge_return_files.MAX_BODY:
                self.send_error(413)
                return
            body = self.rfile.read(count)
            if len(body) != count:
                raise ValueError("Truncated upload.")
            code, result = bridge_return_files.upload(bridge_api, self.path, headers[0], body)
        except bridge_return_files.Conflict:
            self.send_error(409)
            return
        except (PermissionError, KeyError):
            self.send_error(403)
            return
        except (ValueError, TypeError, TimeoutError):
            self.send_error(400)
            return
        except (OSError, sqlite3.Error):
            self.send_error(503)
            return
        payload = json.dumps(result, ensure_ascii=False).encode()
        self.send_response(code)
        self.send_header("Cache-Control", "no-store")
        self.send_header("Content-Type", "application/json; charset=utf-8")
        self.send_header("Content-Length", str(len(payload)))
        self.end_headers()
        self.wfile.write(payload)

    def handle_file_download(self):
        self.close_connection = True
        if not self.server.allow_post():
            self.send_error(429)
            return
        headers = self.headers.get_all("Authorization", [])
        try:
            if len(headers) != 1:
                raise PermissionError("Attachment authorization required.")
            payload = bridge_files.download(bridge_api, self.path, headers[0])
        except (PermissionError, KeyError, IndexError, TypeError, ValueError, OSError, sqlite3.Error):
            self.send_error(403)
            return
        self.send_response(200)
        self.send_header("Cache-Control", "no-store")
        self.send_header("Content-Type", "application/octet-stream")
        self.send_header("Content-Disposition", "attachment")
        self.send_header("X-Content-Type-Options", "nosniff")
        self.send_header("Content-Length", str(len(payload)))
        self.end_headers()
        self.wfile.write(payload)

    def do_GET(self):
        if self.command == "GET" and bridge_files.PATH.fullmatch(self.path):
            return self.handle_file_download()
        if self.command == "GET" and cloud_inbox.PATH.fullmatch(self.path):
            self.close_connection = True
            if not self.server.allow_post():
                self.send_error(429)
                return
            return self.handle_cloud_inbox()
        if self.path == claude_connector.PATH:
            self.send_response(405)
            self.send_header("Allow", "POST")
            self.send_header("Content-Length", "0")
            self.end_headers()
            return
        self.send_error(404)

    def handle_cloud_inbox(self):
        headers = self.headers.get_all("Authorization", [])
        if len(headers) != 1:
            print("Codex Cloud inbox denied: missing or repeated authorization.", flush=True)
            self.send_error(403)
            return
        try:
            body = b""
            if self.command == "POST":
                if (self.headers.get("Transfer-Encoding") or self.headers.get_content_type() != "text/plain"
                        or len(self.headers.get_all("Content-Length", [])) != 1):
                    raise ValueError("Invalid inbox request framing.")
                count = int(self.headers["Content-Length"])
                if not 0 < count <= LIMIT:
                    raise ValueError("Invalid reply size.")
                body = self.rfile.read(count)
                if len(body) != count:
                    raise ValueError("Truncated inbox reply.")
            result = cloud_inbox.access(bridge_api, self.command, self.path, headers[0], body)
        except (PermissionError, KeyError, TypeError, ValueError, OSError, sqlite3.Error) as error:
            allowed_reasons = {
                "Cloud inbox authorization required.",
                "Expired cloud inbox authorization.",
                "Cloud inbox is unavailable.",
                "Invalid cloud inbox authorization.",
                "Cloud inbox authorization was already used.",
                "No received request for this Codex chat.",
                "Bridge request destination no longer matches this Codex chat.",
            }
            reason = str(error) if str(error) in allowed_reasons else type(error).__name__
            print(f"Codex Cloud inbox denied: {reason}", flush=True)
            self.send_error(403)
            return
        payload = json.dumps(result, ensure_ascii=False).encode() if result else b""
        self.send_response(200 if payload else 204)
        self.send_header("Cache-Control", "no-store")
        self.send_header("Content-Length", str(len(payload)))
        if payload:
            self.send_header("Content-Type", "application/json; charset=utf-8")
        self.end_headers()
        if payload:
            self.wfile.write(payload)

    do_PUT = do_GET
    do_DELETE = do_GET


class Server(ThreadingHTTPServer):
    slots = threading.BoundedSemaphore(16)
    daemon_threads = True

    def __init__(self, *args, **kwargs):
        self.rate_lock = threading.Lock()
        self.rate_window = time.monotonic()
        self.rate_count = 0
        super().__init__(*args, **kwargs)

    def allow_post(self):
        with self.rate_lock:
            now = time.monotonic()
            if now - self.rate_window >= 10:
                self.rate_window, self.rate_count = now, 0
            self.rate_count += 1
            return self.rate_count <= 60

    def process_request(self, request, address):
        if not self.slots.acquire(blocking=False):
            self.shutdown_request(request)
            return
        try:
            super().process_request(request, address)
        except BaseException:
            self.slots.release()
            raise

    def process_request_thread(self, request, address):
        try:
            super().process_request_thread(request, address)
        finally:
            self.slots.release()


def refresh_agents(config_file):
    from register_orca_adapter import blockers
    discovered = agent_mesh.discover_orca(orca_bridge.ORCA, blockers, orca_bridge.invoke)
    try:
        discovered.update(agent_mesh.paired_inventory(
            lambda host, *args: orca_bridge.invoke_on(host, *args, timeout=4), blockers,
        ))
    except (OSError, RuntimeError, KeyError, TypeError, ValueError, subprocess.SubprocessError):
        pass
    with (ROOT / "enrollment.lock").open("a") as lock:
        fcntl.flock(lock, fcntl.LOCK_EX)
        config = secret_file(config_file)
        paths = {"codex": config_file.with_name("client.json"),
                 agent_mesh.LOCAL_CLIENT: config_file.with_name("agent-client.json")}
        clients = {name: secret_file(path) for name, path in paths.items()}
        before = json.dumps(config, sort_keys=True)
        agent_mesh.merge_inventory(config, clients, discovered)
        if json.dumps(config, sort_keys=True) != before:
            put(config_file, config)
            for name, path in paths.items():
                put(path, clients[name])


def main():
    os.umask(0o077)
    parser = argparse.ArgumentParser()
    commands = parser.add_subparsers(dest="command", required=True)
    commands.add_parser("list-orca")
    setup = commands.add_parser("configure")
    setup.add_argument("--origin", required=True)
    setup.add_argument("--claude")
    setup.add_argument("--orca-handle")
    setup.add_argument("--client-label", default="Codex MCP")
    worker = commands.add_parser("worker")
    worker.add_argument("config", type=Path)
    callback = commands.add_parser("callback")
    callback.add_argument("--port", type=int, default=8766)
    for name in ("read", "reply"):
        cmd = commands.add_parser(name)
        cmd.add_argument("rid")
        cmd.add_argument("token")
    args = parser.parse_args()
    if args.command == "configure":
        targets = {}
        if args.claude:
            targets["claude"] = {"transport": "claude", "id": session_id(args.claude)}
        if args.orca_handle:
            matches = [t for t in orca_bridge.terminals(None) if t["handle"] == args.orca_handle and orca_bridge.is_agent(t)]
            if not matches or not matches[0].get("incarnationId"):
                raise SystemExit("The Orca handle is missing or has no process incarnation.")
            targets["orca"] = {"transport": "orca", "id": args.orca_handle,
                               "incarnation": matches[0]["incarnationId"]}
        if not targets:
            raise SystemExit("Configure at least one destination.")
        key = secrets.token_hex(32)
        worker_path, client_path = BASE / "worker.json", BASE / "client.json"
        if worker_path.exists() or client_path.exists():
            raise SystemExit("Configuration already exists. Edit worker.json locally to change access.")
        client = {"key": key, "allow": list(targets), "label": args.client_label}
        for path, value in ((worker_path, {"https_origin": origin(args.origin), "clients": {"codex": client}, "targets": targets}),
                            (client_path, {"id": "codex", **client})):
            with path.open("x", encoding="utf-8") as stream:
                json.dump(value, stream, ensure_ascii=False, indent=2)
        print("Configured " + ", ".join(targets))
    elif args.command == "callback":
        with Server(("127.0.0.1", args.port), Callback) as server:
            server.serve_forever()
    elif args.command == "list-orca":
        print(json.dumps([{**orca_bridge.describe_terminal(t), "incarnation": t.get("incarnationId")}
                          for t in orca_bridge.terminals(None) if orca_bridge.is_agent(t)], indent=2, ensure_ascii=False))
    elif args.command == "read":
        with database("callback") as con:
            row = con.execute("SELECT request FROM replies WHERE id=? AND token=? AND transport='orca' AND expires>?",
                              (args.rid, token_hash(args.token), time.time())).fetchone()
        if not row or row[0] is None:
            raise SystemExit("Invalid or expired request.")
        print(row[0])
    elif args.command == "reply":
        if not receive(args.rid, args.token, "orca", sys.stdin.read(LIMIT + 1)):
            raise SystemExit("Reply rejected.")
    else:
        from bridge_admin import run_pending
        import codex_delegation
        import codex_outbound
        import remote_orca_mail
        from threading import Thread

        ensure_state()
        with (ROOT / "worker.lock").open("a") as lock, request_wakeup() as (wait_for_request, notify_ready), \
                ThreadPoolExecutor(max_workers=MAX_CONCURRENT_DESTINATIONS) as executor:
            fcntl.flock(lock, fcntl.LOCK_EX | fcntl.LOCK_NB)
            print("Secure worker ready", flush=True)
            Thread(target=remote_orca_mail.watch, args=(bridge_api,), name="paired-orca-mail", daemon=True).start()
            next_scan = 0
            next_heartbeat = 0
            inflight = {}
            deferred = {}
            while True:
                if time.monotonic() >= next_heartbeat:
                    (ROOT / "worker.heartbeat").touch(mode=0o600)
                    next_heartbeat = time.monotonic() + 15
                run_pending(args.config)
                if time.monotonic() >= next_scan:
                    next_scan = time.monotonic() + agent_mesh.SCAN_SECONDS
                    try:
                        refresh_agents(args.config)
                    except (OSError, ValueError, RuntimeError, KeyError, subprocess.SubprocessError) as error:
                        print("Agent discovery unavailable:", type(error).__name__, flush=True)
                config = secret_file(args.config)
                purge()
                dispatch_pending(config, executor, inflight, deferred, notify_ready)
                collect(config)
                orca_reply_return.notify(bridge_api, config)
                cloud_inbox.notify_returns(bridge_api, config)
                claude_peer.notify_returns(bridge_api, config)
                codex_delegation.notify(bridge_api, config)
                codex_outbound.notify(bridge_api, config)
                wait_for_request(2)


if __name__ == "__main__":
    main()
