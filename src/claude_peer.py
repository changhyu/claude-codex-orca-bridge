"""Scoped, independently initiated messages from the registered Claude peer."""

import contextlib
import hashlib
import hmac
import json
import re
import sqlite3
import time

from agent_mesh import RELAY_CLIENT, VICE_ALIAS
from bridge_message import normalize_message, reply_excerpt
from bridge_settings import CLAUDE_PEER_ALIAS, CLAUDE_PEER_ROUTE
from cloud_roster import CONNECTOR_CLIENT


CLAUDE_ALIAS = CLAUDE_PEER_ALIAS
ROUTE = CLAUDE_PEER_ROUTE
RATE_LIMIT_PER_MINUTE = 12
ENROLLMENT_MARKER = "BRIDGE_CLAUDE_PEER_ENROLL_V1\n"
RETURN_STATES = {"replied", "reply_failed", "reply_expired", "send_rejected", "target_denied"}
RETURN_MARKER = f"Bridge-Reply-To: {CLAUDE_ALIAS}\n"


@contextlib.contextmanager
def database(bridge):
    with contextlib.closing(sqlite3.connect(bridge.ROOT / "claude-peer.sqlite3", timeout=5)) as conn, conn:
        conn.execute("CREATE TABLE IF NOT EXISTS credentials (peer TEXT PRIMARY KEY, fingerprint TEXT NOT NULL)")
        conn.execute("""CREATE TABLE IF NOT EXISTS outbound (
            id TEXT PRIMARY KEY, nonce TEXT UNIQUE NOT NULL, digest TEXT NOT NULL, created REAL NOT NULL
        )""")
        yield conn


def enroll(bridge, bearer, data):
    if set(data) != {"request_id", "fingerprint"}:
        raise ValueError("Invalid enrollment fields.")
    request_id, fingerprint = data["request_id"], data["fingerprint"]
    if not all(isinstance(value, str) for value in (request_id, fingerprint)):
        raise ValueError("Invalid enrollment types.")
    if not bridge.REQUEST_ID.fullmatch(request_id) or not bridge.TOKEN.fullmatch(fingerprint):
        raise ValueError("Invalid enrollment values.")
    with bridge.database("worker") as conn:
        source = conn.execute("SELECT client,target FROM audit WHERE id=?", (request_id,)).fetchone()
    with bridge.database("callback") as conn:
        lease = conn.execute(
            "SELECT 1 FROM replies WHERE id=? AND token=? AND transport='claude' AND expires>? AND reply IS NULL",
            (request_id, bridge.token_hash(bearer), time.time()),
        ).fetchone()
    if source != ("codex", CLAUDE_ALIAS) or not lease or hmac.compare_digest(bridge.token_hash(bearer), fingerprint):
        raise PermissionError("Invalid Claude enrollment grant.")
    config = bridge.secret_file(bridge.BASE / "worker.json")
    signed_request = bridge.verify(bridge.load(bridge.location("requests", request_id)), config["clients"]["codex"]["key"])
    if not signed_request["message"].startswith(ENROLLMENT_MARKER):
        raise PermissionError("The request does not grant peer enrollment.")
    with database(bridge) as conn:
        conn.execute("BEGIN IMMEDIATE")
        existing = conn.execute("SELECT fingerprint FROM credentials WHERE peer=?", (CLAUDE_ALIAS,)).fetchone()
        if existing and not hmac.compare_digest(existing[0], fingerprint):
            raise PermissionError("The Claude peer credential is already registered.")
        conn.execute("INSERT OR IGNORE INTO credentials VALUES (?, ?)", (CLAUDE_ALIAS, fingerprint))
    return {"state": "enrolled", "target": VICE_ALIAS}


def authenticate(bridge, conn, bearer):
    row = conn.execute("SELECT fingerprint FROM credentials WHERE peer=?", (CLAUDE_ALIAS,)).fetchone()
    if not row or not hmac.compare_digest(row[0], bridge.token_hash(bearer)):
        raise PermissionError("Invalid Claude peer credential.")


def send(bridge, bearer, data):
    if set(data) not in ({"nonce", "message"}, {"nonce", "message", "return_to_sender"}):
        raise ValueError("Invalid message fields.")
    push = data.get("return_to_sender", False)
    if type(push) is not bool:
        raise ValueError("return_to_sender must be a boolean.")
    message = data["message"]
    if isinstance(message, str) and message.startswith(RETURN_MARKER):
        if data.get("return_to_sender") is False:
            raise ValueError("Conflicting Claude return settings.")
        push = True
        message = message.removeprefix(RETURN_MARKER)
    return queue_message(bridge, bearer, data["nonce"], message, VICE_ALIAS, roster=False,
                         return_to_sender=push)


def queue_message(bridge, bearer, nonce, value, target, *, roster, return_to_sender=False, no_reply=False):
    if not isinstance(nonce, str):
        raise ValueError("Invalid nonce.")
    if not re.fullmatch(r"[0-9a-f]{32}", nonce):
        raise ValueError("Invalid nonce.")
    if not isinstance(target, str) or not bridge.ALIAS.fullmatch(target):
        raise ValueError("Invalid bridge alias.")
    sender = "Claude MCP connector" if roster else CLAUDE_ALIAS
    body = normalize_message(value)
    if roster and body.startswith(RETURN_MARKER):
        if no_reply:
            raise ValueError("no_reply cannot be combined with Bridge-Reply-To.")
        return_to_sender = True
        body = body.removeprefix(RETURN_MARKER)
    if not body.strip():
        raise ValueError("Expected a nonblank message.")
    message = f"[Bridge from {sender}]\n{body}"
    bridge.validate_message(message)
    stored_nonce = f"roster:{nonce}" if roster else nonce
    request_id = hashlib.sha256(("bridge:" + CLAUDE_ALIAS + ":" + stored_nonce).encode()).hexdigest()[:32]
    digest = hashlib.sha256((target + "\n" + message if roster else message).encode()).hexdigest()
    config = bridge.secret_file(bridge.BASE / "worker.json")
    client_id = CONNECTOR_CLIENT if roster else RELAY_CLIENT
    client = config["clients"][client_id]
    destination = config["targets"].get(target)
    if not destination or target not in client["allow"]:
        raise PermissionError("The destination is outside the approved scope or unavailable.")
    callback = None
    if return_to_sender:
        receiver = config["targets"].get(CLAUDE_ALIAS, {})
        if (receiver.get("transport") != "claude"
                or CLAUDE_ALIAS not in config["clients"]["codex"]["allow"]
                or (destination["transport"] == "claude" and destination["id"] == receiver["id"])):
            raise PermissionError("The registered Claude peer return is unavailable.")
        callback = bridge.destination_identity(receiver)
        digest = hashlib.sha256((digest + "\n" + json.dumps(callback, sort_keys=True)).encode()).hexdigest()
    now = time.time()
    with database(bridge) as conn:
        conn.execute("BEGIN IMMEDIATE")
        authenticate(bridge, conn, bearer)
        existing = conn.execute("SELECT digest FROM outbound WHERE nonce=?", (stored_nonce,)).fetchone()
        if existing:
            if not hmac.compare_digest(existing[0], digest):
                raise ValueError("The nonce was already used for another message.")
            return {"state": "queued", "request_id": request_id}
        recent, = conn.execute("SELECT COUNT(*) FROM outbound WHERE created>=?", (now - 60,)).fetchone()
        if recent >= RATE_LIMIT_PER_MINUTE:
            raise BlockingIOError("Claude bridge sending rate exceeded.")
        request = {"request_id": request_id, "client": client_id, "target": target,
                   "created": now, "message": message, "destination": bridge.destination_identity(destination)}
        if roster:
            request["destination_id"] = destination["id"]
        if callback:
            request["claude_return_to"] = callback
            request["claude_return_alias"] = CLAUDE_ALIAS
        if no_reply:
            request["no_reply"] = True
        path = bridge.location("requests", request_id)
        conn.execute("INSERT INTO outbound VALUES (?, ?, ?, ?)", (request_id, stored_nonce, digest, now))
        # The queue and audit also carry a stable ID, so an ambiguous retry cannot deliver twice.
        if not path.exists():
            bridge.put(path, {"data": request, "signature": bridge.mac(client["key"], request)})
    return {"state": "queued", "request_id": request_id}


def status(bridge, bearer, data):
    if set(data) != {"request_id"} or not isinstance(data["request_id"], str):
        raise ValueError("Invalid status request.")
    request_id = data["request_id"]
    if not bridge.REQUEST_ID.fullmatch(request_id):
        raise ValueError("Invalid request ID.")
    with database(bridge) as conn:
        authenticate(bridge, conn, bearer)
        if not conn.execute("SELECT 1 FROM outbound WHERE id=?", (request_id,)).fetchone():
            raise PermissionError("Unknown peer request.")
    with bridge.database("worker") as conn:
        row = conn.execute("SELECT state FROM audit WHERE id=?", (request_id,)).fetchone()
    state = row[0] if row else "queued"
    response = {"state": state, "request_id": request_id}
    path = bridge.location("results", request_id)
    if not path.is_file():
        return response
    envelope = bridge.load(path)
    client_id = envelope["data"].get("client")
    if client_id not in {CONNECTOR_CLIENT, RELAY_CLIENT}:
        return response
    config = bridge.secret_file(bridge.BASE / "worker.json")
    result = bridge.verify(envelope, config["clients"][client_id]["key"])
    if result["request_id"] != request_id or result["state"] != state:
        return response
    for field in ("reply", "reply_pending"):
        if field in result:
            response[field] = result[field]
    returned = bridge.location("results", return_id(request_id))
    if returned.is_file():
        child = bridge.verify(bridge.load(returned), config["clients"]["codex"]["key"])
        if child["request_id"] == return_id(request_id) and child["target"] == CLAUDE_ALIAS:
            response["callback_state"] = child["state"]
    if "callback_state" not in response:
        original = bridge.verify(bridge.load(bridge.location("requests", request_id)), config["clients"][client_id]["key"])
        if original.get("claude_return_to"):
            response["callback_state"] = "pending"
    return response


def return_id(parent):
    return hashlib.sha256(("claude-vice-return:" + parent).encode()).hexdigest()[:32]


def notify_returns(bridge, config):
    sender = config["clients"].get("codex")
    if not sender:
        return
    with bridge.database("worker") as conn:
        completed = conn.execute(
            """SELECT id,client FROM audit WHERE client IN (?,?) AND created>?
               AND state IN ('replied','reply_failed','reply_expired','send_rejected','target_denied')""",
            (RELAY_CLIENT, CONNECTOR_CLIENT, time.time() - bridge.DAY),
        ).fetchall()
    for parent, client_id in completed:
        rid = return_id(parent)
        path = bridge.location("requests", rid)
        if path.exists() or bridge.location("results", rid).exists():
            continue
        try:
            key = config["clients"][client_id]["key"]
            original = bridge.verify(bridge.load(bridge.location("requests", parent)), key)
            if original["client"] != client_id or original["request_id"] != parent:
                continue
            alias = original.get("claude_return_alias", CLAUDE_ALIAS)
            receiver = config["targets"].get(alias, {})
            if receiver.get("transport") != "claude" or alias not in sender["allow"]:
                continue
            expected = bridge.destination_identity(receiver)
            if "claude_return_alias" not in original and original.get("claude_return_to") != expected:
                continue
            if not original.get("claude_return_to"):
                continue
            result = bridge.verify(bridge.load(bridge.location("results", parent)), key)
            target = original["target"]
            if result["request_id"] != parent or result["target"] != target or result["state"] not in RETURN_STATES:
                continue
            message = f"[작업 회신] {target} · {result['state']} · {parent}"
            reply = reply_excerpt(result.get("reply", ""))
            if reply:
                message += "\n" + reply
            data = {"request_id": rid, "client": "codex", "target": alias, "created": time.time(),
                    "message": message, "destination": expected, "claude_return_of": parent}
            bridge.put(path, {"data": data, "signature": bridge.mac(sender["key"], data)})
        except (OSError, ValueError, TypeError, KeyError):
            continue


def handle(bridge, path, bearer, raw):
    data = json.loads(raw)
    if not isinstance(data, dict):
        raise ValueError("Expected an object.")
    action = path.removeprefix(ROUTE + "/")
    if action == "enroll":
        return 201, enroll(bridge, bearer, data)
    if action == "send":
        return 202, send(bridge, bearer, data)
    if action == "status":
        return 200, status(bridge, bearer, data)
    raise ValueError("Invalid peer action.")
