"""HTTPS mailbox authorization for the explicitly enrolled Codex Cloud chat."""

from base64 import b64decode
import hashlib
import hmac
import os
import re
import secrets
import sqlite3
import time
import uuid

from bridge_message import reply_excerpt
from agent_mesh import VICE_ALIAS, VICE_THREAD
import desktop_mailbox


CLOCK_WINDOW = 90
PATH = re.compile(r"/v1/inbox/([a-f0-9]{32})")
PROOF = re.compile(r"Bridge-Ed25519 (\d{1,12})\.([a-f0-9]{32})\.([A-Za-z0-9+/]{86}==)")
RETURN_HEADER = "Bridge-Cloud-Return: "
RETURN_STATES = {"replied", "reply_failed", "reply_expired", "send_rejected", "target_denied"}


def key_for(config, alias, destination):
    if alias != VICE_ALIAS or destination.get("id") != VICE_THREAD or destination.get("host") != "durable":
        return None
    enrolled = config.get("vice_cloud_inbox", {})
    return enrolled.get("public_key") if enrolled.get("thread") == VICE_THREAD else None


def public_key(encoded):
    from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey
    from cryptography.hazmat.primitives.serialization import load_der_public_key

    key = load_der_public_key(b64decode(encoded, validate=True))
    if not isinstance(key, Ed25519PublicKey):
        raise ValueError("Expected an Ed25519 public key.")
    return key


def verify_proof(encoded, method, signed_target, authorization, body, now):
    from cryptography.exceptions import InvalidSignature

    proof = PROOF.fullmatch(authorization)
    if not proof:
        raise PermissionError("Cloud inbox authorization required.")
    timestamp, nonce, signature = proof.groups()
    if abs(now - int(timestamp)) > CLOCK_WINDOW:
        raise PermissionError("Expired cloud inbox authorization.")
    canonical = "\n".join((method, signed_target, timestamp, nonce, hashlib.sha256(body).hexdigest())).encode("ascii")
    try:
        public_key(encoded).verify(b64decode(signature, validate=True), canonical)
    except (InvalidSignature, ValueError) as error:
        raise PermissionError("Invalid cloud inbox authorization.") from error
    return timestamp, nonce


def save_once(bridge, rid, data, key):
    path = bridge.location("requests", rid)
    scratch = path.with_name(".cloud-return-" + uuid.uuid4().hex)
    try:
        bridge.put(scratch, {"data": data, "signature": bridge.mac(key, data)})
        try:
            os.link(scratch, path)
        except FileExistsError:
            pass
    finally:
        scratch.unlink(missing_ok=True)


def approve_return(bridge, client, target, config, value, *, observed=None):
    header, _, message = value.partition("\n")
    destination = config["targets"].get(target, {})
    receiver = config["targets"].get(VICE_ALIAS, {})
    encoded = key_for(config, VICE_ALIAS, receiver)
    allowed = config["clients"].get("codex", {}).get("allow", [])
    if (client != "codex" or target not in allowed or not destination or not encoded
            or (destination.get("transport") == "codex-desktop" and destination.get("id") == VICE_THREAD)):
        raise PermissionError("Cloud return is unavailable for this route.")
    stamp, nonce = verify_proof(encoded, "DELEGATE", target, header.removeprefix(RETURN_HEADER),
                                message.encode("utf-8"), time.time() if observed is None else observed)
    identity = "\n".join((target, stamp, nonce, message))
    rid = hashlib.sha256(("vice-delegate:" + identity).encode()).hexdigest()[:32]
    return rid, message


def return_id(parent, *, late=False):
    prefix = "vice-late-return:" if late else "vice-return:"
    return hashlib.sha256((prefix + parent).encode()).hexdigest()[:32]


def claim_return(bridge, proof_id, rid):
    with bridge.database("worker") as conn:
        conn.execute("""CREATE TABLE IF NOT EXISTS vice_return_claims (
            proof_id TEXT PRIMARY KEY, request_id TEXT NOT NULL, created REAL NOT NULL
        )""")
        conn.execute("DELETE FROM vice_return_claims WHERE created<?", (time.time() - bridge.DAY,))
        conn.execute("INSERT OR IGNORE INTO vice_return_claims VALUES (?,?,?)", (proof_id, rid, time.time()))
        return conn.execute("SELECT request_id FROM vice_return_claims WHERE proof_id=?", (proof_id,)).fetchone() == (rid,)


def authorize_queued_return(bridge, data, config):
    rid = data["request_id"]
    if data.get("signed_vice_return") is True:
        proof = data.get("vice_return_claim", rid)
        if not claim_return(bridge, proof, rid):
            raise PermissionError("A callback request already used this proof.")
        return
    if data["message"].startswith(RETURN_HEADER):
        proof, body = approve_return(bridge, data["client"], data["target"], config, data["message"],
                                     observed=data["created"])
        if not claim_return(bridge, proof, rid):
            raise PermissionError("A callback request already used this proof.")
        data.update(message=body, signed_vice_return=True, vice_return_claim=proof)


def notify_returns(bridge, config):
    receiver = config["targets"].get(VICE_ALIAS, {})
    if not key_for(config, VICE_ALIAS, receiver):
        return
    client = config["clients"].get("codex")
    if not client or VICE_ALIAS not in client["allow"]:
        return
    with bridge.database("worker") as conn:
        completed = conn.execute(
            """SELECT id FROM audit WHERE client='codex' AND target<>? AND created>?
               AND state IN ('replied','reply_failed','reply_expired','send_rejected','target_denied')""",
            (VICE_ALIAS, time.time() - bridge.DAY),
        ).fetchall()
    for parent, in completed:
        rid = return_id(parent)
        if not bridge.location("requests", parent).is_file():
            continue
        try:
            result = bridge.verify(bridge.load(bridge.location("results", parent)), client["key"])
            late = result["state"] == "replied" and result.get("receipt") == "desktop_late_reply"
            if late and (bridge.location("requests", rid).exists() or bridge.location("results", rid).exists()):
                rid = return_id(parent, late=True)
            else:
                late = False
            if bridge.location("requests", rid).exists() or bridge.location("results", rid).exists():
                continue
            original = bridge.verify(bridge.load(bridge.location("requests", parent)), client["key"])
            authorize_queued_return(bridge, original, config)
            if original.get("signed_vice_return") is not True:
                continue
            target = original["target"]
            if (result["request_id"] != parent or result["target"] != target
                    or result["state"] not in RETURN_STATES):
                continue
            body = reply_excerpt(result.get("reply", ""), limit=None)
            message = f"[작업 회신] {target} · {result['state']} · {parent}"
            if late:
                message += "\n이전 만료 알림 이후에 같은 요청의 최종 답변을 확인했습니다."
            if body:
                message += "\n" + body
                if len(message.encode()) > bridge.LIMIT:
                    message = body
            data = {"request_id": rid, "client": "codex", "target": VICE_ALIAS, "created": time.time(),
                    "message": message,
                    "destination": bridge.destination_identity(receiver), "vice_return_of": parent}
            if late:
                data["vice_late_reply"] = True
            save_once(bridge, rid, data, client["key"])
        except (OSError, ValueError, TypeError, KeyError):
            continue


def issue_turn_lease(bridge, rid, thread, expires, *, can_reply):
    token = secrets.token_hex(32)
    with bridge.database("callback") as conn:
        conn.execute("""CREATE TABLE IF NOT EXISTS cloud_turn_leases (
            id TEXT PRIMARY KEY, thread TEXT NOT NULL, token_hash TEXT NOT NULL,
            expires REAL NOT NULL, can_reply INTEGER NOT NULL
        )""")
        conn.execute("DELETE FROM cloud_turn_leases WHERE expires <= ?", (time.time(),))
        conn.execute("INSERT OR REPLACE INTO cloud_turn_leases VALUES (?,?,?,?,?)",
                     (rid, thread, bridge.token_hash(token), expires, can_reply))
    return token


def active_turn_access(bridge, rid, method, token, body):
    from codex_outbound import eligible

    if not bridge.TOKEN.fullmatch(token):
        raise PermissionError("Invalid cloud inbox authorization.")
    with bridge.database("callback") as conn:
        desktop_mailbox.setup(conn)
        conn.execute("BEGIN IMMEDIATE")
        try:
            row = conn.execute(
                "SELECT thread,token_hash,can_reply FROM cloud_turn_leases WHERE id=? AND expires>?",
                (rid, time.time()),
            ).fetchone()
        except sqlite3.OperationalError as error:
            raise PermissionError("Cloud inbox is unavailable.") from error
        if not row or not hmac.compare_digest(row[1], bridge.token_hash(token)):
            raise PermissionError("Invalid cloud inbox authorization.")
        thread, _, can_reply = row
        data, policy = desktop_mailbox.request_data(bridge, rid, thread, conn, "durable")
        config = bridge.secret_file(bridge.BASE / "worker.json")
        if not eligible(config["targets"].get(data["target"], {})):
            raise PermissionError("Cloud inbox is unavailable.")
        if method == "GET":
            return {"request_id": rid, "source": policy["label"], "message": data["message"]}
        if not can_reply or data.get("vice_return_of"):
            raise PermissionError("A completion notification only supports reading.")
        reply = body.decode("utf-8")
        bridge.validate_message(reply)
        if not conn.execute("UPDATE desktop_mailbox SET reply=? WHERE id=? AND reply IS NULL",
                            (reply, rid)).rowcount:
            raise PermissionError("Cloud inbox authorization was already used.")
        conn.execute("DELETE FROM cloud_turn_leases WHERE id=?", (rid,))


def access(bridge, method, path, authorization, body):
    match = PATH.fullmatch(path)
    if not match or method not in {"GET", "POST"}:
        raise PermissionError("Cloud inbox authorization required.")
    rid = match[1]
    if authorization.startswith("Bearer "):
        return active_turn_access(bridge, rid, method, authorization.removeprefix("Bearer "), body)
    now = time.time()
    config = bridge.secret_file(bridge.BASE / "worker.json")
    destination = config["targets"].get(VICE_ALIAS, {})
    encoded = key_for(config, VICE_ALIAS, destination)
    if not encoded:
        raise PermissionError("Cloud inbox is unavailable.")
    timestamp, nonce = verify_proof(encoded, method, path, authorization, body, now)
    with bridge.database("callback") as conn:
        desktop_mailbox.setup(conn)
        conn.execute("BEGIN IMMEDIATE")
        data, policy = desktop_mailbox.request_data(bridge, rid, VICE_THREAD, conn, "durable")
        if data["target"] != VICE_ALIAS or conn.execute(
            "SELECT reply FROM desktop_mailbox WHERE id=?", (rid,)
        ).fetchone()[0] is not None:
            raise PermissionError("Cloud inbox is unavailable.")
        conn.execute("CREATE TABLE IF NOT EXISTS vice_inbox_proofs (nonce TEXT PRIMARY KEY, expires REAL)")
        conn.execute("DELETE FROM vice_inbox_proofs WHERE expires < ?", (now,))
        if not conn.execute("INSERT OR IGNORE INTO vice_inbox_proofs VALUES (?,?)",
                            (nonce, int(timestamp) + CLOCK_WINDOW)).rowcount:
            raise PermissionError("Cloud inbox authorization was already used.")
        if method == "GET":
            return {"request_id": rid, "source": policy["label"], "message": data["message"]}
        if data.get("vice_return_of"):
            raise PermissionError("A completion notification only supports reading.")
        reply = body.decode("utf-8")
        bridge.validate_message(reply)
        conn.execute("UPDATE desktop_mailbox SET reply=? WHERE id=?", (reply, rid))
