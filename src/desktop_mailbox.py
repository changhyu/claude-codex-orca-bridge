"""Recipient-bound request and reply storage for active local Codex turns."""

import argparse
import json
import os
from pathlib import Path
import sqlite3
import sys
import tempfile
import time


INCOMING = Path(os.environ.get("BRIDGE_MAILBOX_DIR", str(Path(__file__).resolve().parent / "state" / "mailbox-replies")))


def setup(conn):
    conn.execute("""CREATE TABLE IF NOT EXISTS desktop_mailbox (
        id TEXT PRIMARY KEY, thread TEXT NOT NULL, expires REAL NOT NULL, reply TEXT
    )""")


def prepare(bridge, rid, thread, expires):
    with bridge.database("callback") as conn:
        setup(conn)
        conn.execute("INSERT OR IGNORE INTO desktop_mailbox VALUES (?,?,?,NULL)", (rid, thread, expires))
        return conn.execute("SELECT thread,expires FROM desktop_mailbox WHERE id=?", (rid,)).fetchone() == (thread, expires)


def discard(bridge, rid):
    with bridge.database("callback") as conn:
        setup(conn)
        conn.execute("DELETE FROM desktop_mailbox WHERE id=? AND reply IS NULL", (rid,))


def request_data(bridge, rid, thread, conn, host="local"):
    row = conn.execute("SELECT thread,expires FROM desktop_mailbox WHERE id=?", (rid,)).fetchone()
    if not row or row[0] != thread or row[1] <= time.time():
        raise ValueError("No received request for this Codex chat.")
    config = bridge.secret_file(bridge.BASE / "worker.json")
    envelope = bridge.load(bridge.location("requests", rid))
    policy = config["clients"][envelope["data"]["client"]]
    data = bridge.verify(envelope, policy["key"])
    alias = data["target"]
    destination = config["targets"].get(alias, {})
    if (data["request_id"] != rid or alias not in policy["allow"] or destination.get("transport") != "codex-desktop"
            or destination.get("id") != thread or destination.get("host", "local") != host
            or "destination" in data and data["destination"] != bridge.destination_identity(destination)):
        raise ValueError("Bridge request destination no longer matches this Codex chat.")
    return data, policy


def access(bridge, rid, thread, reply=None):
    if not thread or not bridge.REQUEST_ID.fullmatch(rid):
        raise ValueError("Open this request from its receiving Codex chat.")
    with bridge.database("callback") as conn:
        setup(conn)
        data, policy = request_data(bridge, rid, thread, conn)
        if reply is None:
            return {"request_id": rid, "source": policy["label"], "message": data["message"]}
        if data.get("completion_of"):
            raise ValueError("A completion notification only supports reading.")
        bridge.validate_message(reply)
        if conn.execute("SELECT reply FROM desktop_mailbox WHERE id=?", (rid,)).fetchone()[0] is not None:
            raise ValueError("This request already has a reply or has expired.")
        signed = {"request_id": rid, "thread": thread, "reply": reply}
        stage_reply(rid, {"data": signed, "signature": bridge.mac(policy["key"], signed)})
        return {"request_id": rid, "state": "reply_queued"}


def stage_reply(rid, envelope):
    INCOMING.mkdir(mode=0o700, exist_ok=True)
    info = INCOMING.lstat()
    if INCOMING.is_symlink() or not INCOMING.is_dir() or info.st_uid != os.getuid() or info.st_mode & 0o077:
        raise ValueError("The mailbox reply directory is unavailable.")
    fd, temporary = tempfile.mkstemp(dir=INCOMING, prefix="reply-")
    try:
        with os.fdopen(fd, "w", encoding="utf-8") as stream:
            json.dump(envelope, stream, ensure_ascii=False)
        try:
            os.link(temporary, INCOMING / (rid + ".json"))
        except FileExistsError as error:
            raise ValueError("A reply is already queued.") from error
    finally:
        Path(temporary).unlink(missing_ok=True)


def import_replies(bridge, conn):
    if INCOMING.is_symlink():
        return
    for path in INCOMING.glob("*.json"):
        rid = path.stem
        if not bridge.REQUEST_ID.fullmatch(rid):
            continue
        try:
            staged = bridge.load(path)
            data = staged["data"]
            _, policy = request_data(bridge, rid, data["thread"], conn)
            data = bridge.verify(staged, policy["key"])
            if data["request_id"] != rid:
                raise ValueError("Mismatched mailbox reply.")
            bridge.validate_message(data["reply"])
            conn.execute("UPDATE desktop_mailbox SET reply=? WHERE id=? AND reply IS NULL AND expires>?",
                         (data["reply"], rid, time.time()))
        except (KeyError, OSError, TypeError, ValueError):
            pass
        conn.commit()
        path.unlink(missing_ok=True)


def collect(bridge, config):
    with bridge.database("callback") as conn:
        setup(conn)
        import_replies(bridge, conn)
        rows = conn.execute("SELECT id,expires,reply FROM desktop_mailbox").fetchall()
        conn.execute("DELETE FROM desktop_mailbox WHERE expires < ?", (time.time() - bridge.DAY,))
    with bridge.database("worker") as conn:
        active = {rid: (client, target) for rid, client, target in conn.execute(
            "SELECT id,client,target FROM audit WHERE state IN ('delivered','delivery_unknown')"
        )}
    for rid, expires, reply in rows:
        if rid not in active:
            continue
        client, target = active[rid]
        policy = config["clients"].get(client)
        if not policy:
            continue
        if reply is not None:
            bridge.publish(rid, client, target, "replied", policy["key"], reply=reply, receipt="desktop_mailbox")
        elif expires <= time.time():
            bridge.publish(rid, client, target, "reply_expired", policy["key"])
    return {rid for rid, _, _ in rows}


if __name__ == "__main__":
    import secure_bridge as bridge

    os.umask(0o077)
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("request_id")
    parser.add_argument("--reply", action="store_true")
    args = parser.parse_args()
    try:
        response = access(bridge, args.request_id, os.environ.get("CODEX_THREAD_ID"),
                          sys.stdin.read(bridge.LIMIT + 1) if args.reply else None)
    except (KeyError, TypeError, ValueError, OSError, sqlite3.Error):
        print(json.dumps({"error": "This request is unavailable for the current Codex chat."}))
        raise SystemExit(1)
    print(json.dumps(response, ensure_ascii=False))


