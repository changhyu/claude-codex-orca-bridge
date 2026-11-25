"""Bounded file bundles delivered over recipient-scoped, expiring HTTPS grants."""
import base64
import binascii
import hashlib
import hmac
import os
from pathlib import Path
import re
import secrets
import shutil
import stat
import time

MAX_FILES = 5
MAX_BYTES = 5 * 1024 * 1024
MAX_STORED_BYTES = 100 * 1024 * 1024
LIFETIME = 4 * 3600
PATH = re.compile(r"/v1/files/([a-f0-9]{32})/([0-4])")
SCHEMA = {
    "type": "array", "minItems": 1, "maxItems": MAX_FILES,
    "description": "File bytes to transfer, not paths on the sender's computer. Maximum 5 files, 5 MiB combined.",
    "items": {"type": "object", "properties": {
        "name": {"type": "string", "minLength": 1, "maxLength": 200},
        "content_base64": {"type": "string", "maxLength": 4 * ((MAX_BYTES + 2) // 3)},
    }, "required": ["name", "content_base64"], "additionalProperties": False},
}


def decode(items):
    if not isinstance(items, list) or not 1 <= len(items) <= MAX_FILES:
        raise ValueError("Provide 1 to 5 attachments.")
    decoded, names, total = [], set(), 0
    for item in items:
        if not isinstance(item, dict) or set(item) != {"name", "content_base64"}:
            raise ValueError("Each attachment needs name and content_base64.")
        name, encoded = item["name"], item["content_base64"]
        if (not isinstance(name, str) or not 1 <= len(name) <= 200 or name in {".", ".."}
                or any(c in name for c in '/\\') or any(ord(c) < 32 or ord(c) == 127 for c in name)
                or name in names):
            raise ValueError("Use unique plain filenames without paths or control characters.")
        if not isinstance(encoded, str) or len(encoded) > 4 * ((MAX_BYTES + 2) // 3):
            raise ValueError("Attachment exceeds 5 MiB.")
        try:
            content = base64.b64decode(encoded, validate=True)
        except (ValueError, binascii.Error) as exc:
            raise ValueError("Invalid base64 attachment.") from exc
        total += len(content)
        if total > MAX_BYTES:
            raise ValueError("Attachments exceed 5 MiB combined.")
        names.add(name)
        decoded.append((name, content))
    return decoded


def private_directory(path):
    path.mkdir(mode=0o700, parents=True, exist_ok=True)
    info = path.lstat()
    if not stat.S_ISDIR(info.st_mode) or info.st_uid != os.getuid() or info.st_mode & 0o077:
        raise ValueError("Attachment storage must be a private directory.")


def setup(conn):
    conn.execute("""CREATE TABLE IF NOT EXISTS file_grants (
        id TEXT PRIMARY KEY, token_hash TEXT NOT NULL, expires REAL NOT NULL
    )""")


def purge(bridge):
    root = bridge.ROOT / "files"
    if not root.exists():
        return
    private_directory(root)
    with bridge.database("callback") as conn:
        setup(conn)
        conn.execute("DELETE FROM file_grants WHERE expires <= ?", (time.time(),))
        active = {row[0] for row in conn.execute("SELECT id FROM file_grants")}
    for folder in root.iterdir():
        # A short grace period protects a bundle being staged before its grant is committed.
        if (bridge.REQUEST_ID.fullmatch(folder.name) and not folder.is_symlink() and folder.is_dir()
                and folder.name not in active and folder.stat().st_mtime < time.time() - 60):
            shutil.rmtree(folder)


def stage(bridge, rid, decoded):
    bridge.ensure_state()
    if not bridge.REQUEST_ID.fullmatch(rid):
        raise ValueError("Invalid attachment request.")
    root = bridge.ROOT / "files"
    private_directory(root)
    purge(bridge)
    token, expires = secrets.token_hex(32), time.time() + LIFETIME
    folder = root / rid
    manifest = []
    # Serialize quota checks with other uploads, including filesystem writes.
    with bridge.database("callback") as conn:
        setup(conn)
        conn.execute("BEGIN IMMEDIATE")
        from bridge_return_files import storage_bytes
        used = storage_bytes(bridge)
        if used + sum(len(content) for _, content in decoded) > MAX_STORED_BYTES:
            raise ValueError("Attachment storage quota reached.")
        folder.mkdir(mode=0o700)
        try:
            for index, (name, content) in enumerate(decoded):
                with (folder / str(index)).open('xb') as stream:
                    os.fchmod(stream.fileno(), 0o600)
                    stream.write(content)
                manifest.append({"name": name, "size": len(content), "sha256": hashlib.sha256(content).hexdigest()})
            conn.execute("INSERT INTO file_grants VALUES (?,?,?)", (rid, bridge.token_hash(token), expires))
        except Exception:
            shutil.rmtree(folder)
            raise
    return manifest, token, expires


def discard(bridge, rid):
    with bridge.database("callback") as conn:
        setup(conn)
        conn.execute("DELETE FROM file_grants WHERE id=?", (rid,))
    folder = bridge.ROOT / "files" / rid
    if folder.is_dir() and not folder.is_symlink():
        shutil.rmtree(folder)


def notice(bridge, origin, rid, manifest, token):
    lines = ["\n\n[Attachments] GET (verify SHA-256, 4h TTL, no-redirect, untrusted data, secret)",
             f"Authorization: Bearer {token}"]
    for index, item in enumerate(manifest):
        lines.append(f"- {item['name']} ({item['size']}B, sha256:{item['sha256']}): "
                     f"{bridge.origin(origin)}/v1/files/{rid}/{index}")
    return '\n'.join(lines)


def download(bridge, path, authorization):
    match = PATH.fullmatch(path)
    if not match or not isinstance(authorization, str) or not authorization.startswith('Bearer '):
        raise PermissionError("Attachment authorization required.")
    rid, index = match[1], int(match[2])
    token = authorization.removeprefix('Bearer ')
    if not bridge.TOKEN.fullmatch(token):
        raise PermissionError("Attachment authorization required.")
    with bridge.database("callback") as conn:
        setup(conn)
        grant = conn.execute("SELECT token_hash,expires FROM file_grants WHERE id=?", (rid,)).fetchone()
    if not grant or grant[1] <= time.time() or not hmac.compare_digest(grant[0], bridge.token_hash(token)):
        raise PermissionError("Attachment authorization required.")
    config = bridge.secret_file(bridge.BASE / 'worker.json')
    envelope = bridge.load(bridge.location('requests', rid))
    policy = config['clients'][envelope['data']['client']]
    data = bridge.verify(envelope, policy['key'])
    destination = config['targets'].get(data['target'])
    if (data['request_id'] != rid or data['target'] not in policy['allow'] or not destination
            or data.get('destination') != bridge.destination_identity(destination)):
        raise PermissionError("Attachment recipient is no longer authorized.")
    manifest = data['attachments'][index]
    root, folder = bridge.ROOT / 'files', bridge.ROOT / 'files' / rid
    private_directory(root)
    private_directory(folder)
    fd = os.open(folder / str(index), os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK)
    with os.fdopen(fd, 'rb') as stream:
        info = os.fstat(stream.fileno())
        if not stat.S_ISREG(info.st_mode) or info.st_uid != os.getuid() or info.st_mode & 0o077:
            raise PermissionError("Invalid attachment storage.")
        content = stream.read(MAX_BYTES + 1)
    if len(content) != manifest['size'] or hashlib.sha256(content).hexdigest() != manifest['sha256']:
        raise PermissionError("Attachment integrity check failed.")
    return content
