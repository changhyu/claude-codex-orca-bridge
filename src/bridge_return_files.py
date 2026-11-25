"""Request-scoped cloud result uploads and authenticated retrieval by their sender."""
import base64
import hashlib
import hmac
import json
import os
import re
import secrets
import shutil
import stat
import time

import bridge_files as files

PATH = re.compile(r'/v1/return-files/([a-f0-9]{32})')
MAX_BODY = 4 * ((files.MAX_BYTES + 2) // 3) + 8192


class Conflict(ValueError):
    pass


def setup(conn):
    conn.execute('''CREATE TABLE IF NOT EXISTS return_file_grants (
        id TEXT PRIMARY KEY, token_hash TEXT NOT NULL, expires REAL NOT NULL, bundle TEXT
    )''')


def issue(bridge, rid):
    if not bridge.REQUEST_ID.fullmatch(rid):
        raise ValueError('Invalid request ID.')
    token, expires = secrets.token_hex(32), time.time() + files.LIFETIME
    with bridge.database('callback') as conn:
        setup(conn)
        conn.execute('INSERT INTO return_file_grants VALUES (?,?,?,NULL)', (rid, bridge.token_hash(token), expires))
    return token, expires


def notice(bridge, origin, rid, token):
    return ('\n\n[Return-Upload] POST application/json '
            f'{bridge.origin(origin)}/v1/return-files/{rid} '
            '(201/200, <=5 files/5MiB, 4h TTL, no-redirect, secret)\n'
            f'Authorization: Bearer {token}\n'
            'Body: {"attachments":[{"name":"result.txt","content_base64":"..."}]}')


def request_data(bridge, rid, client=None):
    config = bridge.secret_file(bridge.BASE / 'worker.json')
    envelope = bridge.load(bridge.location('requests', rid))
    policy = config['clients'][envelope['data']['client']]
    if client is not None and (envelope['data']['client'] != client['id'] or policy['key'] != client['key']):
        raise PermissionError('Only the original sender may retrieve result files.')
    data = bridge.verify(envelope, policy['key'])
    destination = config['targets'].get(data['target'])
    if (data['request_id'] != rid or not data.get('receive_files') or data['target'] not in policy['allow']
            or not destination or data.get('destination') != bridge.destination_identity(destination)):
        raise PermissionError('Result file recipient is no longer authorized.')
    return data, policy


def authorize(bridge, path, authorization):
    match = PATH.fullmatch(path)
    if not match or not isinstance(authorization, str) or not authorization.startswith('Bearer '):
        raise PermissionError('Result upload authorization required.')
    rid, token = match[1], authorization.removeprefix('Bearer ')
    if not bridge.TOKEN.fullmatch(token):
        raise PermissionError('Result upload authorization required.')
    with bridge.database('callback') as conn:
        setup(conn)
        row = conn.execute('SELECT token_hash,expires FROM return_file_grants WHERE id=?', (rid,)).fetchone()
    if not row or row[1] <= time.time() or not hmac.compare_digest(row[0], bridge.token_hash(token)):
        raise PermissionError('Result upload authorization required.')
    data, policy = request_data(bridge, rid)
    return rid, data, policy


def storage_bytes(bridge):
    return sum(p.stat().st_size for bucket in ('files', 'returned-files')
               for p in (bridge.ROOT / bucket).glob('*/*') if p.is_file() and not p.is_symlink())


def upload(bridge, path, authorization, raw):
    rid, data, policy = authorize(bridge, path, authorization)
    if not isinstance(raw, bytes) or not 0 < len(raw) <= MAX_BODY:
        raise ValueError('Invalid upload size.')
    payload = json.loads(raw)
    if not isinstance(payload, dict) or set(payload) != {'attachments'}:
        raise ValueError('Expected attachments only.')
    decoded = files.decode(payload['attachments'])
    manifest = [{'name': name, 'size': len(content), 'sha256': hashlib.sha256(content).hexdigest()}
                for name, content in decoded]
    root = bridge.ROOT / 'returned-files'
    files.private_directory(root)
    purge(bridge)
    folder = root / rid
    with bridge.database('callback') as conn:
        setup(conn)
        conn.execute('BEGIN IMMEDIATE')
        row = conn.execute('SELECT expires,bundle FROM return_file_grants WHERE id=?', (rid,)).fetchone()
        if not row or row[0] <= time.time():
            raise PermissionError('Expired upload grant.')
        if row[1]:
            existing = bridge.verify(json.loads(row[1]), policy['key'])
            if existing['attachments'] != manifest:
                raise Conflict('A different result bundle already exists.')
            return 200, {'request_id': rid, 'state': 'files_received', 'files': manifest}
        if storage_bytes(bridge) + sum(item['size'] for item in manifest) > files.MAX_STORED_BYTES:
            raise ValueError('Attachment storage quota reached.')
        if folder.exists() or folder.is_symlink():
            files.private_directory(folder)
            shutil.rmtree(folder)  # Recover an uncommitted upload after a worker crash.
        folder.mkdir(mode=0o700)
        try:
            for index, (_, content) in enumerate(decoded):
                with (folder / str(index)).open('xb') as stream:
                    os.fchmod(stream.fileno(), 0o600)
                    stream.write(content)
            bundle = {'request_id': rid, 'client': data['client'], 'target': data['target'],
                      'destination': data['destination'], 'attachments': manifest}
            signed = {'data': bundle, 'signature': bridge.mac(policy['key'], bundle)}
            conn.execute('UPDATE return_file_grants SET bundle=? WHERE id=?', (json.dumps(signed), rid))
        except Exception:
            shutil.rmtree(folder)
            raise
    return 201, {'request_id': rid, 'state': 'files_received', 'files': manifest}


def receive(bridge, rid, client, include_content=False):
    data, policy = request_data(bridge, rid, client)
    with bridge.database('callback') as conn:
        setup(conn)
        row = conn.execute('SELECT expires,bundle FROM return_file_grants WHERE id=?', (rid,)).fetchone()
    if not row or row[0] <= time.time():
        raise ValueError('Result files have expired.')
    if not row[1]:
        return {'request_id': rid, 'state': 'awaiting_files', 'files': []}
    bundle = bridge.verify(json.loads(row[1]), policy['key'])
    if any(bundle.get(k) != data[k] for k in ('request_id', 'client', 'target', 'destination')):
        raise PermissionError('Mismatched result bundle.')
    result = []
    root, folder = bridge.ROOT / 'returned-files', bridge.ROOT / 'returned-files' / rid
    files.private_directory(root)
    files.private_directory(folder)
    for index, manifest in enumerate(bundle['attachments']):
        fd = os.open(folder / str(index), os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK)
        with os.fdopen(fd, 'rb') as stream:
            info = os.fstat(stream.fileno())
            if not stat.S_ISREG(info.st_mode) or info.st_uid != os.getuid() or info.st_mode & 0o077:
                raise PermissionError('Invalid result file storage.')
            content = stream.read(files.MAX_BYTES + 1)
        if len(content) != manifest['size'] or hashlib.sha256(content).hexdigest() != manifest['sha256']:
            raise PermissionError('Result file integrity check failed.')
        result.append({**manifest, **({'content_base64': base64.b64encode(content).decode()} if include_content else {})})
    return {'request_id': rid, 'state': 'files_received', 'files': result}


def discard(bridge, rid):
    with bridge.database('callback') as conn:
        setup(conn)
        conn.execute('DELETE FROM return_file_grants WHERE id=?', (rid,))
    folder = bridge.ROOT / 'returned-files' / rid
    if folder.is_dir() and not folder.is_symlink():
        shutil.rmtree(folder)


def purge(bridge):
    root = bridge.ROOT / 'returned-files'
    with bridge.database('callback') as conn:
        setup(conn)
        conn.execute('DELETE FROM return_file_grants WHERE expires <= ?', (time.time(),))
        active = {row[0] for row in conn.execute('SELECT id FROM return_file_grants')}
    if not root.exists():
        return
    files.private_directory(root)
    for folder in root.iterdir():
        if (bridge.REQUEST_ID.fullmatch(folder.name) and not folder.is_symlink() and folder.is_dir()
                and folder.name not in active and folder.stat().st_mtime < time.time() - 60):
            shutil.rmtree(folder)
