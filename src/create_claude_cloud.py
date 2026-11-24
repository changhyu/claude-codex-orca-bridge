"""Create a Claude Cloud session for the configured repository and register its identity."""

import argparse
import hashlib
import fcntl
import json
import os
from pathlib import Path
import re
import subprocess
import sys
from urllib.parse import urlsplit

from agent_mesh import LOCAL_CLIENT, PROJECT
from bridge_settings import CLAUDE_CLI, GIT_CLI
from bridge import LIMIT
from bridge_message import normalize_message
from cloud_roster import sync_connector_targets
from mcp_server import session_id
import secure_bridge as bridge


EXPECTED_REMOTE = os.environ.get("BRIDGE_GIT_REMOTE_REGEX", "").strip()
SOURCE = "bridge-claude-created"


def git(project, *args):
    result = subprocess.run([GIT_CLI, "-C", str(project), *args], check=True,
                            capture_output=True, text=True, timeout=10)
    return result.stdout.strip()


def checkout(cwd):
    root = Path(git(cwd, "rev-parse", "--show-toplevel"))
    if git(root, "rev-parse", "--path-format=absolute", "--git-common-dir") != git(
            PROJECT, "rev-parse", "--path-format=absolute", "--git-common-dir"):
        raise ValueError("Claude Cloud creation requires the configured BRIDGE_PROJECT_DIR repository.")
    if EXPECTED_REMOTE and not re.fullmatch(EXPECTED_REMOTE, git(root, "remote", "get-url", "origin"), re.I):
        raise ValueError("Repository origin does not match BRIDGE_GIT_REMOTE_REGEX.")
    return root


def receipt(output, returncode):
    data = json.loads(output)
    if returncode != 0 or data.get("ok") is not True:
        raise ValueError("Claude did not confirm cloud session creation.")
    identity = data["session_id"]
    link = urlsplit(data["url"])
    if (session_id(identity) != identity or link.scheme != "https" or link.netloc != "claude.ai"
            or link.path != f"/code/{identity}" or link.fragment):
        raise ValueError("Claude returned an invalid cloud session receipt.")
    return identity, data["url"]


def alias_for(identity):
    return "claude-cloud-" + hashlib.sha256(identity.encode()).hexdigest()[:16]


def register(identity, title, *, source=SOURCE):
    bridge.ensure_state()
    with (bridge.ROOT / "enrollment.lock").open("a") as lock:
        fcntl.flock(lock, fcntl.LOCK_EX)
        path = bridge.BASE / "worker.json"
        config = bridge.secret_file(path)
        targets = config["targets"]
        existing = next((name for name, row in targets.items()
                         if row["transport"] == "claude" and row["id"] == identity), None)
        if existing and targets[existing].get("source") != source:
            return existing
        alias = existing or alias_for(identity)
        if (not existing and alias in targets) or alias in config.get("roster_exclusions", []):
            raise ValueError("The generated alias is unavailable.")
        if not existing:
            targets[alias] = {"transport": "claude", "id": identity, "display_name": title, "source": source}
        clients = []
        for filename in ("client.json", "agent-client.json"):
            client_path = bridge.BASE / filename
            client = bridge.secret_file(client_path)
            if client["id"] not in {"codex", LOCAL_CLIENT}:
                raise ValueError("Unexpected local bridge client.")
            policy = config["clients"][client["id"]]
            if policy["key"] != client["key"]:
                raise ValueError("Unmatched bridge client.")
            policy["allow"] = list(dict.fromkeys([*policy["allow"], alias]))
            client["allow"] = policy["allow"]
            clients.append((client_path, client))
        sync_connector_targets(config)
        bridge.put(path, config)
        for client_path, client in clients:
            bridge.put(client_path, client)
    return alias


def create(project, title, prompt):
    result = subprocess.run([CLAUDE_CLI, "-p", "--cloud", "--output-format", "json", "--name", title],
                            cwd=project, input=prompt, check=False, capture_output=True, text=True, timeout=90)
    identity, url = receipt(result.stdout, result.returncode)
    try:
        alias = register(identity, title)
    except (ValueError, OSError, KeyError) as error:
        return {"state": "created_unregistered", "url": url, "error": str(error)}
    return {"state": "registered", "alias": alias, "url": url}


def active_checkout():
    return checkout(Path.cwd())


def main():
    os.umask(0o077)
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--title", required=True)
    args = parser.parse_args()
    title = args.title.strip()
    if not title or len(title) > 80 or not title.isprintable():
        raise ValueError("Use a printable title of up to 80 characters.")
    project = active_checkout()
    prompt = normalize_message(sys.stdin.read(LIMIT + 1))
    bridge.validate_message(prompt)
    return create(project, title, prompt)


if __name__ == "__main__":
    try:
        print(json.dumps(main(), ensure_ascii=False))
    except (ValueError, OSError, KeyError, TypeError, AttributeError, subprocess.SubprocessError):
        print(json.dumps({"state": "creation_unconfirmed",
                          "error": "Check the repository or Claude Cloud session list before retrying."}))
        raise SystemExit(1)
