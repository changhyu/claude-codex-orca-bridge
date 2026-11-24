"""Fetch and apply a published Markdown agent roster without touching any worktree."""

import fcntl
import json
import os
from pathlib import Path
import subprocess

from bridge_settings import GIT_CLI, ROSTER_BRANCH, ROSTER_GIT_URL
import cloud_roster
import orca_bridge
from register_orca_adapter import blockers
import secure_bridge as bridge


URL = ROSTER_GIT_URL
BRANCH = ROSTER_BRANCH
CACHE_REF = "refs/remotes/origin/bridge-roster"
GIT = GIT_CLI


def git(*args):
    return subprocess.run([GIT, *args], capture_output=True, text=True, check=True, timeout=30,
                          env={**os.environ, "GIT_TERMINAL_PROMPT": "0"}).stdout.strip()


def source(cache):
    if not URL:
        raise ValueError("Set BRIDGE_ROSTER_GIT_URL before running sync_cloud_roster.py.")
    def repo(*args):
        return git("--git-dir", str(cache), *args)

    if not (cache / "HEAD").exists():
        git("init", "--bare", str(cache))
        repo("remote", "add", "origin", URL)
        repo("config", "remote.origin.promisor", "true")
        repo("config", "remote.origin.partialclonefilter", "blob:none")
    line = repo("ls-remote", "--exit-code", "origin", BRANCH)
    tip, ref = line.split("\t")
    if ref != BRANCH:
        raise ValueError("Unexpected roster branch.")
    try:
        cached_tip = repo("rev-parse", "--verify", CACHE_REF)
    except subprocess.CalledProcessError:
        cached_tip = None
    if cached_tip != tip:
        repo("fetch", "--quiet", "--no-tags", "--no-write-fetch-head", "--depth=1",
             "--filter=blob:none", "origin", f"+{BRANCH}:{CACHE_REF}")
    roster = cloud_roster.parse(repo("show", f"{CACHE_REF}:{cloud_roster.ROSTER}"))
    policy = repo("show", f"{CACHE_REF}:CLAUDE.md")
    inventory = orca_bridge.invoke("list", "--worktree", f"path:{cloud_roster.REPOSITORY}", "--limit", "1000")
    if inventory.get("truncated"):
        raise ValueError("Cannot reconcile local roles against a truncated Orca inventory.")
    return cloud_roster.apply_published_assignments(roster, policy, inventory["terminals"],
                                                   orca_bridge.describe_terminal, blockers)


def main():
    os.umask(0o077)
    bridge.ensure_state()
    entries = source(bridge.BASE / "roster-remote.git")
    with (bridge.ROOT / "enrollment.lock").open("a") as lock:
        fcntl.flock(lock, fcntl.LOCK_EX)
        worker_path = bridge.BASE / "worker.json"
        config = bridge.secret_file(worker_path)
        previous = json.dumps(config, sort_keys=True)
        cloud_roster.sync(config, entries)
        if json.dumps(config, sort_keys=True) == previous:
            return
        bridge.put(worker_path, config)
        for filename in ("client.json", "agent-client.json"):
            path = bridge.BASE / filename
            client = bridge.secret_file(path)
            client["allow"] = config["clients"][client["id"]]["allow"]
            bridge.put(path, client)
    print("Cloud roster destinations:", sum(row.get("source") == "bridge-roster" for row in config["targets"].values()))


if __name__ == "__main__":
    main()
