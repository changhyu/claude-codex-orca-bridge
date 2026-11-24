"""Synchronize cloud bridge destinations from a Markdown agent roster."""

import hashlib
from pathlib import Path
import re
import subprocess

from bridge_settings import GIT_CLI, PROJECT_DIR, ROSTER_BRANCH, ROSTER_PATH, ROSTER_SECTION


REPOSITORY = PROJECT_DIR
REF = ROSTER_BRANCH
ROSTER = ROSTER_PATH
ORGANIZATION = ROSTER_SECTION
CONNECTOR_CLIENT = "claude_roster_connector"
DISCOVERED_CLOUD_SOURCES = {
    "bridge-claude-created",
    "codex-bridge-environment",
}
PINNED_ROLES = {}

CLAUDE = re.compile(r"`(session_[A-Za-z0-9]{20,48})`")
CODEX = re.compile(
    r"(?:\[[^\]\n]+\]\()?codex://threads/"
    r"([0-9a-f]{8}(?:-[0-9a-f]{4}){3}-[0-9a-f]{12})\?hostId=durable\)?"
)


def parse(document):
    heading = ORGANIZATION.lstrip("#").strip()
    sections = re.split(r"(?m)^## ", document)
    section = next((part for part in sections if part.splitlines()[:1] == [heading]), None)
    if section is None:
        raise ValueError("Agent roster section not found.")
    entries = {}
    for line in section.splitlines():
        if not line.startswith("|"):
            continue
        cells = [part.strip() for part in line.strip("|").split("|")]
        if len(cells) < 3:
            continue
        role, session, _ = cells[:3]
        if not role:
            continue
        claude, codex = CLAUDE.fullmatch(session), CODEX.fullmatch(session)
        if not claude and not codex:
            continue
        provider = "claude" if claude else "codex"
        key = hashlib.sha256(role.encode()).hexdigest()[:12]
        alias = PINNED_ROLES.get(role, f"{provider}-cloud-{key}")
        if alias in entries:
            raise ValueError("Duplicate cloud role.")
        entries[alias] = {
            "id": (claude or codex)[1], "transport": "claude" if claude else "codex-desktop",
            "display_name": role, "source": "bridge-roster",
            **({"host": "durable"} if codex else {}),
        }
    if not entries:
        raise ValueError("Empty cloud roster.")
    return entries


def read():
    result = subprocess.run(
        [GIT_CLI, "-C", str(REPOSITORY), "show", f"{REF}:{ROSTER}"],
        capture_output=True, text=True, check=True, timeout=8,
    )
    return parse(result.stdout)


def apply_published_assignments(discovered, _policy="", _terminals=(), _describe=None, _blockers=None):
    """Return discovered roster entries (hook for optional local assignment overrides)."""
    return dict(discovered)


def sync_connector_targets(config):
    policy = config["clients"].get(CONNECTOR_CLIENT)
    if policy is None:
        return
    published = set(config.get("claude_connector_roster", []))
    exclusions = set(config.get("roster_exclusions", []))
    local_inboxes = config.get("connector_local_inboxes", {})
    policy["allow"] = sorted(
        name for name, row in config["targets"].items()
        if name not in exclusions and (
            name in published or row.get("source") in DISCOVERED_CLOUD_SOURCES
            or row["transport"] == "orca" and (row.get("auto_discovered") is True or row.get("project_live_orca") is True)
            or (row["transport"] == "codex-desktop" and row.get("host", "local") == "local"
                and local_inboxes.get(name) == row["id"])
        )
    )


def sync(config, discovered):
    targets = config["targets"]
    managed = {name for name, row in targets.items() if row.get("source") == "bridge-roster"}
    pinned = {name: row for name, row in targets.items() if name not in managed}
    identities = {(row["transport"], row["id"]) for row in pinned.values()}
    visible = {
        name: row for name, row in discovered.items()
        if name not in pinned and (row["transport"], row["id"]) not in identities
        and name not in config.get("roster_exclusions", [])
    }
    config["targets"] = {**pinned, **visible}
    published_ids = {(row["transport"], row["id"]) for row in discovered.values()}
    exclusions = set(config.get("roster_exclusions", []))
    config["claude_connector_roster"] = sorted(
        name for name, row in config["targets"].items()
        if name not in exclusions and (row["transport"], row["id"]) in published_ids
    )
    names = {(row["transport"], row["id"]): row["display_name"] for row in discovered.values()}
    config["claude_connector_roster_names"] = {
        alias: names[(config["targets"][alias]["transport"], config["targets"][alias]["id"])]
        for alias in config["claude_connector_roster"]
    }
    for client_id, client in config["clients"].items():
        if client_id == CONNECTOR_CLIENT:
            continue
        allowed = [name for name in client["allow"] if name not in managed]
        if client_id in {"codex", "workspace_agent"}:
            allowed.extend(visible)
        client["allow"] = list(dict.fromkeys(allowed))
    sync_connector_targets(config)
