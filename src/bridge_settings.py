"""Centralized environment-driven settings for the Claude-Codex-Orca Secure Bridge."""

import os
from pathlib import Path
import shutil


def executable(env_key: str, default_name: str) -> str:
    override = os.environ.get(env_key, "").strip()
    if override:
        return override
    found = shutil.which(default_name)
    if found:
        return found
    fallback = Path.home() / ".local" / "bin" / default_name
    return str(fallback) if fallback.exists() else default_name


CALLBACK_ORIGIN = os.environ.get("BRIDGE_CALLBACK_ORIGIN", "https://bridge.example.com").rstrip("/")
PROJECT_DIR = Path(os.environ.get("BRIDGE_PROJECT_DIR", str(Path.cwd()))).expanduser()
ORCA_REPOSITORY = os.environ.get("BRIDGE_ORCA_REPOSITORY", "").strip().lower()
ROSTER_GIT_URL = os.environ.get("BRIDGE_ROSTER_GIT_URL", "").strip()
ROSTER_BRANCH = os.environ.get("BRIDGE_ROSTER_BRANCH", "refs/heads/main").strip()
ROSTER_PATH = os.environ.get("BRIDGE_ROSTER_PATH", "docs/AGENT_ROSTER.md").strip()
ROSTER_SECTION = os.environ.get("BRIDGE_ROSTER_SECTION", "## Agents").strip()

CLAUDE_PEER_ALIAS = os.environ.get("BRIDGE_CLAUDE_PEER_ALIAS", "claude-peer").strip()
CLAUDE_MCP_PATH = os.environ.get("BRIDGE_CLAUDE_MCP_PATH", "/mcp/claude").strip()
CLAUDE_PEER_ROUTE = os.environ.get("BRIDGE_CLAUDE_PEER_ROUTE", f"/v1/agents/{CLAUDE_PEER_ALIAS}").strip()

CODEX_ADMIN_ALIAS = os.environ.get("BRIDGE_CODEX_ADMIN_ALIAS", "codex-bridge-admin").strip()
CODEX_ADMIN_THREAD = os.environ.get("BRIDGE_CODEX_ADMIN_THREAD", "00000000-0000-0000-0000-000000000000").strip()
CODEX_CLOUD_ALIAS = os.environ.get("BRIDGE_CODEX_CLOUD_ALIAS", "codex-cloud-peer").strip()
CODEX_CLOUD_THREAD = os.environ.get("BRIDGE_CODEX_CLOUD_THREAD", "00000000-0000-0000-0000-000000000000").strip()
CODEX_ENVIRONMENTS = {
    item.strip()
    for item in os.environ.get("BRIDGE_CODEX_ENVIRONMENTS", "").split(",")
    if item.strip()
}

LAUNCHD_PREFIX = os.environ.get("BRIDGE_LAUNCHD_PREFIX", "io.agentbridge").strip()
CLAUDE_CLI = executable("BRIDGE_CLAUDE_BIN", "claude")
ORCA_CLI = executable("BRIDGE_ORCA_BIN", "orca")
CODEX_CLI = executable("BRIDGE_CODEX_BIN", "codex")
GIT_CLI = executable("BRIDGE_GIT_BIN", "git")
