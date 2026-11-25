"""Automated security, protocol, and sanitization smoke tests for the open-source bridge."""

import base64
import json
import os
from pathlib import Path
import re
import secrets
import shutil
import subprocess
import sys
import tempfile
import unittest
from unittest.mock import patch

REPO_ROOT = Path(__file__).resolve().parent.parent
SRC_DIR = REPO_ROOT / "src"
sys.path.insert(0, str(SRC_DIR))


class BridgeSmokeTest(unittest.TestCase):
    def test_release_files(self):
        patterns = [re.compile(r"(?:ghp_|gho_)[A-Za-z0-9]{20,}")]
        private_terms = os.environ.get("BRIDGE_PRIVATE_TERMS_FILE")
        if private_terms:
            terms = Path(private_terms).read_text(encoding="utf-8").splitlines()
            patterns.extend(re.compile(re.escape(term), re.I) for term in terms if term.strip())

        if (REPO_ROOT / ".git").exists():
            names = subprocess.check_output(["git", "ls-files", "-z"], cwd=REPO_ROOT)
            paths = [REPO_ROOT / os.fsdecode(name) for name in names.split(b"\0") if name]
        else:
            paths = [p for p in REPO_ROOT.rglob("*") if p.is_file() and "__pycache__" not in p.parts]
        self.assertIn(Path(__file__).resolve(), paths)
        for path in paths:
            content = path.read_text(encoding="utf-8")
            for pattern in patterns:
                self.assertFalse(pattern.search(content), f"Release scan matched in {path.relative_to(REPO_ROOT)}")

    def test_example_and_legacy_keys_are_rejected(self):
        import secure_bridge

        examples = REPO_ROOT / "examples"
        worker = json.loads((examples / "worker.example.json").read_text())
        keys = [policy["key"] for policy in worker["clients"].values()]
        keys.extend(json.loads(p.read_text())["key"] for p in examples.glob("*client.example.json"))
        for key in keys + [str(n) * 64 for n in range(4)]:
            with self.assertRaises(ValueError):
                secure_bridge.mac(key, {"message": "hello"})
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / "worker.json"
            path.write_text(json.dumps(worker))
            path.chmod(0o600)
            with self.assertRaisesRegex(ValueError, "signing key"):
                secure_bridge.secret_file(path)

    def test_cloud_discovery_requires_explicit_environment(self):
        import codex_cloud_discovery as discovery
        import secure_bridge

        state = {"id": "demo", "hostId": discovery.HOST, "environmentConfigId": "project-a"}
        for allowed in (set(), {"project-b"}):
            with patch.object(discovery, "ENVIRONMENTS", allowed):
                self.assertIsNone(discovery.destination(state, "demo"))
        with patch.object(discovery, "ENVIRONMENTS", {"project-a"}):
            route = discovery.destination(state, "demo")
            self.assertEqual(route["environmentConfigId"], "project-a")
            self.assertIsNone(discovery.destination({**state, "environmentConfigId": None}, "demo"))

        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / "worker.json"
            for stored, allowed, accepted in (
                (route, {"project-a"}, True), (route, {"project-b"}, False),
                (route, set(), False), ({**route, "environmentConfigId": None}, {"project-a"}, False),
            ):
                config = {"clients": {}, "targets": {"demo": stored}}
                path.write_text(json.dumps(config))
                path.chmod(0o600)
                with patch.object(secure_bridge, "CODEX_ENVIRONMENTS", allowed):
                    if accepted:
                        self.assertEqual(secure_bridge.secret_file(path), config)
                    else:
                        with self.assertRaisesRegex(ValueError, "out-of-scope"):
                            secure_bridge.secret_file(path)

    def test_new_install_and_peer_enrollment(self):
        import secure_bridge
        import claude_connector
        import claude_peer

        with tempfile.TemporaryDirectory() as tmp:
            src = Path(tmp) / "src"
            src.mkdir()
            for module in SRC_DIR.glob("*.py"):
                shutil.copyfile(module, src / module.name)
            state = src / "state"
            env = {**os.environ, "SECURE_BRIDGE_STATE": str(state), "BRIDGE_CLAUDE_PEER_ALIAS": "claude-peer"}
            cli = [sys.executable, "-B", str(src / "secure_bridge.py"), "configure",
                   "--origin", "https://bridge.example.com", "--claude", "session_TestInstall",
                   "--workspace-agent", "--claude-connector"]
            subprocess.run(cli, env=env, check=True, capture_output=True)
            cfg = secure_bridge.secret_file(src / "worker.json")
            self.assertEqual(set(cfg["targets"]), {"claude-peer"})
            keys = [policy["key"] for policy in cfg["clients"].values()]
            self.assertEqual(len(set(keys)), 4)
            for filename in ("worker.json", "client.json", "agent-client.json"):
                self.assertEqual((src / filename).stat().st_mode & 0o777, 0o600)
            for filename in ("client.json", "agent-client.json"):
                client = secure_bridge.secret_file(src / filename)
                self.assertEqual(client["key"], cfg["clients"][client["id"]]["key"])
            repeat = subprocess.run(cli, env=env, capture_output=True)
            self.assertNotEqual(repeat.returncode, 0)
            self.assertEqual(cfg, secure_bridge.secret_file(src / "worker.json"))

            credential = secrets.token_hex(32)
            fingerprint = secure_bridge.token_hash(credential)
            message = claude_peer.ENROLLMENT_MARKER + fingerprint
            send = {"jsonrpc": "2.0", "id": 1, "method": "tools/call", "params": {
                "name": "bridge_send", "arguments": {"target": "claude-peer", "message": message}}}
            result = subprocess.run([sys.executable, "-B", str(src / "secure_mcp.py"), str(src / "client.json")],
                                    input=json.dumps(send) + "\n", text=True, capture_output=True, env=env, check=True)
            payload = json.loads(json.loads(result.stdout)["result"]["content"][0]["text"])
            rid = payload["request_id"]
            with patch.object(secure_bridge, "BASE", src), patch.object(secure_bridge, "ROOT", state), \
                    patch.object(claude_peer, "CLAUDE_ALIAS", "claude-peer"):
                secure_bridge.audit(rid, "codex", "claude-peer", "sending")
                ticket = secure_bridge.register_reply(rid, "claude", message)
                enrollment = json.dumps({"request_id": rid, "fingerprint": fingerprint}).encode()
                status, _ = claude_peer.handle(secure_bridge, claude_peer.ROUTE + "/enroll", ticket, enrollment)
                self.assertEqual(status, 201)
                listing = json.dumps({"jsonrpc": "2.0", "id": 2, "method": "tools/call",
                                      "params": {"name": "list_agents", "arguments": {}}}).encode()
                status, response = claude_connector.handle(secure_bridge, credential, listing)
                self.assertEqual(status, 200)
                self.assertEqual(response["result"]["structuredContent"]["agents"], [])

    def test_hmac_sign_and_verify_tamper_closed(self):
        import secure_bridge

        key = secrets.token_hex(32)
        payload = {"request_id": "a" * 32, "client": "codex", "target": "orca-demo", "message": "hello"}
        sig = secure_bridge.mac(key, payload)
        verified = secure_bridge.verify({"data": payload, "signature": sig}, key)
        self.assertEqual(verified["message"], "hello")

        tampered = {**payload, "message": "tampered"}
        with self.assertRaises(ValueError):
            secure_bridge.verify({"data": tampered, "signature": sig}, key)

    def test_envelope_normalization_strips_header_and_preserves_body(self):
        import bridge_message

        rid = "b" * 32
        tok = "c" * 64
        wrapped = bridge_message.claude_prompt("https://bridge.example.com", rid, tok, "Run unit tests please.")
        self.assertIn("Bridge-Forward:", wrapped)
        self.assertEqual(bridge_message.normalize_message(wrapped), "Run unit tests please.")

    def test_secure_mcp_send_status_and_file_attachments(self):
        with tempfile.TemporaryDirectory() as tmp:
            tmp_path = Path(tmp)
            os.chmod(tmp_path, 0o700)
            os.environ["SECURE_BRIDGE_STATE"] = str(tmp_path / "state")

            import importlib
            import secure_bridge
            import secure_mcp
            import bridge_files

            importlib.reload(secure_bridge)
            importlib.reload(secure_mcp)
            secure_bridge.BASE = tmp_path

            codex_key = secrets.token_hex(32)
            worker_cfg = {
                "https_origin": "https://bridge.example.com",
                "clients": {
                    "codex": {"key": codex_key, "allow": ["claude-peer"], "label": "Codex MCP"}
                },
                "targets": {
                    "claude-peer": {"transport": "claude", "id": "session_TestSession1234567890"}
                },
            }
            client_cfg = {"id": "codex", "key": codex_key, "allow": ["claude-peer"], "label": "Codex MCP"}

            worker_file = tmp_path / "worker.json"
            worker_file.write_text(json.dumps(worker_cfg), encoding="utf-8")
            os.chmod(worker_file, 0o600)

            init_resp = secure_mcp.respond({"jsonrpc": "2.0", "id": 1, "method": "initialize", "params": {}}, client_cfg)
            self.assertEqual(init_resp["result"]["serverInfo"]["name"], "secure-mac-bridge")

            tools_resp = secure_mcp.respond({"jsonrpc": "2.0", "id": 2, "method": "tools/list", "params": {}}, client_cfg)
            tool_names = {t["name"] for t in tools_resp["result"]["tools"]}
            self.assertIn("bridge_send", tool_names)
            self.assertIn("bridge_status", tool_names)

            content_bytes = b"hello attachment world"
            send_resp = secure_mcp.call(
                "bridge_send",
                {
                    "target": "claude-peer",
                    "message": "Check attached note",
                    "attachments": [
                        {"name": "note.txt", "content_base64": base64.b64encode(content_bytes).decode()}
                    ],
                },
                client_cfg,
            )
            self.assertEqual(send_resp["state"], "pending_mac")
            rid = send_resp["request_id"]

            status_resp = secure_mcp.call("bridge_status", {"request_id": rid}, client_cfg)
            self.assertEqual(status_resp["request_id"], rid)
            self.assertEqual(status_resp["state"], "pending_mac")

            saved_env = secure_bridge.load(secure_bridge.location("requests", rid))
            token_match = re.search(r"Authorization: Bearer ([0-9a-f]{64})", saved_env["data"]["message"])
            self.assertIsNotNone(token_match)
            downloaded = bridge_files.download(
                secure_bridge, f"/v1/files/{rid}/0", f"Bearer {token_match.group(1)}"
            )
            self.assertEqual(downloaded, content_bytes)

    def test_no_reply_delivers_clean_notification_without_callback_token(self):
        with tempfile.TemporaryDirectory() as tmp:
            tmp_path = Path(tmp)
            os.environ["SECURE_BRIDGE_STATE"] = str(tmp_path / "state")

            import importlib
            import secure_bridge
            import secure_mcp

            importlib.reload(secure_bridge)
            importlib.reload(secure_mcp)
            secure_bridge.BASE = tmp_path
            secure_bridge.ensure_state()

            codex_key = secrets.token_hex(32)
            session_id = "session_NoticeTarget123456789012"
            worker_cfg = {
                "https_origin": "https://bridge.example.com",
                "clients": {
                    "codex": {"key": codex_key, "allow": ["claude-peer"], "label": "Codex MCP"}
                },
                "targets": {
                    "claude-peer": {"transport": "claude", "id": session_id}
                },
            }
            client_cfg = {"id": "codex", "key": codex_key, "allow": ["claude-peer"], "label": "Codex MCP"}
            worker_file = tmp_path / "worker.json"
            worker_file.write_text(json.dumps(worker_cfg), encoding="utf-8")
            os.chmod(worker_file, 0o600)

            with self.assertRaises(ValueError):
                secure_mcp.call(
                    "bridge_send",
                    {"target": "claude-peer", "message": "conflict", "no_reply": True, "reply_to": "orca-123"},
                    client_cfg,
                )

            send_resp = secure_mcp.call(
                "bridge_send",
                {"target": "claude-peer", "message": "One-way routing update", "no_reply": True},
                client_cfg,
            )
            rid = send_resp["request_id"]
            req_path = secure_bridge.location("requests", rid)

            captured = {}

            def fake_run(cmd, *, input=None, **kwargs):
                captured["prompt"] = input
                return subprocess.CompletedProcess(cmd, 0, stdout=json.dumps({"ok": True, "session_id": session_id}), stderr="")

            with patch("secure_bridge.subprocess.run", side_effect=fake_run):
                secure_bridge.process(req_path, worker_cfg)

            # Must not wrap with Bearer token envelope and must finalize as delivered
            self.assertEqual(captured["prompt"], "One-way routing update")
            self.assertNotIn("Bearer:", captured["prompt"])
            status_resp = secure_mcp.call("bridge_status", {"request_id": rid}, client_cfg)
            self.assertEqual(status_resp["state"], "delivered")
            with secure_bridge.database("callback") as con:
                row = con.execute("SELECT 1 FROM replies WHERE id=?", (rid,)).fetchone()
            self.assertIsNone(row)

    def test_orca_sync_preserves_display_name_and_admin_rebind_rename(self):
        import bridge_admin
        import register_orca_adapter

        key = secrets.token_hex(32)
        alias = "orca-aaaa1111-2222-3333-4444-555566667777"
        handle = "term_aaaa1111-2222-3333-4444-555566667777"
        worker = {
            "https_origin": "https://bridge.example.com",
            "clients": {"codex": {"key": key, "allow": [alias, "claude-peer"], "manage_destinations": True}},
            "targets": {
                alias: {
                    "transport": "orca",
                    "id": handle,
                    "incarnation": "inc-old",
                    "display_name": "Local Lead Agent",
                    "project_live_orca": True,
                },
                "claude-peer": {
                    "transport": "claude",
                    "id": "session_OldPeerSession1234567890",
                    "display_name": "Cloud Coordinator",
                },
            },
            "claude_connector_roster_names": {"claude-peer": "Cloud Coordinator"},
        }
        client = {"id": "codex", "key": key, "allow": [alias, "claude-peer"]}
        live_rows = [{
            "handle": handle,
            "incarnationId": "inc-new",
            "executionHostId": "local",
            "connected": True,
            "writable": True,
            "agentIdentity": "antigravity",
        }]
        updated, _ = register_orca_adapter.update(worker, client, live_rows, "sync", None)
        self.assertEqual(updated[alias]["incarnation"], "inc-new")
        self.assertEqual(updated[alias]["display_name"], "Local Lead Agent")
        self.assertTrue(updated[alias]["project_live_orca"])

        rebound = bridge_admin.changes(
            worker, client, {"action": "rebind_claude", "alias": "claude-peer", "session_id": "session_NewPeerSession9876543210"}
        )
        self.assertEqual(rebound["id"], "session_NewPeerSession9876543210")
        self.assertEqual(worker["targets"]["claude-peer"]["display_name"], "Cloud Coordinator")

        renamed = bridge_admin.changes(
            worker, client, {"action": "rename", "alias": "claude-peer", "display_name": "Cloud Coordinator v2"}
        )
        self.assertEqual(renamed["display_name"], "Cloud Coordinator v2")
        self.assertEqual(worker["claude_connector_roster_names"]["claude-peer"], "Cloud Coordinator v2")


if __name__ == "__main__":
    unittest.main()
