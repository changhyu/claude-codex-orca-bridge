"""Automated security, protocol, and sanitization smoke tests for the open-source bridge."""

import base64
import json
import os
from pathlib import Path
import re
import secrets
import sys
import tempfile
import unittest

REPO_ROOT = Path(__file__).resolve().parent.parent
SRC_DIR = REPO_ROOT / "src"
sys.path.insert(0, str(SRC_DIR))


class BridgeSmokeTest(unittest.TestCase):
    def test_no_proprietary_identifiers_anywhere_in_repo(self):
        forbidden = re.compile(
            r"cargoro|car-goro|카고로|changhyu|hdrhd|부사장|준법|홍보팀|에스크로|mbcenter|중계기|"
            r"01a1de11|6af96f89|6af95d7b|asenvcfg_|af5ba4fb|optimistic-fermat|/Users/caro|"
            r"ghp_[A-Za-z0-9]{20,}|gho_[A-Za-z0-9]{20,}",
            re.I,
        )
        checked = 0
        for path in REPO_ROOT.rglob("*"):
            if ".git" in path.parts or "__pycache__" in path.parts or path.is_dir():
                continue
            if path.resolve() == Path(__file__).resolve():
                continue
            text = path.read_text(encoding="utf-8")
            match = forbidden.search(text)
            self.assertIsNone(match, f"Forbidden identifier {match.group(0) if match else ''} in {path}")
            checked += 1
        self.assertGreaterEqual(checked, 30)

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


if __name__ == "__main__":
    unittest.main()
