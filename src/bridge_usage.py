"""Rate-limit snapshots. Only normalized quota windows cross the bridge."""
import datetime
import json
import os
import selectors
import shutil
import subprocess
import sys
import tempfile
import time
from pathlib import Path

FRESH_SECONDS = 300
CLAUDE_WINDOWS = (("five_hour", "5시간"), ("seven_day", "7일"))
_codex_sample = None
_last_attempt = float("-inf")


def window(label, percentage, reset):
    if type(percentage) not in (int, float) or not 0 <= percentage <= 100:
        return None
    return {"window": label, "remaining_percent": round(100 - percentage, 1),
            "resets_at": reset if type(reset) is int and 0 < reset < 253402300799 else None}


def snapshot(provider, rows):
    return {"provider": provider, "source": "local_account", "observed_at": int(time.time()),
            "windows": [item for item in rows if item]}


def codex_rpc():
    executable = shutil.which("codex") or str(Path.home() / ".local/bin/codex")
    with subprocess.Popen([executable, "app-server", "--listen", "stdio://"], stdin=subprocess.PIPE,
                          stdout=subprocess.PIPE, stderr=subprocess.DEVNULL) as child, selectors.DefaultSelector() as receiver:
        try:
            receiver.register(child.stdout, selectors.EVENT_READ)
            deadline = time.monotonic() + 4
            buffer = bytearray()

            def send(packet):
                child.stdin.write(json.dumps(packet).encode() + b"\n")
                child.stdin.flush()

            def wait_for(number):
                while time.monotonic() < deadline:
                    while b"\n" in buffer:
                        line, _, rest = buffer.partition(b"\n")
                        buffer[:] = rest
                        packet = json.loads(line)
                        if isinstance(packet, dict) and packet.get("id") == number:
                            return packet.get("result", {})
                    if not receiver.select(max(0, deadline - time.monotonic())):
                        break
                    chunk = os.read(child.stdout.fileno(), 4096)
                    if not chunk:
                        break
                    buffer.extend(chunk)
                    if len(buffer) > 1024 * 1024:
                        break
                raise TimeoutError("Usage response unavailable.")

            send({"id": 1, "method": "initialize", "params": {
                "clientInfo": {"name": "secure_bridge", "title": "Secure Bridge", "version": "1.0"}}})
            wait_for(1)
            send({"method": "initialized"})
            send({"id": 2, "method": "account/rateLimits/read"})
            return wait_for(2)
        finally:
            if child.poll() is None:
                child.kill()


def codex_usage():
    global _codex_sample, _last_attempt
    now = time.monotonic()
    if now - _last_attempt >= 60:
        _last_attempt = now
        try:
            result = codex_rpc()
            buckets = result.get("rateLimitsByLimitId") or {}
            limits = buckets.get("codex") or result.get("rateLimits") or {}
            rows = []
            for slot, fallback in (("primary", "단기"), ("secondary", "장기")):
                values = limits.get(slot) or {}
                minutes = values.get("windowDurationMins")
                label = f"{minutes}분" if type(minutes) is int and minutes > 0 else fallback
                rows.append(window(label, values.get("usedPercent"), values.get("resetsAt")))
            value = snapshot("codex", rows)
            if value["windows"]:
                _codex_sample = value
        except (OSError, ValueError, AttributeError, TypeError):
            pass
    return checked("codex", _codex_sample)


def checked(provider, sample):
    if not isinstance(sample, dict):
        return {"provider": provider, "status": "unavailable"}
    age = time.time() - sample["observed_at"]
    if not 0 <= age < 86400 or not sample["windows"]:
        return {"provider": provider, "status": "unavailable"}
    rows = []
    for entry in sample["windows"]:
        pct = entry["remaining_percent"]
        if type(pct) not in (int, float) or not 0 <= pct <= 100:
            continue
        reset = entry.get("resets_at")
        if reset is not None and (type(reset) is not int or not time.time() < reset < 253402300799):
            continue
        label = entry["window"]
        if not isinstance(label, str) or len(label) > 24:
            continue
        rows.append({"window": label, "remaining_percent": pct, "resets_at": reset})
    if not rows:
        return {"provider": provider, "status": "unavailable"}
    return {"provider": provider, "status": "fresh" if age <= FRESH_SECONDS else "stale",
            "source": "local_account", "observed_at": sample["observed_at"], "windows": rows}


def claude_snapshot(payload):
    limits = payload.get("rate_limits") or {}
    rows = []
    for field, label in CLAUDE_WINDOWS:
        values = limits.get(field) or {}
        rows.append(window(label, values.get("used_percentage"), values.get("resets_at")))
    return snapshot("claude", rows)


def claude_usage(root):
    path = root / "claude-usage.json"
    try:
        from secure_bridge import secret_file
        return checked("claude", secret_file(path))
    except (OSError, ValueError, TypeError, AttributeError, KeyError):
        return {"provider": "claude", "status": "unavailable"}


def gpt_usage():
    return {
        "codex_local_usage": {**codex_usage(), "scope": "local_codex_account"},
        "gpt_cloud_usage": {"provider": "gpt", "scope": "gpt_cloud_account", "status": "unavailable"},
    }


def format_usage(sample, label):
    if sample["status"] == "unavailable":
        return f"{label} quota: unavailable."
    def timestamp(value):
        return datetime.datetime.fromtimestamp(value, datetime.timezone.utc).isoformat()
    windows = "; ".join(
        f"{item['window']} {item['remaining_percent']:g}% remaining"
        + (f", resets {timestamp(item['resets_at'])}" if item["resets_at"] else "")
        for item in sample["windows"])
    return f"{label} quota ({sample['status']}, observed {timestamp(sample['observed_at'])}): {windows}."


def capture():
    from secure_bridge import ROOT, ensure_state
    try:
        value = claude_snapshot(json.load(sys.stdin))
        if value["windows"]:
            ensure_state()
            with tempfile.NamedTemporaryFile(mode="w", dir=ROOT, delete=False) as pending:
                tmp = Path(pending.name)
                json.dump(value, pending, ensure_ascii=False)
            try:
                tmp.replace(ROOT / "claude-usage.json")
            finally:
                tmp.unlink(missing_ok=True)
    except (OSError, ValueError, TypeError, AttributeError):
        pass


if __name__ == "__main__":
    os.umask(0o077)
    capture()
