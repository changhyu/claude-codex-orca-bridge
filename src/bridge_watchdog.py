"""Track blocked delivery and recover unhealthy local bridge services."""

from contextlib import closing
from hashlib import sha256
from http.client import HTTPConnection, HTTPException
import json
import os
import sqlite3
import subprocess
import sys
import time

from agent_mesh import LOCAL_CLIENT
from bridge_settings import CLAUDE_MCP_PATH, LAUNCHD_PREFIX
from cloud_inbox import save_once
import secure_bridge as bridge

WATCHED = {
    "waiting_for_desktop": "세션 연결 대기 (자동 재시도 중)",
    "delivery_unknown": "전달 여부 미확인 (중복 방지를 위해 자동 재전송 안 함)",
    "target_denied": "브릿지 수신처 권한 거절",
    "send_rejected": "발송 도구가 요청을 거절함",
    "reply_failed": "회신 실패",
    "reply_expired": "회신 기한 만료",
}
SERVICES = ("worker", "callback")
ATTEMPT_INTERVAL = 300


def callback_healthy():
    # An unauthenticated GET to this local MCP route has a stable 405 response.
    with closing(HTTPConnection("127.0.0.1", 8766, timeout=3)) as conn:
        try:
            conn.request("GET", CLAUDE_MCP_PATH)
            return conn.getresponse().status == 405
        except (OSError, HTTPException):
            return False


def worker_healthy(now):
    try:
        return (bridge.ROOT / "worker.heartbeat").stat().st_mtime >= now - 180
    except FileNotFoundError:
        return False


def restart(service):
    label = f"gui/{os.getuid()}/{LAUNCHD_PREFIX}.{service}"
    try:
        return subprocess.run(
            ["/bin/launchctl", "kickstart", "-k", label],
            capture_output=True, timeout=15, check=False,
        ).returncode == 0
    except (OSError, subprocess.TimeoutExpired):
        return False


def service_events(state, now, checks, restart_service):
    events = []
    for service in SERVICES:
        entry = state["services"].setdefault(service, {"misses": 0})
        if checks[service]:
            if entry.get("incident"):
                events.append((f"{service}:recovered:{entry['incident']}", f"{service} 서비스 정상화"))
            entry.clear()
            entry["misses"] = 0
            continue
        entry["misses"] += 1
        if entry["misses"] < 3 or now - entry.get("last_attempt", 0) < ATTEMPT_INTERVAL:
            continue
        entry.setdefault("incident", int(now))
        entry["last_attempt"] = now
        accepted = restart_service(service)
        state_label = "자동 재시작 요청 접수" if accepted else "자동 재시작 요청 실패"
        events.append((f"{service}:restart:{int(now)}", f"{service} 서비스 응답 없음 · {state_label}"))
    return events


def request_events(now, since):
    path = bridge.ROOT / "worker.sqlite3"
    if not path.is_file():
        return []
    with closing(sqlite3.connect(path.as_uri() + "?mode=ro", uri=True, timeout=3)) as conn:
        rows = conn.execute(
            "SELECT id,target,state,created FROM audit WHERE created>=? AND created<=?",
            (max(since, now - bridge.DAY), now),
        ).fetchall()
    return [
        (f"{rid}:{state}", f"{target} · {WATCHED[state]} · {rid}")
        for rid, target, state, created in rows
        if state in WATCHED and target and target != bridge.ADMIN_ALIAS
        and (state != "waiting_for_desktop" or now - created >= 30)
    ]


def send_alert(events, config):
    target = config["targets"].get(bridge.ADMIN_ALIAS, {})
    client = config["clients"].get(LOCAL_CLIENT, {})
    if (bridge.ADMIN_ALIAS not in client.get("allow", [])
            or target.get("id") != bridge.ADMIN_THREAD
            or target.get("transport") != "codex-desktop" or target.get("host", "local") != "local"):
        return None
    rid = sha256(("bridge-watchdog:" + "|".join(key for key, _ in events)).encode()).hexdigest()[:32]
    if not (bridge.location("requests", rid).exists() or bridge.location("results", rid).exists()):
        save_once(bridge, rid, {
            "request_id": rid, "client": LOCAL_CLIENT, "target": bridge.ADMIN_ALIAS, "created": time.time(),
            "destination": bridge.destination_identity(target),
            "message": "[브릿지 장애 알림]\n" + "\n".join(f"- {message}" for _, message in events),
        }, client["key"])
    return rid


def main():
    os.umask(0o077)
    bridge.ensure_state()
    now = time.time()
    path = bridge.ROOT / "watchdog.json"
    state = bridge.load(path) if path.is_file() else {"since": now, "services": {}, "alerts": {}}
    if sys.argv[1:] == ["--status"]:
        recent = sorted(state["alerts"].items(), key=lambda entry: entry[1]["created"], reverse=True)[:20]
        alerts = []
        for event, record in recent:
            rid = record["request_id"]
            result_path = bridge.location("results", rid)
            state_name = bridge.load(result_path)["data"]["state"] if result_path.is_file() else "pending_mac"
            alerts.append({"event": event, **record, "delivery": state_name})
        print(json.dumps({"checked_at": state.get("checked_at"), "services": state["services"], "alerts": alerts}))
        return
    state["alerts"] = dict(sorted(
        ((key, item) for key, item in state["alerts"].items() if item["created"] >= now - bridge.DAY),
        key=lambda entry: entry[1]["created"], reverse=True,
    )[:750])
    state.setdefault("pending_service_events", [])
    state["pending_service_events"].extend(service_events(
        state, now, {"worker": worker_healthy(now), "callback": callback_healthy()}, restart,
    ))
    candidates = state["pending_service_events"] + request_events(now, state["since"])
    events = sorted((key, msg) for key, msg in candidates if key not in state["alerts"])[:20]
    if events:
        rid = send_alert(events, bridge.secret_file(bridge.BASE / "worker.json"))
        for key, message in events:
            print(message, flush=True)
            if rid:
                state["alerts"][key] = {"created": now, "request_id": rid}
    state["pending_service_events"] = [event for event in state["pending_service_events"]
                                       if event[0] not in state["alerts"]]
    state["checked_at"] = now
    bridge.put(path, state)


if __name__ == "__main__":
    main()
