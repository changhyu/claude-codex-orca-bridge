"""Register every eligible local Orca session, with persistent per-handle exclusions."""
import argparse
import fcntl
import os
import re
import sys
from pathlib import Path

INSTALL = Path(__file__).resolve().parent
sys.dont_write_bytecode = True
sys.path.insert(0, str(INSTALL))

from bridge import put
from orca_bridge import describe_terminal, invoke, is_agent
from secure_bridge import ensure_state, ROOT, secret_file

HANDLE = re.compile(r"term_[a-fA-F0-9-]{1,54}")
IDENTITY_FIELDS = ("handle", "sessionId", "agentSessionId", "threadId", "ptyId", "tabId", "leafId", "incarnationId", "orcaSessionId", "providerSessionId", "nativeSessionId")


def terminals():
    result = invoke("list", "--limit", "1000")
    if result.get("truncated"):
        raise ValueError("Orca 목록이 잘렸습니다. 일부 목록으로 운영 설정을 변경하지 않습니다.")
    return result["terminals"]


def blockers(row):
    reasons = []
    if not HANDLE.fullmatch(str(row.get("handle", ""))):
        reasons.append("터미널 핸들 없음")
    if not row.get("incarnationId"):
        reasons.append("프로세스 ID 없음")
    if row.get("executionHostId") not in (None, "local") or row.get("executionHost") not in (None, "local"):
        reasons.append("원격 호스트")
    if row.get("connected") is not True or row.get("writable") is not True:
        reasons.append("터미널 연결 또는 쓰기 불가")
    if not is_agent(row):
        reasons.append("지원되는 에이전트 미확인")
    return reasons


def label(row):
    info = describe_terminal(row)
    values = (info.get("agent"), info.get("name"), info.get("branch"), row.get("handle"))
    return " · ".join("".join(c for c in str(v) if c.isprintable()) for v in values if v)


def matches(row, identifier):
    identifier = identifier.removeprefix("orca_session_id:").strip()
    if not identifier:
        return False
    tab, delimiter, leaf = identifier.partition(":")
    if delimiter:
        return row.get("tabId") == tab and row.get("leafId") == leaf
    return any(isinstance(row.get(key), str)
               and row[key].removeprefix("orca_session_id:") in (identifier, "term_" + identifier)
               for key in IDENTITY_FIELDS)


def update(worker, client, rows, action, identifier):
    entry = worker["clients"][client["id"]]
    if entry["key"] != client["key"]:
        raise ValueError("운영 MCP와 작업자 설정의 클라이언트 키가 다릅니다.")
    targets = worker["targets"]
    previous = {k: v for k, v in targets.items() if v.get("transport") == "orca"}
    excluded = set(worker.get("orca_excluded_handles", []))
    if action in ("disable", "enable"):
        if identifier in previous:
            handle = previous[identifier]["id"]
        else:
            found = {row["handle"] for row in rows if matches(row, identifier) and HANDLE.fullmatch(str(row.get("handle", "")))}
            known = {target["id"] for target in previous.values()} | excluded
            found |= {item for item in known if item in (identifier, "term_" + identifier)}
            if len(found) != 1:
                raise ValueError("세션을 특정할 수 없습니다. list에서 확인한 별칭 또는 핸들을 사용하세요.")
            handle = found.pop()
        if action == "disable":
            excluded.add(handle)
        else:
            excluded.discard(handle)

    # An unavailable snapshot must not revoke a previous registration.
    updated = {name: target for name, target in previous.items() if target["id"] not in excluded}
    if action != "disable":
        aliases = {target["id"]: name for name, target in previous.items()}
        live = [row for row in rows if not blockers(row) and row["handle"] not in excluded]
        if action == "enable":
            live = [row for row in live if row["handle"] == handle]
            if not live:
                raise ValueError("선택한 Orca 터미널이 현재 연결 또는 입력 가능한 상태가 아닙니다.")
        for row in live:
            active_handle = row["handle"]
            name = aliases.get(active_handle, "orca-" + active_handle[5:].lower())
            if name in targets and name not in previous:
                raise ValueError("기존 전송 대상과 Orca 별칭이 겹칩니다.")
            updated[name] = {"transport": "orca", "id": active_handle, "incarnation": row["incarnationId"]}

    for name in previous:
        del targets[name]
    targets.update(updated)
    worker["orca_excluded_handles"] = sorted(excluded)
    for policy in (entry, client):
        policy["allow"] = list(dict.fromkeys([name for name in policy["allow"] if name not in previous] + list(updated)))
    return updated, excluded


def main():
    os.umask(0o077)
    parser = argparse.ArgumentParser()
    parser.add_argument("action", nargs="?", default="sync", choices=("sync", "list", "diagnose", "disable", "enable"))
    parser.add_argument("identifiers", nargs="*")
    args = parser.parse_args()
    if args.action in ("diagnose", "disable", "enable") and not args.identifiers:
        parser.error("세션 ID, 별칭 또는 핸들이 필요합니다.")
    if args.action != "diagnose" and len(args.identifiers) > 1:
        parser.error("여러 ID는 diagnose에서만 사용할 수 있습니다.")
    identifier = args.identifiers[0] if args.identifiers else None
    if args.action == "disable":
        try:
            rows = terminals()
        except (OSError, RuntimeError):
            rows = []
    else:
        rows = terminals()
    if args.action == "diagnose":
        for requested in args.identifiers:
            hits = [row for row in rows if matches(row, requested)]
            if not hits:
                print(f"{requested} · 현재 Orca 터미널 목록에 없음 (조회: {len(rows)}개)")
            for row in hits:
                status = ", ".join(f"{key}={row.get(key)!r}"
                                   for key in ("connected", "writable", "orphaned", "exitCause", "executionHostId"))
                print(label(row), "·", ", ".join(blockers(row)) or "연결 가능", "·", status)
        return

    if args.action == "list":
        worker = secret_file(INSTALL / "worker.json")
        registered = {v["id"]: k for k, v in worker["targets"].items() if v.get("transport") == "orca"}
        excluded = set(worker.get("orca_excluded_handles", []))
        for row in rows:
            reason = ", ".join(blockers(row))
            handle = row.get("handle")
            state = "해제됨" if handle in excluded else registered.get(handle, reason or "연결 가능")
            print(f"{state} · {label(row)}")
        return

    ensure_state()
    with (ROOT / "enrollment.lock").open("a") as lock:
        fcntl.flock(lock, fcntl.LOCK_EX)
        worker_path = INSTALL / "worker.json"
        client_path = INSTALL / "client.json"
        worker = secret_file(worker_path)
        client = secret_file(client_path)
        if args.action != "disable":
            rows = terminals()
        targets, excluded = update(worker, client, rows, args.action, identifier)
        put(worker_path, worker)
        put(client_path, client)
    print(f"Orca 연결 {len(targets)}개 · 개별 해제 {len(excluded)}개")
    labels = {row.get("handle"): label(row) for row in rows}
    for alias, target in targets.items():
        print(f"{alias} → {labels.get(target['id'], target['id'])}")


if __name__ == "__main__":
    try:
        main()
    except (OSError, RuntimeError, ValueError, KeyError) as exc:
        raise SystemExit(str(exc)) from None
