#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
并发会话中央登记表（2026-10-28 建立）。

为什么需要（真实事故）：
  - S5 07:12 在服务器上起的实例，07:15 被别的会话杀掉（日志停在 ONLINE，无崩溃痕迹）→ 跑批中途死。
  - `config.yaml` 被并行会话同时改（留下 `config.yaml.bak-S1-20261027_070649`）。
  - 本机隧道端口 18088 已被占，S5 换 18089 才通。
  - **并发池是账号级 5 格**（换机器不增加容量），`llm_max_concurrent` 是死配置（零引用）→ 无护栏。

守的三条不变量：
  1. 同一 (host, port) 只能被一个活跃会话占用 —— 防"抢端口/抢实例"。
  2. 同一题切片 slice 只能被一个会话占用 —— 防"两个人跑同一批题、数字打架"。
  3. 活跃会话数 ≤ ACCOUNT_CONCURRENCY (5) —— 并发池是账号级，换机器不扩容。

僵尸回收：心跳超过 STALE_MINUTES（默认 45 分钟）的条目自动失效、可被 gc 清理，
          避免"会话早死了但格位永远占着"。

用法：
    python scripts/session_registry.py claim --id S5 --slice misc --port 18088 \
        --host 172.16.222.99 --channel openrouter-free --owner "S5(我)"
    python scripts/session_registry.py heartbeat --id S5
    python scripts/session_registry.py release --id S5
    python scripts/session_registry.py list [--json]
    python scripts/session_registry.py gc
    python scripts/session_registry.py check          # CI 用；登记表缺失时显式降级 rc=0
    python scripts/session_registry.py --self-test    # 变异验证，证明冲突检测真的会拦
"""
from __future__ import annotations

import argparse
import json
import os
import sys
import tempfile
import time
from datetime import datetime, timezone

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
REGISTRY = os.path.join(ROOT, "data", "session_registry.json")

ACCOUNT_CONCURRENCY = 5      # 账号级并发池（换机器不增加，见 .workbuddy/memory/MEMORY.md）
STALE_MINUTES = 45           # 心跳超过这个时长视为僵尸


def _now() -> str:
    return datetime.now(timezone.utc).astimezone().isoformat(timespec="seconds")


def _age_min(ts: str) -> float:
    try:
        t = datetime.fromisoformat(ts).timestamp()
    except Exception:  # noqa: BLE001
        return 1e9     # 解析不了就当极老（fail-closed：不占位）
    return (time.time() - t) / 60.0


def load() -> dict:
    if not os.path.exists(REGISTRY):
        return {"version": 1, "updated_at": _now(), "sessions": []}
    try:
        d = json.load(open(REGISTRY, encoding="utf-8"))
        d.setdefault("sessions", [])
        return d
    except Exception as e:  # noqa: BLE001
        print(f"[warn] 登记表解析失败，按空处理: {e}", file=sys.stderr)
        return {"version": 1, "updated_at": _now(), "sessions": []}


def save(d: dict) -> None:
    os.makedirs(os.path.dirname(REGISTRY), exist_ok=True)
    d["updated_at"] = _now()
    fd, tmp = tempfile.mkstemp(dir=os.path.dirname(REGISTRY), suffix=".tmp")
    try:
        with os.fdopen(fd, "w", encoding="utf-8") as f:
            json.dump(d, f, ensure_ascii=False, indent=2)
        os.replace(tmp, REGISTRY)
    finally:
        if os.path.exists(tmp):
            try:
                os.remove(tmp)
            except OSError:
                pass


def alive(d: dict) -> list[dict]:
    """活跃会话（心跳未过期）。心跳缺失或不可解析 → fail-closed 视为僵尸。"""
    out = []
    for s in d.get("sessions", []):
        hb = s.get("heartbeat_at") or s.get("claimed_at")
        if hb and _age_min(hb) <= STALE_MINUTES:
            out.append(s)
    return out


def conflicts(d: dict, new: dict, exclude_id: str | None = None) -> list[str]:
    """新登记项与现有活跃会话的冲突列表。"""
    bad = []
    act = [s for s in alive(d) if s.get("id") != exclude_id]

    if len(act) >= ACCOUNT_CONCURRENCY:
        bad.append(f"并发池已满：活跃 {len(act)} 个 ≥ 账号级上限 {ACCOUNT_CONCURRENCY} "
                   f"（换机器不增加容量）")

    for s in act:
        if s.get("host") == new.get("host") and s.get("port") and \
                s.get("port") == new.get("port"):
            bad.append(f"端口冲突：{s.get('id')} 已占用 {s.get('host')}:{s.get('port')}")
        if new.get("slice") and s.get("slice") == new.get("slice"):
            bad.append(f"切片冲突：{s.get('id')} 已在跑 slice={s.get('slice')}")
    return bad


def cmd_claim(a) -> int:
    d = load()
    new = {
        "id": a.id, "owner": a.owner or "", "slice": a.slice,
        "host": a.host, "port": a.port, "channel": a.channel or "",
        "note": a.note or "",
        "claimed_at": _now(), "heartbeat_at": _now(),
    }
    bad = conflicts(d, new, exclude_id=a.id)
    if bad:
        print("🔴 拒绝登记（冲突）:")
        for b in bad:
            print("   -", b)
        print("\n现有活跃会话:")
        for s in alive(d):
            print(f"   {s.get('id'):6s} slice={s.get('slice')} "
                  f"{s.get('host')}:{s.get('port')} ch={s.get('channel')} "
                  f"心跳{int(_age_min(s.get('heartbeat_at','')))}分钟前")
        return 1
    d["sessions"] = [s for s in d.get("sessions", []) if s.get("id") != a.id]
    d["sessions"].append(new)
    save(d)
    print(f"🟢 已登记 {a.id}: slice={a.slice} {a.host}:{a.port} "
          f"ch={a.channel}（活跃 {len(alive(d))}/{ACCOUNT_CONCURRENCY}）")
    return 0


def cmd_release(a) -> int:
    d = load()
    before = len(d.get("sessions", []))
    d["sessions"] = [s for s in d.get("sessions", []) if s.get("id") != a.id]
    save(d)
    removed = before - len(d["sessions"])
    print(f"已释放 {a.id}（移除 {removed} 条）")
    return 0


def cmd_heartbeat(a) -> int:
    d = load()
    hit = False
    for s in d.get("sessions", []):
        if s.get("id") == a.id:
            s["heartbeat_at"] = _now()
            hit = True
    if not hit:
        print(f"⚠️ 未找到会话 {a.id}（它可能已被 gc 回收）——请先 claim")
        return 1
    save(d)
    print(f"心跳已更新: {a.id}")
    return 0


def cmd_list(a) -> int:
    d = load()
    act = alive(d)
    if a.json:
        print(json.dumps({"active": act, "stale": [
            s for s in d.get("sessions", []) if s not in act]},
            ensure_ascii=False, indent=2))
        return 0
    print(f"=== 并发会话登记表（{REGISTRY}）===")
    print(f"活跃 {len(act)}/{ACCOUNT_CONCURRENCY}（账号级并发池，换机器不增加）")
    for s in act:
        print(f"  {s.get('id'):6s} slice={str(s.get('slice')):10s} "
              f"{s.get('host')}:{s.get('port')} ch={str(s.get('channel')):16s} "
              f"owner={s.get('owner')} 心跳{int(_age_min(s.get('heartbeat_at','')))}分前")
    stale = [s for s in d.get("sessions", []) if s not in act]
    if stale:
        print(f"僵尸 {len(stale)} 条（心跳 > {STALE_MINUTES} 分钟，不占位）:")
        for s in stale:
            print(f"  {s.get('id')} slice={s.get('slice')}（可用 gc 清理）")
    return 0


def cmd_gc(a) -> int:
    d = load()
    before = len(d.get("sessions", []))
    d["sessions"] = alive(d)
    save(d)
    print(f"gc: 清理僵尸 {before - len(d['sessions'])} 条，剩余活跃 {len(d['sessions'])}")
    return 0


def cmd_check(a) -> int:
    """CI 用。登记表不存在时**显式降级**（CI 无并发会话），不许静默放过也不许误报。"""
    if not os.path.exists(REGISTRY):
        print("DEGRADED: CI/干净检出无 data/session_registry.json（并发登记表是本机运行态产物，"
              "不入库）→ 跳过冲突检查。本条为显式降级，非 PASS。")
        return 0
    d = load()
    act = alive(d)
    bad = []
    if len(act) > ACCOUNT_CONCURRENCY:
        bad.append(f"活跃会话 {len(act)} > 并发池 {ACCOUNT_CONCURRENCY}")
    seen = {}
    for s in act:
        k1 = (s.get("host"), s.get("port"))
        k2 = s.get("slice")
        if k1 in seen:
            bad.append(f"端口重复占用 {k1}: {seen[k1]} 与 {s.get('id')}")
        seen[k1] = s.get("id")
    slices = {}
    for s in act:
        if s.get("slice"):
            slices.setdefault(s["slice"], []).append(s["id"])
    for sl, ids in slices.items():
        if len(ids) > 1:
            bad.append(f"切片重复占用 {sl}: {ids}")
    if bad:
        print("🔴 登记表冲突:")
        for b in bad:
            print("   -", b)
        return 1
    print(f"🟢 登记表无冲突（活跃 {len(act)}/{ACCOUNT_CONCURRENCY}）")
    return 0


# ── 变异验证：证明冲突检测真的会拦，而不是摆设 ──
def self_test() -> int:
    global REGISTRY
    old = REGISTRY
    tmp = tempfile.mkdtemp(prefix="sess_reg_")
    REGISTRY = os.path.join(tmp, "session_registry.json")
    ok = True
    try:
        def claim(i, sl, port, host="172.16.222.99"):
            d = load()
            n = {"id": i, "slice": sl, "host": host, "port": port,
                 "channel": "x", "claimed_at": _now(), "heartbeat_at": _now()}
            c = conflicts(d, n, exclude_id=i)
            if c:
                return 1, c
            d["sessions"] = [s for s in d.get("sessions", []) if s.get("id") != i]
            d["sessions"].append(n)
            save(d)
            return 0, []

        rc, _ = claim("S1", "crypto-a", 18086)
        ok &= rc == 0
        print(f"[1] 首次 claim 应成功 -> rc={rc}")

        rc, why = claim("S2", "crypto-b", 18086)
        ok &= rc == 1 and any("端口冲突" in w for w in why)
        print(f"[2] 同端口二次 claim 应被拒 -> rc={rc} {why[:1]}")

        rc, why = claim("S3", "crypto-a", 18090)
        ok &= rc == 1 and any("切片冲突" in w for w in why)
        print(f"[3] 同切片二次 claim 应被拒 -> rc={rc} {why[:1]}")

        for i, port in [("S2", 18090), ("S3", 18091), ("S4", 18092)]:
            claim(i, f"slice-{i}", port)
        # 第 5 个应放行（并发池正好满），第 6 个才应被拒
        rc5, _ = claim("S6", "slice-S6", 18093)
        n_act = len(alive(load()))
        ok &= rc5 == 0 and n_act == ACCOUNT_CONCURRENCY
        rc, why = claim("S7", "slice-S7", 18094)
        ok &= rc == 1 and any("并发池已满" in w for w in why)
        print(f"[4] 第5个放行(活跃={n_act})、第6个应被拒 -> rc={rc} {why[:1]}")

        # 变异：心跳过期后应重新可用（僵尸不永久占位）
        d = load()
        for s in d["sessions"]:
            if s["id"] == "S1":
                s["heartbeat_at"] = "2000-01-01T00:00:00+08:00"
        save(d)
        rc, _ = claim("S8", "crypto-a", 18086)
        ok &= rc == 0
        print(f"[5] 变异(S1心跳过期后)同端口应可再 claim -> rc={rc}")

        n0 = len(load().get("sessions", []))
        cmd_gc(argparse.Namespace())
        n1 = len(load().get("sessions", []))
        ok &= n1 < n0
        print(f"[6] gc 应清理僵尸 -> {n0} -> {n1}")

        # 变异：check 在登记表缺失时必须显式降级(rc=0 且打印 DEGRADED)
        REGISTRY2 = REGISTRY
        REGISTRY = os.path.join(tmp, "nonexistent.json")
        import io, contextlib
        buf = io.StringIO()
        with contextlib.redirect_stdout(buf):
            rc = cmd_check(argparse.Namespace())
        REGISTRY = REGISTRY2
        ok &= rc == 0 and "DEGRADED" in buf.getvalue()
        print(f"[7] 变异(登记表缺失)应显式降级 -> rc={rc} DEGRADED={'DEGRADED' in buf.getvalue()}")
    finally:
        REGISTRY = old

    print("\nSELFTEST:", "PASS" if ok else "FAIL")
    return 0 if ok else 1


def main() -> int:
    ap = argparse.ArgumentParser(description="并发会话中央登记表")
    ap.add_argument("--self-test", action="store_true")
    sub = ap.add_subparsers(dest="cmd")

    p = sub.add_parser("claim")
    p.add_argument("--id", required=True)
    p.add_argument("--slice", required=True)
    p.add_argument("--host", default="172.16.222.99")
    p.add_argument("--port", type=int, required=True)
    p.add_argument("--channel", default="")
    p.add_argument("--owner", default="")
    p.add_argument("--note", default="")

    p = sub.add_parser("release"); p.add_argument("--id", required=True)
    p = sub.add_parser("heartbeat"); p.add_argument("--id", required=True)
    p = sub.add_parser("list"); p.add_argument("--json", action="store_true")
    p = sub.add_parser("gc")
    p = sub.add_parser("check")

    a = ap.parse_args()
    if a.self_test:
        return self_test()
    return {
        "claim": cmd_claim, "release": cmd_release, "heartbeat": cmd_heartbeat,
        "list": cmd_list, "gc": cmd_gc, "check": cmd_check,
    }.get(a.cmd, lambda _a: ap.print_usage() or 2)(a)


if __name__ == "__main__":
    raise SystemExit(main())
