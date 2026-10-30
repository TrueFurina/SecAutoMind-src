#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""race_stoploss_test.py —— 止损线回归测试（不联网、不写仓库日志）。

判据：
  T1  无记录 → ok
  T2  同类失败 1 次 → ok；2 次 → **stop**
  T3  两次但**不同类** → ok（止损是按「同类」算，不是按次数）
  T4  单题累计 5 次（即使分散在不同类）→ stop
  T5  只影响该题，别的题不受牵连
  T6  已解出的记录不计入失败
  T7  record 命令：第 2 次同类失败时**退出码为 1**（阻断，不是只打印）
  T8  坏行（脏 JSON）不让整条止损线失效
  T9  变异验证：把阈值放宽到 99，T2 必须失败（证明 T2 非恒绿）

用法：python scripts/race_stoploss_test.py
"""
from __future__ import annotations

import io
import json
import os
import sys
import tempfile
import contextlib

sys.path.insert(0, "scripts")
import race_stoploss as S  # noqa: E402

passed = failed = 0


def ok(name: str) -> None:
    global passed
    passed += 1
    print(f"  [PASS] {name}")


def bad(name: str, detail: str = "") -> None:
    global failed
    failed += 1
    print(f"  [FAIL] {name}{('：' + detail) if detail else ''}")


def ent(cid, cls="guess", outcome="fail"):
    return {"challenge": cid, "failure_class": cls, "outcome": outcome}


# ── T1 ──────────────────────────────────────────────────────────────────────
if S.evaluate([], "1")[0] == "ok":
    ok("T1 无记录 → ok")
else:
    bad("T1 空记录被判 stop")

# ── T2 ──────────────────────────────────────────────────────────────────────
one = [ent("1")]
two = [ent("1"), ent("1")]
if S.evaluate(one, "1")[0] == "ok" and S.evaluate(two, "1")[0] == "stop":
    ok("T2 同类失败 1 次 ok、2 次 stop")
else:
    bad("T2 阈值错误", f"1次={S.evaluate(one,'1')[0]} 2次={S.evaluate(two,'1')[0]}")

# ── T3 不同类不算同类 ───────────────────────────────────────────────────────
diff = [ent("1", "guess"), ent("1", "tool_missing")]
if S.evaluate(diff, "1")[0] == "ok":
    ok("T3 两次但不同类 → ok（按同类算，不按次数）")
else:
    bad("T3 不同类被误判 stop", S.evaluate(diff, "1")[1])

# ── T4 总次数上限 ───────────────────────────────────────────────────────────
many = [ent("1", c) for c in ("guess", "tool_missing", "env_dead", "wrong_path", "timeout")]
if S.evaluate(many, "1")[0] == "stop":
    ok("T4 单题累计 5 次（跨类）→ stop")
else:
    bad("T4 总次数上限失效", S.evaluate(many, "1")[1])

# ── T5 题间隔离 ─────────────────────────────────────────────────────────────
mixed = [ent("1"), ent("1"), ent("2")]
if S.evaluate(mixed, "1")[0] == "stop" and S.evaluate(mixed, "2")[0] == "ok":
    ok("T5 只影响该题，别的题不受牵连")
else:
    bad("T5 题间串扰")

# ── T6 已解出不计入失败 ─────────────────────────────────────────────────────
# 1 次失败 + 1 次已解出：若把 solved 也算失败，就会凑够 2 次同类而误判 stop。
solved = [ent("1"), ent("1", outcome="solved")]
if S.evaluate(solved, "1")[0] == "ok":
    ok("T6 已解出记录不计入失败（1 失败 + 1 solved 仍是 ok）")
else:
    bad("T6 solved 被计入失败", S.evaluate(solved, "1")[1])

# ── T7 record 第 2 次同类 → 退出码 1 ────────────────────────────────────────
tmp = tempfile.mkdtemp()
logp = os.path.join(tmp, "a.jsonl")
with contextlib.redirect_stdout(io.StringIO()):
    rc1 = S.main(["record", "--challenge", "9", "--class", "guess", "--log", logp])
    rc2 = S.main(["record", "--challenge", "9", "--class", "guess", "--log", logp])
    rc3 = S.main(["check", "--challenge", "9", "--log", logp])
if (rc1, rc2, rc3) == (0, 1, 1):
    ok("T7 record 第 2 次同类失败退出码 1，check 也返回 1（真阻断）")
else:
    bad("T7 退出码不符合阻断语义", f"{rc1}/{rc2}/{rc3}")

# ── T8 脏行不致失效 ─────────────────────────────────────────────────────────
with open(logp, "a", encoding="utf-8") as f:
    f.write("{this is not json\n")
    f.write(json.dumps(ent("9")) + "\n")
if S.evaluate(S.load(logp), "9")[0] == "stop":
    ok("T8 脏 JSON 行被跳过，止损判定仍生效")
else:
    bad("T8 脏行导致判定失效")

# ── T9 变异验证 ─────────────────────────────────────────────────────────────
if S.evaluate(two, "1", max_same_class=99, max_total=99)[0] == "ok":
    ok("T9 变异验证：阈值放宽到 99 后 T2 会失败（T2 非恒绿）")
else:
    bad("T9 变异未生效", "T2 可能是恒绿的")

print("-" * 60)
if failed == 0:
    print(f"结论：PASS —— {passed} 项全过（含 1 项变异验证）")
    sys.exit(0)
print(f"结论：FAIL —— {failed} 项未过")
sys.exit(1)
