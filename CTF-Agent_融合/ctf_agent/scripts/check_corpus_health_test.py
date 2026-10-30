#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""`check_corpus_health.compare()` 的空池消失判定回归测试。

背景（2026-10-26 实锤）：
  基线里 `questions_real_kpi9` 与 `questions_ext_trial5_20261001` 都记为 `total=0`
  （kpi9 目录从未入 git）。旧实现无条件把「池不在当前快照里」判为回归：

      regressions.append(f"{pool}: 池消失（曾有 {base[pool]['total']} 题）")

  于是出现「盖曾有 **0** 题」这种自相矛盾的告警，且计入**阻断回归** →
  `check_corpus_health.py` 永久 rc=1，真实回归被噪声淹没。

修复：基线 `total <= 0` 的池消失时跳过（语义上不可能丢失任何题目）。

本测试锁住：
  ① 基线 total=0 且池消失 → 不报回归（本次修复的行为）
  ② 基线 total>0 且池消失 → **必须**仍报回归（防止修过头，把真丢失也放过）
  ③ 既有契约不破：坏题数上升仍报回归

用法：python scripts/check_corpus_health_test.py
退出码：0 = 全部通过；1 = 有用例失败。
"""
from __future__ import annotations

import importlib.util
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent


def _load():
    spec = importlib.util.spec_from_file_location(
        "health", ROOT / "scripts" / "check_corpus_health.py")
    m = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(m)  # type: ignore[union-attr]
    return m


def main() -> int:
    health = _load()
    results: list[tuple[str, bool, str]] = []

    def case(name: str, cur: dict, base: dict, want_regression: bool,
             needle: str = "") -> None:
        regs = health.compare(cur, base)["regressions"]
        has = any(needle in r for r in regs) if needle else bool(regs)
        ok = has == want_regression
        results.append((name, ok, f"want_regression={want_regression} got={regs}"))

    # ① 空池消失 → 不报
    case("empty_pool_vanished",
         cur={}, base={"questions_real_kpi9": {"total": 0, "ok": 0, "broken": 0}},
         want_regression=False)

    # ② 非空池消失 → 必须仍报（反向保护）
    case("real_pool_vanished",
         cur={}, base={"questions_real": {"total": 93, "ok": 9, "broken": 82}},
         want_regression=True, needle="questions_real")

    # ③ 既有契约：坏题数上升仍报回归
    case("broken_increased",
         cur={"p": {"total": 10, "ok": 5, "broken": 3}},
         base={"p": {"total": 10, "ok": 8, "broken": 1}},
         want_regression=True, needle="坏题")

    # ④ 混合：空池消失 + 非空池正常 → 只应报非空那个
    cur = {"questions_real": {"total": 93, "ok": 9, "broken": 82}}
    base = {"questions_real": {"total": 93, "ok": 9, "broken": 82},
            "questions_real_kpi9": {"total": 0, "ok": 0, "broken": 0}}
    regs = health.compare(cur, base)["regressions"]
    results.append(("mixed_empty_and_normal", regs == [], f"expected [] got={regs}"))

    failed = [r for r in results if not r[1]]
    for name, ok, msg in results:
        print(f"{'PASS' if ok else 'FAIL'}  {name:24} {msg}")
    print(f"\n{len(results) - len(failed)}/{len(results)} 通过")
    return 1 if failed else 0


if __name__ == "__main__":
    sys.exit(main())
