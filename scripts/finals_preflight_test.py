#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""决赛预检脚本自测（`scripts/finals_preflight.py` 的回归 + 因果验证）。

为什么必须有（AGENTS.md 第四条：门禁自身必须有回归测试，失效的门禁比没有门禁更危险）：
  预检的输出是"GO / NO-GO"—— 现场据此决定是否开赛。若定级逻辑写反，脚本会给出
  与事实相反的结论，而**门禁全绿时没人会去核对那个结论**，属最危险的"看起来能用"。
  09-24 已栽过一次同类：证据包哈希没做行尾归一化，本地永远绿、CI 必然 BLOCK。

因此本测试除正/反用例外，专门做**差异性因果验证**：
  同一组输入下 phase=pre 与 phase=final 必须给出**不同**结论（用例 9）。
  若把 `if phase == "pre"` 写反，两者会变得完全一致 → 该用例 FAIL → 变异被抓住。
  另配一条"空 phase 必须按 final 严格处理"（用例 10），防止空值导致全部放行。

全部用例走纯函数（`parse_phase` / `evaluate`），**不起子进程、不跑 go test**，
秒级完成；真实端到端行为由 finals_arm.sh 与 runbook 覆盖。
"""
import os
import sys
import importlib.util

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
TARGET = os.path.join(ROOT, "scripts", "finals_preflight.py")

spec = importlib.util.spec_from_file_location("finals_preflight_under_test", TARGET)
pf = importlib.util.module_from_spec(spec)
spec.loader.exec_module(pf)

CASES = []


def check(name, got, want):
    ok = got == want
    CASES.append((name, ok, got, want))
    return ok


def main():
    # ── parse_phase：阶段解析（缺省严格、显式 pre、拼错即拒）──────────────
    check("parse_phase 无参 → final（缺省严格）",
          pf.parse_phase([])[0], "final")
    check("parse_phase --json 干扰下仍为 final",
          pf.parse_phase(["--json"])[0], "final")
    check("parse_phase --phase pre → pre",
          pf.parse_phase(["--phase", "pre"])[0], "pre")
    check("parse_phase --phase final → final",
          pf.parse_phase(["--phase", "final"])[0], "final")
    check("parse_phase --full 与 --phase 组合",
          pf.parse_phase(["--full", "--phase", "pre", "--json"])[0], "pre")
    # fail-closed：拼错阶段名必须报错，绝不静默降级成 final（否则现场以为按赛前模式跑）
    check("parse_phase 拼错阶段名 → 报错(fail-closed)",
          pf.parse_phase(["--phase", "bogus"])[1] is not None, True)
    check("parse_phase --phase 缺值 → 报错",
          pf.parse_phase(["--phase"])[1] is not None, True)
    check("parse_phase 大小写错误也不接受",
          pf.parse_phase(["--phase", "PRE"])[1] is not None, True)

    MISS3 = ["CTF_POLL_ENABLED", "CTF_AUTOSOLVE_SUBMIT", "CTF_AUTO_BUILD_ENV"]

    # ── evaluate：定级核心 ───────────────────────────────────────────────
    v = pf.evaluate("final", MISS3, [], [])
    check("final + 三个必需开关未开 → NO-GO", v[0], "NO-GO")
    check("final + 开关未开 → 阻塞项含全部 3 个", len(v[1]), 3)
    check("final + 开关未开 → 无待开项", v[2], [])

    v = pf.evaluate("final", [], [], [])
    check("final + 开关全开 → GO", v[0], "GO")
    check("final + 开关全开 → 无阻塞", v[1], [])

    v = pf.evaluate("pre", MISS3, [], [])
    check("pre + 三个必需开关未开 → GO（赛前正常）", v[0], "GO")
    check("pre + 开关未开 → 列为待开而非阻塞", len(v[2]), 3)
    check("pre + 开关未开 → 阻塞项为空", v[1], [])

    # 关键用例：门禁类硬失败在 pre 阶段**也必须**阻塞。
    # 若 pre 把一切放行，赛前预检就永远 GO，等于这个检查点被废掉。
    v = pf.evaluate("pre", MISS3, ["secret_gate 未通过"], [])
    check("pre + 门禁硬失败 → 仍 NO-GO（不放行门禁）", v[0], "NO-GO")
    check("pre + 门禁硬失败 → 阻塞项只含硬失败", v[1], ["secret_gate 未通过"])
    check("pre + 门禁硬失败 → 开关仍列为待开", len(v[2]), 3)

    v = pf.evaluate("final", [], ["演练台未通过", "密钥门禁未通过"], [])
    check("final + 两项硬失败 → 阻塞 2 项", len(v[1]), 2)

    # ── 因果/差异性验证（防变异假绿）─────────────────────────────────────
    # 同一组输入，pre 与 final 必须给出不同结论 —— 证明判定真的读了 phase 参数。
    a = pf.evaluate("pre", ["CTF_POLL_ENABLED"], [], [])
    b = pf.evaluate("final", ["CTF_POLL_ENABLED"], [], [])
    check("差异性：pre 与 final 对同一输入结论不同", a[0] != b[0], True)
    check("差异性：pre 不阻塞而 final 阻塞同一开关",
          (len(a[1]) == 0, len(b[1]) == 1), (True, True))

    # 空/未知 phase 必须按严格（final）处理，不得当成 pre 全放行
    v = pf.evaluate("", MISS3, [], [])
    check("空 phase 按 final 严格处理 → NO-GO", v[0], "NO-GO")
    v = pf.evaluate(None, MISS3, [], [])
    check("None phase 按 final 严格处理 → NO-GO", v[0], "NO-GO")
    v = pf.evaluate("PRE", MISS3, [], [])   # 大写不得被当成 pre
    check("大写 PRE 不被当成 pre → NO-GO", v[0], "NO-GO")

    # ── 打印 ────────────────────────────────────────────────────────────
    for name, ok, got, want in CASES:
        print("  [%s] %-52s got=%r" % ("OK" if ok else "FAIL", name, got))
    failed = [c for c in CASES if not c[1]]
    print()
    if failed:
        print("决赛预检自测：FAIL（%d/%d 项未过）" % (len(failed), len(CASES)))
        for name, ok, got, want in failed:
            print("  ✗ %s：期望 %r，实得 %r" % (name, want, got))
        return 1
    print("决赛预检自测：PASS（%d 项用例全过，含 3 项差异性/严格性验证）" % len(CASES))
    return 0


if __name__ == "__main__":
    sys.exit(main())
