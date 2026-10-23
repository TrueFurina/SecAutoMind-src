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

    # ── 凭证检查（2026-10-24 事故回归）───────────────────────────────────
    # 事故现场：DASCTF_BASE_URL 与令牌**都未设置**时，预检仍输出
    # 「无阻塞项 —— 可上场 / ✅ GO」。缺凭证上场 = 拉不到题、提交不了 flag = 0 分。
    miss, warns = pf.credential_issues({})
    check("空环境 → 缺 2 项凭证", len(miss), 2)
    check("空环境 → 地址与令牌都被点名",
          (any("BASE_URL" in m for m in miss), any("TOKEN" in m for m in miss)),
          (True, True))
    check("空环境 → 无形态警告", warns, [])

    good = {"DASCTF_BASE_URL": "https://ycb-bk.dasctf.com", "DASCTF_TOKEN": "ak_" + "x" * 37}
    miss, warns = pf.credential_issues(good)
    check("齐全且形态正确 → 无缺失", miss, [])
    check("齐全且形态正确 → 无警告", warns, [])

    # 令牌别名：只设 CTF_AGENT_PLATFORM_TOKEN 也必须认
    alias = {"DASCTF_BASE_URL": "https://ycb-bk.dasctf.com",
             "CTF_AGENT_PLATFORM_TOKEN": "ak_abc"}
    check("仅 CTF_AGENT_PLATFORM_TOKEN 也算有令牌", pf.credential_issues(alias)[0], [])

    # 形态告警（不阻塞，但必须说出来）
    _, warns = pf.credential_issues({"DASCTF_BASE_URL": "ycb-bk.dasctf.com",
                                     "DASCTF_TOKEN": "ak_x"})
    check("地址缺 scheme → 警告", any("http" in w for w in warns), True)
    _, warns = pf.credential_issues({"DASCTF_BASE_URL": "https://x/slab-match",
                                     "DASCTF_TOKEN": "ak_x"})
    check("地址含 /slab-match → 警告（会双拼路径）",
          any("slab-match" in w for w in warns), True)
    _, warns = pf.credential_issues({"DASCTF_BASE_URL": "https://x",
                                     "DASCTF_TOKEN": "plain-password-123"})
    check("令牌不像 ak_ → 警告（疑似门户口令）", any("ak_" in w for w in warns), True)

    # 定级：final 缺凭证必须 NO-GO；pre 只列待填
    v = pf.evaluate("final", [], [], [], missing_credentials=["DASCTF_BASE_URL（平台地址）"])
    check("final + 缺凭证 → NO-GO（本次事故回归）", v[0], "NO-GO")
    check("final + 缺凭证 → 阻塞项含「缺少凭证」",
          any("缺少凭证" in x for x in v[1]), True)
    v = pf.evaluate("pre", [], [], [], missing_credentials=["DASCTF_BASE_URL（平台地址）"])
    check("pre + 缺凭证 → GO（赛前可缺）", v[0], "GO")
    check("pre + 缺凭证 → 列为待填", any("需填" in x for x in v[2]), True)
    # 向后兼容：不传该参数时行为不变（既有调用点不会因新增参数改变结论）
    check("向后兼容：不传 missing_credentials → 仍 GO",
          pf.evaluate("final", [], [], [])[0], "GO")

    # ── 鉴权实探分类（2026-10-24：存在≠可用）──────────────────────────
    # 事故背景：环境里那把 ak_ 令牌对 pro 与 ycb-bk 都返回 40403，
    # 而"凭证存在"检查照样报 SET。必须能区分「通过鉴权」与「被拒」。
    check("40403 → invalid（无权操作）",
          pf.classify_auth_response(200, '{"code":"40403","message":"无权操作"}')[0], "invalid")
    check("40001 → ok（鉴权已过，只缺参数）",
          pf.classify_auth_response(200, '{"code":"40001","message":"方法参数传递不正确"}')[0], "ok")
    check("带空格的 JSON 也能判",
          pf.classify_auth_response(200, '{ "code" : "40403" , "message" : "无权操作" }')[0], "invalid")
    check("非 200 且无业务码 → unknown（不谎报红绿）",
          pf.classify_auth_response(502, "bad gateway")[0], "unknown")
    check("200 但是 HTML 壳 → unknown",
          pf.classify_auth_response(200, "<!DOCTYPE html><html>")[0], "unknown")
    # 因果验证：把 40403 误判成 ok 会让"废令牌"变绿 —— 这里显式钉住两者不相等
    check("差异性：40403 与 40001 的判定必须不同",
          pf.classify_auth_response(200, '{"code":"40403"}')[0]
          != pf.classify_auth_response(200, '{"code":"40001"}')[0], True)

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
    print("决赛预检自测：PASS（%d 项用例全过，含差异性/严格性/凭证事故回归验证）" % len(CASES))
    return 0


if __name__ == "__main__":
    sys.exit(main())
