#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""冻结闸门自测（`scripts/freeze_gate.py` 的回归 + 因果验证）。

为什么必须有（本仓已两次栽在"门禁失效"）：
  09-08 旧 secret 正则漏配 → 门禁报 CLEAN；09-13 省略号被无条件豁免 → 门禁放过真 key 片段。
  教训：**"跑一次全绿"不等于"门禁有效"**。
  所以本测试除了正向/反向用例，还专门做一次**因果验证**：
  把 protected_paths 置空后，同一个受保护文件必须**放行** —— 这证明"被拦截"确实来自路径规则，
  而不是因为脚本恰好在别处失败（后者会让测试假绿）。

全部用例使用临时策略文件 + `--today` + `--files`，**不触碰仓库状态、不依赖当前日期**。
"""
import os
import sys
import json
import shutil
import tempfile
import subprocess

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
GATE = os.path.join(ROOT, "scripts", "freeze_gate.py")

POLICY_HEAD = """version: "v1.7.25"
freeze:
  enabled: %s
  final_date: %s
  freeze_days: %s
  protected_paths: %s
  override_ack_env: FREEZE_OVERRIDE_ACK
server:
  host: 127.0.0.1
"""


def make_policy(tmp, name, enabled="true", final='"%s"' % "2026-11-15", days="14",
                protected="[internal/, agents/, cmd/]"):
    path = os.path.join(tmp, name)
    with open(path, "w", encoding="utf-8", newline="\n") as fh:
        fh.write(POLICY_HEAD % (enabled, final, days, protected))
    return path


def run(policy, extra, env_extra=None, audit_log=None):
    env = dict(os.environ)
    if audit_log:
        env["FREEZE_OVERRIDE_LOG"] = audit_log
    if env_extra:
        env.update(env_extra)
    cmd = [sys.executable, GATE, "--policy-file", policy] + extra
    r = subprocess.run(cmd, cwd=ROOT, shell=False, env=env,
                       capture_output=True, encoding="utf-8", errors="ignore", timeout=180)
    return r.returncode, (r.stdout or "") + (r.stderr or "")


def main():
    tmp = tempfile.mkdtemp(prefix="freeze_test_")
    audit = os.path.join(tmp, "audit.md")
    failures = []
    cases = []

    def check(name, rc, want_rc, out, must_contain=None):
        ok = (rc == want_rc)
        extra = ""
        if ok and must_contain:
            hit = any(m in out for m in must_contain)
            if not hit:
                ok = False
                extra = "（输出未包含 %r）" % must_contain
        cases.append((name, rc, want_rc, ok, extra))
        if not ok:
            failures.append("%s：rc=%d（期望 %d）%s" % (name, rc, want_rc, extra))

    print("=" * 70)
    print("冻结闸门自测")
    print("=" * 70)
    try:
        p_off = make_policy(tmp, "off.yaml", enabled="false", final='""')
        p_on = make_policy(tmp, "on.yaml")
        p_nodate = make_policy(tmp, "nodate.yaml", final='""')
        p_baddate = make_policy(tmp, "baddate.yaml", final='"2026/11/15"')
        p_nopaths = make_policy(tmp, "nopaths.yaml", protected="[]")

        # 1. 未武装 → 放行
        rc, out = run(p_off, ["--status"])
        check("未武装(enabled=false) → SKIP 放行", rc, 0, out, ["SKIP"])
        rc, out = run(p_off, ["--files", "internal/app/app.go"])
        check("未武装 + 架构文件 → 仍放行", rc, 0, out, ["SKIP"])

        # 2. 窗口外（今天 2026-10-01，窗口 11-01~11-15）→ 放行
        rc, out = run(p_on, ["--today", "2026-10-01", "--files", "internal/app/app.go"])
        check("窗口外 → 放行（即使改架构）", rc, 0, out, ["尚未进入冻结窗口"])

        # 3. 窗口内 + 仅材料改动 → 放行
        rc, out = run(p_on, ["--today", "2026-11-05", "--files", "docs/x.md,README.md"])
        check("窗口内 + 材料改动 → 放行", rc, 0, out, ["PASS"])

        # 4. 窗口内 + 架构改动 → 拦截
        rc, out = run(p_on, ["--today", "2026-11-05", "--files", "internal/app/app.go"])
        check("窗口内 + 架构改动 → BLOCK", rc, 1, out, ["BLOCK", "internal/app/app.go"])

        # 5. 边界：窗口起始日当天（11-15 减 14 天 = 11-01）→ 属于窗口内
        rc, out = run(p_on, ["--today", "2026-11-01", "--files", "cmd/server/main.go"])
        check("边界首日(2026-11-01) → BLOCK", rc, 1, out, ["BLOCK"])
        # 再退一天 → 窗口外
        rc, out = run(p_on, ["--today", "2026-10-31", "--files", "cmd/server/main.go"])
        check("边界前一日(2026-10-31) → 放行", rc, 0, out, ["尚未进入冻结窗口"])

        # 6. 决赛日当天仍冻结；次日解除
        rc, out = run(p_on, ["--today", "2026-11-15", "--files", "agents/x.md"])
        check("决赛日当天 → BLOCK", rc, 1, out, ["BLOCK"])
        rc, out = run(p_on, ["--today", "2026-11-16", "--files", "agents/x.md"])
        check("决赛次日 → 解除放行", rc, 0, out, ["已解除"])

        # 7. 配置故障 fail-closed
        rc, out = run(p_nodate, ["--today", "2026-11-05", "--files", "docs/x.md"])
        check("enabled=true 但无 final_date → BLOCK(fail-closed)", rc, 1, out, ["BLOCK", "配置"])
        rc, out = run(p_baddate, ["--today", "2026-11-05", "--files", "docs/x.md"])
        check("final_date 非法 → BLOCK(fail-closed)", rc, 1, out, ["BLOCK"])

        # 8. 逃生阀：缺二次确认 → 拒绝；给确认 → 放行并留审计
        rc, out = run(p_on, ["--today", "2026-11-05", "--files", "internal/x.go",
                             "--freeze-override", "决赛现场发现致命缺陷，必须立即修复并重新打包交付（已取得主理人授权）"],
                      audit_log=audit)
        check("逃生阀缺 ACK → BLOCK", rc, 1, out, ["二次确认"])
        rc, out = run(p_on, ["--today", "2026-11-05", "--files", "internal/x.go",
                             "--freeze-override", "决赛现场发现致命缺陷，必须立即修复并重新打包交付（已取得主理人授权）"],
                      env_extra={"FREEZE_OVERRIDE_ACK": "1"}, audit_log=audit)
        check("逃生阀带 ACK → 放行", rc, 0, out, ["OVERRIDE"])
        audit_ok = False
        if os.path.isfile(audit):
            body = open(audit, encoding="utf-8").read()
            # 断言用**新理由里的片段**（别用旧字符串当子串，否则改了理由就会永久假失败）
            audit_ok = ("决赛现场发现致命缺陷" in body) and ("internal/x.go" in body)
        cases.append(("逃生阀写入审计日志（含命中文件）", 1 if audit_ok else 0, 1, audit_ok, ""))
        if not audit_ok:
            failures.append("逃生阀未写入审计日志：%s" % audit)
        # 理由过短 → 拒绝
        rc, out = run(p_on, ["--today", "2026-11-05", "--files", "internal/x.go",
                             "--freeze-override", "急事"],
                      env_extra={"FREEZE_OVERRIDE_ACK": "1"}, audit_log=audit)
        check("逃生阀理由过短 → BLOCK", rc, 1, out, ["理由过短"])

        # 9. 因果验证：protected_paths 置空 → 同一个受保护文件必须放行
        #    （证明第 4 条的 BLOCK 确实来自路径规则，而不是脚本在别处失败）
        rc, out = run(p_nopaths, ["--today", "2026-11-05", "--files", "internal/app/app.go"])
        check("因果验证：protected_paths 置空 → 同文件放行", rc, 0, out, ["PASS"])
    finally:
        shutil.rmtree(tmp, ignore_errors=True)

    print()
    for name, rc, want, ok, extra in cases:
        print("  [%s] %-46s rc=%d (期望 %d) %s" % ("OK" if ok else "FAIL", name, rc, want, extra))
    print()
    if failures:
        print("冻结闸门自测：FAIL")
        for f in failures:
            print("  ✗ %s" % f)
        return 1
    print("冻结闸门自测：PASS（%d 项用例全过，含 1 项因果验证）" % len(cases))
    return 0


if __name__ == "__main__":
    sys.exit(main())
