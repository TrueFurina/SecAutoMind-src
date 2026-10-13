#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""check_quant_effect 门禁回归测试 —— 防止「对外量化陈述机验」静默空转。

背景（2026-10-14 门禁 fail-closed 审计实锤，三种空洞绿形态）：
    M2. **全 slow**：每条声明都标 `耗时类: slow` → CI 默认 quick 模式选中 0 条，
        脚本打印「PASS —— 本次机验的 0 条量化陈述全部可复现」并 rc=0。
        零机验却报全绿，与 `_audit_llm_pool.py` 当年「池文件缺失 → 自动全真」同构。
    M3. **缺 command/pattern**：声明没给可机验的命令 → 旧版记 `[SKIP]` 且**不计入
        fails**，结论仍是 PASS，甚至谎报「1 条全部可复现」（实际 0 条被验）。
        违反验收第 8 条「对外量化陈述 100% 可指回」——不可机验就该红，不该静默。
    M1. **全 slow + 缺字段叠加**时，门禁彻底变成"什么都不做还报绿"的哑门禁。

本测试在临时仓库里构造上述输入，断言门禁**必须 rc=1**；
同时用 M4/M5 反向锁死「修完没变成恒红」：真实漂移要红、真实一致要绿。

用法：
    python scripts/check_quant_effect_test.py
退出码：0 = 门禁健康；1 = 门禁已退化，必须修 scripts/check_quant_effect.py
"""
import os
import shutil
import subprocess
import sys
import tempfile

try:
    sys.stdout.reconfigure(encoding="utf-8")
except Exception:
    pass

HERE = os.path.dirname(os.path.abspath(__file__))
GATE = os.path.join(HERE, "check_quant_effect.py")

# 可机验的命令（ASCII 输出，规避 Windows 控制台编码差异）。
# ⚠️ 刻意**不用** `python -c "print(...)"`：Windows cmd.exe 对 `-c "..."` 的嵌套引号
# 解析与 POSIX sh 不同（`"%s" -c "print('...')"` 会被拆成无法识别的命令名），
# 曾让本测试的"一致场景"在 Windows 上假红。改用探针脚本文件，两侧通用。
CMD_OK = '"%s" probe_ok.py'
CMD_DRIFT = '"%s" probe_drift.py'
PAT = r"(\d+)/(\d+) = ([\d.]+)%"


def claim(cid, cmd, pat=PAT, expect="5/10 = 50.0%", cost="quick"):
    lines = ["- id: %s" % cid]
    if cmd is not None:
        lines.append("  command: %s" % cmd)
    if pat is not None:
        lines.append("  pattern: '%s'" % pat)
    lines.append("  耗时类: %s" % cost)
    lines.append("  期望: %s" % expect)
    return "\n".join(lines)


def doc_of(claims):
    return "# 量化效果\n\n```yaml\n" + "\n".join(claims) + "\n```\n"


def run_gate(doc_text, full=False):
    """在临时仓库里跑门禁，返回 (rc, 输出)。"""
    tmp = tempfile.mkdtemp(prefix="qe_gate_")
    try:
        root = os.path.join(tmp, "repo")
        os.makedirs(os.path.join(root, "scripts"))
        os.makedirs(os.path.join(root, "docs"))
        shutil.copyfile(GATE, os.path.join(root, "scripts", "check_quant_effect.py"))
        # 探针脚本：命令由门禁以 cwd=ROOT 执行，故放在仓库根
        with open(os.path.join(root, "probe_ok.py"), "w",
                  encoding="utf-8", newline="\n") as fh:
            fh.write('print("hits 5/10 = 50.0%")\n')
        with open(os.path.join(root, "probe_drift.py"), "w",
                  encoding="utf-8", newline="\n") as fh:
            fh.write('print("hits 3/10 = 30.0%")\n')
        with open(os.path.join(root, "docs", "quant_effect.md"), "w",
                  encoding="utf-8", newline="\n") as fh:
            fh.write(doc_text)
        args = [sys.executable, os.path.join(root, "scripts", "check_quant_effect.py")]
        if full:
            args.append("--full")
        p = subprocess.run(args, cwd=root, capture_output=True, text=True,
                           encoding="utf-8", errors="replace", timeout=300)
        return p.returncode, (p.stdout or "") + (p.stderr or "")
    finally:
        shutil.rmtree(tmp, ignore_errors=True)


def main():
    failures = []
    py = sys.executable

    print("=" * 62)
    print("check_quant_effect 门禁回归测试（空洞绿防线）")
    print("=" * 62)

    # ---- 空洞绿三形态：必须 rc=1 ----
    print("\n[1/2] 空洞绿必须变红（fail-closed）")

    cases_empty = [
        ("M2 全部声明标 slow（quick 模式机验 0 条）",
         doc_of([claim("only_slow", CMD_OK % py, cost="slow")]), False),
        ("M3 声明缺 command（不可机验却记 SKIP 报绿）",
         doc_of([claim("no_cmd", None)]), False),
        ("M3b 声明缺 pattern（同上）",
         doc_of([claim("no_pat", CMD_OK % py, pat=None)]), False),
        # M2b：--full 时 slow 会被选中，必须真的执行命令 —— 用会漂移的命令，
        # 断言 rc=1 且**不是**"机验 0 条"那种空转红，以此证明 slow 声明确实跑了。
        ("M2b --full 下 slow 声明必须真实执行命令",
         doc_of([claim("only_slow2", CMD_DRIFT % py, cost="slow")]), True),
    ]
    for label, doc, full in cases_empty[:3]:
        rc, out = run_gate(doc, full)
        ok = (rc == 1)
        print("  %s %s（期望 rc=1，实际 rc=%d）" % ("PASS" if ok else "FAIL", label, rc))
        if not ok:
            failures.append("%s：门禁未 fail-closed（rc=%d）\n    %s"
                            % (label, rc, out.strip().replace("\n", "\n    ")[:400]))

    # M2b：--full 时 slow 会被选中，此时应当真的去跑并因期望不符而红（不是空转红）
    rc, out = run_gate(cases_empty[3][1], full=True)
    ok_full = (rc == 1) and ("0 条" not in out)
    print("  %s --full 下 slow 被真实机验（期望 rc=1 且非空转，实际 rc=%d）"
          % ("PASS" if ok_full else "FAIL", rc))
    if not ok_full:
        failures.append("--full 下 slow 声明未真实机验（rc=%d）\n    %s"
                        % (rc, out.strip().replace("\n", "\n    ")[:400]))

    # ---- 反向变异：不能修成恒红 ----
    print("\n[2/2] 反向变异（门禁不得恒红 / 不得虚报）")

    rc, out = run_gate(doc_of([claim("drift", CMD_DRIFT % py)]))
    ok = (rc == 1)
    print("  %s M4 真实数字漂移必须红（期望 rc=1，实际 rc=%d）" % ("PASS" if ok else "FAIL", rc))
    if not ok:
        failures.append("真实漂移未被检出（rc=%d）——门禁已失效\n    %s"
                        % (rc, out.strip().replace("\n", "\n    ")[:400]))

    rc, out = run_gate(doc_of([claim("ok", CMD_OK % py)]))
    ok = (rc == 0) and ("本次机验的 1 条" in out)
    print("  %s M5 真实一致必须绿且计数真实（期望 rc=0 且报 1 条，实际 rc=%d）"
          % ("PASS" if ok else "FAIL", rc))
    if not ok:
        failures.append("一致场景未通过或计数虚报（rc=%d）\n    %s"
                        % (rc, out.strip().replace("\n", "\n    ")[:400]))

    # 混合场景：1 条真过 + 1 条缺 command → 必须红（缺字段不得被"1 条通过"掩盖）
    rc, out = run_gate(doc_of([claim("ok", CMD_OK % py),
                               claim("no_cmd", None)]))
    ok = (rc == 1)
    print("  %s M6 混合场景缺字段必须连坐红（期望 rc=1，实际 rc=%d）"
          % ("PASS" if ok else "FAIL", rc))
    if not ok:
        failures.append("混合场景下缺 command 的声明被静默放过（rc=%d）\n    %s"
                        % (rc, out.strip().replace("\n", "\n    ")[:400]))

    print("\n" + "=" * 62)
    if failures:
        print("[FAIL] 量化机验门禁已退化，必须修 scripts/check_quant_effect.py：")
        for f in failures:
            print("  - %s" % f)
        print("=" * 62)
        return 1
    print("[PASS] 量化机验门禁健康：3 类空洞绿全部 fail-closed，"
          "真实漂移仍检出，一致场景仍放行且计数真实。")
    print("=" * 62)
    return 0


if __name__ == "__main__":
    sys.exit(main())
