#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""check_material_numbers 门禁回归测试 —— 防「一个都没扫到」静默报绿。

背景（2026-10-14 门禁审计 · 空洞绿，只读探针实证）：
  本门禁的全部结论都由「违规项计数」构成：banned_hits / anchor_hits 都为空即 PASS。
  于是**扫到 0 个文件时会无条件全绿** —— SCAN_DIRS 写错目录名、目录被 .gitignore
  排除（`官网/` 就从未入版本库）、或 SCAN_EXT 被改空，都会让门禁静默失效却报 PASS。
  探针实测：把 SCAN_DIRS 指向一个不存在的目录、根目录也无 *.md，
  旧版 main() 返回 0（PASS）。与 `_audit_llm_pool.py` 当年「池文件缺失 → 空池 → 全绿」
  是同款失效形态：**覆盖条数为 0 本身必须算红**。

本测试锁三半：
  · 回归：扫描覆盖数为 0（目录不存在 / 无可扫扩展名）/ 真值字段缺失 → 必须 SystemExit；
  · 反向变异：材料与真值一致时必须 rc=0（防"改成恒红"），且既有豁免机制
    （CALIBER-SNAPSHOT 标记、文件名历史日期）不得被顺手套坏；
  · 修复清单一致性（2026-10-16 补）：`docs/口径修复清单.md` 过期（声明状态与门禁不符）
    或缺机器可读状态行 → 必须红；缺失 → 跳过；一致 → 绿。

用法：
    python scripts/check_material_numbers_test.py
退出码：0 = 门禁健康；1 = 门禁已退化或仍能静默放行，必须修 scripts/check_material_numbers.py
"""
import contextlib
import importlib.util
import io
import os
import shutil
import sys
import tempfile

try:
    sys.stdout.reconfigure(encoding="utf-8")
except Exception:
    pass

HERE = os.path.dirname(os.path.abspath(__file__))
GATE = os.path.join(HERE, "check_material_numbers.py")


def load_gate():
    spec = importlib.util.spec_from_file_location("cmn_under_test", GATE)
    m = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(m)
    return m


TRUTH = {
    "go_files": 751, "runtime_tools": 143, "ctf_solvers": 177,
    "ctf_real_solvers": 118, "ctf_detectors": 59, "test_files": 299,
    "tools_yaml": 91, "builtin_tools": 52, "skills": 27, "agents_md": 18,
    "roles_yaml": 14, "internal_dirs": 32, "test_packages": 28,
    "non_test_lines": 128094, "total_lines": 171238, "go_packages": 41,
    "head": "deadbeef",
}

# 一份与 TRUTH 完全一致的材料（覆盖每类锚点的一种写法）
CLEAN_DOC = """# 规模一览

- Go 751 文件（299 测试文件）
- 751 Go 文件，171,238 含测试 / 128,094 行（128,094 非测试行）
- 143 运行时工具，52 内置工具
- 177 求解器 = 118 真求解器 + 59 检测器
- 91 YAML 工具（工具 YAML 91）
- 27 技能包，18 Agent，14 角色，internal 目录 32，28 包测试
"""


def run_gate(ve_files, scan_dirs=("docs",), truth=None, extra_root_files=None):
    """在临时仓库里跑门禁，返回 (rc_or_SystemExit_code, 输出)。

    ve_files: {相对 docs/ 的文件名: 内容}。scan_dirs 里的目录若写入 None 表示不创建。
    """
    tmp = tempfile.mkdtemp(prefix="cmn_probe_")
    try:
        for d in scan_dirs:
            if d is not None:
                os.makedirs(os.path.join(tmp, d), exist_ok=True)
        for rel, text in ve_files.items():
            p = os.path.join(tmp, rel)
            os.makedirs(os.path.dirname(p), exist_ok=True)
            with open(p, "w", encoding="utf-8", newline="\n") as fh:
                fh.write(text)
        for name, text in (extra_root_files or {}).items():
            with open(os.path.join(tmp, name), "w", encoding="utf-8", newline="\n") as fh:
                fh.write(text)
        cm = load_gate()
        cm.ROOT = tmp
        cm.SCAN_DIRS = list(d for d in scan_dirs if d is not None)
        cm.load_truth = lambda: (dict(TRUTH) if truth is None else dict(truth))
        buf = io.StringIO()
        with contextlib.redirect_stdout(buf):
            try:
                rc = cm.main()
            except SystemExit as e:
                rc = "SYSEXIT:%s" % (e.code,)
        return rc, buf.getvalue()
    finally:
        shutil.rmtree(tmp, ignore_errors=True)


def main():
    failures = []
    print("=" * 66)
    print("check_material_numbers 门禁回归测试（空洞绿 / 恒红 / 豁免机制）")
    print("=" * 66)

    # ---- 1. 扫描 0 文件（目录不存在）必须 fail-closed ----
    print("\n[1/13] 扫描覆盖数为 0（SCAN_DIRS 目录不存在）必须 fail-closed")
    rc, out = run_gate({}, scan_dirs=("docs",))
    ok = isinstance(rc, str) and rc.startswith("SYSEXIT")
    print("  %s 返回 %s（期望 SystemExit）" % ("PASS" if ok else "FAIL", rc))
    if not ok:
        failures.append("目录不存在时未 fail-closed（rc=%s）——「没扫到」被当成「没问题」" % rc)

    # ---- 2. 扫描 0 文件（目录存在但无可扫扩展名）必须 fail-closed ----
    print("\n[2/13] 扫描覆盖数为 0（目录存在但只有非扫描扩展名）必须 fail-closed")
    rc, out = run_gate({"docs/cover.png": "not text"}, scan_dirs=("docs",))
    ok = isinstance(rc, str) and rc.startswith("SYSEXIT")
    print("  %s 返回 %s（期望 SystemExit）" % ("PASS" if ok else "FAIL", rc))
    if not ok:
        failures.append("扩展名扫不到时未 fail-closed（rc=%s）——SCAN_EXT 被改空会静默失效" % rc)

    # ---- 3. 反向变异：材料与真值一致必须 PASS（防恒红）----
    print("\n[3/13] 材料数字与真值一致必须 PASS（反向变异：防恒红）")
    rc, out = run_gate({"docs/scale.md": CLEAN_DOC})
    ok = (rc == 0)
    print("  %s 返回 %s（期望 0）" % ("PASS" if ok else "FAIL", rc))
    if not ok:
        failures.append("一致场景被判红（rc=%s）——门禁被修成恒红：%s" % (rc, out[-300:]))

    # ---- 4. 锚点漂移必须 FAIL ----
    print("\n[4/13] 锚点漂移（Go 751 → 999）必须 FAIL")
    rc, out = run_gate({"docs/scale.md": CLEAN_DOC.replace("Go 751 文件", "Go 999 文件")})
    ok = (rc == 1)
    print("  %s 返回 %s（期望 1）" % ("PASS" if ok else "FAIL", rc))
    if not ok:
        failures.append("真漂移未判红（rc=%s）" % rc)

    # ---- 5. 已作废旧口径复活必须 FAIL ----
    print("\n[5/13] 已作废旧口径复活（140 运行时工具）必须 FAIL")
    rc, out = run_gate({"docs/scale.md": "官网写 140 运行时工具\n"})
    ok = (rc == 1)
    print("  %s 返回 %s（期望 1）" % ("PASS" if ok else "FAIL", rc))
    if not ok:
        failures.append("黑名单数字未判红（rc=%s）" % rc)

    # ---- 6. CALIBER-SNAPSHOT 历史快照必须豁免（防把豁免机制改坏）----
    print("\n[6/13] 带 CALIBER-SNAPSHOT 标记的历史档案必须豁免")
    snap = "CALIBER-SNAPSHOT: 本文件锚定 2026-09-05 基线\n\n" + CLEAN_DOC.replace("751", "715").replace("299", "257")
    rc, out = run_gate({"docs/old_snapshot.md": snap})
    ok = (rc == 0)
    print("  %s 返回 %s（期望 0）" % ("PASS" if ok else "FAIL", rc))
    if not ok:
        failures.append("历史快照豁免失效（rc=%s）——豁免机制被顺手套坏" % rc)

    # ---- 7. 文件名内嵌历史日期必须豁免 ----
    print("\n[7/13] 文件名内嵌旧日期（report_20260901.md）必须豁免")
    rc, out = run_gate({"docs/report_20260901.md": CLEAN_DOC.replace("751", "715")})
    ok = (rc == 0)
    print("  %s 返回 %s（期望 0）" % ("PASS" if ok else "FAIL", rc))
    if not ok:
        failures.append("文件名日期豁免失效（rc=%s）" % rc)

    # ---- 8. FORCE_CURRENT（名字旧仍是现行作战材料）不得豁免 ----
    print("\n[8/13] FORCE_CURRENT 清单（提交前终检清单_20260903.md）必须照查")
    rc, out = run_gate({"docs/提交前终检清单_20260903.md": CLEAN_DOC.replace("91 YAML 工具", "90 个 YAML")})
    ok = (rc == 1)
    print("  %s 返回 %s（期望 1）" % ("PASS" if ok else "FAIL", rc))
    if not ok:
        failures.append("现行作战材料被误豁免（rc=%s）——按日期豁免会放过现场还在念的材料" % rc)

    # ---- 9. 真值缺锚点字段必须 fail-closed ----
    print("\n[9/13] count_stats 缺锚点字段必须 fail-closed（不许静默跳过）")
    bad_truth = {k: v for k, v in TRUTH.items() if k != "tools_yaml"}
    rc, out = run_gate({"docs/scale.md": CLEAN_DOC}, truth=bad_truth)
    ok = isinstance(rc, str) and rc.startswith("SYSEXIT")
    print("  %s 返回 %s（期望 SystemExit）" % ("PASS" if ok else "FAIL", rc))
    if not ok:
        failures.append("真值字段缺失未 fail-closed（rc=%s）——静默跳过的门禁等于没有门禁" % rc)

    # ---- 10. 口径修复清单缺失 → 跳过（可选件，不因缺失误红）----
    print("\n[10/13] 口径修复清单缺失必须跳过（可选件缺失不得误红）")
    rc, out = run_gate({"docs/scale.md": CLEAN_DOC})
    ok = (rc == 0)
    print("  %s 返回 %s（期望 0）" % ("PASS" if ok else "FAIL", rc))
    if not ok:
        failures.append("清单缺失被误判红（rc=%s）——把可选件当必检会让门禁无法在无清单处使用" % rc)

    # ---- 11. 清单状态与门禁一致 → PASS（反向变异：防恒红）----
    print("\n[11/13] 口径修复清单状态与门禁一致（PASS）必须通过")
    rc, out = run_gate({"docs/scale.md": CLEAN_DOC,
                        "docs/口径修复清单.md": "# 材料口径修复清单\n\n当前门禁状态：PASS\n"})
    ok = (rc == 0)
    print("  %s 返回 %s（期望 0）" % ("PASS" if ok else "FAIL", rc))
    if not ok:
        failures.append("清单状态一致却被判红（rc=%s）——check_ledger 被修成恒红" % rc)

    # ---- 12. 清单过期（写 FAIL 而门禁 PASS）→ 红（核心：钉死 09-09 那种过期快照）----
    print("\n[12/13] 口径修复清单过期（声明 FAIL / 门禁 PASS）必须红")
    rc, out = run_gate({"docs/scale.md": CLEAN_DOC,
                        "docs/口径修复清单.md": "# 材料口径修复清单\n\n当前门禁状态：FAIL\n"})
    ok = (rc == 1)
    print("  %s 返回 %s（期望 1）" % ("PASS" if ok else "FAIL", rc))
    if not ok:
        failures.append("过期清单未判红（rc=%s）——09-09 那种「漂移已修、文件仍写 FAIL」会重现" % rc)

    # ---- 13. 清单缺机器可读状态行 → 红（fail-closed）----
    print("\n[13/13] 口径修复清单缺状态行必须 fail-closed")
    rc, out = run_gate({"docs/scale.md": CLEAN_DOC,
                        "docs/口径修复清单.md": "# 材料口径修复清单\n\n这里没有机器可读状态行。\n"})
    ok = (rc == 1)
    print("  %s 返回 %s（期望 1）" % ("PASS" if ok else "FAIL", rc))
    if not ok:
        failures.append("清单缺状态行未判红（rc=%s）——无状态行则判据无从挂靠" % rc)

    print("\n" + "=" * 66)
    if failures:
        print("FAIL —— %d 项不达标：" % len(failures))
        for f in failures:
            print("  - " + f)
        return 1
    print("PASS —— check_material_numbers 门禁 13/13 用例通过"
          "（零覆盖 fail-closed + 恒红防护 + 豁免机制未退化 + 清单过期双向钉死）。")
    return 0


if __name__ == "__main__":
    sys.exit(main())
