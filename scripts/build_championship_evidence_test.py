#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""build_championship_evidence --check 回归测试 —— 防「活值整段采集失败」静默报绿。

背景（2026-10-14 门禁审计 · 空洞绿，只读探针实证）：
  check() 的字段比对用 `cmp(skip_if_none=True)`：任一侧取不到值就跳过。于是当
  **live 侧整段采集失败**时 drift 恒为空：
    · count_stats 挂了        → caliber={"error": ...}，18 个字段全部 None → 全跳过；
    · summary 缺失            → benchmark={"error": ...}，base/layers/provenance 全 None → 全跳过；
    · golden 哈希取不到       → files_sha256 为空 → 跳过；
    · gates 段压根没采集      → 无任何 _rc 键 → 第 4 段循环不进 → 跳过。
  探针实测：四类失败同时注入，drift = 0 条，--check 打印「对外数字全部一致」PASS。
  证据包存在的意义正是「对外数字与代码不脱节」——采不到真值时必须红。

修法（fail-closed）：新增结构性判据 —— 段级 error/为空、包内有值而活值为 None、
  门禁 RC 一条都没记，全部计入 drift；字段级 skip 仅在**两侧都取不到**时才放行
  （保留 go_packages 这类环境相关字段的既有豁免）。

本测试锁两半：
  · 回归：四类采集失败 / 字段消失 / RC 缺失 → drift 必须非空；
  · 反向变异：包与活值完全一致时 drift 必须为空（防"改成恒红"）。

用法：
    python scripts/build_championship_evidence_test.py
退出码：0 = 门禁健康；1 = 门禁已退化或仍能静默放行，必须修 scripts/build_championship_evidence.py
"""
import copy
import importlib.util
import os
import sys

try:
    sys.stdout.reconfigure(encoding="utf-8")
except Exception:
    pass

HERE = os.path.dirname(os.path.abspath(__file__))
GATE = os.path.join(HERE, "build_championship_evidence.py")


def load_gate():
    spec = importlib.util.spec_from_file_location("bce_under_test", GATE)
    m = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(m)
    return m


def make_saved():
    """一份与当前仓库形态等价的证据包（包内值）。"""
    caliber = {k: 100 + i for i, k in enumerate(BCE.CALIBER_COMPARE)}
    caliber["go_packages"] = 41
    base = {k: {"total": 3, "hit": 3, "miss": 0, "coverage_pct": 100.0}
            for k in BCE.BASE_SETS}
    base["static"].update({"flag_scan_only": 0, "real_solver_hit": 3})
    base["attachment"]["water_filled"] = 0
    return {
        "schema": BCE.SCHEMA,
        "generated_at": "2026-10-14T00:00:00+08:00",
        "caliber": caliber,
        "benchmark": {
            "base": base,
            "layers": {k: {"total": 3, "hit": 3, "miss": 0} for k in BCE.EXPLOIT_LAYERS},
            "web_hints": {"total": 4, "group_a_no_hint": 2,
                          "group_b_with_hint": 2, "delta": 0},
            "provenance": {"real_problems": 12, "synthetic_problems": 8,
                           "total_problems": 20, "synthetic_ratio_pct": 40.0},
            "summary_sha256": "a" * 64,
        },
        "golden": {"freeze_check_rc": 0,
                   "files_sha256": {"internal/ctfplatform/testdata/request_golden.json": "b" * 64}},
        "gates": {"secret_guard_rc": 0, "verify_evidence_rc": 0,
                  "secret_guard_selftest_rc": 0},
        "artifacts": {},
        "build": {},
        "notes": [],
    }


BCE = None  # main() 里赋值（make_saved 要用模块级常量）


def main():
    global BCE
    BCE = load_gate()
    saved = make_saved()
    failures = []
    print("=" * 66)
    print("build_championship_evidence --check 回归测试（空洞绿 / 恒红）")
    print("=" * 66)

    # ---- 1. live caliber 整段采集失败必须算漂移 ----
    print("\n[1/10] 活值 caliber 采集失败（count_stats 挂了）必须算漂移")
    live = copy.deepcopy(saved)
    live["caliber"] = {"error": "count_stats rc=1"}
    drift = BCE.check(live, saved)
    ok = any("caliber" in d for d in drift)
    print("  %s drift %d 条%s" % ("PASS" if ok else "FAIL", len(drift),
                                  "（含 caliber）" if ok else ""))
    if not ok:
        failures.append("count_stats 失败仍零漂移——规模真值整段缺失却报 PASS")

    # ---- 2. live benchmark 整段采集失败必须算漂移 ----
    print("\n[2/10] 活值 benchmark 采集失败（summary 缺失）必须算漂移")
    live = copy.deepcopy(saved)
    live["benchmark"] = {"error": "summary missing"}
    drift = BCE.check(live, saved)
    ok = any("benchmark" in d for d in drift)
    print("  %s drift %d 条%s" % ("PASS" if ok else "FAIL", len(drift),
                                  "（含 benchmark）" if ok else ""))
    if not ok:
        failures.append("基准汇总缺失仍零漂移——四大基础集/利用层整段缺失却报 PASS")

    # ---- 3. 包内未记录任何门禁 RC 必须算漂移 ----
    print("\n[3/10] 证据包未记录任何门禁 RC 必须算漂移")
    live = copy.deepcopy(saved)
    bad_saved = copy.deepcopy(saved)
    bad_saved["gates"] = {"note": "轻量模式未重跑门禁"}
    drift = BCE.check(live, bad_saved)
    ok = any("gates" in d for d in drift)
    print("  %s drift %d 条%s" % ("PASS" if ok else "FAIL", len(drift),
                                  "（含 gates）" if ok else ""))
    if not ok:
        failures.append("门禁 RC 一条都没记却 PASS——证据包的门禁结论段被架空")

    # ---- 4. 包内有值、活值为 None（字段消失）必须算漂移 ----
    print("\n[4/10] 包内有值而活值缺失（caliber.go_files=None）必须算漂移")
    live = copy.deepcopy(saved)
    live["caliber"]["go_files"] = None
    drift = BCE.check(live, saved)
    ok = any("go_files" in d for d in drift)
    print("  %s drift %d 条%s" % ("PASS" if ok else "FAIL", len(drift),
                                  "（含 go_files）" if ok else ""))
    if not ok:
        failures.append("字段消失被 skip_if_none 吞掉——活值缺失等于没变化，防线失效")

    # ---- 5. golden 哈希活值缺失必须算漂移 ----
    print("\n[5/10] golden 文件哈希活值缺失必须算漂移")
    live = copy.deepcopy(saved)
    live["golden"]["files_sha256"] = {}
    drift = BCE.check(live, saved)
    ok = any("files_sha256" in d for d in drift)
    print("  %s drift %d 条%s" % ("PASS" if ok else "FAIL", len(drift),
                                  "（含 files_sha256）" if ok else ""))
    if not ok:
        failures.append("golden 哈希取不到仍放行——跨语言 golden 可被静默改掉")

    # ---- 6. 利用层块消失必须算漂移 ----
    print("\n[6/10] 活值缺利用层块（jwt）必须算漂移")
    live = copy.deepcopy(saved)
    del live["benchmark"]["layers"]["jwt"]
    drift = BCE.check(live, saved)
    ok = any("jwt" in d for d in drift)
    print("  %s drift %d 条%s" % ("PASS" if ok else "FAIL", len(drift),
                                  "（含 jwt）" if ok else ""))
    if not ok:
        failures.append("利用层块消失未计红——删块即可让该层退出比对")

    # ---- 7. 反向变异：完全一致必须零漂移（防恒红）----
    print("\n[7/10] 包内与活值完全一致必须零漂移（反向变异：防恒红）")
    drift = BCE.check(copy.deepcopy(saved), saved)
    ok = (drift == [])
    print("  %s drift %d 条（期望 0）" % ("PASS" if ok else "FAIL", len(drift)))
    if not ok:
        failures.append("一致场景被判漂移（%d 条）——门禁被修成恒红，真退化无从分辨：%s"
                        % (len(drift), " ; ".join(d.strip() for d in drift[:3])))

    # ---- 8. 反向变异：环境相关字段两侧皆 None 必须放行 ----
    print("\n[8/10] go_packages 两侧均 None 必须放行（环境字段豁免保留）")
    live = copy.deepcopy(saved)
    live["caliber"]["go_packages"] = None
    s8 = copy.deepcopy(saved)
    s8["caliber"]["go_packages"] = None
    drift = BCE.check(live, s8)
    ok = (drift == [])
    print("  %s drift %d 条（期望 0）" % ("PASS" if ok else "FAIL", len(drift)))
    if not ok:
        failures.append("go_packages 双侧缺失被误判漂移——无 go list 环境会恒红")

    # ---- 9. 既有判据：真值漂移必须算漂移（未被新逻辑破坏）----
    print("\n[9/10] 真值漂移（go_files 100 → 101）必须算漂移")
    live = copy.deepcopy(saved)
    live["caliber"]["go_files"] = saved["caliber"]["go_files"] + 1
    drift = BCE.check(live, saved)
    ok = any("go_files" in d for d in drift)
    print("  %s drift %d 条%s" % ("PASS" if ok else "FAIL", len(drift),
                                  "（含 go_files）" if ok else ""))
    if not ok:
        failures.append("真值漂移未判红——原有比对逻辑被新判据破坏")

    # ---- 10. 既有判据：门禁 RC 非 0 必须算漂移 ----
    print("\n[10/10] 包内门禁 RC 非 0 必须算漂移（失败不许冻结进证据包）")
    live = copy.deepcopy(saved)
    s10 = copy.deepcopy(saved)
    s10["gates"]["secret_guard_rc"] = 1
    drift = BCE.check(live, s10)
    ok = any("secret_guard_rc" in d for d in drift)
    print("  %s drift %d 条%s" % ("PASS" if ok else "FAIL", len(drift),
                                  "（含 secret_guard_rc）" if ok else ""))
    if not ok:
        failures.append("门禁 RC=1 未判红——一次失败的门禁结论可被冻结进证据包")

    print("\n" + "=" * 66)
    if failures:
        print("FAIL —— %d 项不达标：" % len(failures))
        for f in failures:
            print("  - " + f)
        return 1
    print("PASS —— 证据包一致性门禁 10/10 用例通过"
          "（四类采集失败 fail-closed + 恒红防护 + 既有判据未退化）。")
    return 0


if __name__ == "__main__":
    sys.exit(main())
