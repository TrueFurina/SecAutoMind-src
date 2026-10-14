#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""verify_evidence 门禁回归测试 —— 防「证据包零覆盖 / 输入缺失」静默放行。

背景（2026-10-14 门禁审计 · 空洞绿，只读探针实证）：
  构造一份四大基础集 total 均 >0、但 provenance 全 0
  （real=0 / synthetic=0 / total_problems=0 / synthetic_ratio_pct=0）的 summary，
  旧版 check_evidence() **不报错** —— total<=0 时三条自洽检查
  （real+synth==total、ratio 实算比对、字段类型）全部自动成立，
  门禁照常打印「来源标注（§2.3）：真题 0 题 / 自产题 0 题」并 PASS。
  这与 `_audit_llm_pool.py` 当年「池文件缺失 → 空池 → all_green=True」同构：
  **覆盖条数为 0 本身必须算红**，否则 §2.3 诚信铁律（真题 vs 自产题必须标注）
  形同虚设——对外引用「100% 来自真题」时无任何机器防线。

本测试锁两半（缺一不可，否则门禁会退化成恒红或恒绿）：
  · 回归：provenance 零覆盖 / 字段缺失 / 层未全绿 / 集为空 → 必须抛 AssertionError；
  · 反向变异：完全自洽的 summary 必须**不**抛（证明没有把门禁修成恒红）。

用法：
    python scripts/verify_evidence_test.py
退出码：0 = 门禁健康；1 = 门禁已退化或仍能静默放行，必须修 scripts/verify_evidence.py
"""
import copy
import importlib.util
import json
import os
import shutil
import sys
import tempfile

try:
    sys.stdout.reconfigure(encoding="utf-8")
except Exception:
    pass

HERE = os.path.dirname(os.path.abspath(__file__))
GATE = os.path.join(HERE, "verify_evidence.py")


def load_gate():
    spec = importlib.util.spec_from_file_location("ve_under_test", GATE)
    m = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(m)
    return m


def full_summary():
    """一份完全自洽的 summary（= 当前仓库真实形态的最小等价物）。"""
    s = {
        "static": {"total": 10, "hit": 10, "miss": 0, "coverage_pct": 100.0,
                   "water_filled": 0, "flag_scan_only": 0, "real_solver_hit": 10},
        "execution": {"total": 5, "hit": 5, "miss": 0, "coverage_pct": 100.0},
        "web": {"total": 3, "hit": 3, "miss": 0, "coverage_pct": 100.0},
        "attachment": {"total": 2, "hit": 2, "miss": 0, "coverage_pct": 100.0,
                       "water_filled": 0},
        "provenance": {"real": {"problems": 12}, "synthetic": {"problems": 8},
                       "total_problems": 20, "synthetic_ratio_pct": 40.0},
    }
    for k in ("jwt", "deser", "xxe", "upload", "graphql", "ssrf", "sqli_deep",
              "ssti_deep", "ecdsa_nonce_reuse", "padding_oracle", "blind_oob",
              "hash_ext", "gcm_nonce_reuse", "mt19937_recover", "lfsr_predict",
              "lcg_predict", "crc32_forge"):
        s[k] = {"total": 3, "hit": 3, "miss": 0, "coverage_pct": 100.0}
    return s


def expect_raise(ve, summary, must_raise, must_contain=None):
    """跑 check_evidence，返回 (是否符合期望, 诊断文本)。"""
    tmp = tempfile.mkdtemp(prefix="ve_probe_")
    # relpath 相对模块 ROOT：把 ROOT 指向临时目录，避免跨盘 relpath 崩溃
    old_root, ve.ROOT = ve.ROOT, tmp
    try:
        p = os.path.join(tmp, "all_benchmarks_summary.json")
        with open(p, "w", encoding="utf-8", newline="\n") as fh:
            json.dump(summary, fh, ensure_ascii=False)
        try:
            ve.check_evidence(p)
            # 不抛错：期望"必须红"的用例在此失败，期望"必须绿"的用例在此通过
            return (not must_raise), "（未抛错）"
        except AssertionError as e:
            msg = str(e)
            ok = must_raise and (must_contain is None or must_contain in msg)
            return ok, msg
    finally:
        ve.ROOT = old_root
        shutil.rmtree(tmp, ignore_errors=True)


def main():
    ve = load_gate()
    failures = []
    print("=" * 66)
    print("verify_evidence 门禁回归测试（空洞绿 / 输入缺失 / 反向变异）")
    print("=" * 66)

    cases = []

    def case(idx, title, summary, must_raise, must_contain=None):
        ok, msg = expect_raise(ve, summary, must_raise, must_contain)
        cases.append((idx, title, ok, msg))

    # ---- 1. 反向变异：完全自洽必须放行（防"改成恒红"）----
    case("1/10", "完全自洽的 summary 必须通过（反向变异：防恒红）",
         full_summary(), must_raise=False)

    # ---- 2. provenance 零覆盖必须 fail-closed（2026-10-14 封死的空洞绿）----
    s = full_summary()
    s["provenance"] = {"real": {"problems": 0}, "synthetic": {"problems": 0},
                       "total_problems": 0, "synthetic_ratio_pct": 0}
    case("2/10", "provenance 零覆盖（基础集有题、来源标注为 0）必须算红",
         s, must_raise=True, must_contain="覆盖为 0")

    # ---- 3. provenance 字段缺失（None）必须算红 ----
    s = full_summary()
    del s["provenance"]["total_problems"]
    case("3/10", "provenance 缺 total_problems 必须算红",
         s, must_raise=True, must_contain="字段不完整")

    # ---- 4. provenance 占比不自洽必须算红 ----
    s = full_summary()
    s["provenance"]["synthetic_ratio_pct"] = 99.0
    case("4/10", "provenance 占比与实算不符必须算红",
         s, must_raise=True, must_contain="占比不自洽")

    # ---- 5. real+synth != total 必须算红 ----
    s = full_summary()
    s["provenance"]["total_problems"] = 99
    case("5/10", "provenance real+synth != total 必须算红",
         s, must_raise=True, must_contain="不自洽")

    # ---- 6. 利用层未全绿必须算红 ----
    s = full_summary()
    s["jwt"] = {"total": 3, "hit": 1, "miss": 2, "coverage_pct": 33.3}
    case("6/10", "冠军差异点未全绿（jwt 1/3）必须算红",
         s, must_raise=True, must_contain="未全绿")

    # ---- 7. 基础集 total=0 必须算红 ----
    s = full_summary()
    s["static"]["total"] = 0
    s["static"]["hit"] = 0
    case("7/10", "基础集 total=0 必须算红",
         s, must_raise=True, must_contain="必须 >0")

    # ---- 8. 附件注水必须算红 ----
    s = full_summary()
    s["attachment"]["water_filled"] = 2
    case("8/10", "附件集注水命中（water_filled=2）必须算红",
         s, must_raise=True, must_contain="反注水")

    # ---- 9. 缺利用层块必须算红 ----
    s = full_summary()
    del s["crc32_forge"]
    case("9/10", "缺冠军差异点块必须算红",
         s, must_raise=True, must_contain="缺冠军差异点")

    # ---- 10. 缺基础集块必须算红 ----
    s = full_summary()
    del s["attachment"]
    case("10/10", "缺基础集块必须算红",
         s, must_raise=True, must_contain="缺块")

    for idx, title, ok, msg in cases:
        print("[%s] %s -> %s" % (idx, title, "PASS" if ok else "FAIL"))
        if not ok:
            failures.append("%s %s%s" % (idx, title, ("：" + msg[:90]) if msg else ""))
    print("  （自洽用例不抛错 = 预期；其余用例抛 AssertionError = 预期）")

    print("\n" + "=" * 66)
    if failures:
        print("FAIL —— %d 项不达标：" % len(failures))
        for f in failures:
            print("  - " + f)
        return 1
    print("PASS —— verify_evidence 门禁 %d/%d 用例通过"
          "（零覆盖 fail-closed + 恒红防护 + 既有判据未退化）。" % (len(cases), len(cases)))
    return 0


if __name__ == "__main__":
    sys.exit(main())
