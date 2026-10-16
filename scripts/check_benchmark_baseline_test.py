#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""基准集达标基线门禁（run_all_benchmarks.check_baseline）回归 + 变异测试。

为什么必须有这个测试：
  2026-10-14 前，run_all_benchmarks.py 跑完 22 个基准集后**无论结果如何都 exit 0**，
  而对外材料写着「二十基准集全绿」。某项从 3/3 掉到 1/3 时 CI 照样绿、对外陈述照样
  「全绿」——这是一条静默虚报通道，与 _audit_llm_pool.py 当年的失效形态同构。

本测试锁两件事（缺一不可，否则门禁会退化成"恒红"或"恒绿"）：
  - 回归：基线缺失/为空、命中退化、题数漂移、新增项未上锁 → 必须算未达标；
  - 变异：全部达标时必须判定达标（防止为了不绿而改成恒红）。

用法:
    python scripts/check_benchmark_baseline_test.py
"""
from __future__ import annotations

import copy
import json
import os
import sys
import tempfile

HERE = os.path.dirname(os.path.abspath(__file__))
REPO = os.path.dirname(HERE)
BENCH_DIR = os.path.join(REPO, "data", "ctf_benchmark")
sys.path.insert(0, BENCH_DIR)

import run_all_benchmarks as R  # noqa: E402

SUMMARY_JSON = os.path.join(BENCH_DIR, "all_benchmarks_summary.json")
# 基线在 docs/（data/* 是目录级忽略，放 data/ctf_benchmark/ 下会静默不入仓）
BASELINE_JSON = os.path.join(REPO, "docs", "benchmark_baseline.json")


def load_json(path):
    with open(path, encoding="utf-8") as fh:
        return json.load(fh)


def write_json(path, obj):
    with open(path, "w", encoding="utf-8", newline="\n") as fh:
        json.dump(obj, fh, ensure_ascii=False, indent=2)
        fh.write("\n")


def main():
    failures = []
    print("=" * 66)
    print("check_benchmark_baseline 门禁回归测试（基线缺失 / 空洞绿 / 变异）")
    print("=" * 66)

    if not os.path.exists(SUMMARY_JSON):
        print("FAIL: 缺 %s —— 先跑 run_all_benchmarks.py" % SUMMARY_JSON)
        return 1
    if not os.path.exists(BASELINE_JSON):
        print("FAIL: 缺 %s —— 基线文件必须入仓" % BASELINE_JSON)
        return 1

    summary = load_json(SUMMARY_JSON)
    baseline = load_json(BASELINE_JSON)
    suites = {k: v for k, v in summary.items() if k not in ("provenance", "note")}
    n_suites = len(suites)
    print("\n实况基准集 %d 项，基线已锁 %d 项\n" % (n_suites, len(baseline.get("suites", {}))))

    tmp = tempfile.mkdtemp(prefix="benchbaseline_")

    def with_baseline(mutate, summary_obj=None):
        """把（变异后的）基线写到临时路径，跑 check_baseline，返回 (达标数, 总数, bad)。"""
        base = copy.deepcopy(baseline)
        mutate(base)
        p = os.path.join(tmp, "baseline_%d.json" % len(os.listdir(tmp)))
        write_json(p, base)
        return R.check_baseline(summary_obj if summary_obj is not None else suites, p)

    # ---- 1. 基线文件缺失 → fail-closed（不比对等于没门禁） ----
    print("[1/8] 基线文件缺失必须 fail-closed")
    ok_n, total_n, bad = R.check_baseline(suites, os.path.join(tmp, "nope.json"))
    ok = (ok_n == 0 and bad)
    print("  %s 达标 %d，未达标说明 %d 条（期望 0 达标且有说明）"
          % ("PASS" if ok else "FAIL", ok_n, len(bad)))
    if not ok:
        failures.append("基线缺失却未计红（达标 %d，bad=%s）——静默放行" % (ok_n, bad))

    # ---- 2. suites 为空 → fail-closed（最隐蔽的空洞绿） ----
    print("\n[2/8] 基线存在但 suites 为空必须 fail-closed")
    ok_n, total_n, bad = with_baseline(lambda b: b.update({"suites": {}}))
    ok = (ok_n == 0 and bad)
    print("  %s 达标 %d，未达标说明 %d 条（期望 0 达标且有说明）"
          % ("PASS" if ok else "FAIL", ok_n, len(bad)))
    if not ok:
        failures.append("空基线却未计红——与 _audit_llm_pool.py 同型的空洞绿")

    # ---- 3. 全部达标 → 必须判定达标（反向变异：防"改成恒红"） ----
    print("\n[3/8] 实况全部达标时必须判定达标（防修成恒红）")
    ok_n, total_n, bad = with_baseline(lambda b: None)
    ok = (ok_n == n_suites and total_n == n_suites and not bad)
    print("  %s 达标 %d/%d，未达标 %d 条" % ("PASS" if ok else "FAIL", ok_n, total_n, len(bad)))
    if not ok:
        failures.append("全达标却被判红（%s）——门禁被修成恒红，真退化无从分辨"
                        % " ; ".join(bad[:3]))

    # ---- 4. 变异：某项命中退化 ----
    print("\n[4/8] 变异 · 利用层命中退化（jwt 3/3 → 1/3）必须计红")
    mut = copy.deepcopy(suites)
    mut["jwt"]["hit"] = 1
    mut["jwt"]["miss"] = 2
    ok_n, total_n, bad = with_baseline(lambda b: None, mut)
    ok = any("jwt" in x for x in bad)
    print("  %s 未达标说明 %d 条（含 jwt：%s）"
          % ("PASS" if ok else "FAIL", len(bad), any("jwt" in x for x in bad)))
    if not ok:
        failures.append("jwt 命中退化未被捕获——这正是对外『全绿』虚报的入口")

    # ---- 5. 变异：题数漂移（题目被删） ----
    print("\n[5/8] 变异 · 题数漂移（ssrf 3 → 2）必须计红")
    mut = copy.deepcopy(suites)
    mut["ssrf"]["total"] = 2
    mut["ssrf"]["hit"] = 2
    ok_n, total_n, bad = with_baseline(lambda b: None, mut)
    ok = any("ssrf" in x for x in bad)
    print("  %s 未达标说明 %d 条" % ("PASS" if ok else "FAIL", len(bad)))
    if not ok:
        failures.append("题数漂移未被捕获（删题可绕过门禁）")

    # ---- 6. 变异：新增基准集未上锁 ----
    print("\n[6/8] 变异 · 实测有新基准集但基线未上锁必须计红")
    mut = copy.deepcopy(suites)
    mut["brand_new_suite"] = {"total": 9, "hit": 0, "miss": 9, "coverage_pct": 0.0}
    ok_n, total_n, bad = with_baseline(lambda b: None, mut)
    ok = any("brand_new_suite" in x for x in bad)
    print("  %s 未达标说明 %d 条" % ("PASS" if ok else "FAIL", len(bad)))
    if not ok:
        failures.append("新增基准集未上锁却放行——新增项可零命中混入")

    # ---- 7. 变异：web_hints（非 hit/total 形态）退化 ----
    print("\n[7/8] 变异 · web_hints 读题组退化（6 → 3）必须计红")
    mut = copy.deepcopy(suites)
    mut["web_hints"]["group_b_with_hint"] = 3
    mut["web_hints"]["delta"] = 0
    ok_n, total_n, bad = with_baseline(lambda b: None, mut)
    ok = any("web_hints" in x for x in bad)
    print("  %s 未达标说明 %d 条" % ("PASS" if ok else "FAIL", len(bad)))
    if not ok:
        failures.append("web_hints 退化未被捕获（该集不是 hit/total 形态，易漏判）")

    # ---- 8. 变异：附件集注水命中 ----
    print("\n[8/8] 变异 · 附件集注水题命中（water_filled 0 → 2）必须计红")
    mut = copy.deepcopy(suites)
    mut["attachment"]["water_filled"] = 2
    ok_n, total_n, bad = with_baseline(lambda b: None, mut)
    ok = any("attachment" in x for x in bad)
    print("  %s 未达标说明 %d 条" % ("PASS" if ok else "FAIL", len(bad)))
    if not ok:
        failures.append("附件集注水命中未被捕获——朴素正则命中会被算成能力")

    # ---- 9. 反绕过：--update-baseline 不许把地板改低 ----
    print("\n[9/10] 反绕过 · 地板下降时 --update-baseline 必须拒绝上锁")
    mut = copy.deepcopy(suites)
    mut["jwt"]["hit"] = 1
    p9 = os.path.join(tmp, "baseline_upd.json")
    write_json(p9, copy.deepcopy(baseline))
    wrote = R.update_baseline(mut, p9)
    after = load_json(p9)
    still = after.get("suites", {}).get("jwt", {}).get("min_hit")
    ok = (wrote is False and still == baseline["suites"]["jwt"]["min_hit"])
    print("  %s update_baseline 返回 %s，基线 jwt.min_hit 仍为 %s（期望拒绝写入）"
          % ("PASS" if ok else "FAIL", wrote, still))
    if not ok:
        failures.append("地板可被改低——退化时改基线即可绕过门禁，防线形同虚设")

    # ---- 10. 反向变异：地板抬升必须允许（防止修成"永远拒绝上锁"） ----
    print("\n[10/10] 反向变异 · 地板抬升时 --update-baseline 必须允许上锁")
    mut = copy.deepcopy(suites)
    mut["jwt"]["hit"] = 3
    mut["jwt"]["total"] = 4  # 题目增加，地板随之上抬
    p10 = os.path.join(tmp, "baseline_up2.json")
    low = copy.deepcopy(baseline)
    low["suites"]["jwt"]["min_hit"] = 2
    low["suites"]["jwt"]["total"] = 3
    write_json(p10, low)
    wrote = R.update_baseline(mut, p10)
    after = load_json(p10)
    new_hit = after.get("suites", {}).get("jwt", {}).get("min_hit")
    ok = (wrote is True and new_hit == 3)
    print("  %s update_baseline 返回 %s，jwt.min_hit %s → %s（期望允许并抬升）"
          % ("PASS" if ok else "FAIL", wrote, 2, new_hit))
    if not ok:
        failures.append("地板抬升被拒绝（返回 %s）——门禁被修成永远无法上锁" % wrote)

    # ---- 11. 留痕：--update-baseline 不许吃掉手写 header 元数据 ----
    # 2026-10-16 实锤：旧 update_baseline() 用硬编码文案整份覆盖 header，
    # 一次重新上锁就**静默删掉** location_note 与两条长说明（diff 从 1 字段膨胀到 91 增 24 删）。
    print("\n[11/11] 留痕 · --update-baseline 必须保留手写 header（location_note / note / rule）")
    p11 = os.path.join(tmp, "baseline_hdr.json")
    hdr = {
        "schema": 1,
        "created": "2026-10-14",
        "location_note": "手写留痕，重新上锁不得删除",
        "note": "手写长说明",
        "rule": "手写规则",
        "suites": copy.deepcopy(baseline["suites"]),
    }
    hdr["suites"]["jwt"]["min_hit"] = 2  # 旧值较低 → 本次应被抬升为 3（证明 suites 确实被重写）
    write_json(p11, hdr)
    mut = copy.deepcopy(suites)
    wrote = R.update_baseline(mut, p11)
    after = load_json(p11)
    ok = (wrote is True
          and after.get("location_note") == hdr["location_note"]
          and after.get("note") == hdr["note"]
          and after.get("rule") == hdr["rule"]
          and after.get("created") == hdr["created"]
          and after.get("suites", {}).get("jwt", {}).get("min_hit") == 3)
    print("  %s 返回 %s；location_note=%r；jwt.min_hit 2 → %s（期望：留痕保留且 suites 重写）"
          % ("PASS" if ok else "FAIL", wrote, after.get("location_note"),
             after.get("suites", {}).get("jwt", {}).get("min_hit")))
    if not ok:
        failures.append("--update-baseline 吃掉了手写 header（留痕丢失）或被误修成不再重写 suites")

    print("\n" + "=" * 66)
    if failures:
        print("FAIL —— %d 项不达标：" % len(failures))
        for f in failures:
            print("  - " + f)
        return 1
    print("PASS —— 基线门禁 11/11 用例通过"
          "（空洞绿、恒红、改低基线三个方向都锁住）。")
    return 0


if __name__ == "__main__":
    sys.exit(main())
