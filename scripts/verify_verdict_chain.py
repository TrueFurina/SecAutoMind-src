#!/usr/bin/env python
# -*- coding: utf-8 -*-
"""已入库 verdict 的「代码重算 vs 存盘证据」一致性门禁。

背景（2026-11-06 第八个偏差）：`run_capability_eval.py` 的 `claim_scope` 由
代码重算写入 verdict，评审引用的正是这些 JSON；但**存盘之后没有任何 CI
校验它**。`capability_caliber_test.py` 只跑合成自测，`audit_private_proof.py
--verify` 只比私有性锚点证据，`verify_evidence.py` 全文零处引用 verdict。
于是手改一行 `claim_scope="capability_rate_candidate"` 或把
`capability_rate` 写成 0.9，全门禁依旧绿 —— 「证据自动生成」堵住了填写时的
造假，没堵住事后篡改。

本脚本用**同一生产判据**重算并逐键比对，另校验结果池指纹自洽、算术自洽、
作用域语义自洽。不引入第二套判据，避免口径漂移：

  python scripts/verify_verdict_chain.py --check      # 门禁（异常 exit 1）
  python scripts/verify_verdict_chain.py --selftest  # 变异攻击自证会变红

fail-closed：verdict 集缩小、题池缺失、claim_scope 缺失、分母/命中数缺失、
git 清单不可用（由 claim_scope_for_pool 内部处理）一律判红，绝不猜绿。
本门禁只证明「证据文件没被改坏」，**不证明任何能力**；题源全公开，
作用域仍为 engineering_regression_only，能力证据仍为空。
"""
from __future__ import annotations

import argparse
import glob
import json
import os
import sys
import tempfile

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import run_capability_eval as rce  # noqa: E402

ROOT = rce.ROOT
VERDICT_DIR = os.path.join(ROOT, "docs", "evidence", "capability_eval_20261105")
VERDICT_GLOB = os.path.join(VERDICT_DIR, "verdict_*.json")

# 证据集完整性下限：防止「删掉一份 verdict 让不一致消失」造成空洞绿。
MIN_VERDICTS = 4


def _load(path):
    with open(path, encoding="utf-8") as f:
        return json.load(f)


def verify_one(path):
    """返回 (ok, 问题描述列表)。纯函数，不写文件、不打印。"""
    try:
        d = _load(path)
    except (ValueError, OSError) as exc:
        return False, ["verdict 解析失败：%s" % exc]
    ev = d.get("evidence") or {}
    cs = d.get("claim_scope") or {}
    errs = []
    if not isinstance(cs, dict) or not cs:
        return False, ["claim_scope 缺失 ⇒ fail-closed（禁止手填作用域）"]

    pool_rel = cs.get("pool_path") or ev.get("pool_path") or ""
    audit_rel = cs.get("audit_evidence_path") or ""
    pool_path = os.path.join(ROOT, pool_rel)
    audit_path = os.path.join(ROOT, audit_rel) if audit_rel else ""
    if not pool_rel or not os.path.isfile(pool_path):
        return False, ["绑定的题池文件不存在：%r" % pool_rel]

    bound = (ev.get("result_pool_sha256") or ev.get("pool_sha256")
            or cs.get("pool_sha256"))
    fresh = rce.claim_scope_for_pool(pool_path=pool_path,
                                     audit_path=audit_path,
                                     bound_pool_sha=bound)
    for k in sorted(set(cs) | set(fresh)):
        if cs.get(k) != fresh.get(k):
            errs.append("claim_scope.%s 与代码重算不一致" % k)

    # 结果绑定的池必须就是被审计的池（防换池洗白）。
    if (ev.get("result_pool_sha256") and ev.get("pool_sha256")
            and ev["result_pool_sha256"] != ev["pool_sha256"]):
        errs.append("evidence.result_pool_sha256 != pool_sha256（结果绑定的不是被审计的池）")

    # 算术一致性：rate 必须等于 LLM_SOLVED / claimable_denominator。
    denom = d.get("claimable_denominator")
    solved = (d.get("verdicts") or {}).get("LLM_SOLVED")
    rate = d.get("capability_rate")
    if d.get("claimable") is False:
        if rate is not None:
            errs.append("claimable=False 但 capability_rate 非空（不可归因时须为 null）")
    elif isinstance(denom, int) and denom > 0 and isinstance(solved, int):
        want = solved / denom
        if not isinstance(rate, (int, float)) or abs(float(rate) - want) > 1e-9:
            errs.append("capability_rate=%r != LLM_SOLVED/分母=%.6g" % (rate, want))
    else:
        errs.append("分母/命中数缺失或非法，无法裁定 ⇒ fail-closed")

    # 作用域语义：非 candidate 不得声明可发布能力率。
    if (fresh.get("claim_scope") != "capability_rate_candidate"
            and cs.get("capability_rate_publishable")):
        errs.append("作用域非 capability_rate_candidate 却声明可发布能力率")
    return (not errs), errs


def check(paths=None, quiet=False):
    paths = sorted(glob.glob(VERDICT_GLOB)) if paths is None else list(paths)
    if len(paths) < MIN_VERDICTS:
        print("🔴 FAIL —— verdict 证据集仅 %d 份 < 下限 %d（防删件造成的空洞绿）"
              % (len(paths), MIN_VERDICTS))
        return 1
    bad = 0
    for p in paths:
        ok, errs = verify_one(p)
        if not quiet:
            print("  [%s] %s" % ("OK" if ok else "FAIL", os.path.basename(p)))
            for e in errs:
                print("      · %s" % e)
        bad += 0 if ok else 1
    print("verdict 一致性：%s（%d 份 / %d 份异常）"
          % ("PASS" if not bad else "FAIL", len(paths), bad))
    return 0 if not bad else 1


def selftest():
    """变异攻击：证明本门禁对「事后篡改 verdict」确实会变红，不是恒绿。"""
    base = sorted(glob.glob(VERDICT_GLOB))
    if not base:
        print("FAIL: 找不到可变异的 verdict（fail-closed）")
        return 1
    original = _load(base[0])
    cases = []

    def attack(label, mutate):
        d = json.loads(json.dumps(original))
        mutate(d)
        with tempfile.TemporaryDirectory() as td:
            p = os.path.join(td, "verdict.json")
            with open(p, "w", encoding="utf-8") as f:
                json.dump(d, f, ensure_ascii=False)
            ok, errs = verify_one(p)
        cases.append((label, not ok, errs))

    attack("原件应 PASS", lambda d: None)  # 这一个断言方向相反，下面单独处理
    pristine = cases.pop(0)
    ok = pristine[1] is False  # verify_one(原件) 应 ok=True ⇒ not ok=False
    print("  [%s] %-40s errs=%s"
          % ("OK" if ok else "FAIL", "原件通过（分支可达，非永远红灯）",
             pristine[2][:2]))

    attack("手改作用域为 capability_rate_candidate",
           lambda d: d["claim_scope"].__setitem__("claim_scope",
                                                 "capability_rate_candidate"))
    attack("手改 capability_rate 为 0.9",
           lambda d: d.__setitem__("capability_rate", 0.9))
    attack("换池洗白（改结果池指纹）",
           lambda d: d["evidence"].__setitem__("result_pool_sha256", "0" * 64))
    attack("删除 claim_scope 字段",
           lambda d: d.pop("claim_scope", None))
    attack("伪造私有性外部锚点",
           lambda d: d["claim_scope"].__setitem__("private_proof_anchored", True))
    attack("篡改题面自曝计数",
           lambda d: d["claim_scope"].__setitem__("statement_tainted_count", -1))

    passed = 0
    for label, blocked, errs in cases:
        good = blocked is True
        passed += 1 if good else 0
        print("  [%s] %-40s %s"
              % ("OK" if good else "FAIL", label,
                 "" if good else "未被拦住！errs=%s" % errs[:2]))
    passed += 1 if ok else 0
    total = len(cases) + 1
    print("verdict 篡改变异自测：%d/%d" % (passed, total))
    return 0 if passed == total else 1


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__.splitlines()[1])
    ap.add_argument("--check", action="store_true", help="校验证据一致性（默认行为）")
    ap.add_argument("--selftest", action="store_true", help="变异攻击自测")
    args = ap.parse_args()
    if args.selftest:
        return selftest()
    return check()


if __name__ == "__main__":
    sys.exit(main())
