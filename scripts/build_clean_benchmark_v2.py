#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""从 v1 干净池派生 v2：剔除「题面自然语言自曝答案」题，且**不覆盖 v1**。

2026-11-06 全量 160 题跑批后查实第四个假绿：v1 池里 6 道题的题面
自己写着答案（其中 5 题含「writeup 明确给出」措辞），而明文门禁
`answer_is_in_statement()` 只扫花括号 token、`candidate_variants()` 不去壳
⇒ 真值登记为 sha256(裸内容) 时完全扫不到，门禁报「零违规 = 空洞绿」。

为什么不直接改 v1：v1 的 sha256 (`0835c1f2…`) 已绑定三份已提交 verdict
（smoke3 / smoke3_closed / full160）的 `result_pool_sha256`。改一字节会让
三份历史证据立刻失去可归因性。因此 v2 一律用新文件名，v1 保持只读。

清洗规则（逐题写进 manifest，可复核；证据不含任何明文答案）：
  V1 剔除「自然语言自曝答案」题 —— 判据唯一真值源
      check_benchmark_plaintext_answer.self_disclosure_in_statement
  V2 复验旧判据 answer_is_in_statement 仍为 0（v1 已剔过 2 题）
  V3 保留 requires_airgap 标记、flag 字段仍不回流（v1 已移除 121 个）
  V4 文件名含 benchmark ⇒ 自动落入两个明文门禁的 *benchmark*.json 扫描范围
  V5 记录父池指纹与 v1 已绑 verdict 列表，禁止反向改写

用法：
  python scripts/build_clean_benchmark_v2.py
  python scripts/build_clean_benchmark_v2.py --verify
  python scripts/build_clean_benchmark_v2.py --selftest
"""
from __future__ import annotations

import argparse
import hashlib
import json
import os
import sys

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from check_benchmark_plaintext_answer import (answer_is_in_statement,  # noqa: E402
                                              self_disclosure_in_statement)

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
BENCH_DIR = os.path.join(ROOT, "data", "ctf_benchmark")
PARENT = os.path.join(BENCH_DIR, "purellm_clean_benchmark.json")
OUT = os.path.join(BENCH_DIR, "purellm_clean_benchmark_v2.json")
MANIFEST = os.path.join(BENCH_DIR, "purellm_clean_benchmark_v2.manifest.json")

# v1 指纹已绑定的历史证据；改 v1 会让这些全部失去可归因性。
PARENT_BOUND_VERDICTS = [
    "docs/evidence/capability_eval_20261105/verdict_smoke3.json",
    "docs/evidence/capability_eval_20261105/verdict_smoke3_closed.json",
    "docs/evidence/capability_eval_20261105/verdict_full160.json",
]
KNOWN_DROP_COUNT = 6


def _sha256(path):
    h = hashlib.sha256()
    with open(path, "rb") as f:
        for chunk in iter(lambda: f.read(65536), b""):
            h.update(chunk)
    return h.hexdigest()


def _sha8(s):
    return hashlib.sha256(s.encode("utf-8")).hexdigest()[:8]


def classify(prob):
    """返回 (是否剔除, 证据 dict|None)；证据不含明文答案。"""
    ev = self_disclosure_in_statement(prob)
    if ev:
        return True, {"rule": "V1", "reason": "题面自然语言自曝答案（sha256 反查命中）",
                       "answer_form": ev["answer_form"],
                       "answer_form_length": ev["answer_form_length"],
                       "answer_form_sha8": ev["answer_form_sha8"],
                       "self_disclosing_wording": ev["self_disclosing_wording"]}
    leak, _ = answer_is_in_statement(prob)
    if leak:
        return True, {"rule": "V2", "reason": "旧判据命中花括号明文答案（v1 本应已剔）"}
    return False, None


def build(parent=PARENT, out=OUT, manifest_path=MANIFEST, expect_parent_sha=None):
    if not os.path.isfile(parent):
        raise SystemExit("父池不存在 —— 拒绝生成（fail-closed）")
    parent_sha = _sha256(parent)
    if expect_parent_sha and parent_sha != expect_parent_sha:
        raise SystemExit("父池指纹与登记值不符 —— 拒绝生成（fail-closed）")
    doc = json.load(open(parent, encoding="utf-8"))
    probs = doc.get("problems", doc)
    if not isinstance(probs, dict):
        raise SystemExit("父池 problems 必须是 dict")

    kept, drops, actions = {}, [], []
    for pid, prob in sorted(probs.items()):
        if not isinstance(prob, dict):
            continue
        pid = str(pid)
        drop, ev = classify(prob)
        if drop:
            row = {"id": pid, "action": "DROP", "pool": prob.get("pool", "?"),
                   "category": prob.get("category", "?"),
                   "requires_airgap": bool(prob.get("requires_airgap"))}
            row.update(ev)
            drops.append(row)
            actions.append(row)
            continue
        kept[pid] = prob
        actions.append({"id": pid, "action": "KEEP", "pool": prob.get("pool", "?"),
                        "requires_airgap": bool(prob.get("requires_airgap"))})

    payload = {
        "benchmark": "purellm_clean_benchmark_v2",
        "denominator": len(kept),
        "provenance": {
            "source": os.path.relpath(parent, ROOT).replace("\\", "/"),
            "source_sha256": parent_sha,
            "parent_version": "v1",
            "parent_bound_verdicts": PARENT_BOUND_VERDICTS,
            "rules": [
                "V1 剔除题面自然语言自曝答案题（判据=check_benchmark_plaintext_answer.self_disclosure_in_statement）",
                "V2 复验旧花括号明文判据仍为 0",
                "V3 保留 requires_airgap、不回流 flag 明文字段",
                "V4 文件名含 benchmark，纳入门禁扫描范围",
                "V5 父池只读：禁止反向改写 v1（三份 verdict 已绑其指纹）",
            ],
            "note": (
                "v2 由 build_clean_benchmark_v2.py 从已入库的 v1 派生，不是 188 草稿池直接清洗。"
                "v1 的 6 道自曝题已在本池剔除；父池指纹见 source_sha256。"
                "已知未解决风险：判分 verify_flag() 依赖 candidate_variants()，后者不产生裸内容变体，"
                "真值登记为 sha256(裸内容) 的题「答对也可能判不中」；该文件属他人在途 WIP，本轮未改。"
            ),
            "known_limitations": [
                "题源 100% 公开，任何分母的跑批只能作工程回归读数，不得称能力率",
                "判分不去壳（他人 WIP orchestrator / flag_util 未改），0 命中可能混入假阴性",
                "大量题面过短或缺附件，结构上不可解（v1 全量已实测：题面中位数 78 字符）",
            ],
        },
        "problems": kept,
    }
    with open(out, "w", encoding="utf-8") as f:
        json.dump(payload, f, ensure_ascii=False, indent=2, sort_keys=True)

    mf = {
        "tool": "scripts/build_clean_benchmark_v2.py",
        "out": os.path.relpath(out, ROOT).replace("\\", "/"),
        "out_sha256": _sha256(out),
        "parent": os.path.relpath(parent, ROOT).replace("\\", "/"),
        "parent_sha256": parent_sha,
        "parent_bound_verdicts": PARENT_BOUND_VERDICTS,
        "total_in": len(probs),
        "total_out": len(kept),
        "dropped": len(drops),
        "drop_detail": drops,
        "requires_airgap_ids": sorted(k for k, v in kept.items() if v.get("requires_airgap")),
        "actions": actions,
        "gate_after_build": {
            "self_disclosure_in_statement": sum(
                1 for p in kept.values() if self_disclosure_in_statement(p)),
            "answer_is_in_statement": sum(
                1 for p in kept.values() if answer_is_in_statement(p)[0]),
        },
    }
    with open(manifest_path, "w", encoding="utf-8") as f:
        json.dump(mf, f, ensure_ascii=False, indent=2)
    return mf


def verify(out=OUT, manifest_path=MANIFEST, parent=PARENT):
    if not all(os.path.isfile(p) for p in (out, manifest_path, parent)):
        print("FAIL 池/manifest/父池缺失", file=sys.stderr)
        return 2
    mf = json.load(open(manifest_path, encoding="utf-8"))
    doc = json.load(open(out, encoding="utf-8"))
    probs = doc.get("problems", {})
    checks = [
        ("池指纹", _sha256(out) == mf["out_sha256"]),
        ("父池指纹未漂移", _sha256(parent) == mf["parent_sha256"]),
        ("题数一致", len(probs) == mf["total_out"] == doc.get("denominator")),
        ("剔除数一致", mf["total_in"] - mf["total_out"] == mf["dropped"]),
        ("剔除数等于已知 6", mf["dropped"] == KNOWN_DROP_COUNT),
        ("v2 无自然语言自曝题", not any(self_disclosure_in_statement(p) for p in probs.values())),
        ("v2 无花括号明文题", not any(answer_is_in_statement(p)[0] for p in probs.values())),
        ("manifest 内建门禁计数为 0", all(v == 0 for v in mf["gate_after_build"].values())),
        ("v1 未被改写（指纹在绑定清单内）", mf["parent_sha256"] == _sha256(parent)),
    ]
    for name, ok in checks:
        print("  %s %s" % ("PASS" if ok else "FAIL", name))
    return 0 if all(ok for _, ok in checks) else 1


def selftest():
    """变异验证：自曝题必剔、干净题必留、父池指纹不符必拒。"""
    def prob(desc, sha):
        return {"description": desc, "flag_sha256": sha, "pool": "real"}
    synth = "zz_synthetic_bare_0001"
    bare = hashlib.sha256(synth.encode()).hexdigest()
    cases = [
        ("自然语言自曝裸内容 → DROP", classify(prob("writeup 明确给出 %s。" % synth, bare))[0], True),
        ("题面不含答案 → KEEP", classify(prob("分析流量包找端口。", bare))[0], False),
        ("花括号明文 → DROP（旧判据）",
         classify(prob("答案是 flag{%s}。" % synth,
                       hashlib.sha256(("flag{%s}" % synth).encode()).hexdigest()))[0], True),
        ("真值不同形 → KEEP", classify(prob("writeup 明确给出 %s。" % synth,
                                            hashlib.sha256(b"other").hexdigest()))[0], False),
        ("无合法指纹 → 不裁定(保留)", classify({"description": "x"})[0], False),
    ]
    ok = 0
    for name, got, want in cases:
        ok += int(got == want)
        print("%s %-40s got=%-5s want=%s" % ("PASS" if got == want else "FAIL", name, got, want))
    # 证据无明文
    ev = classify(prob("writeup 明确给出 %s。" % synth, bare))[1]
    no_plain = ev is not None and synth not in json.dumps(ev, ensure_ascii=False)
    ok += int(no_plain)
    print("%s DROP 证据不含明文答案" % ("PASS" if no_plain else "FAIL"))
    # 父池指纹不符 → fail-closed
    import tempfile
    tmp = tempfile.mkdtemp()
    try:
        p = os.path.join(tmp, "parent.json")
        o = os.path.join(tmp, "out.json")
        m = os.path.join(tmp, "out.manifest.json")
        json.dump({"problems": {"q": {"description": "干净题", "flag_sha256": bare}}},
                  open(p, "w", encoding="utf-8"))
        try:
            build(p, o, m, expect_parent_sha="0" * 64)
            rejected = False
        except SystemExit:
            rejected = True
        ok += int(rejected)
        print("%s 父池指纹不符 → 拒绝生成(fail-closed)" % ("PASS" if rejected else "FAIL"))
    finally:
        import shutil
        shutil.rmtree(tmp, ignore_errors=True)
    total = len(cases) + 2
    print("selftest %d/%d" % (ok, total))
    return 0 if ok == total else 1


def main():
    ap = argparse.ArgumentParser(description="从 v1 派生 v2 干净池（不覆盖 v1）")
    ap.add_argument("--parent", default=PARENT)
    ap.add_argument("--out", default=OUT)
    ap.add_argument("--manifest", default=MANIFEST)
    ap.add_argument("--expect-parent-sha", default=None,
                    help="登记父池指纹，不符则拒绝生成（fail-closed）")
    ap.add_argument("--verify", action="store_true")
    ap.add_argument("--selftest", action="store_true")
    args = ap.parse_args()
    if args.selftest:
        return selftest()
    if args.verify:
        return verify(args.out, args.manifest, args.parent)
    mf = build(args.parent, args.out, args.manifest, args.expect_parent_sha)
    print("v2 生成完成：%d -> %d 题（剔除 %d，标 requires_airgap %d）"
          % (mf["total_in"], mf["total_out"], mf["dropped"], len(mf["requires_airgap_ids"])))
    for d in mf["drop_detail"]:
        print("  DROP %-52s [%s] form=%-7s len=%d sha8=%s 自曝=%s"
              % (d["id"][:52], d["rule"], d.get("answer_form", "?"),
                 d.get("answer_form_length", -1), d.get("answer_form_sha8", "?"),
                 d.get("self_disclosing_wording", "?")))
    print("父池 sha256=%s（只读，三份 verdict 已绑定）" % mf["parent_sha256"])
    print("v2   sha256=%s" % mf["out_sha256"])
    print("内建门禁计数=%s" % mf["gate_after_build"])
    return 0


if __name__ == "__main__":
    sys.exit(main())
