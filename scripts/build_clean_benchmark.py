#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""从 176 题草稿池生成「可引用」能力池，并留下逐题处置与指纹。

背景（2026-11-05 评审 §11）：`data/ctf_benchmark/purellm_full188.json` 是
gitignore 的本地草稿，含 2 题把真答案写进 description（其中 1 题就是 1/176 的
唯一命中）、4 题 flag 字段与真值自洽、1 题训练白名单题。且文件名不匹配门禁
`*benchmark*.json`，所以伪解从未被拦下。

清洗规则（每条都写进 manifest，可逐题复核）：
  R1 剔除「题面即答案」伪解 —— 判据复用 check_benchmark_plaintext_answer.answer_is_in_statement
  R2 剔除训练白名单题 —— 复用 check_pure_llm_caliber.load_trained_ids
  R3 移除全部 flag 明文字段，只留 flag_sha256（判分只需哈希；133 个不自洽的
     flag 字段多为题面已知输入，留着只会制造「答案在数据文件里」的隐患）
  R4 官方仓库可直接下载 flag 的题**不剔除**，但打 requires_airgap=True；
     只有 CTF_AIRGAP=1 且零外网留痕时才允许计入（由判据层裁决）
  R5 输出文件名含 benchmark，使其落入明文答案门禁的扫描范围

用法：
  python scripts/build_clean_benchmark.py                 # 用默认路径
  python scripts/build_clean_benchmark.py --src ... --out ... --manifest ...
  python scripts/build_clean_benchmark.py --verify       # 只验指纹，不重写
"""
from __future__ import annotations

import argparse
import hashlib
import json
import os
import sys

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from check_benchmark_plaintext_answer import answer_is_in_statement  # noqa: E402
from check_pure_llm_caliber import load_leak_ids, load_trained_ids  # noqa: E402

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
DEFAULT_SRC = os.path.join(ROOT, "data", "ctf_benchmark", "purellm_full188.json")
DEFAULT_OUT = os.path.join(ROOT, "data", "ctf_benchmark", "purellm_clean_benchmark.json")
DEFAULT_MANIFEST = os.path.join(ROOT, "data", "ctf_benchmark", "purellm_clean_benchmark.manifest.json")
DEFAULT_LEAK = os.path.join(ROOT, ".workbuddy", "tmp", "rev_leak.out")


def _sha256(path):
    h = hashlib.sha256()
    with open(path, "rb") as f:
        for chunk in iter(lambda: f.read(65536), b""):
            h.update(chunk)
    return h.hexdigest()


def build(src, out, manifest_path, leak_path):
    doc = json.load(open(src, encoding="utf-8"))
    probs = doc.get("problems", doc)
    if not isinstance(probs, dict):
        raise SystemExit("题池 problems 必须是 dict")

    trained, trained_ok = load_trained_ids(ROOT)
    leak_ids, leak_ok = load_leak_ids(leak_path)
    if not trained_ok:
        raise SystemExit("训练白名单解析失败 —— 拒绝生成（fail-closed）")
    if not leak_ok:
        raise SystemExit("官方 flag 泄漏集解析失败 —— 拒绝生成（fail-closed）")

    kept = {}
    actions = []
    for pid, prob in sorted(probs.items()):
        if not isinstance(prob, dict):
            continue
        pid = str(pid)
        plaintext, _ = answer_is_in_statement(prob)
        if plaintext:
            actions.append({"id": pid, "action": "DROP", "rule": "R1",
                            "reason": "题面内存在 sha256 命中的真答案（伪解）"})
            continue
        if pid in trained or str(prob.get("id", "")) in trained:
            actions.append({"id": pid, "action": "DROP", "rule": "R2",
                            "reason": "命中 AUTHORIZED_KPI_SOLVES 训练白名单"})
            continue
        clean = dict(prob)
        removed_flag = clean.pop("flag", None)
        tags = []
        if removed_flag is not None:
            tags.append("R3:移除flag明文字段")
        if pid in leak_ids:
            tags.append("R4:官方仓库可下载flag")
            clean["requires_airgap"] = True
        actions.append({"id": pid, "action": "KEEP", "rule": "+".join(tags) or "-",
                        "pool": clean.get("pool"),
                        "reason": "requires_airgap=True（仅 airgap 跑批可计分）"
                        if clean.get("requires_airgap") else ""})
        kept[pid] = clean

    payload = {
        "benchmark": "purellm_clean_benchmark",
        "denominator": len(kept),
        "provenance": {
            "source": os.path.relpath(src, ROOT).replace("\\", "/"),
            "source_sha256": _sha256(src),
            "rules": ["R1 题面即答案剔除", "R2 训练白名单剔除",
                      "R3 移除flag明文字段", "R4 泄漏题标requires_airgap",
                      "R5 文件名纳入*benchmark*.json门禁"],
            "note": "本池仍为本地草稿（data/ 被 .gitignore 忽略）。对外引用前须由持有提交权的会话入库或把指纹写进 docs/evidence/。",
        },
        "problems": kept,
    }
    with open(out, "w", encoding="utf-8") as f:
        json.dump(payload, f, ensure_ascii=False, indent=2, sort_keys=True)

    drops = [a for a in actions if a["action"] == "DROP"]
    mf = {
        "out": os.path.relpath(out, ROOT).replace("\\", "/"),
        "out_sha256": _sha256(out),
        "source_sha256": payload["provenance"]["source_sha256"],
        "total_in": len(probs),
        "total_out": len(kept),
        "dropped": len(drops),
        "drop_detail": drops,
        "requires_airgap_ids": sorted(k for k, v in kept.items() if v.get("requires_airgap")),
        "trained_whitelist_size": len(trained),
        "leak_set_size": len(leak_ids),
        "flag_fields_removed": sum(1 for a in actions if "R3" in a["rule"]),
        "actions": actions,
    }
    with open(manifest_path, "w", encoding="utf-8") as f:
        json.dump(mf, f, ensure_ascii=False, indent=2)
    return mf


def verify(out, manifest_path):
    mf = json.load(open(manifest_path, encoding="utf-8"))
    actual = _sha256(out)
    ok = actual == mf["out_sha256"]
    print("指纹校验：%s (expected=%s actual=%s)" % ("OK" if ok else "FAIL",
                                                   mf["out_sha256"][:16], actual[:16]))
    return 0 if ok else 1


def main():
    ap = argparse.ArgumentParser(description="生成可引用能力池（带逐题处置与指纹）")
    ap.add_argument("--src", default=DEFAULT_SRC)
    ap.add_argument("--out", default=DEFAULT_OUT)
    ap.add_argument("--manifest", default=DEFAULT_MANIFEST)
    ap.add_argument("--leak-set", default=DEFAULT_LEAK)
    ap.add_argument("--verify", action="store_true", help="只验指纹")
    args = ap.parse_args()
    if args.verify:
        return verify(args.out, args.manifest)
    mf = build(args.src, args.out, args.manifest, args.leak_set)
    print("清洗完成：%d -> %d 题（剔除 %d，标 requires_airgap %d）"
          % (mf["total_in"], mf["total_out"], mf["dropped"], len(mf["requires_airgap_ids"])))
    for d in mf["drop_detail"]:
        print("  DROP %s [%s] %s" % (d["id"], d["rule"], d["reason"]))
    print("移除 flag 字段 %d 题；池 sha256=%s" % (mf["flag_fields_removed"], mf["out_sha256"]))
    print("manifest=%s" % args.manifest)
    return 0


if __name__ == "__main__":
    sys.exit(main())
