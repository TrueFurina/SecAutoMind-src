#!/usr/bin/env python
# -*- coding: utf-8 -*-
"""题源先验审计：判定「题池能否支撑一条能力率结论」。

背景（2026-11-05/06 评审 §13）：干净池 160 题已剔除题面伪解与训练白名单，
判据链也已能给出 claimable=True。但 `pure_llm` 路径排除不了「模型在训练时
见过这些公开题 / 见过公开 writeup」。唯一能支撑「能力」叙事的前提是题目私有
且可证明未公开。

本脚本 **fail-closed**：只有同时满足下列四条才计为 `private_proven`；任一条
不满足即判「公开或来源不明」，绝不靠猜测替题目开绿：
  1. 题面自带显式来源字段（source / origin / provenance / source_url 之一）；
  2. 来源值含私有标记（private / internal / unreleased / self-authored /
     authored / 自产 / 未公开）；
  3. 题面自证创建时间在模型训练截止之后（created_at / authored_at，且
     带可解析的 ISO 日期，晚于 PRIOR_CUTOFF）；
  4. id / name / description / pool 均不含公开赛事或公开基准标识。

任何「解出率」结论都必须先读本脚本的 `capability_rate_publishable`。
0 私有题时全量跑批仍只能作为**工程回归读数**，不得对外当能力率。

用法：
  python scripts/audit_pool_prior.py                 # 审计并写证据 json
  python scripts/audit_pool_prior.py --verify        # 复核证据与池指纹一致
  python scripts/audit_pool_prior.py --selftest      # 分类逻辑变异验证
"""
from __future__ import annotations

import argparse
import hashlib
import json
import os
import re
import sys
from datetime import date, datetime

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
POOL = os.path.join(ROOT, "data", "ctf_benchmark", "purellm_clean_benchmark.json")
EVIDENCE = os.path.join(ROOT, "docs", "evidence", "capability_eval_20261105",
                       "pool_prior_audit.json")

# 模型训练截止：只有严格晚于此日期、且题面自证创建时间的题才可能排除先验。
# 这是保守线（早于多数在售模型截止时间），日期来源不明一律不算。
PRIOR_CUTOFF = date(2025, 1, 1)

SOURCE_FIELDS = ("source", "origin", "provenance", "source_url", "source_ref")
PRIVATE_MARKS = ("private", "internal", "unreleased", "self-authored",
                 "self_authored", "authored", "自产", "自建", "未公开", "未发布")
TIME_FIELDS = ("created_at", "authored_at", "written_at", "first_seen_at")
PUBLIC_MARKS = (
    r"\bext_", r"\breal_", r"\bpublic_", r"gctf", r"google[ _-]?ctf",
    r"nyu[ _-]?ctf", r"ctf[ _-]?bench", r"cybench", r"hackthebox",
    r"anxun", r"dasctf", r"羊城杯", r"西湖论剑", r"picoctf", r"wolvctf",
    r"ctftime", r"defcon", r"hitcon", r"seccon", r"github", r"writeup",
    r"ctf[ _-]?show", r"buuctf", r"nssctf", r"攻防世界",
)
PUBLIC_RE = re.compile("|".join(PUBLIC_MARKS), re.I)
POOL_PUBLIC = {"external", "ext88", "cybench", "heldout", "real", "public", "gctf"}
URL_RE = re.compile(r"https?://|\bwww\.", re.I)


def _sha256(path: str) -> str:
    h = hashlib.sha256()
    with open(path, "rb") as f:
        for chunk in iter(lambda: f.read(1 << 20), b""):
            h.update(chunk)
    return h.hexdigest()


def _parse_date(value) -> date | None:
    if not isinstance(value, str) or not value.strip():
        return None
    s = value.strip().replace("Z", "+00:00")
    try:
        return datetime.fromisoformat(s).date()
    except ValueError:
        pass
    m = re.match(r"^(\d{4})[-/.](\d{1,2})[-/.](\d{1,2})", s)
    if m:
        try:
            return date(int(m.group(1)), int(m.group(2)), int(m.group(3)))
        except ValueError:
            return None
    return None


def classify(pid: str, problem: dict) -> tuple[str, list[str]]:
    """返回 (类别, 未通过的判据列表)。类别 ∈ private_proven / public_named / unknown。"""
    blob = " ".join(str(problem.get(k, "")) for k in
                    ("id", "name", "description", "pool", "source", "origin",
                     "provenance", "source_url", "source_ref"))
    pool = str(problem.get("pool", "")).lower()
    has_public_mark = bool(PUBLIC_RE.search(blob)) or pool in POOL_PUBLIC or pid.startswith(
        ("ext_", "real_", "public_"))

    missing = []
    src = next((str(problem.get(k, "")).strip() for k in SOURCE_FIELDS
                if problem.get(k)), "")
    if not src:
        missing.append("no_source_field")
    if src and not any(m in src.lower() for m in PRIVATE_MARKS):
        missing.append("source_not_marked_private")
    created = _parse_date(next((problem.get(k) for k in TIME_FIELDS
                                if problem.get(k)), None))
    if created is None:
        missing.append("no_post_cutoff_timestamp")
    elif created <= PRIOR_CUTOFF:
        missing.append("timestamp_not_after_cutoff")
    if has_public_mark:
        missing.append("public_identifier_present")

    if missing:
        # 有公开标识的是「确定公开」，其余是「无法证明私有」，两者都不进分母。
        return ("public_named" if has_public_mark else "unknown"), missing
    return "private_proven", []


def audit(pool_path: str) -> dict:
    with open(pool_path, "r", encoding="utf-8") as f:
        d = json.load(f)
    problems = d.get("problems", d)
    if isinstance(problems, list):
        problems = {p.get("id", str(i)): p for i, p in enumerate(problems)}
    if not isinstance(problems, dict):
        raise ValueError("题池 problems 必须是 dict 或 list")

    buckets: dict[str, list[str]] = {"private_proven": [], "public_named": [], "unknown": []}
    reasons: dict[str, int] = {}
    for pid, p in problems.items():
        kind, missing = classify(pid, p)
        buckets[kind].append(pid)
        for m in missing:
            reasons[m] = reasons.get(m, 0) + 1

    total = len(problems)
    private = len(buckets["private_proven"])
    airgap = sum(1 for p in problems.values() if p.get("requires_airgap"))
    publishable = private > 0 and private == total
    return {
        "tool": "scripts/audit_pool_prior.py",
        "generated_at": datetime.now().astimezone().isoformat(timespec="seconds"),
        "pool_path": os.path.relpath(pool_path, ROOT).replace("\\", "/"),
        "pool_sha256": _sha256(pool_path),
        "prior_cutoff": PRIOR_CUTOFF.isoformat(),
        "total": total,
        "counts": {k: len(v) for k, v in buckets.items()},
        "requires_airgap": airgap,
        "missing_criteria_histogram": dict(sorted(reasons.items())),
        "public_by_pool": _by_pool(problems, buckets["public_named"]),
        "private_proven_ids": sorted(buckets["private_proven"]),
        "capability_rate_publishable": publishable,
        "conclusion": (
            "题池全部题目可证明为私有 ⇒ 本池跑批结果可作为能力率候选（仍需逐题排除模型先验与外网访问）"
            if publishable else
            "题池存在 %d/%d 题「公开或来源不明」⇒ 全量跑批只能作工程回归读数，不得对外称为能力率"
            % (total - private, total)
        ),
        "scope_note": (
            "即使全为私有题，pure_llm 路径仍须逐题证明：无外网访问（本路径 N/A）、"
            "无题面明文、无训练白名单命中、通道归属单一；本脚本只裁「题源先验」一维。"
        ),
    }


def _by_pool(problems: dict, ids: list[str]) -> dict:
    out: dict[str, int] = {}
    for pid in ids:
        pool = str(problems[pid].get("pool", "?"))
        out[pool] = out.get(pool, 0) + 1
    return dict(sorted(out.items(), key=lambda x: -x[1]))


def selftest() -> int:
    cases = [
        # (说明, 题, 期望类别)
        ("公开基准题（带 ext_ 前缀）",
         {"id": "ext_nyu_ctf_bench_2017q_cry_lowe", "pool": "heldout",
          "description": "NYU CTF Bench 2017 crypto lowe"}, "public_named"),
        ("公开赛题（real_ 前缀 + 赛事名）",
         {"id": "real_crypto_anxun2020_aes", "pool": "real",
          "description": "安洵杯 2020 AES"}, "public_named"),
        ("无来源字段的自产题 ⇒ fail-closed 不算私有",
         {"id": "q001", "pool": "mine", "description": "本地生成的一道 RSA 题"}, "unknown"),
        ("自称私有但无时间戳 ⇒ 不算私有",
         {"id": "q002", "pool": "mine", "description": "自产题",
          "source": "internal self-authored"}, "unknown"),
        ("时间戳早于截止线 ⇒ 不算私有",
         {"id": "q003", "pool": "mine", "description": "自产题",
          "source": "private self-authored", "created_at": "2024-06-01"}, "unknown"),
        ("四项齐备 ⇒ 可证明私有",
         {"id": "q004", "pool": "mine", "description": "自产题",
          "source": "private self-authored", "created_at": "2026-10-01"}, "private_proven"),
        ("四项齐备但描述里带公开赛名 ⇒ 仍不算私有",
         {"id": "q005", "pool": "mine", "description": "改编自 Google CTF 2021",
          "source": "private self-authored", "created_at": "2026-10-01"}, "public_named"),
        ("来源字段为空串 ⇒ 不算私有",
         {"id": "q006", "pool": "mine", "description": "自产题",
          "source": "  ", "created_at": "2026-10-01"}, "unknown"),
        ("带 URL 但无来源字段 ⇒ 不算私有",
         {"id": "q007", "pool": "mine", "description": "见 https://example.com/x",
          "created_at": "2026-10-01"}, "unknown"),
    ]
    ok = 0
    for name, prob, want in cases:
        got, missing = classify(prob.get("id", "x"), prob)
        good = got == want
        ok += int(good)
        print("%s %-46s got=%-14s want=%s%s" %
              ("PASS" if good else "FAIL", name, got, want,
               "" if good else "  missing=%s" % ",".join(missing)))
    print("selftest %d/%d" % (ok, len(cases)))
    return 0 if ok == len(cases) else 1


def main() -> int:
    ap = argparse.ArgumentParser(description="题源先验审计（fail-closed）")
    ap.add_argument("--pool", default=POOL)
    ap.add_argument("--out", default=EVIDENCE)
    ap.add_argument("--verify", action="store_true", help="复核证据与当前池指纹一致")
    ap.add_argument("--selftest", action="store_true")
    args = ap.parse_args()

    if args.selftest:
        return selftest()
    if not os.path.isfile(args.pool):
        print("题池不存在: %s" % args.pool, file=sys.stderr)
        return 2

    if args.verify:
        if not os.path.isfile(args.out):
            print("证据文件不存在: %s" % args.out, file=sys.stderr)
            return 2
        ev = json.load(open(args.out, encoding="utf-8"))
        now = audit(args.pool)
        same = (ev.get("pool_sha256") == now["pool_sha256"]
                and ev.get("counts") == now["counts"]
                and ev.get("capability_rate_publishable") == now["capability_rate_publishable"])
        print("%s 证据与题池%s (pool_sha=%s)" %
              ("PASS" if same else "FAIL", "一致" if same else "不一致/已漂移",
               now["pool_sha256"][:16]))
        return 0 if same else 1

    ev = audit(args.pool)
    os.makedirs(os.path.dirname(args.out), exist_ok=True)
    with open(args.out, "w", encoding="utf-8") as f:
        json.dump(ev, f, ensure_ascii=False, indent=2)
        f.write("\n")
    print("题源先验审计 → %s" % os.path.relpath(args.out, ROOT))
    print("  pool_sha256      = %s" % ev["pool_sha256"][:16])
    print("  total            = %d" % ev["total"])
    print("  private_proven   = %d" % ev["counts"]["private_proven"])
    print("  public_named     = %d" % ev["counts"]["public_named"])
    print("  unknown          = %d" % ev["counts"]["unknown"])
    print("  requires_airgap  = %d" % ev["requires_airgap"])
    print("  publishable      = %s" % ev["capability_rate_publishable"])
    print("  %s" % ev["conclusion"])
    return 0


if __name__ == "__main__":
    sys.exit(main())
