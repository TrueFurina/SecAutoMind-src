"""附件可读性静态核对：台账里的题，附件路径是否真的指向一个可读文件。

用途
----
附件读不到时 presolve 会静默返回 None，失败会被记成「模型解不出」。
所以任何一份失败归因台账，都应先确认它的题目附件在**当前平台**上读得到。

本脚本只做这一件事：
1) 按台账的 per_question 取 id；
2) 从题库逐池 load_questions（会走加载层的 stage_question_attachments，
   把附件复制进沙盒并改成绝对路径）；
3) 对每条附件路径 os.path.isfile。

不跑解题、不调求解器、不读题面内容、不打印任何 flag。

用法
----
    PYTHONPATH=. ~/sm_venv/bin/python scripts/audit_att_readability.py \
        --ledger data/questions_real/_audit/ext47_20261111.json \
        --out /tmp/att_audit_47.json

退出码
------
0 = 全部可读（或题目无附件）；2 = 存在找不到的题 / 存在不可读附件。
"""

from __future__ import annotations

import argparse
import json
import os
import sys

DEFAULT_POOLS = [
    "data/questions_ext",
    "data/questions_ext_cybench",
    "data/questions_ext_L2_pure_reasoning",
    "data/questions_real",
    "data/questions_ext_A_20261001",
    "data/questions_ext_trial5_20261001",
    "data/questions_ext_westlake_probe",
    "data/questions_llm_trial",
    "data/questions_ext_L2b_pure10",
]


def audit(ledger: str, pools: list[str]) -> dict:
    from core.solver_sandbox import cleanup
    from eval.cases import load_questions

    try:
        with open(ledger, encoding="utf-8") as fh:
            audit_doc = json.load(fh)
        ids = [str(q["id"]) for q in audit_doc.get("per_question", [])]
        if not ids:
            raise SystemExit("台账里没有 per_question[].id：%s" % ledger)

        pool_map: dict[str, list] = {}
        pool_sizes: dict[str, int] = {}
        for pool in pools:
            try:
                questions = load_questions(pool)
            except Exception as exc:  # noqa: BLE001 - 缺池不算失败
                print("  POOL_FAIL %s (%s)" % (pool, type(exc).__name__))
                continue
            pool_sizes[pool] = len(questions)
            for q in questions:
                pool_map.setdefault(str(getattr(q, "id", "")), []).append((pool, q))

        missing: list[str] = []
        no_attachment: list[str] = []
        ok: list[dict] = []
        bad: list[dict] = []
        for qid in ids:
            hits = pool_map.get(qid) or []
            if not hits:
                missing.append(qid)
                continue
            pool, question = hits[0]
            atts = [str(a) for a in (getattr(question, "attachments", None) or [])]
            if not atts:
                no_attachment.append(qid)
                continue
            unreadable = [a for a in atts if not os.path.isfile(a)]
            if unreadable:
                bad.append({"id": qid, "pool": pool, "total": len(atts),
                            "unreadable": unreadable})
            else:
                ok.append({"id": qid, "pool": pool, "total": len(atts)})

        return {"ledger": ledger, "pools_loaded": pool_sizes, "total": len(ids),
                "missing": missing, "no_attachment": no_attachment,
                "ok": ok, "bad": bad}
    finally:
        cleanup()


def main(argv: list[str] | None = None) -> int:
    ap = argparse.ArgumentParser(description="台账附件可读性静态核对")
    ap.add_argument("--ledger", required=True)
    ap.add_argument("--out", default="")
    ap.add_argument("--pools", nargs="*", default=DEFAULT_POOLS)
    args = ap.parse_args(argv)

    result = audit(args.ledger, args.pools)

    print("ledger ids = %d" % result["total"])
    for pool, n in result["pools_loaded"].items():
        print("  loaded %-48s %d" % (pool, n))
    print("")
    print("in_pool            = %d / %d" % (
        result["total"] - len(result["missing"]), result["total"]))
    print("no_attachment      = %d" % len(result["no_attachment"]))
    print("attachment_present = %d" % (len(result["ok"]) + len(result["bad"])))
    print("  all_readable     = %d" % len(result["ok"]))
    print("  has_unreadable   = %d" % len(result["bad"]))
    if result["missing"]:
        print("MISSING_IDS =", result["missing"])
    for item in result["bad"]:
        print("BAD  %s  pool=%s  %d/%d unreadable" % (
            item["id"], item["pool"], len(item["unreadable"]), item["total"]))
        for path in item["unreadable"]:
            print("       %s (exists=%s)" % (path, os.path.exists(path)))

    if args.out:
        with open(args.out, "w", encoding="utf-8") as fh:
            json.dump(result, fh, ensure_ascii=False, indent=2)
        print("\nwrote %s" % args.out)

    return 2 if (result["missing"] or result["bad"]) else 0


if __name__ == "__main__":
    sys.exit(main())
