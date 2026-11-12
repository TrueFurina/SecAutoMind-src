"""从 CTF² 平台拉题面，落到 data/questions_plat/（与 questions_real 隔离，不污染现有题库）。

为什么单独建库：
- platform_ctf2.py 的详情接口只给 name/description/files，**不给 flag，也不给 flag_sha256**。
- 而 eval.cases.Question.flag_matches 在没有 expected_sha256 且 flag 为空时恒 False
  （eval/cases.py:174-180）。所以这些题在本地只能跑出「候选 flag」，判分必须回平台
  submit_flag 在线做。混进 data/questions_real 会让「离线可判分」的口径失真。

用法：
    export CTF2_TOKEN="<登录后从请求头取的 JWT>"
    export CTF2_PRACTICE="<练习场 UUID>"
    python scripts/fetch_plat_statements.py --ids 10716,10717,...  \
        --out data/questions_plat --report /tmp/fetch_plat.json

不传 --ids 则整场拉取（分页）。

只读题面，不提交、不写 flag。
"""
import argparse
import json
import os
import re
import sys
from typing import Optional

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

import platform_ctf2 as api  # noqa: E402

# 题目 text 里通常写「flag格式为DASCTF{}」，用它提 pattern
_PATTERN_RE = re.compile(r"flag\s*格式\s*为\s*([A-Za-z0-9_]+)\s*\{", re.IGNORECASE)
_PATTERN_RE2 = re.compile(r"([A-Za-z0-9_]+)\s*\{\s*\}\s*(?:的)?\s*格式", re.IGNORECASE)

# 平台 category 字段 -> 本地目录名
_CAT_MAP = {
    "crypto": "crypto", "misc": "misc", "pwn": "pwn", "reverse": "reverse",
    "web": "web", "blockchain": "blockchain", "forensics": "misc",
}


def extract_flag_pattern(description: str) -> Optional[str]:
    """从题面里提 flag 形态（如 DASCTF{ -> 'DASCTF\\{...\\}'）。提不到返回 None。"""
    if not description:
        return None
    for rx in (_PATTERN_RE, _PATTERN_RE2):
        m = rx.search(description)
        if m:
            brand = m.group(1)
            return brand + r"\{.*\}"
    if "flag{" in description.lower():
        return r"flag\{.*\}"
    return None


def normalize(detail: dict, cid: str) -> dict:
    """把平台详情转换成 eval.cases 能读的题目 JSON。"""
    desc = str(detail.get("description") or "")
    cat_raw = str(detail.get("category") or "").strip().lower()
    cat = _CAT_MAP.get(cat_raw, cat_raw or "misc")
    files = detail.get("files") or detail.get("attachment") or []
    names = []
    for f in files:
        if isinstance(f, dict):
            n = f.get("name") or f.get("filename") or ""
            if n:
                names.append(n)
        elif isinstance(f, str):
            names.append(f)
    return {
        "id": str(cid),
        "category": cat,
        "difficulty": str(detail.get("difficulty") or "MEDIUM"),
        "description": desc,
        "flag_pattern": extract_flag_pattern(desc) or "",
        "attachments": names,
        # 平台不给真值，留空即表示「本地不可判分，须在线提交」
        "flag": "",
        "flag_sha256": "",
        "score": str(detail.get("score") or ""),
        "_source": "ctf2.platform",
        "_note": "题面来自平台详情接口；无 flag/flag_sha256，判分须调 submit_flag",
    }


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--ids", default="", help="逗号分隔的题号；空则整场拉取")
    ap.add_argument("--out", default="data/questions_plat")
    ap.add_argument("--report", default="/tmp/fetch_plat.json")
    ap.add_argument("--page-size", type=int, default=50)
    ap.add_argument("--max-pages", type=int, default=40)
    a = ap.parse_args()

    token = os.environ.get("CTF2_TOKEN", "")
    pid = os.environ.get("CTF2_PRACTICE", "")
    if not token or not pid:
        print("MISSING_ENV: 需要 CTF2_TOKEN 与 CTF2_PRACTICE", file=sys.stderr)
        return 3

    # 1) 候选题号
    if a.ids:
        targets = [x.strip() for x in a.ids.split(",") if x.strip()]
    else:
        targets = []
        for page in range(1, a.max_pages + 1):
            try:
                items = api.fetch_challenges(pid, page=page, page_size=a.page_size)
            except Exception as exc:  # noqa: BLE001
                print(f"LIST_FAIL page={page}: {type(exc).__name__} {exc}", file=sys.stderr)
                break
            if not items:
                break
            for it in items:
                cid = str(it.get("id") or "")
                if cid:
                    targets.append(cid)
        print(f"列表拉到 {len(targets)} 道")

    # 2) 逐题拉详情
    os.makedirs(a.out, exist_ok=True)
    ok, fail = [], []
    for cid in targets:
        try:
            detail = api.fetch_challenge(pid, cid)
        except Exception as exc:  # noqa: BLE001
            fail.append({"id": cid, "error": f"{type(exc).__name__}: {exc}"})
            continue
        if not detail:
            fail.append({"id": cid, "error": "empty detail"})
            continue
        q = normalize(detail, cid)
        d = os.path.join(a.out, q["category"])
        os.makedirs(d, exist_ok=True)
        p = os.path.join(d, f"{cid}.json")
        with open(p, "w", encoding="utf-8") as f:
            json.dump(q, f, ensure_ascii=False, indent=1)
        ok.append({"id": cid, "category": q["category"],
                   "has_pattern": bool(q["flag_pattern"]),
                   "attachments": len(q["attachments"]),
                   "desc_len": len(q["description"])})

    rep = {"practice": pid, "requested": len(targets), "ok": len(ok),
           "fail": len(fail), "items": ok, "errors": fail}
    with open(a.report, "w", encoding="utf-8") as f:
        json.dump(rep, f, ensure_ascii=False, indent=1)
    print(f"写出 {len(ok)} 道，失败 {len(fail)} 道；报告 {a.report}")
    for e in fail[:10]:
        print("  FAIL", e["id"], e["error"])
    return 0 if ok else 1


if __name__ == "__main__":
    raise SystemExit(main())
