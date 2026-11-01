#!/usr/bin/env python3
"""审计：题集的真值是否能从**公开仓库**直接下载到。

为什么要有这个门禁（2026-11-01 实测）：`data/questions_external_bench` 的 40 道题里，
**16 道**的官方仓库 `challenge/flag*.txt` 的 sha256 与题集登记的真值**逐位相等**。
只要被测子进程能联网，一条 `curl` 就能拿到答案 —— 在这种题池上跑出的任何
"解出率"都不成立。审计题源、剔除题目都不解决问题（剔完池子几乎清空），
正确做法是**执行期断网**（见 internal/airgap）；本脚本负责把"哪些题有这条通道"
钉成可复核的清单。

用法：
    python scripts/audit_public_flag_leak.py                # 审计 external_bench 全部题
    python scripts/audit_public_flag_leak.py --json out.json

注意：全程只比 sha256，**绝不打印/落盘 flag 明文**。明文入的是 flag 本身的价值，
入库即等于把答案上传到仓库。
"""
from __future__ import annotations

import argparse
import hashlib
import json
import re
import sys
import urllib.request

UA = {"User-Agent": "secautomind-audit"}
DEFAULT_BENCH = "data/questions_external_bench/external_bench.json"
TREE_API = "https://api.github.com/repos/%s/git/trees/%s?recursive=1"
RAW = "https://raw.githubusercontent.com/%s/%s/%s"
FLAG_NAME_RE = re.compile(r"(^|/)(flag|flags|flag\.txt|flag\.bin|flag\.out)$", re.I)


def fetch(url: str, timeout: int = 25) -> bytes:
    req = urllib.request.Request(url, headers=UA)
    with urllib.request.urlopen(req, timeout=timeout) as r:
        return r.read()


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--bench", default=DEFAULT_BENCH)
    ap.add_argument("--json", default="", help="把结果写成 json（不含明文）")
    args = ap.parse_args()

    bench = json.load(open(args.bench, encoding="utf-8"))
    probs = bench["problems"]

    trees: dict[str, list[str]] = {}
    rows = []
    for pid, p in sorted(probs.items()):
        want = (p.get("flag_sha256") or "").lower()
        repo = p.get("source_repo") or ""
        m = re.search(r"github\.com/([^/]+/[^/]+)/tree/([^/]+)/(.+)", repo)
        if not want or not m:
            rows.append({"id": pid, "status": "NO_REPO", "hit": "", "cands": []})
            continue
        slug, branch, path = m.group(1), m.group(2), m.group(3).rstrip("/")

        if slug not in trees:
            try:
                tree = json.loads(fetch(TREE_API % (slug, branch)))["tree"]
            except Exception as e:  # noqa: BLE001
                print("[WARN] 取仓库树失败 %s: %s" % (slug, e), file=sys.stderr)
                tree = []
            trees[slug] = [t["path"] for t in tree if t.get("type") == "blob"]

        prefix = path + "/"
        cands = [x for x in trees[slug] if x.startswith(prefix) and FLAG_NAME_RE.search(x)]

        hit = ""
        for cp in cands:
            try:
                body = fetch(RAW % (slug, branch, cp))
            except Exception:  # noqa: BLE001
                continue
            for cand in (body, body.strip()):
                if hashlib.sha256(cand).hexdigest() == want:
                    hit = cp
                    break
            if hit:
                break
        rows.append({
            "id": pid,
            "category": p.get("category"),
            "status": "OK",
            "cands": [c.replace(prefix, "") for c in cands],
            "hit": hit,
        })

    leaks = [r for r in rows if r["hit"]]
    for r in rows:
        if r["status"] != "OK":
            print("%-42s %-10s" % (r["id"], r["status"]))
        elif r["hit"] or r["cands"]:
            print("%-42s %-28s %s" % (r["id"], ",".join(r["cands"])[:28], r["hit"] or "-"))
    print()
    print("题数 %d；含 flag 形文件的 %d；**可直接下载且命中真值** %d（%.0f%%）"
          % (len(rows), sum(1 for r in rows if r.get("cands")), len(leaks),
             100.0 * len(leaks) / max(len(rows), 1)))
    for r in leaks:
        print("  LEAK:", r["id"], "->", r["hit"])

    if args.json:
        json.dump({"total": len(rows), "leak": len(leaks), "rows": rows},
                  open(args.json, "w", encoding="utf-8"), ensure_ascii=False, indent=2)
        print("写出:", args.json)
    return 0


if __name__ == "__main__":
    sys.exit(main())
