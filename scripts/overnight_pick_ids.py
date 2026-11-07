#!/usr/bin/env python3
"""从结果 json 里挑 id 列表，供「解出题复现」与「超时题加时重跑」使用。

--what solved   取 solved=True 的题
--what timeout  取 timeout_rounds>0 的题（接口硬截止，不是答错）
--what api      取 api_error_rounds>0 的题
多个结果文件会取并集（同一模型两轮里解出的题都要复现）。
"""
import argparse
import json


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--what", default="solved", choices=["solved", "timeout", "api"])
    ap.add_argument("files", nargs="*")
    a = ap.parse_args()

    ids = []
    for p in a.files:
        try:
            d = json.load(open(p, encoding="utf-8"))
        except Exception:
            continue
        for r in d.get("details") or []:
            if a.what == "solved" and r.get("solved"):
                ids.append(r.get("id"))
            elif a.what == "timeout" and (r.get("timeout_rounds") or 0) > 0:
                ids.append(r.get("id"))
            elif a.what == "api" and (r.get("api_error_rounds") or 0) > 0:
                ids.append(r.get("id"))
    seen, out = set(), []
    for i in ids:
        if i and i not in seen:
            seen.add(i)
            out.append(i)
    print(",".join(out))


if __name__ == "__main__":
    main()
