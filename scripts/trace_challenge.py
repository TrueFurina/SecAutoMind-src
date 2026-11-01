#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""取出某个 challenge 在日志里的逐轮工具调用与返回（截断预览）。

用于回答「模型的 flag 从哪来」这类溯源问题：只看日志里真实记录的
args / is_error / result，不做任何推断。
"""
import json
import re
import sys

TOOL = re.compile(r"工具执行\t(\{.*)$")


def main() -> int:
    if len(sys.argv) < 3:
        print("usage: trace_challenge.py <log> <challenge-substr> [max_round]", file=sys.stderr)
        return 2
    path, key = sys.argv[1], sys.argv[2]
    max_round = int(sys.argv[3]) if len(sys.argv) > 3 else 99
    shown = 0
    with open(path, encoding="utf-8", errors="replace") as f:
        for ln in f:
            if key not in ln:
                continue
            m = TOOL.search(ln)
            if not m:
                continue
            try:
                d = json.loads(m.group(1))
            except Exception:
                continue
            r = d.get("round")
            if not isinstance(r, int) or r > max_round:
                continue
            args = str(d.get("args", ""))
            res = str(d.get("result", "")).replace("\n", "\\n")
            shown += 1
            print("r%-3d %-18s err=%-5s" % (r, d.get("tool"), d.get("is_error")))
            print("   args : %s" % args[:150])
            print("   rslt : %s" % res[:200])
    print("--- 共 %d 轮 ---" % shown)
    return 0


if __name__ == "__main__":
    sys.exit(main())
