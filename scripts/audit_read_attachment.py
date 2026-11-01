#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""统计日志里 read_attachment 的成功/失败分布，按失败类型归类。

回答的问题：模型为什么老是绕过 read_attachment 改用 python_session？
只在日志里数出现次数，不推断原因。
"""
import json
import re
import sys
from collections import Counter

TOOL = re.compile(r"工具执行\t(\{.*)$")


def main() -> int:
    if len(sys.argv) < 2:
        print("usage: audit_read_attachment.py <log> [<log>...]", file=sys.stderr)
        return 2
    ok = Counter()
    bad = Counter()
    total = Counter()
    for path in sys.argv[1:]:
        with open(path, encoding="utf-8", errors="replace") as f:
            for ln in f:
                if '"read_attachment"' not in ln:
                    continue
                m = TOOL.search(ln)
                if not m:
                    continue
                try:
                    d = json.loads(m.group(1))
                except Exception:
                    continue
                if d.get("tool") != "read_attachment":
                    continue
                total[path] += 1
                res = str(d.get("result", ""))
                if d.get("is_error"):
                    # 归因：把失败结果归类成可读类型
                    if "unsupported protocol scheme" in res:
                        key = "scheme 不被支持（本地路径 / file://）"
                    elif "HTTP 404" in res:
                        key = "HTTP 404（附件 token 失效/路径错）"
                    elif "handshake timeout" in res:
                        key = "TLS handshake timeout（出网被阻/过慢）"
                    elif "HTTP 403" in res:
                        key = "HTTP 403"
                    else:
                        key = res[:60].replace("\n", " ")
                    bad[key] += 1
                else:
                    ok[path] += 1

    print("=== read_attachment 调用统计 ===")
    tot = sum(total.values())
    tot_ok = sum(ok.values())
    print("总调用 %d 次 | 成功 %d | 失败 %d | 成功率 %.1f%%"
          % (tot, tot_ok, tot - tot_ok, (100.0 * tot_ok / tot) if tot else 0))
    print()
    print("=== 失败类型分布 ===")
    for k, v in bad.most_common():
        print("%5d  %s" % (v, k))
    print()
    print("=== 按文件 ===")
    for p in total:
        print("%5d 总 / %5d 成功  %s" % (total[p], ok[p], p))
    return 0


if __name__ == "__main__":
    sys.exit(main())
