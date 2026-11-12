#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""check_web_js_mutation.py 的自测（AGENTS 第四条：门禁自身必须有回归测试）。

这里不重跑 node（那是门禁本体的事），只锁三件**会让门禁静默失效**的事：
  T1 用例清单非空且 --list 可用（清单被清空 = 门禁假绿）
  T2 每条 anchor 必须存在于工作树源码中（源码重构后锚点消失 → 门禁会 BLOCK，
     但那时才发现；本自测提前到"提交前"就红，并给出可定位信息）
  T3 每条 replace 必须与 anchor 不同（写成一样 = 变异是空操作，永远绿）
  T4 变异文件路径必须在依赖树复刻范围内（改了个测试根本不读的文件 = 假 decisive）
"""
import io
import os
import subprocess
import sys

try:
    sys.stdout.reconfigure(encoding="utf-8")
except Exception:
    pass

HERE = os.path.dirname(os.path.abspath(__file__))
ROOT = os.path.dirname(HERE)
sys.path.insert(0, HERE)
import check_web_js_mutation as gate  # noqa: E402

RESULTS = []


def case(name, ok, detail):
    RESULTS.append((name, ok, detail))
    print("  [%s] %-56s %s" % ("PASS" if ok else "FAIL", name, detail))


def main():
    py = sys.executable
    cases = gate.CASES
    case("T1 用例清单非空（清空即假绿）", len(cases) >= 2, "%d 条" % len(cases))

    miss = []
    for i, c in enumerate(cases, 1):
        p = os.path.join(ROOT, c["file"])
        if not os.path.isfile(p):
            miss.append("M%d 文件不存在 %s" % (i, c["file"]))
            continue
        s = io.open(p, encoding="utf-8", errors="ignore").read()
        if c["anchor"] not in s:
            miss.append("M%d 锚点已失效 %s" % (i, c["anchor"][:40]))
        if c["replace"] == c["anchor"]:
            miss.append("M%d replace 与 anchor 相同（空变异）" % i)
    case("T2+T3 锚点存在且非空变异", not miss, "全通过" if not miss else "; ".join(miss[:3]))

    # T4：被测文件必须是"根 web/ 副本"——测试 readFileSync('web/static/js/...') 读的那份。
    # 若有人把变异指向 internal/app/web 副本，node 侧读不到它，变异永远不 decisive。
    bad = [c["file"] for c in cases if "web" + os.sep not in c["file"] or c["file"].startswith("internal")]
    case("T4 变异落在测试真正读的根 web/ 副本", not bad,
         "全合规" if not bad else "错位：%s" % ", ".join(bad))

    r = subprocess.run([py, os.path.join(HERE, "check_web_js_mutation.py"), "--list"],
                       capture_output=True, text=True, encoding="utf-8", errors="ignore")
    listed = r.returncode == 0 and r.stdout.count("M") >= len(cases)
    case("T5 --list 可用且条目数吻合", listed, "rc=%d" % r.returncode)

    failed = [n for n, ok, _ in RESULTS if not ok]
    print("-" * 66)
    if failed:
        print("  自测结论：FAIL（%d/%d 未过）" % (len(failed), len(RESULTS)))
        return 1
    print("  自测结论：PASS（%d 项全过，锚点/空变异/路径错位三类静默失效已锁）" % len(RESULTS))
    return 0


if __name__ == "__main__":
    sys.exit(main())
