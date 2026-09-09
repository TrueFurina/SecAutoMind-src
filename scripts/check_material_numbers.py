#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""材料口径门禁：自动比对 docs/ PPT/ 官网 中的关键数字与 count_stats.py 真值。

为什么需要它
------------
本项目历史上有过三次材料数字漂移，全部靠人肉发现：
  - 并行会话新增 tools/_shared_args.yaml 后，YAML 工具 90 -> 91
  - 求解器 169 -> 170
  - 官网长期写「140 运行时工具」，而 140 既不等于 90 也不等于 142，属凭空漂移
写死的数字在提交完成的下一秒就可能过期，靠人肉同步永远追不上。

它检查两件事
------------
1) 黑名单：已作废旧口径复活（带上下文匹配，避免误伤行号/端口等无关数字）
2) 锚点比对：材料里出现的「Go N 文件」「N 运行时工具」「N 求解器」必须等于真值

退出码：0 = 通过；1 = 口径漂移（禁止合入 / 禁止打包）
"""

import json
import os
import re
import subprocess
import sys

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
PY = sys.executable

# 扫描范围：对外材料。代码/数据/日志不扫（里面出现数字是正常的）。
SCAN_DIRS = ["docs", "SecAutoMind_PPT", "官网"]
SCAN_FILES = ["README.md", "README_CN.md", "SECURITY.md", "AGENTS.md"]
SCAN_EXT = {".md", ".html", ".py", ".txt"}

# ---------------------------------------------------------------------------
# 1) 黑名单：已作废的旧口径。必须带上下文，否则 "662" 可能只是行号或端口。
# ---------------------------------------------------------------------------
BANNED = [
    (r"662\s*文件|242\s*(个)?测试|123,149|153,987", "旧口径 A（662/242/123,149/153,987）"),
    (r"677\s*文件|250\s*(个)?测试|125,954|158,247", "旧口径 B（677/250/125,954/158,247）"),
    (r"151\s*(个)?求解器", "旧求解器数 151"),
    (r"140\s*(个)?(运行时)?工具", "三不管数字 140 工具（既非 90 也非 142）"),
    (r"Go\s*613\s*文件|613\s*文件", "手写漂移的 Go 文件数 613"),
]

# ---------------------------------------------------------------------------
# 2) 锚点比对：材料中出现的数字必须等于真值。
#    (正则, 真值字段名, 人类可读名称)
# ---------------------------------------------------------------------------
# 字段名必须与 count_stats.py 输出一致（实测是 ctf_solvers，不是 solvers）。
# 取不到真值时**必须崩**，不能静默跳过 —— 静默跳过的门禁等于没有门禁。
ANCHORS = [
    (r"Go\s*(\d+)\s*文件", "go_files", "Go 文件数"),
    (r"(\d+)\s*(个)?运行时工具", "runtime_tools", "运行时工具数"),
    (r"(\d+)\s*(个)?(确定性)?求解器", "ctf_solvers", "CTF 求解器数"),
]

# 历史档案豁免：文件**内容里**带 CALIBER-SNAPSHOT 标记即视为历史快照。
# 用文件内标记而非维护文件清单 —— 规则可审计（打开文档就能看见），不会因重命名/新增
# 文件而悄悄失效。加标记时必须同时在文首写明「锚定哪个基线」。
SNAPSHOT_MARK = "CALIBER-SNAPSHOT"

# 规范文档自身（它要列举禁用清单来说明规则，列举 ≠ 使用）
EXEMPT_FILES = ["AGENTS.md"]

SKIP_DIR_PARTS = {".git", ".workbuddy", "node_modules", "logs", "data", "installer"}


def load_truth():
    """从单一真值源取数。取不到就直接崩 —— 没有真值的门禁毫无意义。"""
    out = subprocess.run(
        [PY, os.path.join(ROOT, "scripts", "count_stats.py"), "--json"],
        cwd=ROOT, capture_output=True, text=True,
    )
    if out.returncode != 0:
        raise SystemExit("FATAL: count_stats.py 执行失败，无法取得真值：\n" + out.stderr)
    return json.loads(out.stdout)


def iter_files():
    for d in SCAN_DIRS:
        base = os.path.join(ROOT, d)
        if not os.path.isdir(base):
            continue
        for dirpath, dirnames, filenames in os.walk(base):
            dirnames[:] = [x for x in dirnames if x not in SKIP_DIR_PARTS]
            for fn in filenames:
                if os.path.splitext(fn)[1].lower() in SCAN_EXT:
                    yield os.path.join(dirpath, fn)
    for fn in SCAN_FILES:
        p = os.path.join(ROOT, fn)
        if os.path.isfile(p):
            yield p


def rel(path):
    return os.path.relpath(path, ROOT).replace("\\", "/")


def main():
    truth = load_truth()
    # 自检：锚点用到的字段必须全部存在于真值中。缺失就崩，绝不静默跳过。
    missing = [k for _, k, _ in ANCHORS if truth.get(k) is None]
    if missing:
        raise SystemExit(
            "FATAL: count_stats.py 未返回锚点字段 %s（脚本字段名可能已改）。\n"
            "门禁绝不静默跳过检查 —— 请先修复字段名，否则本门禁形同虚设。" % missing
        )
    banned_hits, anchor_hits = [], []
    exempted = 0

    for path in iter_files():
        rpath = rel(path)
        try:
            with open(path, "r", encoding="utf-8", errors="ignore") as fh:
                lines = fh.readlines()
        except Exception:
            continue
        is_snapshot = SNAPSHOT_MARK in "".join(lines[:40])
        for lineno, line in enumerate(lines, 1):
            if is_snapshot:
                exempted += len([1 for pat, _ in BANNED if re.search(pat, line)])
                continue
            if rpath in EXEMPT_FILES:
                continue
            for pat, why in BANNED:
                if re.search(pat, line):
                    banned_hits.append((rpath, lineno, why, line.strip()[:120]))
            for pat, key, label in ANCHORS:
                m = re.search(pat, line)
                if not m:
                    continue
                want = truth[key]
                got = int(m.group(1))
                if got != int(want):
                    anchor_hits.append((rpath, lineno, label, got, int(want), line.strip()[:120]))

    print("=" * 70)
    print("材料口径门禁 · 真值来自 scripts/count_stats.py --json")
    print("  锚定 HEAD: %s" % truth.get("head"))
    print("  go_files=%s  ctf_solvers=%s  runtime_tools=%s  tools_yaml=%s  builtin_tools=%s"
          % (truth.get("go_files"), truth.get("ctf_solvers"), truth.get("runtime_tools"),
             truth.get("tools_yaml"), truth.get("builtin_tools")))
    if exempted:
        print("  [豁免] 历史档案中 %d 处旧口径已豁免（文首已声明锚定旧基线）" % exempted)
    print("-" * 70)

    if banned_hits:
        print("  [FAIL] 已作废旧口径复活 %d 处：" % len(banned_hits))
        for fp, ln, why, txt in banned_hits[:25]:
            print("    %s:%d  (%s)" % (fp, ln, why))
            print("        %s" % txt)
    else:
        print("  [PASS] 无已作废旧口径")

    if anchor_hits:
        print("  [FAIL] 材料数字与真值不符 %d 处：" % len(anchor_hits))
        for fp, ln, label, got, want, txt in anchor_hits[:25]:
            print("    %s:%d  %s=%d，真值=%d" % (fp, ln, label, got, want))
            print("        %s" % txt)
    else:
        print("  [PASS] 材料数字与真值一致")

    print("=" * 70)
    if banned_hits or anchor_hits:
        print("  结论：FAIL —— 口径漂移，禁止合入/打包。请改为从 count_stats.py 取值。")
        return 1
    print("  结论：PASS —— 材料口径与单一真值源一致。")
    return 0


if __name__ == "__main__":
    sys.exit(main())
