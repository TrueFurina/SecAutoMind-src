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
from datetime import date

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
PY = sys.executable

# 扫描范围：对外材料。代码/数据/日志不扫（里面出现数字是正常的）。
SCAN_DIRS = ["docs", "SecAutoMind_PPT", "官网"]
# 根目录材料**自动发现** *.md，不写死清单 —— 09-09 实锤：本门禁曾因写死
# SCAN_FILES 而完全漏扫根目录的《提交前终检清单》《决赛对标分析》等作战材料，
# 导致 09-03 一代旧口径（90 工具 / 226 测试 / 26 包 / 31 internal）长期无人发现。
# 写一个新 .md 却忘了登记进清单 = 门禁静默失效，这是不可接受的失效模式。
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
    # 09-03 一代旧口径：曾长期存活于根目录《提交前终检清单》，因门禁漏扫根目录而未被发现
    (r"工具\s*YAML\s*\**\s*90|90\s*(个)?(工具|YAML)", "旧工具数 90（现 YAML 91 / 运行时 143）"),
    (r"226\s*(个)?测试|228\s*(个)?测试|224\s*(个)?测试", "旧测试文件数（现 257）"),
    (r"24/26\s*测试|26/26|26\s*包全绿|26\s*(个)?包测试", "旧测试包数 26（现 28）"),
    (r"31\s*internal|internal\s*(子)?(目录|包)\s*\**\s*31", "旧 internal 子目录数 31（现 32）"),
    (r"111,933|113,\d{3}", "旧非测试行数（现 122,601）"),
]

# ---------------------------------------------------------------------------
# 2) 锚点比对：材料中出现的数字必须等于真值。
#    (正则, 真值字段名, 人类可读名称)
# ---------------------------------------------------------------------------
# 字段名必须与 count_stats.py 输出一致（实测是 ctf_solvers，不是 solvers）。
# 取不到真值时**必须崩**，不能静默跳过 —— 静默跳过的门禁等于没有门禁。
# 所有正则的数字必须写成命名组 (?P<n>...) —— 有些正则带可选前缀组，
# 用 group(1) 会取到 None 或取错组（曾踩：internal 那条数字其实在第 3 组）。
# (?<![\d.]) 前缀：排除章节号/版本号/端口号被当成规模数（实测误报源：
#   "### 5.2 Agent" 里的 2、"v1.7.25" 里的 25、"8090 端口" 里的 8090）。
# (?!化) 后缀：排除"18 个角色化子代理"被误判成 RBAC 角色数（那是 Agent 数）。
ANCHORS = [
    (r"Go\s*(?P<n>\d+)\s*文件", "go_files", "Go 文件数"),
    # 09-15 新增：材料里"711 Go 文件"（数字在前）同样常见 —— 此前只认"Go 711 文件"，
    # 导致 `规划-移植与优化总纲.md` 的 711（真值 715）漏检。同属「锚点覆盖不全」类盲区。
    (r"(?<![\d.])(?P<n>\d+)\s*Go\s*文件", "go_files", "Go 文件数（数字在前）"),
    (r"(?<![\d.])(?P<n>\d+)\s*(个)?运行时工具", "runtime_tools", "运行时工具数"),
    (r"(?<![\d.])(?P<n>\d+)\s*(个)?(确定性)?求解器", "ctf_solvers", "CTF 求解器数"),
    # 09-09 新增：此前只锚定 3 个数，导致「测试文件/工具 YAML/技能/Agent/角色/internal」
    # 整类数字漂移无人把关（终检清单写 226 测试时真值已 257）。
    (r"(?<![\d.])(?P<n>\d{3})\s*(个)?测试文件", "test_files", "测试文件数"),
    (r"测试文件\s*\**(?P<n>\d+)", "test_files", "测试文件数（后置）"),
    (r"工具\s*YAML\s*\**\s*(?P<n>\d+)", "tools_yaml", "工具 YAML 数"),
    (r"(?<![\d.])(?P<n>\d+)\s*(个)?内置\s*(MCP\s*)?工具", "builtin_tools", "内置 MCP 工具数"),
    (r"(?<![\d.])(?P<n>\d+)\s*(个)?技能(包)?", "skills", "技能包数"),
    # (?<![一-龥]) 排除 "3人2Agent" 这类「数字紧跟中文」的误命中
    (r"(?<![\d.])(?<![一-龥])(?P<n>\d+)\s*(个)?(角色化\s*)?Agent", "agents_md", "Agent(md) 数"),
    (r"(?<![\d.])(?P<n>\d+)\s*(个)?角色(定义)?(?!化)", "roles_yaml", "RBAC 角色数"),
    (r"internal\s*(子)?(目录|包)\s*\**\s*(?P<n>\d+)", "internal_dirs", "internal 子目录数"),
    # 「N 包测试全绿」= 有测试的包数（28），**不等于** go list 总包数（41）。
    # 两者混用正是「26 包」长期漂移却无人能自动校验的根因 —— 以前真值源里根本没有这个数。
    (r"(?<![\d.])(?P<n>\d+)\s*(个)?包(测试|全绿|有测)", "test_packages", "有测试的包数"),
    # 09-15 新增：代码行数此前**完全没有锚点** —— 122,131 / 125,998 / 126,396 这类数字
    # 只能靠人肉比对，正是官网"行数差 7 倍却长期无人发现"的根因之一。
    (r"(?<![\d,.])(?P<n>\d{2,3},\d{3})\s*行", "non_test_lines", "非测试代码行数"),
]

# 历史档案豁免：文件**内容里**带 CALIBER-SNAPSHOT 标记即视为历史快照。
# 用文件内标记而非维护文件清单 —— 规则可审计（打开文档就能看见），不会因重命名/新增
# 文件而悄悄失效。加标记时必须同时在文首写明「锚定哪个基线」。
SNAPSHOT_MARK = "CALIBER-SNAPSHOT"

# 文件名内嵌历史日期（如 xxx_20260905.md）→ 自动视为该日快照。
# 用「文件名日期」而非手写清单，新写的材料带新日期，规则不会因新增文件悄悄失效。
HIST_DATE_RE = re.compile(r"2026(\d{2})(\d{2})")

# ⚠️ 反向例外：名字带旧日期但**仍是现行作战材料**，不得豁免。
# 判据是「决赛现场还会照着念/照着做」，不是「文件多旧」。
# 精确文件名（不用模糊前缀），改这里必须在提交信息里说明理由。
FORCE_CURRENT = {
    "提交前终检清单_20260903.md",       # 决赛打包作战手册，现场照着走
    "PPT数字清单_E1E5_20260905.md",      # PPT 改数字的现行依据
    "final-race-readiness_20260905.md", # 赛前就绪度检查，仍在用
}

# 修复/生成类脚本：它们**必须列举**旧数字才能完成替换，列举 ≠ 使用。
# 精确文件名，理由同上（secret_guard 的 SELF_EXEMPT 同款教训）。
TOOL_EXEMPT = {
    "fix_stale_numbers.py",   # 批量替换旧数字的修复脚本
    "_qc_final.py",           # PPT 质检脚本，正则里必须写旧数字才能查它
    "PPT_制作提示词.md",       # 同一份旧数字禁用清单的说明文档
    "口径修复清单.md",         # 门禁自己产出的修复清单（固定名，覆盖更新）：列举旧数字是它的功能
}

# 规范文档自身（它要列举禁用清单来说明规则，列举 ≠ 使用）
EXEMPT_FILES = ["AGENTS.md"]

SKIP_DIR_PARTS = {".git", ".workbuddy", "node_modules", "logs", "data", "installer"}

# 明细显示上限。设太小的后果已实测：报 112 处却只显示 25 条，
# 让人误以为只有 25 处（截断本身也是一种「掩盖失败」）。
MAX_SHOW = 500


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
    seen = set()
    for d in SCAN_DIRS:
        base = os.path.join(ROOT, d)
        if not os.path.isdir(base):
            continue
        for dirpath, dirnames, filenames in os.walk(base):
            dirnames[:] = [x for x in dirnames
                           if x not in SKIP_DIR_PARTS and not x.startswith("_")]
            for fn in filenames:
                if os.path.splitext(fn)[1].lower() in SCAN_EXT:
                    if fn.startswith("_"):  # PPT QA 中间产物（gitignore 已排除，磁盘仍在）
                        continue
                    p = os.path.join(dirpath, fn)
                    if p not in seen:
                        seen.add(p)
                        yield p
    # 根目录 *.md 自动发现（含 SCAN_FILES，这里统一处理，去重由 seen 保证）
    for fn in sorted(os.listdir(ROOT)):
        if os.path.splitext(fn)[1].lower() != ".md":
            continue
        p = os.path.join(ROOT, fn)
        if os.path.isfile(p) and p not in seen:
            seen.add(p)
            yield p


def rel(path):
    return os.path.relpath(path, ROOT).replace("\\", "/")


def is_historical(rpath):
    """历史档案判定：内容带 SNAPSHOT_MARK，或**路径**内嵌早于今天的日期。

    用 rpath 而非 basename：像 docs/evidence-20260905/ 这种按日期分目录归档的证据包，
    目录名带日期、文件名不带，只看 basename 会漏判。
    """
    base = os.path.basename(rpath)
    if base in FORCE_CURRENT:
        return False  # 名字虽旧，但仍是现行材料 —— 必须检查
    if base in TOOL_EXEMPT:
        return True   # 修复脚本必须列举旧数字，列举 ≠ 使用
    for m in HIST_DATE_RE.finditer(rpath):
        mm, dd = int(m.group(1)), int(m.group(2))
        if (mm, dd) < (date.today().month, date.today().day):
            return True
    return False


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
        is_snapshot = SNAPSHOT_MARK in "".join(lines[:40]) or is_historical(rpath)
        # HTML 材料：先把标签替换为空格再做锚点匹配。
        # 实测盲区（2026-09-15）：官网 stats 区 `>268</div><div class="lbl">自动化测试文件`
        # 因数字与单位被标签隔断，命中不了 `(?P<n>\d{3})\s*(个)?测试文件` → 门禁 PASS 却漏检。
        # 用"替换为空格"而非"删除"，避免把相邻文本粘起来产生新误报。
        strip_html = rpath.lower().endswith((".html", ".htm"))
        for lineno, line in enumerate(lines, 1):
            if strip_html:
                line = re.sub(r"<[^>]*>", " ", line)
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
                got = int(m.group("n").replace(",", ""))  # 行数锚点带千分位（如 126,396）
                if got != int(want):
                    anchor_hits.append((rpath, lineno, label, got, int(want), line.strip()[:120]))

    print("=" * 70)
    print("材料口径门禁 · 真值来自 scripts/count_stats.py --json")
    print("  锚定 HEAD: %s" % truth.get("head"))
    print("  go_files=%s  test_files=%s  ctf_solvers=%s  runtime_tools=%s  "
          "tools_yaml=%s  builtin_tools=%s  go_packages=%s  test_packages=%s"
          % (truth.get("go_files"), truth.get("test_files"), truth.get("ctf_solvers"),
             truth.get("runtime_tools"), truth.get("tools_yaml"), truth.get("builtin_tools"),
             truth.get("go_packages"), truth.get("test_packages")))
    if exempted:
        print("  [豁免] 历史档案中 %d 处旧口径已豁免（文首已声明锚定旧基线）" % exempted)
    print("-" * 70)

    if banned_hits:
        print("  [FAIL] 已作废旧口径复活 %d 处：" % len(banned_hits))
        for fp, ln, why, txt in banned_hits[:MAX_SHOW]:
            print("    %s:%d  (%s)" % (fp, ln, why))
            print("        %s" % txt)
    else:
        print("  [PASS] 无已作废旧口径")

    if anchor_hits:
        print("  [FAIL] 材料数字与真值不符 %d 处：" % len(anchor_hits))
        for fp, ln, label, got, want, txt in anchor_hits[:MAX_SHOW]:
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
