#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""材料数字真值同步器 —— 把 docs/ PPT/ 官网 里漂移的规模数字改回 count_stats.py 真值。

为什么需要它
------------
`check_material_numbers.py`（口径门禁）**每次 Go 代码变更后都会变红**：行数/文件数
被写死在 11+ 处材料里，改一行代码就要人肉 grep + 逐处替换。这已成固定工序
（见 3122b16 / 11a8c0e / a5a94f5 及 4ce977d 之后的口径刷新），每次靠肉眼找、手改，
漏一处门禁又红 —— 而"靠人肉同步永远追不上"正是口径门禁自己的立项理由。

本脚本把这件事机械化，关键设计是**检测逻辑完全复用门禁的 ANCHORS 表**：
另写一份规则必然与门禁渐行渐远，最终出现「修复器说修好了、门禁说还红」的
更隐蔽失效。这里宁可让修复器依赖门禁，也不允许两套判定并存。

安全性（对齐 fix_doc_port.py 的约定）
------------------------------------
- 默认 **dry-run**，必须显式 `--apply` 才落盘
- 只改**锚点命中**的数字；命中 BANNED（已作废旧口径）的**不猜、不改**，列出来交人工
- **保留原文件换行符**：按 bytes 语义读写（`newline=""`），写回按**行号索引**定位，
  不做内容搜索、不做换行转换 —— 改了行尾会让 line-endings-gate 变红（09-24 已裁过一次）
- 幂等：连跑两次，第二次 0 改动
- 复用门禁的 `HIST_DATE_RE` / `SNAPSHOT_MARK` / `TOOL_EXEMPT` 豁免，历史档案不动

用法：
    python scripts/fix_material_numbers.py            # 预览（不写盘）
    python scripts/fix_material_numbers.py --apply    # 落盘
    python scripts/fix_material_numbers.py --apply --check   # 落盘后复跑门禁

退出码：0 = 无需修复 / 已修复；1 = 仍有需人工处理的漂移；2 = 取不到真值（fail-closed）
"""
import argparse
import os
import re
import sys

try:
    sys.stdout.reconfigure(encoding="utf-8")
except Exception:
    pass

HERE = os.path.dirname(os.path.abspath(__file__))
if HERE not in sys.path:
    sys.path.insert(0, HERE)

# 复用门禁：ANCHORS / BANNED / 扫描范围 / 豁免判定，全部以门禁为准。
# 这不是"绕过门禁"，恰恰相反 —— 修复器的判定口径与门禁**逐字相同**。
import check_material_numbers as cmn  # noqa: E402


def format_like(orig, want):
    """跟随原写法保留千分位：'126,659' -> '126,675'；'724' -> '1234'（不带逗号）。"""
    return format(int(want), ",") if "," in orig else str(int(want))


def _token_rx(got):
    """匹配数字字面量本身，两侧不再接数字/千分位符 —— 防止改到别的数字的一部分。"""
    return re.compile(r"(?<![\d,.])" + re.escape(got) + r"(?![\d,])")


def fix_line(line, truth, anchors=None, strip_html=False):
    """把 line 里"锚点命中且与真值不符"的数字改成真值。

    返回 (新行, [(label, got, new), ...])。

    strip_html=True 时先用门禁同款的"标签→空格"做检测，但**原文 span 无法映射**回
    未剥离的行（例如 `<div>126,659</div><div>行 Go</div>`，数字与"行"被标签隔断），
    因此退化为"按数字字面量整体替换"。该分支只影响 *.html（本仓仅官网，且被
    .gitignore 排除，CI 检出里不存在）。
    """
    anchors = cmn.ANCHORS if anchors is None else anchors
    changes = []

    def want_of(key):
        v = truth.get(key)
        if v is None:
            # 与门禁同款 fail-closed：字段名变了就必须崩，绝不静默跳过
            raise SystemExit(
                "FATAL: count_stats 未返回锚点字段 %s（字段名可能已改），"
                "修复器拒绝在无真值的情况下工作" % key)
        return int(v)

    if strip_html:
        probe = re.sub(r"<[^>]*>", " ", line)
        for pat, key, label in anchors:
            for m in re.finditer(pat, probe):
                got = m.group("n")
                new = format_like(got, want_of(key))
                if new == got or got not in line:
                    continue
                line = _token_rx(got).sub(new, line)
                changes.append((label, got, new))
        return line, changes

    for pat, key, label in anchors:
        want = want_of(key)

        def _repl(m, _label=label, _want=want):
            got = m.group("n")
            new = format_like(got, _want)
            if new == got:
                return m.group(0)
            s = m.start("n") - m.start(0)
            e = m.end("n") - m.start(0)
            changes.append((_label, got, new))
            return m.group(0)[:s] + new + m.group(0)[e:]

        line = re.sub(pat, _repl, line)
    return line, changes


def collect(truth):
    """扫全量材料。

    返回 (fixable, manual)：
      fixable = [(abs_path, rpath, [(lineno_1based, old_body, new_body, changes)])]
      manual  = [(rpath, lineno, why, text)]  —— 命中 BANNED，交人工
    纯扫描，不写盘。
    """
    fixable, manual = [], []
    for path in cmn.iter_files():
        rpath = cmn.rel(path)
        try:
            # newline="" —— 换行符原样读入，写回时原样输出，不做任何转换
            with open(path, "r", encoding="utf-8", errors="ignore", newline="") as fh:
                raw_lines = fh.readlines()
        except OSError:
            continue

        if cmn.SNAPSHOT_MARK in "".join(raw_lines[:40]) or cmn.is_historical(rpath):
            continue
        if rpath in cmn.EXEMPT_FILES:
            continue

        strip_html = rpath.lower().endswith((".html", ".htm"))
        edits = []
        for i, raw in enumerate(raw_lines, 1):
            body = raw.rstrip("\r\n")
            for pat, why in cmn.BANNED:
                if re.search(pat, body):
                    manual.append((rpath, i, why, body.strip()[:120]))
            # 检测与门禁逐字一致：HTML 先剥标签
            probe = re.sub(r"<[^>]*>", " ", body) if strip_html else body
            if not any(re.search(p, probe) for p, _, _ in cmn.ANCHORS):
                continue
            new_body, changes = fix_line(body, truth, strip_html=strip_html)
            if changes:
                edits.append((i, body, new_body, changes))
        if edits:
            fixable.append((path, rpath, edits))
    return fixable, manual


def apply_edits(path, edits):
    """按**行号索引**写回（不做内容搜索，避免同名行误命中），换行符原样保留。"""
    with open(path, "r", encoding="utf-8", errors="ignore", newline="") as fh:
        raw_lines = fh.readlines()
    for lineno, _old, new_body, _changes in edits:
        idx = lineno - 1
        if idx >= len(raw_lines):
            raise SystemExit("FATAL: %s 行号 %d 越界，文件可能已被并发修改" % (path, lineno))
        cur = raw_lines[idx]
        ending = cur[len(cur.rstrip("\r\n")):]  # 保住 \n / \r\n
        raw_lines[idx] = new_body + ending
    with open(path, "w", encoding="utf-8", newline="") as fh:
        fh.writelines(raw_lines)


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--apply", action="store_true", help="真正写盘（默认只预览）")
    ap.add_argument("--check", action="store_true", help="写盘后复跑口径门禁")
    args = ap.parse_args()

    try:
        truth = cmn.load_truth()
    except SystemExit as e:
        print("[FAIL-CLOSED] %s" % e, file=sys.stderr)
        return 2

    print("=" * 70)
    print("材料数字真值同步器 · 真值来自 scripts/count_stats.py --json")
    print("  锚定 HEAD: %s" % truth.get("head"))
    print("-" * 70)

    fixable, manual = collect(truth)

    n_edit = 0
    for path, rpath, edits in fixable:
        print("  %s" % rpath)
        for lineno, _old, _new, changes in edits:
            n_edit += len(changes)
            for label, got, want in changes:
                print("    L%-5d %s: %s -> %s" % (lineno, label, got, want))
        if args.apply:
            apply_edits(path, edits)

    if not fixable:
        print("  [OK] 无可修复的锚点漂移（材料数字已与真值一致）")

    if manual:
        print("-" * 70)
        print("  [需人工] 命中已作废旧口径 %d 处 —— 本脚本不猜替换目标：" % len(manual))
        for rpath, lineno, why, txt in manual[:50]:
            print("    %s:%d  (%s)" % (rpath, lineno, why))
            print("        %s" % txt)

    print("-" * 70)
    if args.apply and fixable:
        print("  已落盘 %d 个文件 / %d 处数字。改用前请 git diff 复核。" % (len(fixable), n_edit))
    elif fixable:
        print("  [DRY-RUN] %d 个文件 / %d 处待修改，加 --apply 落盘。" % (len(fixable), n_edit))
    else:
        print("  无需落盘。")

    if args.apply and args.check:
        import subprocess
        rc = subprocess.run([sys.executable, os.path.join(HERE, "check_material_numbers.py")],
                            cwd=cmn.ROOT).returncode
        print("  复跑 check_material_numbers.py -> exit %d" % rc)
        return rc

    return 1 if manual else 0


if __name__ == "__main__":
    sys.exit(main())
