#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""css_shadow_audit.py —— style.css 同名顶层块（影子块）审计与安全清理。

背景（2026-10-18 徽章配色 bug）：CSS 里两个同名同特异性 `.external-tool-badge`
定义靠出现顺序决胜，后一个把全局刷成错色。全量实测（见 HANDOFF §17）：
6,696 个顶层块里有 130 组同名选择器、179 处同名属性不同值。

本脚本只处理**可证明安全**的那一类：
  「某一块的每个属性，都被文件中更靠后的、同选择器的顶层块设置过，
    且后来块的重要性不低于本块（!important 压过普通声明）」
  ⇒ 该块在任何元素上都不可能赢下任何属性，删除它是严格的无副作用操作
     —— 与其它规则如何插队无关。
其余「部分存活」的组（前块有属性没被可靠覆盖）只报告，不自动动。

用法：
    python scripts/css_shadow_audit.py            # 只报告
    python scripts/css_shadow_audit.py --apply    # 删除可证明安全的影子块（含等价性验证）
    python scripts/css_shadow_audit.py --check    # 门禁模式：存在可证明安全的影子块即 rc=1
退出码：0 = 无（或已清空）；1 = 仍有全死影子块 / 验证失败。
"""
import argparse
import hashlib
import json
import os
import re
import sys
from collections import Counter

HERE = os.path.dirname(os.path.abspath(__file__))
ROOT = os.path.dirname(HERE)
CSS = os.path.join(ROOT, "internal", "app", "web", "static", "css", "style.css")


def disp(p):
    """相对路径显示；跨盘（relpath 抛 ValueError）时退回原路径。"""
    try:
        return os.path.relpath(p, ROOT)
    except ValueError:
        return p


def scan_top_level_blocks(text):
    """扫描顶层规则块。返回 [(selector, props:dict, start_off, end_off)]。

    - 跳过注释（不破坏偏移，行号按原文算）；
    - 跳过字符串字面量里的大括号（`content: "}"` 之类）；
    - @media/@supports/@keyframes 内部一律不进顶层清单。
    """
    blocks = []
    i, n = 0, len(text)
    depth = 0
    seg_start = 0          # 当前选择器文本起点（文件偏移）
    body_start = 0
    in_comment = in_str = False
    quote = ""
    line_of = [0] * (n + 1)
    ln = 1
    for idx in range(n + 1):
        line_of[idx] = ln
        if idx < n and text[idx] == "\n":
            ln += 1

    while i < n:
        c = text[i]
        if in_comment:
            if c == "*" and i + 1 < n and text[i + 1] == "/":
                in_comment = False
                i += 2
                continue
            i += 1
            continue
        if in_str:
            if c == "\\":
                i += 2
                continue
            if c == quote:
                in_str = False
            i += 1
            continue
        if c == "/" and i + 1 < n and text[i + 1] == "*":
            in_comment = True
            i += 2
            continue
        if c in "\"'":
            in_str = True
            quote = c
            i += 1
            continue
        if c == "{":
            if depth == 0:
                sel = text[seg_start:i]
                sel = re.sub(r"/\*.*?\*/", " ", sel, flags=re.S)
                sel = re.sub(r"\s+", " ", sel).strip()
                body_start = i + 1
            depth += 1
            i += 1
            continue
        if c == "}":
            depth -= 1
            if depth == 0:
                body = text[body_start:i]
                body_nc = re.sub(r"/\*.*?\*/", " ", body, flags=re.S)
                props = parse_props(body_nc)
                if sel and not sel.startswith("@"):
                    blocks.append((sel, props, seg_start, i))
                seg_start = i + 1
            i += 1
            continue
        i += 1
    return blocks


def parse_props(body):
    """prop -> (value, important_bool)。同一块内重复声明取先者（CSS 语义）。

    important 必须保留：同选择器块之间并非只按"后来者必胜"——
    被删块的属性若带 !important，而覆盖它的后来块只是普通声明，
    删掉它会把生效值从"important 的旧值"换成"后来块的普通新值"。
    """
    out = {}
    for chunk in body.split(";"):
        if ":" not in chunk:
            continue
        k, v = chunk.split(":", 1)
        k = k.strip().lower()
        v = re.sub(r"\s+", " ", v).strip()
        m = re.search(r"!\s*important\s*$", v)
        imp = bool(m)
        if m:
            v = v[:m.start()].strip()
        if k and re.fullmatch(r"-?[a-z]+(-[a-z]+)*", k):
            out.setdefault(k, (v, imp))
    return out


def final_property_map(blocks):
    """每个顶层选择器的最终生效属性表 sel -> {prop: (value, important)}。

    级联规则（同选择器、同一样式表内）：!important 压过普通声明；
    同等级后来者压先者 —— 所以普通声明不能覆盖已有的 important。
    """
    final = {}
    for sel, props, _s, _e in blocks:
        d = final.setdefault(sel, {})
        for k, v in props.items():
            cur = d.get(k)
            if cur is None or v[1] >= cur[1]:
                d[k] = v
    return final


def analyse(blocks):
    """返回 (fully_dead, partial)。
    fully_dead: [(selector, start_off, end_off)] —— 每个属性都被更靠后的、
                且重要性不更低的同选择器块声明过（这样的块不可能赢下任何属性）
    partial:    [(selector, [未被可靠覆盖的属性])]
    """
    by_sel = {}
    for idx, (sel, props, s, e) in enumerate(blocks):
        by_sel.setdefault(sel, []).append((idx, s, e, props))
    fully_dead, partial = [], []
    for sel, defs in by_sel.items():
        if len(defs) < 2:
            continue
        for pos, (idx, s, e, props) in enumerate(defs):
            later = defs[pos + 1:]
            if not later:
                # 组内最后一块没有任何后来者，必然整体存活，不是"部分存活"
                continue
            gap = [k for k, (v, imp) in props.items()
                   if not any(k in p2 and p2[k][1] >= imp
                              for _i2, _s2, _e2, p2 in later)]
            if props and not gap:
                fully_dead.append((sel, s, e))
            elif gap:
                partial.append((sel, gap))
    return fully_dead, partial


def main():
    ap = argparse.ArgumentParser(description=__doc__,
                                 formatter_class=argparse.RawDescriptionHelpFormatter)
    g = ap.add_mutually_exclusive_group()
    g.add_argument("--apply", action="store_true",
                   help="删除可证明安全的影子块（先做等价性验证，失败则不落盘）")
    g.add_argument("--check", action="store_true",
                   help="门禁模式：仍存在可证明安全的影子块即 rc=1")
    ap.add_argument("--json", metavar="PATH",
                    help="把本次删除清单（selector/起止行）写到 PATH，供浏览器等价性复验使用")
    args = ap.parse_args()

    with open(CSS, "r", encoding="utf-8", newline="") as fh:
        text = fh.read()

    blocks = scan_top_level_blocks(text)
    fully_dead, partial = analyse(blocks)

    print("=" * 68)
    print("style.css 影子块审计 · %s" % disp(CSS))
    cnt = Counter(b[0] for b in blocks)
    print("  顶层块 %d 个；同名选择器组 %d 组" %
          (len(blocks), sum(1 for v in cnt.values() if v > 1)))
    print("  可证明安全（每属性都被更靠后、重要性不更低的同选择器块覆盖）：%d 块" % len(fully_dead))
    print("  部分存活（需人工判定，本脚本不动）：%d 组" % len(partial))
    if not args.apply and not args.check:
        for sel, alive in sorted(partial, key=lambda x: x[0])[:20]:
            print("    [部分存活] %-46s 仍生效属性: %s" % (sel[:46], ",".join(alive[:6])))

    if args.check:
        if fully_dead:
            print("  [FAIL] 仍有 %d 个可证明安全的影子块未清理" % len(fully_dead))
            return 1
        print("  [PASS] 无可证明安全的影子块")
        return 0

    if not args.apply:
        return 0

    if not fully_dead:
        print("  没有可删除的影子块，无需 --apply")
        return 0

    before_map = final_property_map(blocks)
    # 备份原文（供浏览器等价性复验）。路径按目标 CSS 的绝对路径哈希派生：
    # 自测在临时文件上跑 --apply 时备份落在另一处，不会覆盖真实备份
    # （2026-10-19 实测教训：硬编码同一个路径被测试夹具冲掉过）。
    tag = hashlib.sha1(os.path.abspath(CSS).encode("utf-8")).hexdigest()[:8]
    bak = os.path.join(ROOT, ".workbuddy", "tmp", "style_%s_before.css" % tag)
    os.makedirs(os.path.dirname(bak), exist_ok=True)
    with open(bak, "w", encoding="utf-8", newline="") as fh:
        fh.write(text)

    # 自后往前删（偏移不失效）。删除区间取「块前换行 → 块右花杠」：
    # 保留块尾换行，删完前一个块的 } 与下一个选择器之间仍恰好一个换行，
    # 不会出现 `}  .next {` 粘行。
    spans = sorted(fully_dead, key=lambda x: x[1], reverse=True)

    def offset_to_line(off):
        return text.count("\n", 0, off) + 1

    deleted = []
    new_text = text
    for sel, s, e in spans:
        ln_s = offset_to_line(s)
        # e 指向块的右花杠；删 [s, e]，留住其后的换行作为下一个块的分隔
        new_text = new_text[:s] + new_text[e + 1:]
        deleted.append({"selector": sel, "start_line": ln_s})
    deleted.reverse()

    # ---- 等价性验证：删除后每个选择器的最终属性表必须逐项一致 ----
    blocks_after = scan_top_level_blocks(new_text)
    after_map = final_property_map(blocks_after)
    diffs = []
    for sel in sorted(set(before_map) | set(after_map)):
        b = before_map.get(sel, {})
        a = after_map.get(sel, {})
        if b != a:
            keys = sorted(set(b) | set(a))
            for k in keys:
                if b.get(k) != a.get(k):
                    diffs.append("%s :: %s : %r -> %r" % (sel, k, b.get(k), a.get(k)))
    if diffs:
        print("  [FAIL] 等价性验证不通过，拒绝落盘（%d 处差异）：" % len(diffs))
        for d in diffs[:10]:
            print("      " + d)
        return 1
    if abs(len(blocks) - len(blocks_after)) != len(spans):
        print("  [FAIL] 块数变化 %d 与删除数 %d 不符，解析可能失真，拒绝落盘"
              % (len(blocks) - len(blocks_after), len(spans)))
        return 1

    with open(CSS, "w", encoding="utf-8", newline="") as fh:
        fh.write(new_text)

    print("  [OK] 已删除 %d 个影子块；等价性验证通过（全部选择器最终属性表逐项一致）"
          % len(spans))
    print("       块数 %d -> %d" % (len(blocks), len(blocks_after)))
    for d in deleted[:10]:
        print("       - %-46s 原第 %d 行" % (d["selector"][:46], d["start_line"]))
    if len(deleted) > 10:
        print("       …… 另 %d 块" % (len(deleted) - 10))
    print("  原文件已备份到 %s" % disp(bak))
    if args.json:
        with open(args.json, "w", encoding="utf-8") as fh:
            json.dump({"deleted": deleted,
                       "before_css": disp(bak),
                       "after_css": disp(CSS)}, fh,
                      ensure_ascii=False, indent=1)
        print("  删除清单已写入 %s（供浏览器等价性复验）" % args.json)
    # 删除后立刻复查：应当清零
    blocks_re = scan_top_level_blocks(new_text)
    fd2, _pa = analyse(blocks_re)
    print("  复查：仍可证明安全的影子块 %d 个" % len(fd2))
    return 0


if __name__ == "__main__":
    sys.exit(main())
