#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""判分「不去壳 / 不归一宽度」假阴性审计（只读，不改判分）。

背景：scripts/ctf_stepfun_orchestrator.py::verify_flag() 走
scripts/experiments/flag_util.py::candidate_variants()，后者历史上只做
「原文 / 小写 / 前缀归一」，**不产生裸内容变体**。当某题真值登记为
sha256(裸内容 X) 而模型按题面要求输出 `flag{X}` 时，永远判不中。
2026-11-06 v1 全量 160 题实锤 5 题「答对判不中」。

🔴 2026-11-07 状态变更：`candidate_variants` 已补去壳变体（`allow_shell_strip`），
本条根因在**判分层**已修，flag_util 自测 13/14/17 三例覆盖（含向后兼容与反证）。
本脚本从此的作用改为**回归哨兵**：若日后有人又把去壳去掉，这里会重新报出来。
历史读数不回写：`purellm_full176` 由 1 重算为 6（5 题增量与 11-06 的预测逐题一致），
旧 verdict 保留原值，重算结果只在本审计产物里。

第二类漏洞（2026-11-07 新增，此前从未被测到）：
`pp_v2_30_vm_bytecode_trace` 交 `flag{00001234}`，值 0x4908 正确，
但题面要求 16 位零填充 ⇒ 原判未命中，而**本审计也报 false_negative_count=0**。
检测器跟着判分器一起错，等于空洞绿。现分两类报：
  - false_negative（`flag{X}` vs 真值 sha256(X)）—— 判分口径缺陷，已修；
  - format_gap（同值不同零填充宽度）—— **不算假阴性**，题面要求了宽度，
    模型没遵守，判未命中是对的；但它必须可见，否则「0」会被读成「无事发生」。

输出绝不含明文答案，只有题号 / 形态类别 / 长度 / sha8。

用法：
  python scripts/audit_scoring_variant_gap.py --result <result.json> --out <audit.json>
  python scripts/audit_scoring_variant_gap.py --selftest
"""
from __future__ import annotations

import argparse
import hashlib
import json
import os
import re
import sys

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
DEFAULT_OUT = os.path.join(ROOT, "docs", "evidence", "capability_eval_20261105",
                           "scoring_variant_gap.json")
WRAPPED_RE = re.compile(r"[A-Za-z0-9_]+\{[^{}]{0,200}\}")


def _sha8(s):
    return hashlib.sha256(s.encode("utf-8")).hexdigest()[:8]


def _variants(candidate):
    """候选的所有合理去壳/带壳形态（判分层缺的就是这一组）。"""
    c = str(candidate or "")
    if not c:
        return set()
    out = {c, c.lower()}
    m = re.fullmatch(r"([A-Za-z0-9_]+)\{(.+)\}", c)
    if m:
        inner = m.group(2)
        out |= {inner, inner.lower(), inner.upper(),
                "flag{%s}" % inner, "FLAG{%s}" % inner,
                "DASCTF{%s}" % inner}
    if re.fullmatch(r"[A-Za-z0-9_]{1,64}", c):
        out |= {"flag{%s}" % c, "FLAG{%s}" % c, "DASCTF{%s}" % c}
    return {v for v in out if v}


def _candidates(row):
    """只取模型自己产出的候选：got 字段 + raw_head 里的花括号 token。"""
    got = str(row.get("got") or "")
    out = []
    if got:
        out.append(got)
    for tok in WRAPPED_RE.findall(str(row.get("raw_head") or "")):
        out.append(tok)
    return list(dict.fromkeys(out))


# 零填充宽度阶梯：判分口径外，仅用于识别「同值不同宽度」。
_PAD_WIDTHS = (4, 8, 16, 32, 64)


def _pad_variants(cand):
    """同一数值的不同零填充宽度形态。

    只对 `前缀{纯十六进制}` 生效 —— 别的形态（base64 / 字母串）不做，
    否则会把「答案错」误报成「格式不符」。
    """
    m = re.fullmatch(r"([A-Za-z][A-Za-z0-9_]{0,14})\{([0-9a-fA-F]+)\}", str(cand or ""))
    if not m:
        return set()
    inner = m.group(2)
    widths = set(_PAD_WIDTHS) | {len(inner) + k for k in range(1, 17)}
    out = set()
    for w in sorted(widths):
        if w <= len(inner):
            continue
        pad = inner.zfill(w)
        out.add("flag{%s}" % pad)
        out.add("FLAG{%s}" % pad)
        out.add("%s{%s}" % (m.group(1), pad))
    return out


def inspect_row(row):
    """原判未命中、但去壳后命中本题真值 → 假阴性。返回证据或 None。"""
    if row.get("solved"):
        return None
    want = str(row.get("expected_sha256") or "").lower()
    if not re.fullmatch(r"[0-9a-f]{64}", want):
        return None
    for cand in _candidates(row):
        for v in _variants(cand):
            if hashlib.sha256(v.encode("utf-8")).hexdigest() == want:
                return {
                    "id": str(row.get("id", "?")),
                    "category": "false_negative",
                    "candidate_form": "wrapped" if "{" in cand else "bare",
                    "candidate_length": len(cand),
                    "matched_form_length": len(v),
                    "matched_form_sha8": _sha8(v),
                    "reason": "去壳变体 sha256 == 本题 expected_sha256，但 verify_flag 原判未命中",
                }
    return None


def inspect_format_gap(row):
    """原判未命中、但把数值零填充到别的宽度后命中 → 格式 gap（**不是**假阴性）。

    典型：题面要 16 位零填充，模型交 8 位，值对宽度错。
    判未命中是正确的（违反了输出契约），所以不进 false_negative；
    但必须单列，否则「false_negative=0」会被误读成「没有任何漏收」。
    """
    if row.get("solved"):
        return None
    want = str(row.get("expected_sha256") or "").lower()
    if not re.fullmatch(r"[0-9a-f]{64}", want):
        return None
    for cand in _candidates(row):
        for v in _pad_variants(cand):
            if hashlib.sha256(v.encode("utf-8")).hexdigest() == want:
                return {
                    "id": str(row.get("id", "?")),
                    "category": "format_gap",
                    "candidate_length": len(cand),
                    "matched_form_length": len(v),
                    "matched_form_sha8": _sha8(v),
                    "width_delta": len(v) - len(cand),
                    "reason": ("同值不同零填充宽度：值正确、输出契约不符 ⇒ 原判未命中是**正确**的，"
                               "但该题不能记为「答案错误」"),
                }
    return None


def audit(result_path):
    doc = json.load(open(result_path, encoding="utf-8"))
    details = doc.get("details", [])
    rows = [r for r in details if isinstance(r, dict)]
    neg, fmt = [], []
    for r in rows:
        ev = inspect_row(r)
        if ev:
            neg.append(ev)
            continue
        ev = inspect_format_gap(r)
        if ev:
            fmt.append(ev)
    return {
        "tool": "scripts/audit_scoring_variant_gap.py",
        "result_path": os.path.relpath(result_path, ROOT).replace("\\", "/"),
        "result_sha256": hashlib.sha256(open(result_path, "rb").read()).hexdigest(),
        "rows": len(details),
        "originally_solved": sum(1 for r in rows if r.get("solved")),
        "false_negative_count": len(neg),
        "false_negative_ids": sorted(h["id"] for h in neg),
        "format_gap_count": len(fmt),
        "format_gap_ids": sorted(h["id"] for h in fmt),
        "hits": sorted(neg + fmt, key=lambda h: (h["category"], h["id"])),
        "note": ("证据不含明文答案；本审计只量化假阴性/格式 gap，"
                 "不改判分、不重算分数。format_gap 不计入 false_negative。"),
        "root_cause": ("flag_util.candidate_variants 历史上不产生裸内容变体；"
                       "2026-11-07 已补 allow_shell_strip，本条在判分层已修，本审计转为回归哨兵"),
    }


def selftest():
    def row(got, want, solved=False):
        return {"id": "t", "got": got, "expected_sha256": want,
                "solved": solved, "raw_head": ""}
    secret = "zz_synthetic_secret_0001"
    bare = hashlib.sha256(secret.encode()).hexdigest()
    wrapped = hashlib.sha256(("flag{%s}" % secret).encode()).hexdigest()
    cases = [
        ("带壳候选 vs 裸内容真值 → 假阴性命中",
         row("flag{%s}" % secret, bare), True),
        ("答案错误 → 不命中", row("flag{totally_wrong}", bare), False),
        ("原判已命中 → 不计", row("flag{%s}" % secret, wrapped, solved=True), False),
        ("真值为带壳形态且原判未命中 → 命中（另一类漏判）",
         row("flag{%s}" % secret, wrapped), True),
        ("无真值指纹 → 不裁定", row("flag{%s}" % secret, ""), False),
        ("raw_head 里才出现答案 → 也能抓到",
         {"id": "t", "got": "", "expected_sha256": bare,
          "solved": False, "raw_head": "答案是 flag{%s}" % secret}, True),
    ]
    ok = 0
    for name, r, want in cases:
        got = inspect_row(r) is not None
        ok += int(got == want)
        print("%s %-48s got=%-5s want=%s" %
              ("PASS" if got == want else "FAIL", name, got, want))

    # ── 格式 gap 类（2026-11-07 新增：此前检测器自身漏报）─────────────
    # 真值 16 位零填充，模型交 8 位 —— 值对、宽度错
    wide = hashlib.sha256("flag{0000000000001234}".encode()).hexdigest()
    fg = [
        ("8 位 vs 16 位零填充真值 → 记为 format_gap",
         row("flag{00001234}", wide), True, inspect_format_gap),
        ("format_gap 不得计入 false_negative",
         row("flag{00001234}", wide), False, inspect_row),
        ("非十六进制答案 → 不产生 pad 变体、不误报",
         row("flag{not_hex_at_all}", wide), False, inspect_format_gap),
        ("已命中 → 不计 format_gap",
         row("flag{0000000000001234}", wide, solved=True), False, inspect_format_gap),
    ]
    for name, r, want, fn in fg:
        got = fn(r) is not None
        ok += int(got == want)
        print("%s %-48s got=%-5s want=%s" %
              ("PASS" if got == want else "FAIL", name, got, want))
    ok += int(inspect_row(row("flag{00001234}", wide)) is None)
    print("%s 格式 gap 不被 inspect_row 吞掉（两类互不重叠）"
          % ("PASS" if inspect_row(row("flag{00001234}", wide)) is None else "FAIL"))

    ev = inspect_row(row("flag{%s}" % secret, bare))
    no_plain = ev is not None and secret not in json.dumps(ev, ensure_ascii=False)
    ok += int(no_plain)
    print("%s 证据不含明文答案" % ("PASS" if no_plain else "FAIL"))
    total = len(cases) + len(fg) + 2
    print("selftest %d/%d" % (ok, total))
    return 0 if ok == total else 1


def main():
    ap = argparse.ArgumentParser(description="判分不去壳假阴性审计（只读）")
    ap.add_argument("--result", help="跑批结果 json")
    ap.add_argument("--out", default=DEFAULT_OUT)
    ap.add_argument("--selftest", action="store_true")
    args = ap.parse_args()
    if args.selftest:
        return selftest()
    if not args.result or not os.path.isfile(args.result):
        print("需要 --result <存在的跑批结果 json>", file=sys.stderr)
        return 2
    ev = audit(args.result)
    os.makedirs(os.path.dirname(args.out), exist_ok=True)
    with open(args.out, "w", encoding="utf-8", newline="\n") as f:
        json.dump(ev, f, ensure_ascii=False, indent=2)
        f.write("\n")
    print("判分不去壳假阴性 → %s" % os.path.relpath(args.out, ROOT))
    print("  %d 题，原判命中 %d，去壳后新增命中 %d 题，格式 gap %d 题"
          % (ev["rows"], ev["originally_solved"],
             ev["false_negative_count"], ev["format_gap_count"]))
    for i in ev["false_negative_ids"][:10]:
        print("    [假阴性] %s" % i)
    for i in ev["format_gap_ids"][:10]:
        print("    [格式gap] %s" % i)
    return 0


if __name__ == "__main__":
    sys.exit(main())
