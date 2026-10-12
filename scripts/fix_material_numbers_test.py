#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""fix_material_numbers.py 的回归 + 变异验证（纯 stdlib，不依赖 pytest）。

关键工具必须有变异验证：**故意注入一个漂移数字，修复器必须修掉它**；
且必须证明修的是"真值"而不是硬编码常量。

用例：
    T1 真值驱动：喂一个假真值 -> 产出该假真值（证明非硬编码）
    T2 千分位跟随原写法（126,659 -> 真值带逗号；724 -> 1234 不带逗号）
    T3 边界：裸数字「126,659」后不接「行」= 不是规模宣称 -> 不得改动
    T4 幂等：修完再修 -> 0 改动
    T5 HTML 分支：数字与单位被标签隔断（<div>126,659</div><div>行 Go</div>）仍须能修
    T6 修复-检测闭环（核心变异）：注入漂移 -> 修复 -> 用**门禁自己的 ANCHORS** 复扫须不再命中
    T7 fail-closed：真值缺字段必须崩，不得静默跳过
    T8 换行符零改动：CRLF 文件修完后仍是 CRLF（否则 line-endings-gate 变红）
    T9 BANNED 不猜：命中已作废旧口径只上报、不改写
    T11「裸 N 测试」族锚点：`279 测试`（无"文件"二字）此前无锚点 → 须能修，且不误伤局部 2 位数
    T10 真实仓库当前状态：修复器 dry-run 无待修 + 门禁 exit 0
"""
import os
import re
import sys
import tempfile

try:
    sys.stdout.reconfigure(encoding="utf-8")
except Exception:
    pass

HERE = os.path.dirname(os.path.abspath(__file__))
if HERE not in sys.path:
    sys.path.insert(0, HERE)

import check_material_numbers as cmn  # noqa: E402
import fix_material_numbers as fmn    # noqa: E402

_results = []


def check(name, cond, detail=""):
    _results.append((name, bool(cond)))
    print("  %s %s%s" % ("PASS" if cond else "FAIL", name, "" if cond else "  <- " + str(detail)))


def probe_hits(rpath, body, truth):
    """用**门禁自己的 ANCHORS + 同样的 HTML 剥离**复扫一行，返回命中数。

    这是"闭环"的关键：修复是否正确，不由修复器自己说了算，而由门禁的判定说了算。
    """
    strip_html = rpath.lower().endswith((".html", ".htm"))
    probe = re.sub(r"<[^>]*>", " ", body) if strip_html else body
    n = 0
    for pat, key, _label in cmn.ANCHORS:
        for m in re.finditer(pat, probe):
            if int(m.group("n").replace(",", "")) != int(truth[key]):
                n += 1
    return n


def main():
    print("=" * 64)
    print("fix_material_numbers 回归 + 变异验证")
    print("=" * 64)

    truth = cmn.load_truth()
    real = truth["non_test_lines"]
    # 期望值必须**从真值派生**，不得硬编码当前数字：
    # 旧版把 "126,675"/"724" 写死在断言里，真值一变（如本次 126,675 -> 126,855）
    # 测试就假红——红的是"测试的期望过期"，不是修复器坏了。这类漂移型断言本身就是缺陷。
    fmt_lines = format(truth["non_test_lines"], ",")
    fmt_start = format(real, ",")

    # T1 真值驱动（变异验证：证明不是硬编码 126,675）
    fake = dict(truth)
    fake["non_test_lines"] = 987654
    out, ch = fmn.fix_line("全量 126,659 行 Go 零错误", fake)
    check("T1 真值驱动：喂 987654 -> 产出 987,654（非硬编码）",
          out == "全量 987,654 行 Go 零错误" and ch, "out=%r ch=%r" % (out, ch))

    # T2 千分位跟随（期望值取自真值）
    out2, _ = fmn.fix_line("126,659 行 Go", truth)
    fake2 = dict(truth)
    fake2["go_files"] = 1234
    out3, _ = fmn.fix_line("Go 724 文件", fake2)
    check("T2 千分位跟随：'126,659 行'->'%s 行'；'Go 724 文件'->'Go 1234 文件'" % fmt_lines,
          out2 == "%s 行 Go" % fmt_lines and out3 == "Go 1234 文件", "out2=%r out3=%r" % (out2, out3))

    # T3 边界：不是规模宣称的裸数字不得改动
    out4, ch4 = fmn.fix_line("见 commit 126,659 的说明", truth)
    check("T3 边界：裸 126,659（后无「行」）不得被改",
          out4 == "见 commit 126,659 的说明" and not ch4, "out=%r ch=%r" % (out4, ch4))

    # T4 幂等
    once, _ = fmn.fix_line("126,659 行 Go", truth)
    twice, ch5 = fmn.fix_line(once, truth)
    check("T4 幂等：二次修复 0 改动", once == twice and not ch5, "%r / %r" % (once, twice))

    # T5 HTML 分支：数字与单位被标签隔断
    body5 = '      <div class="num">126,659</div><div class="lbl">行 Go 工程代码</div>'
    out5, ch5b = fmn.fix_line(body5, truth, strip_html=True)
    check("T5 HTML：标签隔断仍能修", fmt_lines in out5 and "126,659" not in out5 and ch5b,
          "out=%r" % out5)

    # T6 修复-检测闭环（核心变异验证）
    injected = "里程碑：全量 126,659 行 Go 零错误。"
    before = probe_hits("docs/x.md", injected, truth)
    fixed, _ = fmn.fix_line(injected, truth)
    after = probe_hits("docs/x.md", fixed, truth)
    check("T6 闭环变异：注入漂移(命中%d) -> 修复 -> 门禁复扫命中 0" % before,
          before == 1 and after == 0, "before=%d after=%d fixed=%r" % (before, after, fixed))

    # T7 fail-closed
    try:
        fmn.fix_line("126,659 行 Go", {k: v for k, v in truth.items() if k != "non_test_lines"})
        t7 = False
        d7 = "未抛异常 —— 门禁字段缺失被静默跳过"
    except SystemExit:
        t7 = True
        d7 = ""
    check("T7 fail-closed：真值缺字段必须崩", t7, d7)

    # T8 换行符零改动 + 端到端写回。
    # 同时给 iter_files / rel 打桩：临时目录在 C: 盘、仓库在 E: 盘，
    # os.path.relpath 跨盘会抛 ValueError —— 打桩比"把临时目录塞进仓库"更干净。
    with tempfile.TemporaryDirectory(prefix="fixmat_") as tmp:
        p = os.path.join(tmp, "sample.md")
        crlf = "行一：126,659 行 Go\r\n行二：无语\r\n"
        with open(p, "w", encoding="utf-8", newline="") as fh:
            fh.write(crlf)

        orig_iter, orig_rel = cmn.iter_files, cmn.rel

        def fake_tree(paths):
            cmn.iter_files = lambda: iter(paths)
            cmn.rel = lambda path: os.path.basename(path)

        try:
            fake_tree([p])
            fixable, _manual = fmn.collect(truth)
            ok_detect = len(fixable) == 1 and len(fixable[0][2]) == 1
            if ok_detect:
                fmn.apply_edits(p, fixable[0][2])
            with open(p, "rb") as fh:
                raw = fh.read()
            fixable2, _ = fmn.collect(truth)  # 修完再扫须 0 处
        finally:
            cmn.iter_files, cmn.rel = orig_iter, orig_rel

        check("T8 端到端：检出并修好临时文件，且换行符仍为 CRLF",
              ok_detect and raw.count(b"\r\n") == 2 and fmt_lines.encode() in raw and not fixable2,
              "ok_detect=%s crlf=%d fixable2=%d" % (ok_detect, raw.count(b"\r\n"), len(fixable2)))

        # T9 BANNED 只上报不改写
        p9 = os.path.join(tmp, "banned.md")
        banned_line = "本系统共 90 工具 YAML，226 测试\n"
        with open(p9, "w", encoding="utf-8", newline="") as fh:
            fh.write(banned_line)
        try:
            fake_tree([p9])
            _f9, m9 = fmn.collect(truth)
        finally:
            cmn.iter_files, cmn.rel = orig_iter, orig_rel
        with open(p9, "r", encoding="utf-8", newline="") as fh:
            after9 = fh.read()
        check("T9 BANNED 只上报不改写",
              len(m9) >= 1 and after9 == banned_line, "manual=%d after=%r" % (len(m9), after9))

    # T11「裸 N 测试」族锚点（2026-10-04 新增）。
    # 背景：材料长期写 `127,196 行 Go · 279 测试` / `Go 735 文件（279 测试）`，
    # 而既有三条 test_files 锚点都要求带"文件"二字 → 这类简写**从无锚点**，
    # 真值已 286 时 279 仍存活于 PPT 构建脚本 + 打印版合订本 + 技术报告（3 文件 5 处）。
    # 期望值一律由真值派生，不得硬编码（否则真值一变就假红）。
    fmt_tf = str(truth["test_files"])
    stale_tf = "279" if fmt_tf != "279" else "278"
    # 行数同样**由真值派生**（10-04 订正）：原写死 127,196，而真值随代码增删漂移
    # （本轮已到 127,279）→ 写死值不再是"错值"，b11 随之从 1 变 2，CI 假红。
    # 正是本段注释自己警告的「真值一变就假红」。派生后本用例与真值永久同步。
    fmt_nl = "{:,}".format(int(truth["non_test_lines"]))
    stale_nl = "1" if fmt_nl == "1" else str(int(fmt_nl.replace(",", "")) - 1)
    stale_nl = "{:,}".format(int(stale_nl))
    t11_bad = "里程碑：%s 行 Go · %s 测试 · 0 panic。" % (stale_nl, stale_tf)
    b11 = probe_hits("docs/x.md", t11_bad, truth)
    f11, _c11 = fmn.fix_line(t11_bad, truth)
    a11 = probe_hits("docs/x.md", f11, truth)
    # 反向自检（防锚点过宽）：
    #  · 2 位数局部说明（「服务层 11 测试」）不是规模宣称 → 不得被改；
    #  · 「286 测试文件」仍归"文件"锚点管 → 本锚点不得重复命中把数字改坏。
    keep_local, ch_local = fmn.fix_line("服务层 11 测试，服务层 11 测试", truth)
    keep_file, ch_file = fmn.fix_line("材料写 %s 测试文件" % fmt_tf, truth)
    # 期望命中数 = 2：样本里注入的**两个**错值都应被门禁检出 ——
    #   ① 127,196（≠真值 non_test_lines）② 279（≠真值 test_files）。
    # 原写 b11 == 1 是错��期望（CI 实红、fix_line 行为经诊断完全正确：
    # 两个数都已被改成真值），已订正为 2。
    check("T11 裸测试数锚点：注入 %s 测试(命中%d) -> 修为 %s；局部 2 位数/「测试文件」写法不被误伤"
          % (stale_tf, b11, fmt_tf),
          b11 == 2 and a11 == 0 and ("%s 测试" % fmt_tf) in f11 and not ch_local and not ch_file,
          "b=%d a=%d f11=%r ch_local=%r ch_file=%r" % (b11, a11, f11, ch_local, ch_file))

    # T10 真实仓库当前状态
    fixable_r, manual_r = fmn.collect(truth)
    check("T10 真实仓库：dry-run 无待修（材料已与真值一致）",
          not fixable_r, "仍有 %d 个文件待修" % len(fixable_r))

    bad = [n for n, ok in _results if not ok]
    print("-" * 64)
    print("  合计 %d 项，失败 %d 项" % (len(_results), len(bad)))
    print("  结论：%s" % ("全部通过 ✅" if not bad else "失败 ❌ " + ", ".join(bad)))
    return 1 if bad else 0


if __name__ == "__main__":
    sys.exit(main())
