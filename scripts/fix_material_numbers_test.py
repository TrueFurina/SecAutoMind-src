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
    T12 体积字段 1 位小数：`99.4 MB` -> `89.5 MB`，不得 int() 截断成 89
    T13 CI 缺二进制：体积锚点真值 null 必须「跳过」而非 FATAL（缺件≠故障，与门禁同口径）
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
    """用**门禁自己的 ANCHORS + 同一个 scan_texts 探针**复扫一行，返回命中数。

    这是"闭环"的关键：修复是否正确，不由修复器自己说了算，而由门禁的判定说了算。
    2026-10-18：探针从「自抄一份 HTML 剥离」改为调用门禁的 `cmn.scan_texts`——
    两边必须同源，否则属性值盲区修复后这里会让闭环验证失真。
    """
    n = 0
    for text, _via in cmn.scan_texts(body, cmn.is_html_path(rpath)):
        for pat, key, _label in cmn.ANCHORS:
            for m in re.finditer(pat, text):
                # 与门禁同源比较（整数计数 / 1 位小数体积），别再各写一遍 int()
                got, want = cmn.coerce_num(m.group("n"), truth[key])
                if got != want:
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
        banned_line = "本系统共 91 工具 YAML，226 测试\n"
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

    # T12 体积字段是 1 位小数：修复器不得 int() 截断（2026-10-18 实锤）
    # 背景：新增 `setup_mb`/`exe_mb`（89.5 / 20.3）后，`want_of` 与 `format_like` 里的
    # `int()` 把 89.5 变成 89 → 修复器把「89.5」改成「89」，门禁立刻又报漂移 →
    # **改完立刻再红**的死循环。CI caliber-gate 第 6 步就是这么红的。
    # 真值缺失时跳过（本用例只针对小数逻辑，不引入新的 fail-closed 判据）。
    want_mb = truth.get("exe_mb")
    if isinstance(want_mb, float):
        wrong_mb = "%.1f" % (want_mb + 9.9)
        line_mb = "下载页写 绿色版 %s MB" % wrong_mb
        fixed_mb, ch_mb = fmn.fix_line(line_mb, truth)
        hits_after = probe_hits("docs/x.md", fixed_mb, truth)
        check("T12 体积小数：%s MB -> %.1f MB（不得截断成整数）" % (wrong_mb, want_mb),
              ("%.1f MB" % want_mb) in fixed_mb and hits_after == 0 and bool(ch_mb),
              "fixed=%r hits=%d ch=%r" % (fixed_mb, hits_after, ch_mb))
    else:
        check("T12 体积小数（本检出无 installer 产物 → 跳过，不误红）", True, "exe_mb=%r" % (want_mb,))

    # T13 CI 缺二进制：体积锚点真值为 null 必须「跳过」而非 FATAL（2026-10-18 第二次 CI 反扑）
    # 背景：`installer/*.exe` 不入库 → CI 检出里 setup_mb/exe_mb 为 null。门禁已用
    # missing_anchor_fields 分流「缺件≠故障」，但修复器 want_of 仍写「None 即崩」，
    # 扫到 docs 里的「20.3 MB」就 FATAL，caliber-gate 第 6 步红。必须与门禁同口径：
    # 缺件 = 未核验跳过；产物在却读不出 = 才崩。
    _orig_find = cmn.find_local_installer_products
    cmn.find_local_installer_products = lambda: []
    fmn._has_local_binaries.cache_clear()
    try:
        ci_truth = dict(truth)
        ci_truth["setup_mb"] = None
        ci_truth["exe_mb"] = None
        ci_out, ci_ch = fmn.fix_line("Setup 安装版 20.3 MB / 绿色版 89.5 MB", ci_truth)
        t13_skip = (not ci_ch) and "20.3 MB" in ci_out
        # 非体积字段缺失在 CI 下仍必须 fail-closed（不得被上面的「跳过」误伤）
        try:
            fmn.fix_line("126,659 行 Go", {k: v for k, v in ci_truth.items() if k != "non_test_lines"})
            t13_fc = False
        except SystemExit:
            t13_fc = True
    finally:
        cmn.find_local_installer_products = _orig_find
        fmn._has_local_binaries.cache_clear()
    check("T13 CI 缺二进制：体积锚点跳过不崩 + 非体积缺失仍 fail-closed",
          t13_skip and t13_fc, "skip=%r fc=%r" % (t13_skip, t13_fc))

    # T14~T18（2026-11-10）：修复器复用「已裁定明确不修」登记的变异验证。
    # 背景：发布节点跑 `--apply --check` 曾把官网 5 行刷成真值，导致 3 条登记项
    # 「已不再复现」→ 门禁反而继续红，且违反用户 2026-11-08「官网不用动」裁定。
    # 锚点实际形态是「N 行 Go」；写「非测试代码行数: N」不命中任何锚点（会造出假绿/假红）
    line_skip = "146,571 行 Go"
    base_out, base_ch = fmn.fix_line(line_skip, truth)
    skip_hit = frozenset({("非测试代码行数", 146571)})
    out_hit, ch_hit = fmn.fix_line(line_skip, truth, skip=skip_hit)
    check("T14 登记项命中：保持原文且不计 changes（不刷官网）",
          bool(base_ch) and base_out != line_skip and out_hit == line_skip and not ch_hit,
          "base_ch=%r out=%r ch=%r" % (base_ch, out_hit, ch_hit))

    skip_miss = frozenset({("非测试代码行数", 999999)})
    out_miss, ch_miss = fmn.fix_line(line_skip, truth, skip=skip_miss)
    check("T15 数值不匹配：照常改写（跳过不是全局放水）",
          out_miss != line_skip and bool(ch_miss),
          "out=%r ch=%r" % (out_miss, ch_miss))

    html_line = "<div>146,571</div><div>行 Go</div>"
    _, h_base_ch = fmn.fix_line(html_line, truth, strip_html=True)
    h_label = h_base_ch[0][0].split("（HTML 属性值）")[0] if h_base_ch else None
    h_num = fmn._num(h_base_ch[0][1]) if h_base_ch else None
    h_skip = frozenset({(h_label, h_num)}) if h_base_ch else frozenset()
    h_out, h_ch = fmn.fix_line(html_line, truth, strip_html=True, skip=h_skip)
    check("T16 HTML 分支同样遵守登记跳过（官网是 HTML）",
          bool(h_base_ch) and h_out == html_line and not h_ch,
          "base_ch=%r out=%r ch=%r" % (h_base_ch, h_out, h_ch))

    _orig_load = cmn.load_known_drift
    cmn.load_known_drift = lambda: ([{"file": "官网/index.html",
                                      "label": "非测试代码行数", "got": 146571}],
                                     ["模拟：台账已过期"])
    try:
        bad_keys = fmn._drift_skip_keys()
    finally:
        cmn.load_known_drift = _orig_load
    check("T17 坏台账 fail-closed：不据此跳过任何数字",
          bad_keys == {}, "keys=%r" % (bad_keys,))

    real_keys = fmn._drift_skip_keys()
    t18 = ("官网/index.html" in real_keys
           and len(real_keys["官网/index.html"]) == 3)
    check("T18 真实登记可解析：官网 3 条 / 路径已归一正斜杠",
          t18, "keys=%r" % ({k: len(v) for k, v in real_keys.items()},))

    # T10 真实仓库当前状态
    #
    # 🔴 2026-11-09 修：旧写法断言「dry-run 无待修」，隐含假设「材料必须 100% 等于真值」。
    # 但用户 2026-11-08 明确裁定「官网也就不用动了，因为其实也没人看」，官网那 5 处
    # **本轮确定不修**，并登记在 material_known_drift.json 里。于是旧断言变成
    # 「用户按裁定的不修 = 修复器失控」，把一条合规状态判成红——又是「判据没跟上裁定」。
    # 现在改成：待修的每一处**必须**落在已知漂移登记里；只要有一处没登记就红。
    # 这样既允许裁定过的例外，也能抓「悄悄多出一处没人批的漂移」。
    fixable_r, manual_r = fmn.collect(truth)
    drift_entries, drift_issues = cmn.load_known_drift()

    def _num(v):
        s = str(v).replace(",", "")
        return float(s) if "." in s else int(s)

    def _key(f, label, got):
        """与门禁同一口径：label 去掉 HTML 探针后缀，数字一律去掉千分位再比。
        登记里 got 写的是 146571（无千分位），而待修项拿到的是原文 '146,571' ——
        不归一就永远匹配不上，T10 会变成"永远红"，那等于没有判据。
        （注意不能直接用 cmn.coerce_num：它的签名是 coerce_num(raw, want) → 返回一对数，
        用途是「材料数字 vs 真值」的成对比对，不是单值归一。）"""
        return (f, str(label).split("（HTML 属性值）")[0], _num(got))

    allowed = {_key(e["file"], e["label"], e["got"]) for e in drift_entries}
    unreg = []
    for _abs, rpath, edits in fixable_r:
        for lineno, _old, _new, changes in edits:
            for ch in changes:
                if _key(rpath, ch[0], ch[1]) not in allowed:
                    unreg.append("%s:%d %s=%s" % (rpath, lineno, ch[0], ch[1]))
    check("T10 真实仓库：dry-run 待修项全部落在已知漂移登记里",
          not unreg and not drift_issues,
          "未登记待修 %d 处%s%s" % (len(unreg),
                                  (" ｜ " + "; ".join(unreg[:4])) if unreg else "",
                                  (" ｜ 登记自身有问题：" + "; ".join(drift_issues)) if drift_issues else ""))

    bad = [n for n, ok in _results if not ok]
    print("-" * 64)
    print("  合计 %d 项，失败 %d 项" % (len(_results), len(bad)))
    print("  结论：%s" % ("全部通过 ✅" if not bad else "失败 ❌ " + ", ".join(bad)))
    return 1 if bad else 0


if __name__ == "__main__":
    sys.exit(main())
