#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""产物数字门禁的回归测试 —— 11 项，含变异自检与 fail-closed 自检（故意制造漂移，门禁必须变红）。

为什么必须有它
--------------
`check_artifact_numbers.py` 是**本地/打包时**才跑的门禁（产物是 .gitignore 的二进制，
CI 检出里没有），所以 CI 唯一能守的就是"门禁本体逻辑正确"。做法与
secret-gate / web-parity-gate / caliber-gate 完全一致：**夹具驱动 + 变异自检**。

夹具是 stdlib zipfile 手搓的最小 .pptx / .docx（只含门禁要读的那几个 XML part），
**刻意不依赖 python-pptx / python-docx** —— 否则 CI 得为此多装两个包，
而门禁本身对 pptx/docx 用的就是 zipfile+ElementTree（见 check_artifact_numbers.py）。

"通过"必须不是空转：T4/T5 会把夹具改成漂移态，要求门禁**必须**报出来。

退出码：0 = 全部通过；1 = 有用例失败
"""
import os
import shutil
import sys
import tempfile
import zipfile

HERE = os.path.dirname(os.path.abspath(__file__))
if HERE not in sys.path:
    sys.path.insert(0, HERE)

import check_material_numbers as cmn          # noqa: E402
import check_artifact_numbers as can         # noqa: E402

A_NS = "http://schemas.openxmlformats.org/drawingml/2006/main"
P_NS = "http://schemas.openxmlformats.org/presentationml/2006/main"
W_NS = "http://schemas.openxmlformats.org/wordprocessingml/2006/main"


# ---------------------------------------------------------------------------
# 夹具构造（stdlib only）
# ---------------------------------------------------------------------------
def make_pptx(path, shapes):
    """shapes = [[run, run, ...], ...]，每个子列表是一个形状（形状内 run 不加分隔拼接）。"""
    sps = []
    for runs in shapes:
        ts = "".join("<a:t>%s</a:t>" % r for r in runs)
        sps.append("<p:sp><p:txBody><a:p>%s</a:p></p:txBody></p:sp>" % ts)
    xml = ('<?xml version="1.0" encoding="UTF-8"?>'
           '<p:sld xmlns:p="%s" xmlns:a="%s"><p:cSld><p:spTree>%s</p:spTree></p:cSld></p:sld>'
           % (P_NS, A_NS, "".join(sps)))
    with zipfile.ZipFile(path, "w") as z:
        z.writestr("ppt/slides/slide1.xml", xml)


def make_docx(path, paras):
    ps = "".join("<w:p><w:r><w:t>%s</w:t></w:r></w:p>" % t for t in paras)
    xml = ('<?xml version="1.0" encoding="UTF-8"?>'
           '<w:document xmlns:w="%s"><w:body>%s</w:body></w:document>' % (W_NS, ps))
    with zipfile.ZipFile(path, "w") as z:
        z.writestr("word/document.xml", xml)


def hits_of(root, truth):
    hits, files, problems = can.scan(root, truth)
    return hits, files, problems


def labels(hits):
    return sorted({h[3] for h in hits})


def has_label(hits, frag):
    """标签是按「人类可读全称」输出的（如「工具 YAML 数（正序：N YAML …）」），
    断言必须用子串匹配 —— 用 `frag in labels(hits)` 是集合精确匹配，会假红。"""
    return any(frag in x for x in labels(hits))


def main():
    truth = cmn.load_truth()
    lines_val = truth["non_test_lines"]
    testfiles = truth["test_files"]
    toolsyaml = truth["tools_yaml"]

    base = tempfile.mkdtemp(prefix="artgate-")
    good, bad = os.path.join(base, "good"), os.path.join(base, "bad")
    os.makedirs(good)
    os.makedirs(bad)
    fail = []

    def check(tag, cond, detail=""):
        print("  %-4s %s%s" % ("[OK]" if cond else "[FAIL]", tag,
                               ("  —— " + detail) if detail else ""))
        if not cond:
            fail.append(tag)

    print("=" * 74)
    print("产物数字门禁 · 回归 + 变异自检   锚定 HEAD=%s" % truth.get("head"))
    print("  真值：non_test_lines=%s  test_files=%s  tools_yaml=%s"
          % (lines_val, testfiles, toolsyaml))
    print("-" * 74)

    # ---- T1 正确产物 → 必须零命中（真值驱动，不写死）----------------------
    make_pptx(os.path.join(good, "ok.pptx"),
              [["%s 行 Go" % format(lines_val, ",")], ["%d 测试文件" % testfiles],
               ["%d" % toolsyaml, "YAML 工具配方"]])
    make_docx(os.path.join(good, "ok.docx"),
              ["平台内置 %d 个 YAML 安全工具配方。" % toolsyaml,
               "代码卫生：%d 测试文件 · 0 panic。" % testfiles])
    hits, files, problems = hits_of(good, truth)
    check("T1 正确产物零命中（真值驱动）", not hits and not problems,
          "hits=%s problems=%s" % (labels(hits), problems))

    # ---- T2 PPT 漂移（数字与单位拆成两个形状，数字在前）→ 必须命中 ----------
    make_pptx(os.path.join(bad, "drift_tool.pptx"),
              [["%d" % (toolsyaml - 1), "YAML 工具配方"],
               ["%s 行 Go" % format(lines_val, ",")]])
    hits, _f, _p = hits_of(bad, truth)
    check("T2 拆分字面量「N | YAML 工具配方」被抓（数字在前）",
          has_label(hits, "工具 YAML 数"),
          "hits=%s" % labels(hits))

    # ---- T3 DOCX 漂移（段落拆开）→ 必须命中 test_files ---------------------
    make_docx(os.path.join(bad, "drift_test.docx"),
              ["%d" % (testfiles - 16), "测试文件"])
    hits, _f, _p = hits_of(bad, truth)
    check("T3 拆分段落「N | 测试文件」被抓",
          has_label(hits, "测试文件数"),
          "hits=%s" % labels(hits))

    # ---- T4 变异自检 A：把 T1 的正确值改错 → 门禁必须变红 ------------------
    mut = os.path.join(base, "mut_a")
    os.makedirs(mut)
    make_pptx(os.path.join(mut, "m.pptx"), [["%d 测试文件" % (testfiles - 1)]])
    hits, _f, _p = hits_of(mut, truth)
    check("T4 [变异] 正确值 -1 必须被抓（证明 T1 不是空转）",
          any(h[3] == "测试文件数" for h in hits), "hits=%s" % labels(hits))

    # ---- T5 变异自检 B：BANNED 复活 → 必须变红 ----------------------------
    mutb = os.path.join(base, "mut_b")
    os.makedirs(mutb)
    make_docx(os.path.join(mutb, "b.docx"), ["平台内置 140 个运行时工具。"])
    hits, _f, _p = hits_of(mutb, truth)
    check("T5 [变异] BANNED「140 个运行时工具」必须被抓",
          any(h[2] == "banned" for h in hits), "hits=%s" % labels(hits))

    # ---- T6 形状分隔回归：隔墙的「0」不得与「286 测试文件」粘成 0286 --------
    sep = os.path.join(base, "sep")
    os.makedirs(sep)
    make_pptx(os.path.join(sep, "s.pptx"), [["0"], ["%d 测试文件" % testfiles]])
    hits, _f, _p = hits_of(sep, truth)
    check("T6 形状分隔：粘连成 0286 导致漏检的回归",
          not hits, "hits=%s" % labels(hits))

    # ---- T7 fail-closed：无法解析的产物必须拦下，不能静默放过 --------------
    broken = os.path.join(base, "broken")
    os.makedirs(broken)
    with open(os.path.join(broken, "corrupt.pptx"), "wb") as fh:
        fh.write(b"not a zip at all")
    _h, _f, problems = hits_of(broken, truth)
    check("T7 [fail-closed] 损坏产物计入 problems", bool(problems), "problems=%s" % problems)

    # ---- T8 快照豁免：带 CALIBER-SNAPSHOT 的产物整件豁免 -------------------
    snap = os.path.join(base, "snap")
    os.makedirs(snap)
    make_pptx(os.path.join(snap, "history.pptx"),
              [["CALIBER-SNAPSHOT 锚定 2026-09-05 基线"], ["140 个运行时工具"]])
    hits, _f, _p = hits_of(snap, truth)
    check("T8 带 CALIBER-SNAPSHOT 的历史产物被豁免", not hits, "hits=%s" % labels(hits))

    # ---- T9 跨形状方向判据（数字在前=真；标签在前=拼接产物）----------------
    # T9a：标签在前 → 纯属两张互不相干的卡片被空格拼起来，**必须不报**
    d1 = os.path.join(base, "bound_a")
    os.makedirs(d1)
    make_pptx(os.path.join(d1, "a.pptx"), [["测试文件"], ["%d" % (testfiles + 7)]])
    hits, _f, _p = hits_of(d1, truth)
    check("T9a 跨形状「测试文件 | 293」不得误报（后置式拼接产物）",
          not hits, "hits=%s" % labels(hits))
    # T9b：数字在前 → 数值卡 + 紧邻标签卡，是真实语义，**必须报**
    d2 = os.path.join(base, "bound_b")
    os.makedirs(d2)
    make_pptx(os.path.join(d2, "b.pptx"), [["%d" % (testfiles + 7)], ["测试文件"]])
    hits, _f, _p = hits_of(d2, truth)
    check("T9b 跨形状「293 | 测试文件」必须报（数值卡+标签卡）",
          has_label(hits, "测试文件数"), "hits=%s" % labels(hits))

    # ---- T10 恒久排除（构建输入件）：必须真跳过，且不是"因为夹具无害"---------
    # ALWAYS_EXCLUDE 里的件是构建输入（如 make_template_ppt.py 只克隆其背景图的视觉母版），
    # 文字不构成交付语义。要求两条**同时**成立，否则本用例是空转：
    #   a) 裸扫（仅带 ALWAYS_EXCLUDE）时该件被跳过；
    #   b) 同一份漂移内容换个不被排除的名字 → 必须被抓。
    ex_dir = os.path.join(base, "always_excl")
    os.makedirs(ex_dir)
    drift = [["%d" % (toolsyaml - 1), "YAML 工具配方"]]
    tpl_name = can.ALWAYS_EXCLUDE[0] if can.ALWAYS_EXCLUDE else "NONE"
    make_pptx(os.path.join(ex_dir, tpl_name), drift)
    _h, files, _p = can.scan(ex_dir, truth, list(can.ALWAYS_EXCLUDE))
    skipped = not any(rel == tpl_name for _p, rel in files)
    mut_ex = os.path.join(base, "always_excl_mut")
    os.makedirs(mut_ex)
    make_pptx(os.path.join(mut_ex, "NOT_" + tpl_name), drift)
    mhits, _f, _p = can.scan(mut_ex, truth, list(can.ALWAYS_EXCLUDE))
    check("T10 恒久排除：构建输入件被跳过，同内容换名必被抓（非空转）",
          bool(can.ALWAYS_EXCLUDE) and skipped and has_label(mhits, "工具 YAML 数"),
          "skipped=%s mut_hits=%s" % (skipped, labels(mhits)))

    print("-" * 74)
    try:
        shutil.rmtree(base)
    except OSError:
        pass
    if fail:
        print("  结论：FAIL —— %d 项未通过：%s" % (len(fail), ", ".join(fail)))
        return 1
    print("  结论：PASS —— 11/11（含 T4/T5/T10 变异自检、T7 fail-closed、T9 跨形状方向判据）")
    return 0


if __name__ == "__main__":
    sys.exit(main())
