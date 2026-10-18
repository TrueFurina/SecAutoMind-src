#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""css_shadow_audit 门禁回归测试 —— 防「importance 盲区」与「空扫全绿」。

背景（2026-10-18/19 影子块清理实操）：
  第一版 analyse() 只按"后来者必胜"判定可证明安全，忽略 !important。
  实删前复核发现被删块里有 15 处 !important —— 若其中某一处只被后来块的
  **普通声明**覆盖，删除就会把生效值从 important 旧值换成普通新值，
  等价性验证（同样是 importance 盲的）也看不见。本测试把这条钉死：
    · 正向：普通影子块 / important 被同级或更高 important 覆盖 → 判可安全；
    · 反向变异：important 只被普通声明覆盖 → 必须判"部分存活"，绝不删；
    · 级联表：important 压普通、普通不压 important、同级后来者压先者；
    · 空扫防呆：解析出 0 个顶层块时必须算红（防 --check 恒绿的"空洞绿"）；
    · 端到端 --apply：等价性验证 + 重要性不足的块不得落盘删除。

用法：
    python scripts/css_shadow_audit_test.py
退出码：0 = 门禁健康；1 = 门禁已退化（含 importance 盲区复发），必须修脚本
"""
import importlib.util
import io
import json
import os
import sys
import tempfile
from contextlib import redirect_stdout

try:
    sys.stdout.reconfigure(encoding="utf-8")
except Exception:
    pass

HERE = os.path.dirname(os.path.abspath(__file__)
                       )
GATE = os.path.join(HERE, "css_shadow_audit.py")


def load_gate():
    spec = importlib.util.spec_from_file_location("css_shadow_under_test", GATE)
    m = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(m)
    return m


def sel_of(fully_dead):
    return sorted(s for s, _a, _b in fully_dead)


def main():
    m = load_gate()
    fails = []

    def check(name, cond, detail=""):
        if cond:
            print("  [PASS] %s" % name)
        else:
            print("  [FAIL] %s %s" % (name, detail))
            fails.append(name)

    # ---------- [1] 普通影子块：每属性都被后来同选择器块覆盖 → 可证明安全 ----------
    css1 = """
.a { color: red; padding: 4px; }
.b { color: green; }
.a { color: blue; padding: 8px; }
"""
    b1 = m.scan_top_level_blocks(css1)
    fd1, p1 = m.analyse(b1)
    # 注意：scan_top_level_blocks 按"出现顺序"返回；第一个 .a 整块被第二个 .a 覆盖
    check("[1] 普通影子块可证明安全", sel_of(fd1) == [".a"], "got %s" % sel_of(fd1))
    check("[1] .b 单块不误判", ".b" not in sel_of(fd1))

    # ---------- [2] 🔴 importance 反向变异：important 只被普通声明覆盖 → 绝不可删 ----------
    css2 = """
.a { color: red !important; padding: 4px; }
.a { color: blue; padding: 8px; }
"""
    fd2, p2 = m.analyse(m.scan_top_level_blocks(css2))
    check("[2] important 未被同级覆盖 → 不得判安全", sel_of(fd2) == [],
          "got %s（importance 盲区复发）" % sel_of(fd2))
    gap2 = dict(p2).get(".a", [])
    check("[2] 缺口属性是 color", "color" in gap2, "got %s" % gap2)
    check("[2] padding 已被可靠覆盖不进缺口", "padding" not in gap2, "got %s" % gap2)

    # ---------- [3] important 被同级/更高 important 覆盖 → 可证明安全 ----------
    css3 = """
.a { color: red !important; }
.a { color: blue !important; }
"""
    fd3, _p3 = m.analyse(m.scan_top_level_blocks(css3))
    check("[3] important 被后来 important 覆盖 → 安全", sel_of(fd3) == [".a"],
          "got %s" % sel_of(fd3))

    # ---------- [4] 级联表：important 压普通；普通不能压 important；同级后来者胜 ----------
    css4 = """
.a { color: red; }
.a { color: blue !important; }
.a { color: green; }
"""
    fm4 = m.final_property_map(m.scan_top_level_blocks(css4))[".a"]
    check("[4] important 压过两侧普通声明", fm4["color"] == ("blue", True),
          "got %r" % (fm4.get("color"),))
    css4b = """
.a { color: red !important; }
.a { color: green; }
"""
    fm4b = m.final_property_map(m.scan_top_level_blocks(css4b))[".a"]
    check("[4] 普通后来者不覆盖 important 先者", fm4b["color"] == ("red", True),
          "got %r" % (fm4b.get("color"),))

    # ---------- [5] @media/@keyframes 内部不进顶层清单；字符串花杠不破解析 ----------
    css5 = """
.a { color: red; }
@media (max-width: 600px) {
  .a { color: blue; }
  .a { color: teal; }
}
.b { content: "}"; width: 1px; }
@keyframes spin { from { transform: rotate(0); } to { transform: rotate(360deg); } }
"""
    b5 = m.scan_top_level_blocks(css5)
    sels5 = [s for s, _p, _a, _b in b5]
    check("[5] 顶层块恰 2 个（media/keyframes 内部不计）", len(b5) == 2,
          "got %d: %s" % (len(b5), sels5))
    fd5, _p5 = m.analyse(b5)
    check("[5] media 内的 .a 影子块不算顶层 → 无 fully_dead", sel_of(fd5) == [],
          "got %s" % sel_of(fd5))
    body5 = dict((s, p) for s, p, _a, _b in b5).get(".b", {})
    check("[5] content: \"}\" 后的块仍解析出属性", "width" in body5 and "content" in body5,
          "got %s" % list(body5))

    # ---------- [6] 空扫防呆：0 顶层块时必须判红（防 --check 空洞绿） ----------
    with tempfile.TemporaryDirectory() as td:
        empty_css = os.path.join(td, "empty.css")
        with open(empty_css, "w", encoding="utf-8") as fh:
            fh.write("/* only a comment */\n")
        b6 = m.scan_top_level_blocks(open(empty_css, encoding="utf-8").read())
        check("[6] 空 CSS 解析出 0 块", len(b6) == 0)
        # 有内容时解析数必须 > 0（否则 --check 会因扫不到东西而恒绿）
        css6 = ".a{color:red}\n.a{color:blue}\n"
        check("[6] 有内容时解析数 > 0", len(m.scan_top_level_blocks(css6)) == 2)

    # ---------- [7] 端到端 --apply：等价删除 + importance 不足块不动 ----------
    css7 = """
/* 前导注释 */
.keep { color: black; }
.shadow { color: red; padding: 4px; }
.imp-trap { color: red !important; }
.next { color: gray; }
.shadow { color: blue; padding: 8px; }
.imp-trap { color: green; }
"""
    with tempfile.TemporaryDirectory() as td:
        css_path = os.path.join(td, "style.css")
        json_path = os.path.join(td, "deleted.json")
        with open(css_path, "w", encoding="utf-8") as fh:
            fh.write(css7)
        saved_css, saved_argv = m.CSS, sys.argv
        try:
            m.CSS = css_path
            sys.argv = ["css_shadow_audit.py", "--apply", "--json", json_path]
            buf = io.StringIO()
            with redirect_stdout(buf):
                rc = m.main()
            out = buf.getvalue()
            after = open(css_path, encoding="utf-8").read()
        finally:
            m.CSS, sys.argv = saved_css, saved_argv
        check("[7] --apply 返回 0", rc == 0, "rc=%r" % rc)
        check("[7] .shadow 旧块被删", ".shadow { color: red; padding: 4px; }" not in after)
        check("[7] .shadow 新块保留", ".shadow { color: blue; padding: 8px; }" in after)
        check("[7] .imp-trap 两块都保留（重要性不足，不删）",
              after.count(".imp-trap") == 2, "count=%d" % after.count(".imp-trap"))
        check("[7] 无关块不受牵连", ".keep { color: black; }" in after and
              ".next { color: gray; }" in after)
        check("[7] 注释保留", "/* 前导注释 */" in after)
        check("[7] 删除后无完全死块", m.analyse(m.scan_top_level_blocks(after))[0] == [])
        with open(json_path, encoding="utf-8") as fh:
            meta = json.load(fh)
        check("[7] 删除清单恰 1 条且是 .shadow",
              len(meta["deleted"]) == 1 and meta["deleted"][0]["selector"] == ".shadow",
              "got %s" % meta["deleted"])
        # 语法完好：花杠配平
        check("[7] 花杠配平", after.count("{") == after.count("}"))

    # ---------- [8] --check 反向变异：存在可证明安全块时必须 rc=1（防恒绿） ----------
    with tempfile.TemporaryDirectory() as td:
        css_path = os.path.join(td, "style.css")
        with open(css_path, "w", encoding="utf-8") as fh:
            fh.write(css7)  # 含一个普通影子块 .shadow
        saved_css, saved_argv = m.CSS, sys.argv
        try:
            m.CSS = css_path
            sys.argv = ["css_shadow_audit.py", "--check"]
            buf = io.StringIO()
            with redirect_stdout(buf):
                rc8 = m.main()
        finally:
            m.CSS, sys.argv = saved_css, saved_argv
        check("[8] 有死块时 --check rc=1", rc8 == 1, "rc=%r" % rc8)
        # 无同名选择器（不存在影子块）时必须 rc=0（防恒红）
        css8 = ".a { color: red; }\n.b { color: blue; }\n"
        with open(css_path, "w", encoding="utf-8") as fh:
            fh.write(css8)
        try:
            m.CSS = css_path
            sys.argv = ["css_shadow_audit.py", "--check"]
            buf = io.StringIO()
            with redirect_stdout(buf):
                rc8b = m.main()
        finally:
            m.CSS, sys.argv = saved_css, saved_argv
        check("[8] 清空后 --check rc=0", rc8b == 0, "rc=%r" % rc8b)

    print("=" * 60)
    if fails:
        print("css_shadow_audit_test: %d 项失败 -> %s" % (len(fails), ", ".join(fails)))
        return 1
    print("css_shadow_audit_test: 全部通过")
    return 0


if __name__ == "__main__":
    sys.exit(main())
