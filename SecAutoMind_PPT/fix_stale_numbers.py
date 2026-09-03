# -*- coding: utf-8 -*-
"""一次性校正 PPT 生成脚本中的过期数字（2026-09-03 复核）。

仅替换**已用仓库事实核验**的数字；无法核实的（如 final 脚本
"27 外部协议/注入型工具"）保持原样，留给人工确认。

核验依据：
- 角色化 Agent 18        : ls agents/*.md
- 测试包 26/26 全绿 0 FAIL: docs/evidence-build-test-20260903.txt
- 测试文件 226           : find . -name '*_test.go'
- 技能包 23              : find skills -name SKILL.md
- internal 包 31         : find internal -mindepth 1 -maxdepth 1 -type d
- Go 代码 26,893 行(非测试): find internal cmd -name '*.go' -not -name '*_test.go' | xargs wc -l
"""
import pathlib

HERE = pathlib.Path(__file__).resolve().parent

# (旧值, 新值) —— 按出现顺序依次替换，均为精确字符串
REPLACEMENTS = [
    ("16Agent", "18Agent"),                      # champion 文档字符串
    ("16 Agent", "18 Agent"),                    # 正文/标题中的 Agent 数
    ("场景 Agent 角色", "角色化 Agent"),          # 标签更精确（18 含 3 个编排器变体）
    ("24/26", "26/26"),                          # 测试包通过数
    ("'223', '测试文件'", "'226', '测试文件'"),   # champion 统计卡
    ("223 测试", "226 测试"),                     # 其余"223 测试文件/测试"
    ("17,927", "26,893"),                        # Go 代码行数
    ("27 个 internal 包", "31 个 internal 包"),
    ("27 包分层", "31 包分层"),
    ("24 技能包", "23 技能包"),
    ("'24', '技能包'", "'23', '技能包'"),
]

TARGETS = ["make_champion_ppt.py", "make_final_ppt.py"]

total = 0
for name in TARGETS:
    p = HERE / name
    text = p.read_text(encoding="utf-8")
    orig = text
    print(f"=== {name} ===")
    for old, new in REPLACEMENTS:
        n = text.count(old)
        if n:
            text = text.replace(old, new)
            total += n
            print(f"  {old!r} -> {new!r}  x{n}")
    if text != orig:
        p.write_text(text, encoding="utf-8")
        print(f"  [written] {name}")
    else:
        print(f"  [unchanged] {name}")

print(f"\n总替换次数: {total}")
