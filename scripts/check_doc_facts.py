#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""文档事实门禁（迷你版）—— AGENTS.md 的规范性数字分解必须等于 count_stats 真值。

为什么需要它（2026-10-20 实锤）
------------------------------
`check_material_numbers.py` 把 AGENTS.md 列入 EXEMPT_FILES——理由正当：
规范文档必须**列举**已作废数字才能说明规则（"140 是三不管数字"必然要写出 140）。
但豁免制造了一个盲区：AGENTS.md 第二条教的**分解式示范**——
「宁可写 "N YAML + K 内置 = R 运行时"」——不是枚举，是**现行事实的示范**。
实测该行写着 "91 YAML + 52 内置 = 143 运行时"，而 count_stats 真值早已是
**90 / 52 / 142**（删 tools/lightx.yaml 后 91→90、143→142，材料门禁修了官网/PPT，
却没有任何判据能看见这条豁免行内的漂移）。规范文档自己违反自己教的纪律，
且靠人肉发现——这正是本项目「三次漂移全靠人肉」的同款失效形态。

它检查三件事
------------
1) 分解式示范必须存在（缺失即红——fail-closed：没找到 != 没问题，
   否则改写法/删示例都会让门禁静默失效）；
2) 分解式三个数字必须分别等于 count_stats 的 tools_yaml / builtin_tools /
   runtime_tools，且 yaml + builtin == runtime（分解式自洽）；
3) 「140 既不等于 N（YAML 工具数）也不等于 M」句中的两个真值引用同样必须现行。

真值来源：scripts/count_stats.py --json（单一真值源，与材料门禁同一个）。
取不到真值 / AGENTS.md 缺失 → 退出码 2（fail-closed），绝不静默跳过。

退出码：0 = 通过；1 = 漂移；2 = fail-closed（无真值 / 缺 AGENTS.md / 无分解式）
"""
import json
import os
import re
import subprocess
import sys

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
PY = sys.executable
DOC = os.path.join(ROOT, "AGENTS.md")

# 分解式示范：「91 YAML + 52 内置 = 143 运行时」
DECOMP_RE = re.compile(
    r"(?P<yaml>\d+)\s*YAML\s*\+\s*(?P<builtin>\d+)\s*内置\s*=\s*(?P<runtime>\d+)\s*运行时"
)
# 「140 既不等于 90（YAML 工具数）也不等于 142」句中的两个真值引用
NEITHER_RE = re.compile(
    r"既不等于\s*(?P<yaml>\d+)\s*（YAML 工具数）也不等于\s*(?P<runtime>\d+)"
)


def load_truth():
    """从单一真值源取数。取不到就直接崩 —— 没有真值的门禁毫无意义。"""
    out = subprocess.run(
        [PY, os.path.join(ROOT, "scripts", "count_stats.py"), "--json"],
        cwd=ROOT, capture_output=True, text=True,
    )
    if out.returncode != 0:
        raise SystemExit("FATAL: count_stats.py 执行失败，无法取得真值。")
    try:
        return json.loads(out.stdout)
    except json.JSONDecodeError as e:
        raise SystemExit("FATAL: count_stats.py 输出不是合法 JSON（真值源坏了）: %s" % e)


def check_text(text, truth):
    """纯函数：校验一段文本（AGENTS.md 内容）对真值的一致性。返回问题清单。"""
    issues = []
    for field in ("tools_yaml", "builtin_tools", "runtime_tools"):
        if truth.get(field) is None:
            raise SystemExit(
                "FATAL: count_stats.py 未返回 %s（真值源字段缺失）——门禁绝不静默跳过。"
                % field
            )
    m = DECOMP_RE.search(text)
    if not m:
        issues.append("AGENTS.md 未找到分解式示范「N YAML + K 内置 = R 运行时」"
                      "——缺失即红（fail-closed）：改写法会让本门禁静默失效")
        return issues
    yaml_n, builtin_n, runtime_n = (int(m.group("yaml")), int(m.group("builtin")),
                                    int(m.group("runtime")))
    if yaml_n != truth["tools_yaml"]:
        issues.append("分解式 YAML 数 %d != 真值 %d" % (yaml_n, truth["tools_yaml"]))
    if builtin_n != truth["builtin_tools"]:
        issues.append("分解式内置数 %d != 真值 %d" % (builtin_n, truth["builtin_tools"]))
    if runtime_n != truth["runtime_tools"]:
        issues.append("分解式运行时数 %d != 真值 %d" % (runtime_n, truth["runtime_tools"]))
    if yaml_n + builtin_n != runtime_n:
        issues.append("分解式不自洽：%d + %d != %d" % (yaml_n, builtin_n, runtime_n))
    m2 = NEITHER_RE.search(text)
    if not m2:
        issues.append("AGENTS.md 未找到「140 既不等于 N（YAML 工具数）也不等于 M」句"
                      "——该句是旧口径活教材，缺失即红（fail-closed）")
    else:
        if int(m2.group("yaml")) != truth["tools_yaml"]:
            issues.append("「既不等于」句 YAML 引用 %s != 真值 %d"
                          % (m2.group("yaml"), truth["tools_yaml"]))
        if int(m2.group("runtime")) != truth["runtime_tools"]:
            issues.append("「既不等于」句运行时引用 %s != 真值 %d"
                          % (m2.group("runtime"), truth["runtime_tools"]))
    return issues


def main():
    truth = load_truth()
    if not os.path.isfile(DOC):
        print("FATAL: 未找到 %s —— 规范性文档缺失，fail-closed。" % DOC)
        return 2
    with open(DOC, "r", encoding="utf-8") as fh:
        text = fh.read()
    issues = check_text(text, truth)
    print("=" * 70)
    print("文档事实门禁 · 真值来自 scripts/count_stats.py --json")
    print("  真值: tools_yaml=%s builtin_tools=%s runtime_tools=%s"
          % (truth.get("tools_yaml"), truth.get("builtin_tools"), truth.get("runtime_tools")))
    print("-" * 70)
    if issues:
        for x in issues:
            print("  [FAIL] %s" % x)
        print("=" * 70)
        print("  结论：FAIL —— AGENTS.md 示范数字与真值漂移，请同步后重跑。")
        return 1
    print("  [PASS] AGENTS.md 分解式示范与真值一致（含自洽与「既不等于」句引用）")
    print("=" * 70)
    print("  结论：PASS")
    return 0


if __name__ == "__main__":
    sys.exit(main())
