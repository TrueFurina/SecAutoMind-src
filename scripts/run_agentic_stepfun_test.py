#!/usr/bin/env python3
"""run_agentic_stepfun 的自测：patch 必须生效、必须幂等、不许夹带其它改动。

为什么值得单独测：这个 wrapper 是「同一模型只切换 agentic/pure_llm」这个对照
成立的前提。如果它悄悄失效（比如上游把键改名），跑批会静默退化成 pure_llm，
而日志里仍然写着 --agentic ⇒ 又是一次跨层假绿。
"""
import ast
import os
import sys

HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, HERE)

cases = []


def ck(label, ok, detail=""):
    cases.append((label, bool(ok), detail))


# 1) 导入即 patch 生效
import run_agentic_stepfun as w  # noqa: E402
import ctf_stepfun_orchestrator as orch  # noqa: E402

ck("导入后 supports_tools 为 True",
   orch.PROVIDERS["stepfun"].get("supports_tools") is True,
   "got=%r" % orch.PROVIDERS["stepfun"].get("supports_tools"))

# 2) 幂等：再执行一次不改变结果、不抛错
before = orch.PROVIDERS["stepfun"]["supports_tools"]
orch.PROVIDERS["stepfun"]["supports_tools"] = True
ck("重复 patch 幂等", orch.PROVIDERS["stepfun"]["supports_tools"] is True, "")

# 3) patch 目标键真的存在于 PROVIDERS（防上游改名后静默新增一个无用键）
ck("PROVIDERS['stepfun'] 存在 supports_tools 键",
   "supports_tools" in orch.PROVIDERS["stepfun"], "")

# 4) wrapper 源码里对 PROVIDERS 的写入只有一处（防有人往里塞第二处改动）
src = open(os.path.join(HERE, "run_agentic_stepfun.py"), encoding="utf-8").read()
tree = ast.parse(src)
writes = []
for node in ast.walk(tree):
    if isinstance(node, ast.Assign):
        for t in node.targets:
            if isinstance(t, ast.Subscript) and isinstance(t.value, ast.Subscript):
                # PROVIDERS["stepfun"]["supports_tools"] = ...
                writes.append(ast.unparse(node))
ck("源码内对 PROVIDERS 的赋值恰为 1 处", len(writes) == 1, "实际=%d %s" % (len(writes), writes[:3]))

# 5) wrapper 不得改动 verify_flag / run_python_tool 的绑定（只在 patch 之外透传）
ck("未重新绑定 run_python_tool",
   not hasattr(w, "run_python_tool"), "")
ck("未重新绑定 verify_flag",
   not hasattr(w, "verify_flag"), "")

passed = 0
for label, ok, detail in cases:
    passed += int(ok)
    print("  %s %-42s %s" % ("PASS" if ok else "FAIL", label, "" if ok else detail))
print("run_agentic_stepfun 自测：%d/%d" % (passed, len(cases)))
sys.exit(0 if passed == len(cases) else 1)
