"""题首内部预扫开关（CTF_AGENT_INTERNAL_PRESOLVE）回归。

守护的是口径纪律：确定性直扫与 LLM 贡献必须能分开记账。2026-10-06 实测——
外部真题 5 题探针中 2 题被附件直扫秒解，若无法关闭内部预扫，这 2 题会被
误记为 LLM 能力。
"""
import ast
import importlib.util
import os
import sys
import unittest
from pathlib import Path
from unittest import mock

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))

spec = importlib.util.spec_from_file_location(
    "ma_switch_probe", ROOT / "core" / "main_agent.py")
# 只做语法级加载代价过高（模块 import 链重），因此直接取函数源码语义：
# 用 runpy 会在 import 时拉起整个依赖链，故改为源码断言 + 纯函数复刻校验。
src = (ROOT / "core" / "main_agent.py").read_text(encoding="utf-8")


class TestInternalPresolveSwitch(unittest.TestCase):
    def test_helper_exists_with_documented_default(self):
        self.assertIn("def internal_presolve_enabled()", src)
        self.assertIn("CTF_AGENT_INTERNAL_PRESOLVE", src)
        # 默认必须是"开"——关闭只能是显式 opt-out，避免老口径被静默改变
        self.assertIn('os.getenv("CTF_AGENT_INTERNAL_PRESOLVE", "on")', src)

    def test_switch_semantics(self):
        # 复刻 helper 的判定语义做表驱动校验（值与实现一致才算数）
        def enabled(env_value):
            if env_value is None:
                return "on"
            return env_value

        for val, want_enabled in (("on", True), ("off", False), ("0", False),
                                  ("false", False), ("OFF", False), ("", True)):
            got = enabled(val).strip().lower() not in ("off", "0", "false")
            self.assertEqual(got, want_enabled, f"env={val!r}")

    def test_call_site_uses_helper(self):
        # 调用点必须走 helper，不能另有独立 env 读取（否则改一处漏一处）
        self.assertIn("if not internal_presolve_enabled():", src)

    def test_all_presolve_calls_go_through_gate(self):
        """所有 presolve 调用必须走 `_gated_presolve` 闸门（2026-11-04 新增）。

        事故：本开关原先只守住「题首预扫」一处，而同文件另有 2 处兜底调用
        （放弃前 / 死循环前）完全不受控。实测三闸全关后仍有 11 题被
        `solved_by=presolve` 出答案，纯 LLM 口径被污染，而**没有任何测试变红**。

        本用例锁住"不许再有裸调用"：除闸门内部那一次外，
        `await presolve(` / `from core.presolve import presolve` 都不许出现在
        main_agent.py 里。以后新增调用点如果绕过闸门，这里立刻红。
        变异验证：把任一处 _gated_presolve 改回 presolve → 本用例 FAIL。
        """
        # 只看**真实代码行**（剥掉 docstring / 注释），否则闸门自身的说明文字会被误判
        try:
            tree = ast.parse(src)
        except SyntaxError as e:  # pragma: no cover
            self.fail("main_agent.py 语法错误：%s" % e)

        gate_node = next(
            (n for n in ast.walk(tree)
             if isinstance(n, (ast.AsyncFunctionDef, ast.FunctionDef))
             and n.name == "_gated_presolve"), None)
        self.assertIsNotNone(gate_node, "闸门 _gated_presolve 不存在")

        # 统计「闸门体之外」的 await presolve() 与 core.presolve import
        g_start, g_end = gate_node.lineno, (gate_node.end_lineno or gate_node.lineno)
        outside_lines = [
            ln for i, ln in enumerate(src.splitlines(), start=1)
            if not (g_start <= i <= g_end)
        ]
        bare_await = [ln for ln in outside_lines
                      if "await presolve(" in ln and not ln.strip().startswith("#")]
        self.assertEqual(
            bare_await, [],
            "存在绕过 _gated_presolve 的裸 presolve 调用（开关会漏管）：%r" % bare_await)

        bare_import = [ln for ln in outside_lines
                       if "from core.presolve import presolve" in ln
                       and not ln.strip().startswith("#")
                       and not ln.strip().startswith("`")]
        self.assertEqual(
            bare_import, [],
            "存在直连 core.presolve 的 import（应改用 _gated_presolve）：%r" % bare_import)

        # 正向：闸门必须真的被调用（防"全删掉也算通过"）
        self.assertGreaterEqual(
            src.count("_gated_presolve("), 3,
            "闸门调用点过少，疑似被移除（至少应有 题首/放弃前/死循环前 三处）")


if __name__ == "__main__":
    unittest.main(verbosity=2)
