"""监督 LLM 越权环境归因的硬闸回归测试（2026-11-11 ext47 事故）。

事故回顾：ext47 跑批 7 道题里，监督 LLM 反复输出
「rea_probe 工具不可用属环境问题而非分析结论」，把「模型没调用该工具」
误诊成「环境缺工具」。实测该工具在注册表里（inventory('rev') 第 5 位）、
容器内 node 与 rea.mjs 均在、日志工具层就绪列表也含它，全程无一次真实
调用失败。误判使整条失败归因链指向环境而非模型行为。

本测试锁住三道防线：
1. _has_env_blame 能识别禁用短语；
2. _llm_review 对含环境归因的输出整条作废（返回 None，退回兜底）；
3. _build_review_prompt 对观察文本里的禁用短语就地标注成因。
"""

from __future__ import annotations

import asyncio
import unittest

from core.supervisor_agent import SupervisorAgent, _has_env_blame
from core.main_agent import VERDICT_SWITCH


class _FakeQuestion:
    title = "某 CTF 题"
    category = "rev"
    description = "附件是一个 ELF"


class _FakeStep:
    def __init__(self, action="tool", tool_used=None, observation="", stage="step",
                 error_category=None):
        self.action = action
        self.tool_used = tool_used
        self.observation = observation
        self.stage = stage
        self.error_category = error_category


class _FakeCtx:
    def __init__(self, steps=None, candidate_flag=None):
        self.question = _FakeQuestion()
        self.steps = steps or []
        self.candidate_flag = candidate_flag
        self.hint_text = ""
        self.correction = None
        self.strategy_switches = 0
        self.model_upgrades = 0
        self.stuck_count = 0


class TestEnvBlameDetection(unittest.TestCase):
    def test_detects_chinese_phrases(self):
        self.assertTrue(_has_env_blame("rea_probe 工具不可用属环境问题"))
        self.assertTrue(_has_env_blame("工具不存在"))
        self.assertTrue(_has_env_blame("依赖缺失导致失败"))
        self.assertTrue(_has_env_blame("这是环境故障"))

    def test_detects_english_phrases(self):
        self.assertTrue(_has_env_blame("tool unavailable in container"))
        self.assertTrue(_has_env_blame("missing dependency"))

    def test_clean_text_passes(self):
        self.assertFalse(_has_env_blame("模型未调用 rea_probe，改用反汇编"))
        self.assertFalse(_has_env_blame("方向正确，继续做静态分析"))
        self.assertFalse(_has_env_blame(""))

    def test_none_safe(self):
        self.assertFalse(_has_env_blame(None))


class TestLlmReviewGate(unittest.TestCase):
    def _run(self, verdict):
        """构造一个返回固定裁决的 fake client，跑一次 _llm_review。"""

        async def _client(system, user, attempt):
            return verdict

        agent = SupervisorAgent(llm_client=_client)
        ctx = _FakeCtx(steps=[_FakeStep(tool_used="file_analyze", observation="识别文件类型")])
        return asyncio.run(agent._llm_review(ctx))

    def test_env_blame_verdict_is_dropped(self):
        """含环境归因的裁决必须整条作废（None），不得返回。"""
        v = self._run({
            "action": "continue",
            "reason": "rea_probe 工具不可用属环境问题而非分析结论",
            "suggestion": "继续当前方向",
        })
        self.assertIsNone(v)

    def test_env_blame_in_suggestion_also_dropped(self):
        """suggestion 字段同样受闸，不能只查 reason。"""
        v = self._run({
            "action": "switch_strategy",
            "reason": "方向不明",
            "suggestion": "换工具，因为环境缺依赖",
        })
        self.assertIsNone(v)

    def test_clean_verdict_passes_through(self):
        v = self._run({
            "action": "switch_strategy",
            "reason": "连续 3 步只做文件识别，未下沉反汇编",
            "suggestion": "调用 rea_probe 的 decompile_batch",
        })
        self.assertIsNotNone(v)
        self.assertEqual(v.action, VERDICT_SWITCH)
        self.assertIn("rea_probe", v.suggestion)

    def test_env_blame_falls_back_to_default_continue(self):
        """作废后 review() 兜底为「默认继续」，而不是让错误裁决生效。"""

        async def _client(system, user, attempt):
            return {"action": "give_up", "reason": "工具不可用，放弃",
                    "suggestion": "跳过"}

        agent = SupervisorAgent(llm_client=_client)
        ctx = _FakeCtx(steps=[_FakeStep(tool_used="file_analyze",
                                        observation="文件已识别，未深入")])
        verdict = asyncio.run(agent.review(ctx))
        # 关键：不能是 give_up（那会被监督误判直接放弃本题）
        self.assertNotEqual(verdict.action, "give_up")


class TestPromptSanitize(unittest.TestCase):
    def test_env_blame_in_observation_is_annotated(self):
        """观察文本里的禁用短语必须就地标注，不能原样喂给监督 LLM。"""
        agent = SupervisorAgent(llm_client=None)
        ctx = _FakeCtx(steps=[
            _FakeStep(tool_used=None, observation="rea_probe 工具不可用，环境问题"),
        ])
        prompt = agent._build_review_prompt(ctx)
        self.assertIn("非已证实的环境事实", prompt)
        self.assertIn("客户端的自我陈述", prompt)

    def test_clean_observation_not_annotated(self):
        agent = SupervisorAgent(llm_client=None)
        ctx = _FakeCtx(steps=[
            _FakeStep(tool_used="file_analyze", observation="ELF 头解析成功，段表可见"),
        ])
        prompt = agent._build_review_prompt(ctx)
        self.assertNotIn("非已证实的环境事实", prompt)


if __name__ == "__main__":
    unittest.main()
