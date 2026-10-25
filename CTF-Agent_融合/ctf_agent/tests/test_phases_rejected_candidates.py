"""rejected_candidates 诊断记录（C 线）单测：7 个弃值点的保留验证。

2026-10-25 C 诊断线：extract_flag 的拒绝分支此前只记"丢弃"，候选值本体
（LLM 产出的错误答案）直接消失——后验分析无法回答"LLM 错在哪"。本组测试
钉住：每个弃值点都把候选值保留进 ctx.rejected_candidates（stage/value/reason），
且主流程行为与记录前完全一致（控制流不变性）。
"""
import os
import sys
import unittest
from types import SimpleNamespace

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from core.phases import extract_flag  # noqa: E402
from verify.flag_checker import V_REJECT  # noqa: E402


def _ctx(flag_pattern=None, category="crypto", tool_obs="crypto_auto done",
         flag_sha256=None):
    q = SimpleNamespace(id="q1", flag_pattern=flag_pattern, category=category,
                        flag_sha256=flag_sha256)
    steps = [SimpleNamespace(action="tool:crypto_auto", observation=tool_obs)]
    ctx = SimpleNamespace(question=q, _extract_failed=False, steps=steps)
    return ctx


def _agent(checker=None):
    return SimpleNamespace(checker=checker)


def _act(out, kind="tool"):
    return {"kind": kind, "output": out}


class _ShaChecker:
    """extract 出固定 flag 的 checker；verdict 可按用例注入三态结果。"""

    verdict = None  # None = 三态不确定 → 走 sha256 仲裁

    @staticmethod
    def extract(s):
        return "flag{from_checker}"

    @classmethod
    def check(cls, f):
        return cls.verdict


class _RejectChecker(_ShaChecker):
    verdict = V_REJECT  # 直落 checker_reject 弃值点


class TestRejectedCandidates(unittest.TestCase):
    """每个弃值点 = 一条 rejected_candidates 记录（stage/value/reason 齐全）。"""

    def test_template_placeholder_recorded(self):
        ctx = _ctx()
        out = "flag{%d-%d}"
        self.assertIsNone(extract_flag(_agent(), ctx, {"output": out}))
        recs = ctx.rejected_candidates
        self.assertEqual(len(recs), 1)
        self.assertEqual(recs[0]["stage"], "template_placeholder")
        self.assertIn("flag{%d", recs[0]["value"])
        self.assertEqual(recs[0]["question"], "q1")

    def test_checker_reject_recorded(self):
        ctx = _ctx()
        agent = _agent(checker=_RejectChecker())
        # provenance 放行（kind=tool），checker.check 返回 V_REJECT → checker_reject 点
        got = extract_flag(agent, ctx, _act("tool output flag{from_checker}"))
        self.assertIsNone(got)
        recs = ctx.rejected_candidates
        self.assertEqual(len(recs), 1)
        self.assertEqual(recs[0]["stage"], "checker_reject")
        self.assertEqual(recs[0]["value"], "flag{from_checker}")

    def test_checker_sha256_mismatch_recorded(self):
        ctx = _ctx(flag_sha256="ab" * 32)  # 官方锚 ≠ 候选 → 仲裁 False
        agent = _agent(checker=_ShaChecker())
        got = extract_flag(agent, ctx, _act("tool output flag{from_checker}"))
        self.assertIsNone(got)
        stages = [r["stage"] for r in ctx.rejected_candidates]
        self.assertIn("checker_sha256_mismatch", stages)

    def test_provenance_reject_recorded(self):
        ctx = _ctx()
        # 无 kind="tool" → provenance 闸拒绝（checker=None → 正则兜底路径）
        got = extract_flag(_agent(), ctx, {"output": "flag{abc123}"})
        self.assertIsNone(got)
        stages = [r["stage"] for r in ctx.rejected_candidates]
        self.assertIn("fallback_provenance_reject", stages)
        values = [r["value"] for r in ctx.rejected_candidates
                  if r["stage"] == "fallback_provenance_reject"]
        self.assertEqual(values, ["flag{abc123}"])

    def test_no_record_on_accept(self):
        ctx = _ctx()
        out = "the flag is flag{abc123}"
        self.assertEqual(extract_flag(_agent(), ctx, _act(out)), "flag{abc123}")
        # 采信路径不产生弃值记录（记录只属于拒绝分支）
        self.assertFalse(hasattr(ctx, "rejected_candidates"))

    def test_control_flow_invariance(self):
        """记录插桩不得改变既有行为：模板拒绝后 E1 兜底仍可救回真候选。"""
        ctx = _ctx()
        out = 'flag{%d}\n{"candidates": ["flag{real_one}"]}'
        self.assertEqual(extract_flag(_agent(), ctx, _act(out)), "flag{real_one}")
        self.assertFalse(ctx._extract_failed)
        # 模板弃值点仍应有记录（主输出被拒）
        stages = [r["stage"] for r in ctx.rejected_candidates]
        self.assertEqual(stages, ["template_placeholder"])


if __name__ == "__main__":
    unittest.main(verbosity=2)
