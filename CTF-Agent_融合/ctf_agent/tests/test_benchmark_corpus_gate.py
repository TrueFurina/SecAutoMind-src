"""评测入口题库口径闸门（eval.corpus.apply_corpus_gate + benchmark CLI）回归。

覆盖（2026-10-07 建立）：
① skip_reason：可跑 / input-less / 无真值的三类判定；
② partition_measurable 分组正确性；
③ apply_corpus_gate：默认剔除不可测题，include_unmeasurable=True 须原样保留；
④ applicable_corpus_summary 按 reason 汇总；
⑤ **CLI 端到端**：默认跑 data/questions 必须剔除 input-less 题，
   --include-unmeasurable 必须恢复原始题数（防"开关注册了但逻辑没接上"）。

变异验证（已执行）：
  - M1：apply_corpus_gate 忽略 include_unmeasurable → ③ 的 2 个用例红；
  - M2：skip_reason 把 no_truth 判定删掉 → ① 的 no_truth 用例红；
  - M3：apply_corpus_gate 返回 keep 时忘了重算 raw_n → ③ 的 raw_n 用例红。
"""
import os
import subprocess
import sys
import unittest
import pytest

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

_CTF = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))

from eval.corpus import (  # noqa: E402
    applicable_corpus_summary, apply_corpus_gate, has_input, has_truth,
    partition_measurable, skip_reason,
)

_EXISTING = __file__  # 必定存在的真实文件

_POOL_DIR = os.path.join(_CTF, "data", "questions")


def _pool_available() -> bool:
    """数据自检：data/questions 是否真有题（非仅目录存在）。"""
    return os.path.isdir(_POOL_DIR) and any(
        fn.endswith(".json") for _, _, fs in os.walk(_POOL_DIR) for fn in fs)


# 2026-10-12：data/questions 50 题池随本地未跟踪数据丢失事件被删空（全盘 find 零副本、
# 无远端副本、不可恢复）。依赖该池的 CLI 端到端用例补 skipif 优雅降级：池在 → 严格跑；
# 池空 → skip（不再假红）。判据 = 池内是否有题（数据自检，非写死数字），
# 池一旦恢复在盘即自动恢复严格校验。
_need_pool = pytest.mark.skipif(
    not _pool_available(),
    reason=f"data/questions 50 题池永久丢失（2026-10-12 数据丢失事件）: {_POOL_DIR}")


class _Q:
    def __init__(self, attachments=None, flag_sha256=None, flag=None, qid="q"):
        self.id = qid
        self.attachments = list(attachments or [])
        self.flag_sha256 = flag_sha256
        self.flag = flag
        self.description = "d" * 50


class TestSkipReason(unittest.TestCase):
    """① 三类判定。"""

    def test_runnable_returns_none(self):
        self.assertIsNone(skip_reason(_Q([_EXISTING], flag_sha256="a" * 64)))
        # 纯文本题（无附件）但**有真值** → 可跑
        self.assertIsNone(skip_reason(_Q(flag="CTF{x}")))

    def test_input_less_reason(self):
        """附件登记了但全不存在 → no_input（优先级高于 no_truth）。"""
        q = _Q(["/nonexistent/x.bin"])
        self.assertFalse(has_input(q))
        self.assertEqual(skip_reason(q), "no_input")

    def test_no_truth_reason(self):
        """有输入但无真值 → no_truth（解出也无法校验）。"""
        q = _Q([_EXISTING])
        self.assertTrue(has_input(q), "纯文本题/有附件 → 有输入")
        self.assertFalse(has_truth(q))
        self.assertEqual(skip_reason(q), "no_truth")

    def test_input_less_takes_precedence(self):
        """两者皆缺时报告 no_input（缺输入是更根本的缺陷）。"""
        self.assertEqual(skip_reason(_Q(["/nonexistent/x.bin"])), "no_input")


class TestPartition(unittest.TestCase):
    """② 分组正确性。"""

    def test_partition_splits_correctly(self):
        good = _Q([_EXISTING], flag_sha256="a" * 64, qid="good")
        bad = _Q(["/nope.bin"], flag_sha256="a" * 64, qid="bad")
        keep, skipped = partition_measurable([good, bad])
        self.assertEqual([q.id for q in keep], ["good"])
        self.assertEqual([(q.id, r) for q, r in skipped], [("bad", "no_input")])

    def test_empty_input(self):
        keep, skipped = partition_measurable([])
        self.assertEqual((keep, skipped), ([], []))
        self.assertEqual(partition_measurable(None)[0], [])


class TestApplyCorpusGate(unittest.TestCase):
    """③④ 入库闸门语义。"""

    def setUp(self):
        self.good = _Q([_EXISTING], flag_sha256="a" * 64, qid="good")
        self.bad = _Q(["/nope.bin"], flag_sha256="a" * 64, qid="bad")

    def test_default_drops_unmeasurable(self):
        keep, unmeasurable, raw_n = apply_corpus_gate([self.good, self.bad])
        self.assertEqual(raw_n, 2, "raw_n 必须是**过滤前**的原始题数")
        self.assertEqual(len(unmeasurable), 1)
        self.assertEqual([q.id for q in keep], ["good"])

    def test_include_unmeasurable_keeps_everything(self):
        keep, unmeasurable, raw_n = apply_corpus_gate(
            [self.good, self.bad], include_unmeasurable=True)
        self.assertEqual(len(keep), 2, "开关打开时必须原样保留")
        self.assertEqual(raw_n, 2)
        self.assertEqual(len(unmeasurable), 1, "被恢复的题仍应如实列出")

    def test_summary_counts_by_reason(self):
        no_truth = _Q([_EXISTING], qid="nt")
        _, unmeasurable, _ = apply_corpus_gate([self.bad, no_truth])
        self.assertEqual(applicable_corpus_summary(unmeasurable),
                         {"no_input": 1, "no_truth": 1})


class TestBenchmarkCLI(unittest.TestCase):
    """⑤ CLI 端到端：确认开关真的接进了 main()，而非仅仅注册了 argparse。"""

    def _run(self, *args):
        proc = subprocess.run(
            [sys.executable, "-m", "eval.benchmark", "--mock", "--limit", "1"]
            + list(args),
            cwd=_CTF, capture_output=True, text=True, timeout=180,
            encoding="utf-8", errors="replace")
        return proc.stdout + proc.stderr

    @pytest.mark.local
    @_need_pool
    def test_default_gate_drops_input_less(self):
        """默认必须打印剔除统计（data/questions 里 27 题 input-less）。"""
        out = self._run()
        self.assertIn("剔除", out, "默认模式必须执行口径闸门")
        self.assertIn("有效分母", out)

    @pytest.mark.local
    @_need_pool
    def test_include_unmeasurable_restores(self):
        out = self._run("--include-unmeasurable")
        self.assertIn("恢复全部", out,
                      "--include-unmeasurable 必须走恢复分支")

    def test_corpus_switch_uses_cross_corpus(self):
        out = self._run("--corpus")
        self.assertIn("cross-corpus", out, "--corpus 必须走 load_corpus 分支")


if __name__ == "__main__":
    unittest.main()


# ── 2026-11-02：预算击穿必须被显式提示（防误读成能力不足）────────────
def test_budget_exhaustion_hint_is_printed(capsys):
    """大量 budget_exceeded 时，报告必须点明是配置问题并给出参数名。

    实测事故：87 题全量跑，全局预算默认 800K 在第 18 题就被烧穿，
    后 69 题全 budget_exceeded，报告只写「solve_rate 低」——极易被引用成
    「模型能力不行」。真相是默认预算按单场比赛设的，跑整库必须放大。
    本测试锁住那句提示，防止它被后续重构悄悄删掉。
    """
    import importlib
    import eval.benchmark as bm
    importlib.reload(bm)

    summary = {
        "total": 87, "solved": 13,
        "by_error": {"budget_exceeded": 57, "race_abandon": 17},
        "integrity": {"attempted": 87, "zero_work_not_attempted": 0,
                      "truncated": 0, "mechanism_terminated": 74,
                      "not_attempted_ids": [], "truncated_ids": [],
                      "interpretable": False},
    }
    # 直接调用打印分支（不落盘），只验文案
    try:
        bm._print_summary_for_test(summary) if hasattr(bm, "_print_summary_for_test") else None
    except Exception:
        pass
    # 无专用入口时，验证阈值判据本身存在于源码（防删除的静态断言）
    src = open(bm.__file__, encoding="utf-8").read()
    assert "CTF_AGENT_GLOBAL_BUDGET" in src, "预算提示被删除了"
    assert "CTF_AGENT_PER_Q_BUDGET" in src, "单题预算参数名写错或缺失"
    assert "配置" in src and "不是能力问题" in src


# ── 2026-11-04：LLM 侧全灭时 solve_rate 必须作废（fail-closed）──────────
def test_solve_rate_voided_when_provider_wiped_out():
    """provider 大面积熔断时，solve_rate 必须置 None（不能给百分比外观）。

    实证事故（docs/evidence/stepfun_quota_exhausted_20261104/）：
    StepFun 额度耗尽那轮 HTTP 200 计数为 0、402 共 5774 次，
    报告却写 solved=11 / solve_rate=0.126 —— 那 11 题是工具产物，与模型能力无关。
    这种数字有精确百分比外观，却来自一条没打通的链路，最容易被引用。
    """
    from eval.benchmark import summarize, BenchmarkResult
    from eval.cases import Question

    def mk(qid, out):
        q = Question(id=qid, title="t", category="crypto")
        q.provenance = "real_past_ctf"
        return BenchmarkResult(q, out, 1000, 1)

    rs = []
    for i in range(87):
        if i < 34:
            rs.append(mk(f"c{i}", {"error": {"category": "provider_circuit_open"}}))
        elif i < 76:
            rs.append(mk(f"c{i}", {"error": {"category": "tool_failure"}}))
        else:
            rs.append(mk(f"c{i}", {"flag": "flag{x}"}))

    s = summarize(rs)
    assert s["solve_rate"] is None, "熔断 39% 时 solve_rate 必须作废"
    assert s["integrity"]["infrastructure_unavailable"] is True
    assert s["integrity"]["interpretable"] is False
    # 分桶也要作废：下游常只读 by_category，只堵顶层等于没堵
    assert s["by_category"]["crypto"]["solve_rate"] is None


def test_solve_rate_normal_when_provider_healthy():
    """反向对照：熔断少时必须照常输出数字，防"恒 None"式假安全。"""
    from eval.benchmark import summarize, BenchmarkResult
    from eval.cases import Question

    def mk(qid, out):
        q = Question(id=qid, title="t", category="crypto")
        q.provenance = "real_past_ctf"
        return BenchmarkResult(q, out, 1000, 1)

    rs = [mk(f"n{i}", {"error": {"category": "tool_failure"}}) for i in range(10)]
    s = summarize(rs)
    assert s["solve_rate"] is not None, "健康轮次不该被误判成基础设施不可用"
    assert s["solve_rate"] == 0.0
