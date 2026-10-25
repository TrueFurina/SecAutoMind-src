#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""`audit_flag_provenance.py` 的回归测试。

要点：
  - 真值集抽取只认 64 位十六进制 + 哈希类键名（不许把任意字符串当哈希）
  - 四档分诊各有判别力（把 `demo`/占位词/真答案分别喂进去）
  - **与 secret_guard 的命中总数必须相等** —— 两条独立扫描路径对不上就说明
    有一边漏扫/多扫，那这份审计的所有数字都不可信（本仓「数字单一真值源」纪律）
  - 非 git 目录 fail-closed
"""
import json
import os
import sys
import tempfile
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))
import audit_flag_provenance as A  # noqa: E402
import secret_guard as sg  # noqa: E402

def _mk(prefix, body):
    """动态拼接 flag 串。

    源码里**不留** `前缀{正文}` 的连续字面量：否则本测试文件自己就成了
    secret_guard 的「真品牌命中」，给要清的队列添噪音（本仓实测被这条咬过）。
    """
    return prefix + "{" + body + "}"

SHA_A = "a" * 64
SHA_B = "b" * 64


class TestHarvest(unittest.TestCase):
    def _mk_tree(self, td, payload, local=None):
        data = Path(td) / "data"
        data.mkdir(parents=True)
        (data / "benchmark.json").write_text(json.dumps(payload), encoding="utf-8")
        if local is not None:
            (data / "flag_truth.local.json").write_text(json.dumps(local), encoding="utf-8")

    def test_picks_up_flag_sha256(self):
        with tempfile.TemporaryDirectory() as td:
            self._mk_tree(td, {"problems": {"1": {"flag_sha256": SHA_A}}})
            truth, stats = sg.harvest_truth_hashes(td, use_local=False)
            self.assertEqual(truth, {SHA_A})
            self.assertEqual(stats["benchmark_files"], 1)

    def test_ignores_non_hash_strings(self):
        """`flag` 明文字段、短串、非 16 进制串都不许当哈希收进来。"""
        with tempfile.TemporaryDirectory() as td:
            self._mk_tree(td, {"problems": {"1": {
                "flag_sha256": "not-a-hash",
                "flag": _mk("DASCTF", "abc"),
                "note_sha256": "Z" * 64,  # 大写 Z 非 16 进制
            }}})
            truth, _ = sg.harvest_truth_hashes(td, use_local=False)
            self.assertEqual(truth, set())

    def test_local_truth_optional(self):
        with tempfile.TemporaryDirectory() as td:
            self._mk_tree(td, {"p": {"flag_sha256": SHA_A}}, local={"x": {"sha256": SHA_B}})
            t_on, st_on = sg.harvest_truth_hashes(td, use_local=True)
            t_off, st_off = sg.harvest_truth_hashes(td, use_local=False)
            self.assertEqual(t_on, {SHA_A, SHA_B})
            self.assertEqual(t_off, {SHA_A})
            self.assertTrue(st_on["local_file"])
            self.assertFalse(st_off["local_file"])

    def test_uppercase_hash_is_normalized(self):
        with tempfile.TemporaryDirectory() as td:
            self._mk_tree(td, {"p": {"flag_sha256": SHA_A.upper()}})
            truth, _ = sg.harvest_truth_hashes(td, use_local=False)
            self.assertEqual(truth, {SHA_A})


class TestClassify(unittest.TestCase):
    def test_known_answer(self):
        raw = _mk("DASCTF", "selftest_real_body")
        import hashlib
        sha = hashlib.sha256(raw.encode()).hexdigest()
        kind, got = sg.classify_provenance(raw, {sha})
        self.assertEqual((kind, got), ("known_answer", sha))

    def test_unknown_brand_when_hash_absent(self):
        kind, _ = sg.classify_provenance(_mk("DASCTF", "selftest_real_body"), set())
        self.assertEqual(kind, "unknown_brand")

    def test_placeholder_wins_over_brand(self):
        """占位符即便品牌像真、即便哈希恰好在真值集里，也必须先判占位符。"""
        raw = _mk("DASCTF", "init1-init2")
        import hashlib
        sha = hashlib.sha256(raw.encode()).hexdigest()
        kind, _ = sg.classify_provenance(raw, {sha})
        self.assertEqual(kind, "placeholder")

    def test_self_bucket(self):
        kind, _ = sg.classify_provenance(_mk("flag", "selftest_body"), set())
        self.assertEqual(kind, "self")

    def test_low_information_is_placeholder(self):
        """与 Go 引擎同判据：`{aaaa}` 这类单字符种类串不是答案。"""
        self.assertEqual(sg.classify_provenance(_mk("DASCTF", "aaaaaaaa"), set())[0], "placeholder")


class TestAuditConsistency(unittest.TestCase):
    """两条独立扫描路径必须对得上（全仓只走一遍，避免测试跑成分钟级）。"""

    @classmethod
    def setUpClass(cls):
        cls.rep = A.audit(A.REPO_ROOT)
        cls.tracked = sg._git_tracked(A.REPO_ROOT)
        hits, _ = sg.scan_plaintext_flags(A.REPO_ROOT, cls.tracked)
        cls.guard_hits = [h for h in hits if h["tracked"]]

    def test_total_matches_secret_guard(self):
        """审计的四档总数必须等于 secret_guard 的已入库命中数（两条路径互校）。"""
        audited = sum(self.rep["counts"].values())
        self.assertEqual(audited, len(self.guard_hits),
                         f"审计 {audited} 条 vs 门禁 {len(self.guard_hits)} 条 —— "
                         f"有一边漏扫/多扫")

    def test_known_answer_not_limited_by_brand(self):
        """铁实锤必须按**哈希**统计，不许按品牌过滤。

        这是本仓实测最严重的一次漏报：首版只认 `brand == "real"`，把 987 条
        `flag{真答案}`（通用前缀 + 真题正文）归进「自产构造」，对外报的真泄露数
        少了 6 倍。下面用一条独立算式与审计分档对账，口径一改就红。
        """
        truth, _ = sg.harvest_truth_hashes(A.REPO_ROOT, use_local=True)
        direct = {h["sha256"] for h in self.guard_hits
                  if h.get("brand") != "placeholder" and h["sha256"] in truth}
        audited = {r["sha256"] for r in self.rep["buckets"].get("known_answer", [])}
        self.assertEqual(direct - audited, set(),
                         f"有 {len(direct - audited)} 个命中真值的串没进铁实锤档")
        self.assertEqual(audited - direct, set(),
                         f"铁实锤档里混进 {len(audited - direct)} 个不命中真值的串")
        self.assertEqual(self.rep["distinct_answers"], len(audited),
                         "distinct_answers 与铁实锤档的去重数不一致（报数会失真）")


class TestFailClosed(unittest.TestCase):
    def test_not_a_git_repo_raises(self):
        with tempfile.TemporaryDirectory() as td:
            with self.assertRaises(RuntimeError):
                A.audit(td)


if __name__ == "__main__":
    unittest.main(verbosity=2)
