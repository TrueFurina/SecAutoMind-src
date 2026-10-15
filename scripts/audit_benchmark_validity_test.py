#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""audit_benchmark_validity 自测：回归 + 变异。

门禁三铁律在本文件里的落法：
1. **覆盖度**：分层题数之和必须等于总数（脚本内断言），避免分类漏题仍报 PASS。
2. **0 值态必须是红**：变异用例证明「无问题」时 PASS、「有问题」时 FAIL，
   两边都验，防止判据恒真或恒假。
3. **断言彼此独立**：只污染 A 层、或只污染 C 层，各自都能独立触发 FAIL，
   证明两条断言不是被同一条短路掩盖。
"""

from __future__ import annotations

import io
import json
import os
import sys
import tempfile
import unittest
from contextlib import redirect_stdout

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import audit_benchmark_validity as abv  # noqa: E402


def write_fixture(tmp: str, problems: dict, results: list, attach=None):
    bpath = os.path.join(tmp, "bench.json")
    rpath = os.path.join(tmp, "report.json")
    with open(bpath, "w", encoding="utf-8") as fh:
        json.dump({"problems": problems}, fh, ensure_ascii=False)
    with open(rpath, "w", encoding="utf-8") as fh:
        json.dump({"total": len(results), "results": results}, fh, ensure_ascii=False)
    adir = os.path.join(tmp, "attach")
    os.makedirs(adir, exist_ok=True)
    for name in attach or []:
        os.makedirs(os.path.join(adir, name), exist_ok=True)
    return bpath, rpath, adir


def run_with(bpath, rpath, adir, argv):
    old = (abv.BENCH, abv.REPORT, abv.ATTACH)
    abv.BENCH, abv.REPORT, abv.ATTACH = bpath, rpath, adir
    try:
        buf = io.StringIO()
        with redirect_stdout(buf):
            rc = abv.main(argv)
        return rc, buf.getvalue()
    finally:
        abv.BENCH, abv.REPORT, abv.ATTACH = old


CLEAN_PROB = {
    # 有真实载荷：长 base64
    "t_b64": {"id": "t_b64", "category": "crypto", "description": "YidkM0JxZGtwQlRYdHFhR3g2YUhsZmF6TnFlVGwzWVROc"},
    # 有附件
    "t_att": {"id": "t_att", "category": "misc", "description": "分析附件"},
}
CLEAN_RES = [
    {"id": "t_b64", "sha256_match": True, "presolve_engine": "base64_multilayer"},
    {"id": "t_att", "sha256_match": True, "presolve_engine": "attachment"},
]


class TestRegression(unittest.TestCase):
    """真实仓库数据上的回归：分层结果必须与人工核查一致。"""

    def test_real_data_layers(self):
        problems, results, attach = abv.load()
        layers = abv.classify(problems, attach)
        self.assertEqual(len(problems), 55, "真实题库应 55 题")
        self.assertEqual(
            len(layers["A"]) + len(layers["B"]) + len(layers["C"]),
            len(problems),
            "分层之和必须等于总数（覆盖度）",
        )
        # 人工核查值（2026-10-15）：题面即答案 4 / 有输入 12 / 无输入 39
        self.assertEqual(len(layers["A"]), 4)
        self.assertEqual(len(layers["B"]), 12)
        self.assertEqual(len(layers["C"]), 39)

    def test_real_data_check_fails(self):
        """当前基准确实注水，--check 必须报红（否则门禁形同虚设）。"""
        rc, out = run_with(abv.BENCH, abv.REPORT, abv.ATTACH, ["--check"])
        self.assertEqual(rc, 1)
        self.assertIn("门禁结论：FAIL", out)
        self.assertIn("题面直接含 flag 明文", out)
        self.assertIn("物理不可解却计入分母", out)


class TestMutation(unittest.TestCase):
    """变异用例：证明判据两端都灵。"""

    def test_clean_benchmark_passes(self):
        """0 值态：干净基准必须 PASS——证明断言不是恒假。"""
        with tempfile.TemporaryDirectory() as tmp:
            b, r, a = write_fixture(tmp, CLEAN_PROB, CLEAN_RES, attach=["t_att"])
            rc, out = run_with(b, r, a, ["--check"])
            self.assertEqual(rc, 0, out)
            self.assertIn("门禁结论：PASS", out)

    def test_all_noinput_fails(self):
        """全是无输入题 → C 层 100%，必须 FAIL——证明判据不是恒真。"""
        prob = {("p%d" % i): {"id": "p%d" % i, "description": "查看网页源码找 flag"}
                for i in range(5)}
        res = [{"id": k, "sha256_match": False, "presolve_engine": None} for k in prob]
        with tempfile.TemporaryDirectory() as tmp:
            b, r, a = write_fixture(tmp, prob, res)
            rc, out = run_with(b, r, a, ["--check"])
            self.assertEqual(rc, 1)
            self.assertIn("物理不可解却计入分母", out)

    def test_only_flag_plain_fails_independently(self):
        """只污染 A 层（C 层为 0）→ 仍须 FAIL，证明 A 断言未被 C 断言短路。"""
        prob = dict(CLEAN_PROB)
        prob["evil"] = {"id": "evil", "category": "web",
                        "description": "<!-- secret: flag{plain_in_stem} -->"}
        res = list(CLEAN_RES) + [
            {"id": "evil", "sha256_match": True, "presolve_engine": "flag_scan"}
        ]
        with tempfile.TemporaryDirectory() as tmp:
            b, r, a = write_fixture(tmp, prob, res, attach=["t_att"])
            rc, out = run_with(b, r, a, ["--check"])
            self.assertEqual(rc, 1, out)
            self.assertIn("题面直接含 flag 明文", out)
            self.assertNotIn("物理不可解却计入分母", out, "C 层为 0 时不应报 C 断言")

    def test_flag_plain_detected_regardless_of_hit(self):
        """题面含 flag 明文即入 A 层，与是否命中无关（分类不靠结果）。"""
        self.assertTrue(abv.FLAG_PLAIN_RE.search("flag{abc}"))
        self.assertTrue(abv.FLAG_PLAIN_RE.search("picoCTF{x_y_z}"))
        self.assertFalse(abv.FLAG_PLAIN_RE.search("YidkM0JxZGtwQlRYdHFhR3g2YUhsZmF6TnFlVGwz"))

    def test_report_mode_never_fails(self):
        """仅报数模式恒 0：报数不得因数据差而中断流水线。"""
        with tempfile.TemporaryDirectory() as tmp:
            prob = {("p%d" % i): {"id": "p%d" % i, "description": "摘要"} for i in range(3)}
            res = [{"id": k, "sha256_match": False} for k in prob]
            b, r, a = write_fixture(tmp, prob, res)
            rc, _ = run_with(b, r, a, [])
            self.assertEqual(rc, 0)


if __name__ == "__main__":
    unittest.main(verbosity=2)
