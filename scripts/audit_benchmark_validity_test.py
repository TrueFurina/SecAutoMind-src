#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""audit_benchmark_validity 自测：回归 + 变异。

门禁三铁律在本文件里的落法：
1. **覆盖度**：分层题数之和必须等于总数（脚本内断言），避免分类漏题仍报 PASS。
2. **0 值态必须是红**：变异用例证明「无问题」时 PASS、「有问题」时 FAIL，
   两边都验，防止判据恒真或恒假。
3. **断言彼此独立**：只污染 A 层、或只污染 C 层，各自都能独立触发 FAIL，
   证明两条断言不是被同一条短路掩盖。

判据语义变更（2026-10-16）
--------------------------
A 层判据由「正则看着像」改为 **sha256 比对**（题面 flag 串的 sha256 == flag_sha256），
与 scripts/check_benchmark_plaintext_answer.py 同源。原因是 CRC32 伪造、LCG 参数恢复
一类题的 flag 是**已知输入**，形态也是 flag{...} 但与答案指纹不等——按外观判会误伤。
相应地，--check 默认阈值改为**登记基线（不许恶化）**，而非理想阈值（A=0 / C≤20%）。

因此本文件的「当前数据必须报红」用例已改为「当前数据在基线内 PASS」，
并**新增证明基线模式仍抓得住恶化**的用例——否则"放低阈值"就真的成了放水。
"""

from __future__ import annotations

import hashlib
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

    def test_real_data_check_passes_within_baseline(self):
        """当前数据在登记基线内 → PASS。

        注意语义：基线 = 「不许再恶化」，不是「已合格」。理想目标仍是 A=0、C 层尽量低。
        用理想阈值（--max-a 0 --max-noinput-pct 20）跑则必须报红，见下一个用例。
        """
        rc, out = run_with(abv.BENCH, abv.REPORT, abv.ATTACH, ["--check"])
        self.assertEqual(rc, 0, out)
        self.assertIn("门禁结论：PASS", out)

    def test_real_data_still_fails_ideal_threshold(self):
        """用理想阈值跑当前数据 → 必须报红（证明基线不是自我安慰）。"""
        rc, out = run_with(abv.BENCH, abv.REPORT, abv.ATTACH,
                           ["--check", "--max-a", "0", "--max-noinput-pct", "20"])
        self.assertEqual(rc, 1)
        self.assertIn("门禁结论：FAIL", out)
        self.assertIn("题面即答案", out)
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

    def test_only_a_layer_fails_independently(self):
        """只污染 A 层（C 层为 0）→ 仍须 FAIL，证明 A 断言未被 C 断言短路。

        fixture 必须为 evil 题配 flag_sha256，否则新判据（sha256 比对）判不出 A 层。
        """
        prob = dict(CLEAN_PROB)
        evil_flag = "flag{plain_in_stem}"
        prob["evil"] = {"id": "evil", "category": "web",
                        "description": "<!-- secret: %s -->" % evil_flag,
                        "flag_sha256": hashlib.sha256(evil_flag.encode()).hexdigest()}
        res = list(CLEAN_RES) + [
            {"id": "evil", "sha256_match": True, "presolve_engine": "flag_scan"}
        ]
        with tempfile.TemporaryDirectory() as tmp:
            b, r, a = write_fixture(tmp, prob, res, attach=["t_att"])
            rc, out = run_with(b, r, a, ["--check", "--max-a", "0"])
            self.assertEqual(rc, 1, out)
            self.assertIn("题面即答案", out)
            self.assertNotIn("物理不可解却计入分母", out, "C 层为 0 时不应报 C 断言")

    def test_a_layer_over_baseline_fails(self):
        """基线模式仍抓得住恶化：A 层 5 题 > 基线 4 → FAIL。

        这条是"放低阈值"后必须补的自证：否则登记基线就等同于放水。
        """
        prob = dict(CLEAN_PROB)
        res = list(CLEAN_RES)
        for i in range(5):
            f = "flag{leak_%d}" % i
            prob["evil%d" % i] = {"id": "evil%d" % i, "category": "web",
                                  "description": "答案在题面 " + f,
                                  "flag_sha256": hashlib.sha256(f.encode()).hexdigest()}
            res.append({"id": "evil%d" % i, "sha256_match": True,
                        "presolve_engine": "flag_scan"})
        with tempfile.TemporaryDirectory() as tmp:
            b, r, a = write_fixture(tmp, prob, res, attach=["t_att"])
            rc, out = run_with(b, r, a, ["--check"])   # 用默认基线 BASELINE_A=4
            self.assertEqual(rc, 1, out)
            self.assertIn("题面即答案", out)

    def test_answer_in_statement_needs_sha256_match(self):
        """新判据单测：sha256 相等才算答案在题面；仅"形态像"不算。"""
        f = "flag{real_one}"
        self.assertTrue(abv.answer_in_statement(
            {"description": "答案在题面 " + f,
             "flag_sha256": hashlib.sha256(f.encode()).hexdigest()}))
        # 已知输入型：形态是 flag{...} 但与答案指纹不等 → 不算【防误伤，关键】
        self.assertFalse(abv.answer_in_statement(
            {"description": "给定原文 flag{input_only} 伪造 CRC32",
             "flag_sha256": hashlib.sha256("flag{the_real_answer}".encode()).hexdigest()}))
        # 没有 flag_sha256 → 无法裁定，不误伤
        self.assertFalse(abv.answer_in_statement({"description": "flag{abc}"}))

    def test_input_flag_not_classified_as_a(self):
        """端到端防误伤：CRC32 式题（flag 是输入）不得落入 A 层。"""
        prob = dict(CLEAN_PROB)
        prob["crc"] = {"id": "crc", "category": "misc",
                       "description": "给定原文 flag{admin_forge} 伪造其 CRC32 碰撞",
                       "flag_sha256": hashlib.sha256("flag{other_value}".encode()).hexdigest()}
        res = list(CLEAN_RES) + [{"id": "crc", "sha256_match": True,
                                  "presolve_engine": "crc32_forge"}]
        with tempfile.TemporaryDirectory() as tmp:
            b, r, a = write_fixture(tmp, prob, res, attach=["t_att"])
            layers = abv.classify(prob, {"t_att"})
            self.assertNotIn("crc", layers["A"], "输入型 flag 不得判为 A 层")
            rc, out = run_with(b, r, a, ["--check", "--max-a", "0"])
            self.assertEqual(rc, 0, out)

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
