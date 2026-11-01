#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""scope_allowlist.py 自测（REA #169：豁免必须有保质期）

准入清单最容易退化成后门的方式不是"写错"，是**慢慢没人看**：
理由写成"业务需要"、日期一栏永远空着、到期日写了但从不检查。
本文件把四类退化都钉死：

  1. 缺字段（尤其过期日）→ 条目无效，不得默认永久有效
  2. 理由空洞（"业务需要"/"历史原因"）→ 无效
  3. 过期 → decide() 返回 "expired"，**不等于** allowed
  4. 类别不匹配 → 不得跨类复用（上次为 A 类放行，这次 B 类不能跟着过）

运行：python -X utf8 scripts/scope_allowlist_test.py
"""
from __future__ import annotations

import json
import tempfile
import unittest
from datetime import date
from pathlib import Path
import sys

sys.path.insert(0, str(Path(__file__).resolve().parent))

import scope_allowlist as sa  # noqa: E402

GOOD = {
    "pattern": "webshell_*",
    "category": "C3_利用载荷与凭证窃取与持久化",
    "reason": "授权渗透管理：已建连场景下的受控执行，目标授权由用户显式提供",
    "audited_on": "2026-10-20",
    "expires_on": "2027-01-18",
    "reviewer": "tester",
}


class ValidateTest(unittest.TestCase):
    def test_good_entry_is_valid(self):
        self.assertEqual(sa.validate(dict(GOOD)), [])

    def test_missing_expiry_is_invalid(self):
        e = dict(GOOD)
        e.pop("expires_on")
        problems = sa.validate(e)
        self.assertTrue(any("expires_on" in p for p in problems),
                        "缺过期日不得默认永久有效")

    def test_vague_reason_is_invalid(self):
        for bad in ("业务需要", "历史原因", "tbd", "   "):
            e = dict(GOOD, reason=bad)
            self.assertTrue(sa.validate(e), f"空洞理由 {bad!r} 必须判无效")

    def test_expiry_must_be_after_audit(self):
        e = dict(GOOD, expires_on="2026-10-19")
        self.assertTrue(any("晚于" in p for p in sa.validate(e)))

    def test_overlong_ttl_is_invalid(self):
        e = dict(GOOD, expires_on="2027-12-31")
        self.assertTrue(any("180" in p for p in sa.validate(e)))

    def test_bad_date_format_is_invalid(self):
        e = dict(GOOD, audited_on="2026/10/20")
        self.assertTrue(sa.validate(e))


class DecideTest(unittest.TestCase):
    def test_allowed_within_window(self):
        status, entry = sa.decide("webshell_exec", GOOD["category"], [GOOD], today=date(2026, 11, 1))
        self.assertEqual(status, "allowed")
        self.assertIs(entry, GOOD)

    def test_expired_is_not_allowed(self):
        status, _ = sa.decide("webshell_exec", GOOD["category"], [GOOD], today=date(2027, 6, 1))
        self.assertEqual(status, "expired", "过期条目等于没有准入")

    def test_category_must_match(self):
        status, entry = sa.decide("webshell_exec", "C1_商业保护破解与自动还原", [GOOD],
                                 today=date(2026, 11, 1))
        self.assertEqual(status, "none")
        self.assertIsNone(entry, "不得跨类别复用同一条准入")

    def test_wildcard_category_covers_any(self):
        e = dict(GOOD, category="*")
        status, _ = sa.decide("webshell_exec", "C1_商业保护破解与自动还原", [e],
                              today=date(2026, 11, 1))
        self.assertEqual(status, "allowed")

    def test_name_mismatch_is_none(self):
        status, _ = sa.decide("nmap_scan", GOOD["category"], [GOOD], today=date(2026, 11, 1))
        self.assertEqual(status, "none")


class LoadTest(unittest.TestCase):
    def _write(self, doc) -> Path:
        fd, path = tempfile.mkstemp(suffix=".json")
        with __import__("os").fdopen(fd, "w", encoding="utf-8") as f:
            json.dump(doc, f)
        self.addCleanup(Path(path).unlink)
        return Path(path)

    def test_missing_file_is_empty_not_error(self):
        entries, problems = sa.load(Path(tempfile.gettempdir()) / "no-such-allowlist.json")
        self.assertEqual((entries, problems), ([], []), "无清单 = 无准入，不是错误")

    def test_bad_json_reports_problem(self):
        p = self._write([])   # 合法 JSON 但不是对象
        entries, problems = sa.load(p)
        self.assertEqual(entries, [])
        self.assertTrue(problems)

    def test_invalid_entry_is_skipped_not_silently_kept(self):
        bad = dict(GOOD)
        bad.pop("reviewer")
        p = self._write({"entries": [GOOD, bad]})
        entries, problems = sa.load(p)
        self.assertEqual(len(entries), 1)
        self.assertTrue(any("reviewer" in x for x in problems))

    def test_shipped_allowlist_is_clean(self):
        """出厂清单必须能被 --check 直接通过（空清单也合法）。"""
        entries, problems = sa.load()
        self.assertEqual(problems, [], f"出厂清单本身有问题：{problems}")
        self.assertEqual([e for e in entries if sa.is_expired(e)], [],
                         "出厂清单里有过期条目")


class MutationTest(unittest.TestCase):
    """变异验证：证明上面那些断言是「承重」的，而不是恒真的空转。

    做法（与仓库既有门禁一致，如 check_flag_extract_contract --selftest）：
      1. 干净实现跑一遍，拿到正确结果；
      2. 把判据函数替换成失灵版本，再跑一遍；
      3. 断言**结果必然改变** —— 若替换后结果不变，说明那条断言从未真正依赖这个判据，是摆设。

    为什么值得做（2026-10-31）：本文件原有 9 条用例都验得对，但没人证明过
    「判据失灵时它们会变红」。准入清单最危险的退化不是写错，是**悄悄失效却没人发现**。
    """

    # 已过期条目（审计 2019-01-01，到期 2020-01-01）
    EXPIRED = dict(GOOD, audited_on="2019-01-01", expires_on="2020-01-01")

    def _decide_expired(self):
        return sa.decide("webshell_1", GOOD["category"], [self.EXPIRED],
                         today=date(2021, 1, 1))[0]

    def _decide_fresh(self):
        return sa.decide("webshell_1", GOOD["category"], [GOOD],
                         today=date(2026, 12, 1))[0]

    def test_clean_baseline(self):
        """先钉住干净态：过期→expired、在有效期内→allowed。"""
        self.assertEqual(self._decide_expired(), "expired")
        self.assertEqual(self._decide_fresh(), "allowed")

    def test_mutation_is_expired_always_false(self):
        """is_expired 恒 False ⇒ 过期条目被误判 allowed（永久准入后门）。"""
        orig = sa.is_expired
        try:
            sa.is_expired = lambda entry, today=None: False
            self.assertEqual(self._decide_expired(), "allowed",
                             "变异后必须变成 allowed，否则「过期→expired」那条断言是空转")
        finally:
            sa.is_expired = orig

    def test_mutation_is_expired_always_true(self):
        """is_expired 恒 True ⇒ 有效期内条目被误判 expired（另一方向也要验，防恒假）。"""
        orig = sa.is_expired
        try:
            sa.is_expired = lambda entry, today=None: True
            self.assertEqual(self._decide_fresh(), "expired",
                             "变异后必须变成 expired，否则「有效期内→allowed」那条断言是空转")
        finally:
            sa.is_expired = orig

    def test_mutation_parse_date_always_none(self):
        """_parse_date 恒 None ⇒ 日期全部解析失败 ⇒ is_expired 恒 False ⇒ 同样永久准入。

        这一条更隐蔽：日期还在（没人动过条目），只是解析环节坏了，
        表象是「所有条目永远有效」。
        """
        orig = sa._parse_date
        try:
            sa._parse_date = lambda value: None
            self.assertEqual(self._decide_expired(), "allowed",
                             "日期解析失灵也必须被「过期→expired」那条断言抓到")
        finally:
            sa._parse_date = orig

    def test_mutation_after_mutation_restored(self):
        """收尾自检：变异必须被还原，否则会污染同进程里的其他用例。"""
        self.assertIsNot(sa.is_expired.__module__, "__main__")
        self.assertEqual(self._decide_expired(), "expired")
        self.assertEqual(self._decide_fresh(), "allowed")


if __name__ == "__main__":
    unittest.main(verbosity=1)
