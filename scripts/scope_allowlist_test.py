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


if __name__ == "__main__":
    unittest.main(verbosity=2)
