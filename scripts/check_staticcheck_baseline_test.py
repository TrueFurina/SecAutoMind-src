#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""check_staticcheck_baseline.py 自测。

门禁自测的底线（REA #253）：**必须有"已知坏样本必须红"的用例**。
永远绿的门禁比没有门禁更坏——它会让人以为有保护。

覆盖：
  1. 报告缺失 / 为空 / 全坏行 → exit 2（fail-closed，"扫不到"≠"干净"）
  2. 真实基线报告 → exit 0
  3. 新增一条阻断档（SA4006）→ exit 1
  4. 基线未登记的语义类 code（SA5001 之类）→ exit 1（不许靠"没登记"蒙混过关）
  5. 观察档计数变化 → 默认 exit 0 并提示；--strict 下 exit 1
  6. 绝对路径报告能被 SECAUTOMIND_STATICCHECK_ROOT 归一化并与基线匹配
  7. 基线条目自身体检：每条豁免都要有 reason + reviewed_on
"""

from __future__ import annotations

import json
import os
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path

HERE = Path(__file__).resolve().parent
SCRIPT = HERE / "check_staticcheck_baseline.py"
BASELINE = HERE / "staticcheck_baseline.json"


def _row(code: str, file: str, line: int = 1, message: str = "x") -> dict:
    return {"code": code, "location": {"file": file, "line": line}, "message": message}


def _write_report(tmp: Path, rows: list[dict], *, garbage: str = "") -> str:
    path = tmp / "sc.json"
    with path.open("w", encoding="utf-8") as fh:
        for r in rows:
            fh.write(json.dumps(r, ensure_ascii=False) + "\n")
        if garbage:
            fh.write(garbage + "\n")
    return str(path)


def _run(report: str, *extra: str, env_root: str | None = None,
         env_ledger: str | None = None) -> subprocess.CompletedProcess:
    env = dict(os.environ)
    if env_root:
        env["SECAUTOMIND_STATICCHECK_ROOT"] = env_root
    else:
        env.pop("SECAUTOMIND_STATICCHECK_ROOT", None)
    if env_ledger:
        env["SECAUTOMIND_DEAD_CODE_LEDGER"] = env_ledger
    else:
        env.pop("SECAUTOMIND_DEAD_CODE_LEDGER", None)
    return subprocess.run(
        [sys.executable, "-X", "utf8", str(SCRIPT), "--report", report, *extra],
        capture_output=True, text=True, env=env, timeout=120)


class FailClosedTest(unittest.TestCase):
    def test_missing_report_is_exit_2(self):
        out = _run(str(HERE / "__nonexistent__.json"))
        self.assertEqual(out.returncode, 2, "报告缺失不得当成通过")

    def test_empty_report_is_exit_2(self):
        with tempfile.TemporaryDirectory() as d:
            p = Path(d) / "empty.json"
            p.write_text("", encoding="utf-8")
            out = _run(str(p))
        self.assertEqual(out.returncode, 2, "空报告 = 没扫到，不等于干净")

    def test_all_garbage_is_exit_2(self):
        with tempfile.TemporaryDirectory() as d:
            p = Path(d) / "bad.json"
            p.write_text("not json\n{also not json\n", encoding="utf-8")
            out = _run(str(p))
        self.assertEqual(out.returncode, 2)


class GateTest(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.root = Path(self.tmp.name)
        self.baseline = json.loads(BASELINE.read_text(encoding="utf-8"))

    def _baseline_rows(self) -> list[dict]:
        """按基线计数造一份"当前状态"报告（counts 与基线一致即可）。"""
        rows: list[dict] = []
        for code, n in self.baseline["blocking_codes"].items():
            for _ in range(n):
                rows.append(_row(code, "internal/x/y.go"))
        for code, n in self.baseline["observed_codes"].items():
            for _ in range(n):
                rows.append(_row(code, "internal/x/z.go"))
        return rows

    def _ledger_with(self, keys: list[str]) -> str:
        """临时死代码台账（与真台账同 schema）：登记合成 U1000 的 (file::symbol)。

        2026-10-23 起门禁语义：U1000 的唯一真源是 dead_code_ledger.json，
        基线计数只是观察档。合成报告里的 U1000 不在台账 → 阻断，所以凡
        _baseline_rows() 出场的用例都必须挂一份含对应 key 的临时台账，
        否则测的是"台账缺失"而非用例本身想测的事。
        """
        p = self.root / "ledger.json"
        rules = [{"key": k, "file": k.split("::")[0], "symbol": k.split("::")[-1],
                  "auto_class": "synthetic_test", "verdict": "keep",
                  "reason": "self-test synthetic fixture"} for k in keys]
        p.write_text(json.dumps({"rules": rules}, ensure_ascii=False), encoding="utf-8")
        return str(p)

    def test_baseline_report_passes(self):
        report = _write_report(self.root, self._baseline_rows())
        out = _run(report, env_ledger=self._ledger_with(["internal/x/z.go::x"]))
        self.assertEqual(out.returncode, 0, out.stdout + out.stderr)

    def test_new_blocking_finding_is_red(self):
        rows = self._baseline_rows() + [_row("SA4006", "internal/app/new_file.go", 42)]
        report = _write_report(self.root, rows)
        out = _run(report, env_ledger=self._ledger_with(["internal/x/z.go::x"]))
        self.assertEqual(out.returncode, 1, "新增语义类告警必须红")
        self.assertIn("SA4006", out.stderr)

    def test_unregistered_semantic_code_is_red(self):
        """基线里没登记的 SA5xxx = 未知语义类，不许靠"没登记"蒙混过关。"""
        rows = self._baseline_rows() + [_row("SA5001", "internal/app/new.go")]
        report = _write_report(self.root, rows)
        out = _run(report, env_ledger=self._ledger_with(["internal/x/z.go::x"]))
        self.assertEqual(out.returncode, 1, "未登记的语义类 code 必须先裁定归属")
        self.assertIn("SA5001", out.stderr)

    def test_observed_code_drift_warns_but_passes(self):
        rows = self._baseline_rows() + [_row("U1000", "internal/app/another.go")]
        report = _write_report(self.root, rows)
        out = _run(report, env_ledger=self._ledger_with(
            ["internal/x/z.go::x", "internal/app/another.go::x"]))
        self.assertEqual(out.returncode, 0, "死代码新增属观察档，不阻断")
        self.assertIn("观察", out.stdout)

    def test_strict_makes_observed_drift_red(self):
        rows = self._baseline_rows() + [_row("U1000", "internal/app/another.go")]
        report = _write_report(self.root, rows)
        out = _run(report, "--strict", env_ledger=self._ledger_with(
            ["internal/x/z.go::x", "internal/app/another.go::x"]))
        self.assertEqual(out.returncode, 1, "--strict 下观察档变化也应红")

    def test_absolute_paths_are_normalized(self):
        """报告来自服务器（绝对路径）时，必须靠 SCAN_ROOT 归一化才能匹配基线。"""
        abs_root = "/home/user/sm_dev_20261020"
        rows = []
        for code, n in self.baseline["blocking_codes"].items():
            for _ in range(n):
                rows.append(_row(code, f"{abs_root}/internal/x/y.go"))
        for code, n in self.baseline["observed_codes"].items():
            for _ in range(n):
                rows.append(_row(code, f"{abs_root}/internal/x/z.go"))
        report = _write_report(self.root, rows)
        out = _run(report, env_root=abs_root,
                   env_ledger=self._ledger_with(["internal/x/z.go::x"]))
        self.assertEqual(out.returncode, 0, out.stdout + out.stderr)

    def test_msys_converted_root_still_normalizes(self):
        """Git Bash 会把 `/home/user/...` 改写成 `D:/.../PortableGit/home/user/...`，
        导致 env 前缀匹配不上。归一化必须靠"能在仓库里定位到的最长后缀"兜底。"""
        fake_root = "D:/WorkBuddy/resources/vendor/PortableGit/home/user/sm_dev_20261020"
        rows = []
        for code, n in self.baseline["blocking_codes"].items():
            for _ in range(n):
                rows.append(_row(code, f"{fake_root}/internal/x/y.go"))
        for code, n in self.baseline["observed_codes"].items():
            for _ in range(n):
                rows.append(_row(code, f"{fake_root}/internal/x/z.go"))
        # 真实路径（仓库内存在的文件）才能在"最长后缀"兜底里被定位
        rows.append(_row("SA4006", f"{fake_root}/internal/app/tool_error.go"))
        report = _write_report(self.root, rows)
        out = _run(report, env_root=fake_root,
                   env_ledger=self._ledger_with(
                       [f"{fake_root}/internal/x/z.go::x", "internal/x/z.go::x"]))
        # tool_error.go 是基线之外的新增 → 必须红（证明归一化生效、比对真的在跑）
        self.assertEqual(out.returncode, 1, out.stdout + out.stderr)

    def test_bad_lines_are_counted_not_silent(self):
        rows = self._baseline_rows()
        report = _write_report(self.root, rows, garbage="{oops")
        out = _run(report, env_ledger=self._ledger_with(["internal/x/z.go::x"]))
        self.assertEqual(out.returncode, 0, "少量坏行不该让门禁误红")
        self.assertIn("无法解析", out.stdout)


class BaselineHygieneTest(unittest.TestCase):
    """基线自身也要体检：豁免没理由/没复核日期 = 等于没有豁免。"""

    def test_every_exemption_has_reason_and_date(self):
        doc = json.loads(BASELINE.read_text(encoding="utf-8"))
        self.assertTrue(doc["exemptions"], "基线不应为空")
        for e in doc["exemptions"]:
            self.assertTrue(e.get("reason"), f"{e.get('code')} {e.get('file')} 缺理由")
            self.assertTrue(e.get("reviewed_on"), f"{e.get('code')} {e.get('file')} 缺复核日期")

    def test_blocking_codes_are_semantic_only(self):
        doc = json.loads(BASELINE.read_text(encoding="utf-8"))
        for code in doc["blocking_codes"]:
            self.assertTrue(code.startswith(("SA4", "SA5", "SA9", "ST1008")),
                            f"{code} 不是正确性类，不该进阻断档")

    def test_codes_are_not_in_both_buckets(self):
        doc = json.loads(BASELINE.read_text(encoding="utf-8"))
        overlap = set(doc["blocking_codes"]) & set(doc["observed_codes"])
        self.assertFalse(overlap, f"同一 code 不得同时属于两档：{overlap}")


if __name__ == "__main__":
    unittest.main(verbosity=2)
