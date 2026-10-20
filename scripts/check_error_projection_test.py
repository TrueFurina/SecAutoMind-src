#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""check_error_projection.py 自测（REA #248：门禁自测必须含"已知坏样本必须红"）

一个只看"有没有新增"的守卫，最容易以两种方式失效：
  1. **扫描面空了**：internal/ 目录改名或被排除 → 0 命中 → 全绿；
  2. **判据太宽/太窄**：把注释里的反例、把 `toolInternalError(logger, scene, err)`
     也算成直出 → 首日满屏红 → 下一个人加 `--no-verify`。

本文件两头都钉：空扫描走 exit 2；真新增必须红；注释与已收敛写法不得误报。

运行：python -X utf8 scripts/check_error_projection_test.py
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
SCRIPT = HERE / "check_error_projection.py"

#: 与真实基线里完全一致的一行（入参校验，允许直出）
BASELINE_LINE = '		return textResult("错误: "+err.Error(), true), nil'


def _repo(root: Path, body: str, rel: str = "internal/app/x_tools.go") -> Path:
    p = root / rel
    p.parent.mkdir(parents=True, exist_ok=True)
    p.write_text(body, encoding="utf-8")
    return root


def _run(root: Path, *args: str) -> subprocess.CompletedProcess:
    env = dict(os.environ, SECAUTOMIND_ERROR_SCAN_ROOT=str(root),
               PYTHONIOENCODING="utf-8")
    return subprocess.run([sys.executable, "-X", "utf8", str(SCRIPT), *args],
                           capture_output=True, text=True, encoding="utf-8", env=env)


class ScanCase(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.root = Path(self.tmp.name)
        self.addCleanup(self.tmp.cleanup)

    def test_empty_scan_is_fail_closed(self):
        """目录存在但无 Go 文件 → 0 命中，但那不是"干净"，是守卫瞎了。"""
        (self.root / "internal").mkdir()
        out = _run(self.root)
        self.assertEqual(out.returncode, 2, "扫描面为空不得当作干净")
        self.assertIn("fail-closed", out.stderr)

    def test_missing_internal_exits_2(self):
        out = _run(self.root)
        self.assertEqual(out.returncode, 2)
        self.assertIn("扫描面为空", out.stderr)

    def test_new_direct_leak_is_red(self):
        _repo(self.root, "package app\n\nfunc f() {\n" + BASELINE_LINE + "\n}\n")
        out = _run(self.root, "--gate")
        self.assertEqual(out.returncode, 1, "新增直出必须让门禁变红")
        self.assertIn("新增", out.stderr)

    def test_comment_example_is_not_a_hit(self):
        """注释里引用反例写法是文档，不是会执行的代码。"""
        _repo(self.root, "package app\n\n// 反例：textResult(\"错误: \"+err.Error(), true)\n"
                         "func f() {}\n")
        out = _run(self.root, "--json")
        self.assertEqual(out.returncode, 0, out.stderr)
        self.assertEqual(json.loads(out.stdout)["hits"], [])

    def test_converged_call_is_not_a_hit(self):
        """已收敛到 toolInternalError 的调用不该再算直出。"""
        body = ('package app\n\nfunc f() {\n'
                '\tif err != nil {\n'
                '\t\treturn toolInternalError(logger, "保存失败（已记日志）", err), nil\n'
                '\t}\n}\n')
        _repo(self.root, body)
        out = _run(self.root, "--json")
        self.assertEqual(out.returncode, 0, out.stderr)
        self.assertEqual(json.loads(out.stdout)["hits"], [])


class ClassifyCase(unittest.TestCase):
    """分类逻辑（基线内 / 新增 / 失效）不依赖文件系统，直接单测。"""

    def setUp(self):
        sys.path.insert(0, str(HERE))
        import check_error_projection as cep
        self.cep = cep

    def test_known_and_fresh_are_separated(self):
        self.cep.load_baseline = lambda: {"entries": [
            {"file": "a.go", "text": "knownLine", "reason": "x", "reviewed_on": "2026-10-21"}]}
        res = self.cep.classify([
            {"file": "a.go", "line": 1, "text": "knownLine"},
            {"file": "a.go", "line": 2, "text": "brandNewLine"},
        ])
        self.assertEqual(len(res["known"]), 1)
        self.assertEqual(len(res["fresh"]), 1)
        self.assertEqual(res["fresh"][0]["text"], "brandNewLine")

    def test_stale_entry_is_reported(self):
        """基线里登记过、现在代码里找不到了 —— 通常意味着那段代码被改写，要清理。"""
        self.cep.load_baseline = lambda: {"entries": [
            {"file": "a.go", "text": "goneLine", "reason": "x", "reviewed_on": "2026-10-21"}]}
        res = self.cep.classify([{"file": "a.go", "line": 1, "text": "otherLine"}])
        self.assertEqual(len(res["stale"]), 1)
        self.assertEqual(res["stale"][0]["text"], "goneLine")

    def test_real_baseline_entries_carry_reason_and_date(self):
        """豁免表自身也得体检：无理由/无复核日期 = 没有豁免（#169）。"""
        doc = json.loads((HERE / "error_projection_baseline.json").read_text(encoding="utf-8"))
        self.assertTrue(doc["entries"], "基线为空说明判据又被放宽成无条件放行")
        for e in doc["entries"]:
            self.assertTrue(e.get("reason") and "待裁定" not in e["reason"],
                            f"{e['file']} 基线条目缺实质理由")
            self.assertTrue(e.get("reviewed_on"), f"{e['file']} 基线条目缺复核日期")
            self.assertEqual(e.get("kind", ""), "入参校验（err 由本项目校验函数产生）")


if __name__ == "__main__":
    unittest.main(verbosity=2)
