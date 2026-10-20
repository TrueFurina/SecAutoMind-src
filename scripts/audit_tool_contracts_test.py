#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""audit_tool_contracts.py 自测（REA #176：抽样器本身也要能被判对错）

抽样脚本最危险的失效是"扫到 0 个工具却报干净"——本仓就踩过：
早期版本只认 `Name: "literal"`，而真实注册多用 `Name: builtin.ToolX` 常量，
结果 52 个工具只扫到 8 个，还把 4 个真工具判成"缺 schema"。

本文件用**构造的假仓库**（环境变量 `SECAUTOMIND_TOOL_SCAN_ROOT` 指过去）钉住：
  1. 常量引用能解析成工具名（不能只认字面量）
  2. 缺 InputSchema / 缺 required 能被识别
  3. 结果里拼 err.Error() 能被识别
  4. 一个工具都扫不到 → 退出码 2（fail-closed，不许静默全绿）
  5. --gate 对 T0 硬缺陷（缺 schema/required）退出 1

运行：python -X utf8 scripts/audit_tool_contracts_test.py
"""
from __future__ import annotations

import os
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path

HERE = Path(__file__).resolve().parent
SCRIPT = HERE / "audit_tool_contracts.py"

_CONST_GO = '''package builtin

const (
	ToolGoodTool = "good_tool"
	ToolBadTool  = "bad_tool"
)
'''

_TOOLS_GO = '''package app

func register() {
	server.RegisterTool(mcp.Tool{
		Name: builtin.ToolGoodTool,
		ShortDescription: "ok",
		Description:      "good one",
		InputSchema: map[string]interface{}{"type": "object", "properties": map[string]interface{}{"id": map[string]interface{}{"type": "string"}}, "required": []string{"id"}},
	}, func(ctx context.Context, args map[string]interface{}) (*mcp.ToolResult, error) {
		if err := db.Get(); err != nil {
			return textResult("错误: "+err.Error(), true), nil
		}
		return textResult("ok", false), nil
	})

	server.RegisterTool(mcp.Tool{
		Name:             builtin.ToolBadTool,
		ShortDescription: "bad",
		Description:      "no schema at all",
	}, func(ctx context.Context, args map[string]interface{}) (*mcp.ToolResult, error) {
		return textResult("done", false), nil
	})
}
'''


class AuditToolContractsTest(unittest.TestCase):
    def setUp(self):
        self.root = Path(tempfile.mkdtemp())
        (self.root / "internal" / "mcp" / "builtin").mkdir(parents=True)
        (self.root / "internal" / "app").mkdir(parents=True)
        (self.root / "internal" / "mcp" / "builtin" / "constants.go").write_text(
            _CONST_GO, encoding="utf-8")
        (self.root / "internal" / "app" / "tools.go").write_text(
            _TOOLS_GO, encoding="utf-8")
        self.addCleanup(self._cleanup)

    def _cleanup(self):
        for p in sorted(self.root.rglob("*"), reverse=True):
            p.unlink() if p.is_file() else p.rmdir()
        self.root.rmdir()

    def _run(self, *args: str) -> subprocess.CompletedProcess:
        env = dict(os.environ, SECAUTOMIND_TOOL_SCAN_ROOT=str(self.root),
                   PYTHONIOENCODING="utf-8")
        return subprocess.run([sys.executable, "-X", "utf8", str(SCRIPT), *args],
                              capture_output=True, text=True, env=env, timeout=120)

    def test_constant_names_are_resolved(self):
        out = self._run("--json")
        self.assertEqual(out.returncode, 0, out.stderr)
        self.assertIn("good_tool", out.stdout, "常量引用必须能解析成工具名")
        self.assertIn("bad_tool", out.stdout)

    def test_missing_schema_and_error_leak_detected(self):
        out = self._run("--json")
        import json
        summary = json.loads(out.stdout)["summary"]
        self.assertEqual(summary["no_input_schema"], ["bad_tool"],
                         "缺 InputSchema 必须被识别，且只列 bad_tool")
        self.assertEqual(summary["raw_err_error_in_result"], ["good_tool"],
                         "拼 err.Error() 必须被识别")
        self.assertEqual(summary["no_iserror_path"], ["bad_tool"])

    def test_empty_scan_is_fail_closed(self):
        empty = Path(tempfile.mkdtemp())
        self.addCleanup(empty.rmdir)
        env = dict(os.environ, SECAUTOMIND_TOOL_SCAN_ROOT=str(empty))
        out = subprocess.run([sys.executable, "-X", "utf8", str(SCRIPT)],
                             capture_output=True, text=True, env=env, timeout=120)
        self.assertEqual(out.returncode, 2, "扫到 0 个工具不得当作干净")


if __name__ == "__main__":
    unittest.main(verbosity=2)
