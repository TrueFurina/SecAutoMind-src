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


#: T0 名字才能触发门禁，故假仓里必须造真名（取自 T0_TOOLS）
_T0_CONST = '''package builtin

const (
\tToolGetAsset     = "get_asset"
\tToolCreateAsset  = "create_asset"
\tToolCompleteScan = "complete_asset_scan"
)
'''

_T0_NO_SCHEMA = '''package app

func register() {
\tserver.RegisterTool(mcp.Tool{
\t\tName: builtin.ToolGetAsset, Description: "no schema",
\t}, nil)
}
'''

_T0_NO_REQUIRED_EXEMPT = '''package app

func register() {
\tserver.RegisterTool(mcp.Tool{
\t\tName: builtin.ToolCreateAsset, Description: "三选一，故意不声明 required",
\t\tInputSchema: map[string]interface{}{"type": "object", "properties": map[string]interface{}{"host": map[string]interface{}{"type": "string"}}},
\t}, nil)
}
'''

_T0_NO_REQUIRED_UNJUSTIFIED = '''package app

func register() {
\tserver.RegisterTool(mcp.Tool{
\t\tName: builtin.ToolCompleteScan, Description: "有必填却没声明",
\t\tInputSchema: map[string]interface{}{"type": "object", "properties": map[string]interface{}{"scan_id": map[string]interface{}{"type": "string"}}},
\t}, nil)
}
'''


class GateTest(unittest.TestCase):
    """门禁判据本身也要能被判错（REA #248）。

    2026-10-20 实测：初版判据「T0 缺 required = 硬缺陷」一上线就把 4 个**故意**
    不声明 required 的工具判红（create_asset 的三选一约束 Bedrock 表达不了、
    另三个是纯可选筛选的列表工具）。修法是给豁免登记理由+复核日期，而不是删掉
    判据——删了它就再也发现不了"有必填却没声明"。下面三测钉住这个分档。
    """

    def _root_with(self, tools_go: str) -> Path:
        root = Path(tempfile.mkdtemp())
        (root / "internal" / "mcp" / "builtin").mkdir(parents=True)
        (root / "internal" / "app").mkdir(parents=True)
        (root / "internal" / "mcp" / "builtin" / "constants.go").write_text(
            _T0_CONST, encoding="utf-8")
        (root / "internal" / "app" / "tools.go").write_text(tools_go, encoding="utf-8")

        def cleanup():
            for p in sorted(root.rglob("*"), reverse=True):
                p.unlink() if p.is_file() else p.rmdir()
            root.rmdir()
        self.addCleanup(cleanup)
        return root

    def _run_gate(self, root: Path) -> subprocess.CompletedProcess:
        env = dict(os.environ, SECAUTOMIND_TOOL_SCAN_ROOT=str(root),
                   PYTHONIOENCODING="utf-8")
        return subprocess.run([sys.executable, "-X", "utf8", str(SCRIPT), "--gate"],
                              capture_output=True, text=True, env=env, timeout=120)

    def test_gate_blocks_t0_missing_schema(self):
        out = self._run_gate(self._root_with(_T0_NO_SCHEMA))
        self.assertEqual(out.returncode, 1, "T0 缺 InputSchema 必须红")
        self.assertIn("缺 InputSchema", out.stderr)

    def test_gate_allows_registered_no_required(self):
        """已登记理由与复核日期的"故意不声明"放行（否则门禁首日全红，下场必是 --no-verify）。"""
        out = self._run_gate(self._root_with(_T0_NO_REQUIRED_EXEMPT))
        self.assertEqual(out.returncode, 0, out.stderr)

    def test_gate_blocks_unregistered_no_required(self):
        """没登记理由的缺 required 仍要红——判据不能因为放宽而失效。"""
        out = self._run_gate(self._root_with(_T0_NO_REQUIRED_UNJUSTIFIED))
        self.assertEqual(out.returncode, 1, "未登记豁免的缺 required 必须红")
        self.assertIn("未登记豁免理由", out.stderr)

    def test_every_exemption_carries_reason_and_date(self):
        """豁免表自身也得体检：无理由/无复核日期的条目等同"没有豁免"。"""
        sys.path.insert(0, str(HERE))
        import audit_tool_contracts as m
        self.assertTrue(m.NO_REQUIRED_EXEMPT, "豁免表为空说明判据又被放宽成无条件放行")
        for name, meta in m.NO_REQUIRED_EXEMPT.items():
            self.assertTrue(meta.get("reason"), f"{name} 豁免缺理由")
            self.assertTrue(meta.get("reviewed_on"), f"{name} 豁免缺复核日期")


if __name__ == "__main__":
    unittest.main(verbosity=2)
