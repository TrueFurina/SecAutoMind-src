#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""audit_yaml_tool_contracts.py 自测（REA #176 YAML 侧 / #248 门禁自测纪律）

本脚本最容易以两种方式变成"永远绿"：
  1. **扫不到就通过**：目录名写错、环境变量指空，parse 出 0 份 → 摘要全空 → 退出 0；
  2. **判据不咬人**：四维度写成了永远成立的判断（例如把"89% 工具都有
     additional_args"设成硬缺陷，首日全红 → 下一个人就加 --no-verify）。

所以自测必须证明**已知坏样本会红**，并且证明"扫不到"走 exit 2 而不是 exit 0。

运行：python -X utf8 scripts/audit_yaml_tool_contracts_test.py
"""
from __future__ import annotations

import json
import os
import subprocess
import sys
import tempfile
import textwrap
import unittest
from pathlib import Path

HERE = Path(__file__).resolve().parent
SCRIPT = HERE / "audit_yaml_tool_contracts.py"
sys.path.insert(0, str(HERE))

GOOD = """\
name: "{name}"
command: "{name}"
enabled: true
version: "1.0.0"
source: "upstream"
license: "Apache-2.0"
upstream: "https://example.invalid/{name}"
trust: "builtin"
short_description: "说明"
description: |
  多行说明
parameters:
  - name: "target"
    type: "string"
    description: "目标"
    required: true
    flag: "-t"
    format: "flag"
"""

# 追加一个"原样透传"参数（缩进必须与 parameters 列表项一致；首版用 dedent 手拼
# 缩进被吃掉，列表项掉到顶层 → 解析成别的东西，断言当场变红）。
RAW_ARG = (
    '  - name: "additional_args"\n'
    '    type: "string"\n'
    '    description: "额外参数"\n'
    '    required: false\n'
    '    format: "positional"\n'
)


def _write(root: Path, rel: str, body: str) -> None:
    p = root / rel
    p.parent.mkdir(parents=True, exist_ok=True)
    p.write_text(body, encoding="utf-8")


def _run(root: Path, *args: str) -> subprocess.CompletedProcess:
    env = dict(os.environ)
    env["SECAUTOMIND_YAML_TOOL_SCAN_ROOT"] = str(root)
    env["PYTHONIOENCODING"] = "utf-8"
    return subprocess.run([sys.executable, "-X", "utf8", str(SCRIPT), *args],
                          capture_output=True, text=True, encoding="utf-8", env=env)


class FakeRepoCase(unittest.TestCase):
    """构造一个假仓库：1 份好样本 + 各类坏样本，验证判据真的会红。"""

    @classmethod
    def setUpClass(cls):
        cls.tmp = tempfile.TemporaryDirectory()
        root = Path(cls.tmp.name)
        cls.root = root
        _write(root, "tools/good.yaml", GOOD.format(name="goodtool"))
        # 参数缺 type：exec 层只能按字符串处理，约束消失
        _write(root, "tools/no-type.yaml", GOOD.format(name="notype").replace(
            '    type: "string"\n', ""))
        # source=upstream 却没 upstream URL：自述与事实不符
        _write(root, "tools/no-upstream.yaml", GOOD.format(name="noupstream").replace(
            'upstream: "https://example.invalid/noupstream"\n', ""))
        # trust 不在允许集：HITL 档位无从判定
        _write(root, "tools/bad-trust.yaml", GOOD.format(name="badtrust").replace(
            'trust: "builtin"', 'trust: "community"'))
        # 无 parameters
        _write(root, "tools/no-params.yaml", textwrap.dedent("""\
            name: "noparams"
            command: "noparams"
            source: "self"
            trust: "builtin"
            """))
        # 非工具文件：登记在 count_stats 的"计入但非工具"名单里
        _write(root, "tools/_shared_args.yaml", "shared_args:\n  - name: x\n")
        # 非工具文件：既未登记排除、也不像工具 → 口径差值无法解释
        _write(root, "tools/policy.yaml", "policy_version: 1\ndefault_risk: low\n")

    @classmethod
    def tearDownClass(cls):
        cls.tmp.cleanup()

    def test_scan_counts_only_real_tool_declarations(self):
        out = _run(self.root, "--json")
        self.assertEqual(out.returncode, 0, out.stderr)
        s = json.loads(out.stdout)["summary"]
        # 7 份文件里只有 5 份是工具声明（_shared_args / policy 不是）
        self.assertEqual(s["files_total"], 7)
        self.assertEqual(s["declared_tools"], 5)

    def test_each_hard_defect_kind_is_caught(self):
        s = json.loads(_run(self.root, "--json").stdout)["summary"]
        kinds = {(h["tool"], h["kind"]) for h in s["hard_defects"]}
        self.assertIn(("notype", "参数缺 type"), kinds)
        self.assertIn(("noupstream", "source=upstream 但缺 upstream URL"), kinds)
        self.assertIn(("badtrust", "trust 不在允许集"), kinds)
        self.assertIn(("noparams", "缺 parameters"), kinds)

    def test_good_tool_produces_no_defect(self):
        s = json.loads(_run(self.root, "--json").stdout)["summary"]
        self.assertNotIn("goodtool", {h["tool"] for h in s["hard_defects"]})

    def test_gate_fails_on_fresh_defects(self):
        out = _run(self.root, "--gate")
        self.assertEqual(out.returncode, 1, "坏样本必须让门禁变红")
        self.assertIn("[gate] 新增硬缺陷", out.stderr)

    def test_raw_passthrough_is_measured_not_gated(self):
        """89% 命中率的设计不能当缺陷：计量、落档，但不阻断。"""
        _write(self.root, "tools/with-args.yaml", GOOD.format(name="withargs") + RAW_ARG)
        try:
            out = _run(self.root, "--json")
            s = json.loads(out.stdout)["summary"]
            self.assertIn("withargs", s["raw_passthrough_tools"])
            self.assertNotIn("withargs", {h["tool"] for h in s["hard_defects"]})
        finally:
            (self.root / "tools" / "with-args.yaml").unlink()

    def test_budget_is_declared_out_of_scope(self):
        s = json.loads(_run(self.root, "--json").stdout)["summary"]
        self.assertFalse(s["budget_field_present_any"])
        self.assertIn("exec 层", s["budget_out_of_scope_note"])


class FailClosedCase(unittest.TestCase):
    def test_missing_tools_dir_exits_2(self):
        with tempfile.TemporaryDirectory() as d:
            out = _run(Path(d))
            self.assertEqual(out.returncode, 2, "扫描面为空不得当作干净")
            self.assertIn("fail-closed", out.stderr)

    def test_empty_tools_dir_exits_2(self):
        with tempfile.TemporaryDirectory() as d:
            (Path(d) / "tools").mkdir()
            out = _run(Path(d))
            self.assertEqual(out.returncode, 2)
            self.assertIn("一个工具声明都没扫到", out.stderr)

    def test_broken_yaml_blocks_gate(self):
        """解析不了 ≠ 合规：坏文件必须让门禁红，而不是被静默跳过。"""
        with tempfile.TemporaryDirectory() as d:
            root = Path(d)
            _write(root, "tools/good.yaml", GOOD.format(name="goodtool"))
            _write(root, "tools/broken.yaml", "name: [未闭合\n")
            out = _run(root, "--gate")
            self.assertEqual(out.returncode, 1)
            self.assertIn("解析失败", out.stderr)


class ReconcileCase(unittest.TestCase):
    """口径对账的纯函数部分：差值必须能被逐项解释。"""

    def setUp(self):
        import audit_yaml_tool_contracts as m
        self.m = m

    def test_delta_explained_by_registered_nontool(self):
        r = self.m.reconcile_sets(
            all_yaml={"a.yaml", "b.yaml", "_shared_args.yaml"},
            exclude=set(),
            counted_nontool={"_shared_args.yaml"},
            declared_files={"a.yaml", "b.yaml"},
        )
        self.assertEqual(r["delta"], 1)
        self.assertEqual(r["counted_but_not_a_tool"], ["_shared_args.yaml"])
        self.assertEqual(r["unreconciled"], [], "差值已解释 → 不该报不可解释")

    def test_unregistered_nontool_is_unreconciled(self):
        """新增非工具 YAML 却没登记 → 必须现形（这正是 risk_policy 虚报 92 的复现）。"""
        r = self.m.reconcile_sets(
            all_yaml={"a.yaml", "policy.yaml"},
            exclude=set(),
            counted_nontool=set(),
            declared_files={"a.yaml"},
        )
        self.assertEqual(r["unreconciled"], ["policy.yaml"])

    def test_excluded_file_leaves_scope(self):
        r = self.m.reconcile_sets(
            all_yaml={"a.yaml", "risk_policy.yaml"},
            exclude={"risk_policy.yaml"},
            counted_nontool=set(),
            declared_files={"a.yaml"},
        )
        self.assertEqual(r["authoritative_tools_yaml"], 1)
        self.assertEqual(r["delta"], 0)
        self.assertEqual(r["unreconciled"], [])


if __name__ == "__main__":
    unittest.main(verbosity=2)
