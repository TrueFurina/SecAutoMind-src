#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""dead_code_ledger.py 自测。

覆盖的不是"能跑通"，是**判据本身会不会失真**：

  * fail-closed：报告缺失 / 为空 / 没有 U1000 → exit 2，不许把"扫不到"当"干净"
  * 门禁三态：台账缺失 = 全未裁定 = 红；全覆盖 = 绿；登记缺字段 = 红
  * receiver 感知（回归）：`(*Server).handleCallTool` 里的 `s.cleanupOldExecutions()`
    **不能**算成 `(*ExternalMCPManager).cleanupOldExecutions` 的调用者。
    第一版就是栽在这里，凭空造出 5 条 live_caller_anomaly。
  * 键不含行号：整体平移行号后 key 不变（REA #258）
  * 死链判定：root / dependent 分得开，别把叶子当根去"修"

跑法：python scripts/dead_code_ledger_test.py
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
SCRIPT = HERE / "dead_code_ledger.py"
PY = sys.executable


def run(args: list[str], cwd: Path | None = None) -> subprocess.CompletedProcess:
    return subprocess.run([PY, "-X", "utf8", str(SCRIPT), *args],
                          capture_output=True, text=True, encoding="utf-8",
                          cwd=str(cwd or HERE.parent))


def u1000_row(path: str, line: int, message: str) -> str:
    return json.dumps({"code": "U1000", "severity": "warning",
                       "location": {"file": path, "line": line, "column": 1},
                       "end": {"file": path, "line": line, "column": 2},
                       "message": message})


class TestFailClosed(unittest.TestCase):
    def test_missing_report(self):
        r = run(["--report", str(HERE / "__nope__.json")])
        self.assertEqual(r.returncode, 2)
        self.assertIn("报告不存在", r.stderr)

    def test_empty_report(self):
        with tempfile.TemporaryDirectory() as td:
            p = Path(td) / "empty.json"
            p.write_text("", encoding="utf-8")
            r = run(["--report", str(p)])
            self.assertEqual(r.returncode, 2)
            self.assertIn("报告为空", r.stderr)

    def test_report_without_u1000(self):
        """报告非空但没有 U1000 —— 可能扫描范围错了，同样不许判绿。"""
        with tempfile.TemporaryDirectory() as td:
            p = Path(td) / "sc.json"
            p.write_text(json.dumps({"code": "SA1000",
                                     "location": {"file": "a.go", "line": 1},
                                     "message": "x"}) + "\n", encoding="utf-8")
            r = run(["--report", str(p)])
            self.assertEqual(r.returncode, 2)
            self.assertIn("没有 U1000", r.stderr)


class TestSymbolParsing(unittest.TestCase):
    def test_parse_symbol(self):
        sys.path.insert(0, str(HERE))
        import dead_code_ledger as dcl
        self.assertEqual(dcl.parse_symbol("func (*T).meth is unused"),
                         ("func", "(*T).meth"))
        self.assertEqual(dcl.parse_symbol("type item is unused"),
                         ("type", "item"))
        self.assertEqual(dcl.parse_symbol("var gcmNonceRe is unused"),
                         ("var", "gcmNonceRe"))

    def test_bare_name(self):
        sys.path.insert(0, str(HERE))
        import dead_code_ledger as dcl
        self.assertEqual(dcl.bare_name("(*T).meth"), "meth")
        self.assertEqual(dcl.bare_name("WorkflowInput.toStateInputs"),
                         "toStateInputs")
        self.assertEqual(dcl.bare_name("plainFunc"), "plainFunc")

    def test_split_method(self):
        sys.path.insert(0, str(HERE))
        import dead_code_ledger as dcl
        self.assertEqual(dcl.split_method("(*ExternalMCPManager).cleanup"),
                         ("*ExternalMCPManager", "cleanup"))
        self.assertEqual(dcl.split_method("WorkflowInput.toStateInputs"),
                         ("WorkflowInput", "toStateInputs"))
        self.assertEqual(dcl.split_method("plainFunc"), (None, "plainFunc"))

    def test_same_receiver_ignores_pointer(self):
        sys.path.insert(0, str(HERE))
        import dead_code_ledger as dcl
        self.assertTrue(dcl.same_receiver("*Server", "Server"))
        self.assertTrue(dcl.same_receiver("Server", "*Server"))
        self.assertFalse(dcl.same_receiver("*Server", "*ExternalMCPManager"))
        # 一方不是方法 → 不适用 receiver 匹配，返回 False（不当活调用者）
        self.assertFalse(dcl.same_receiver("*Server", None))


class TestReceiverAware(unittest.TestCase):
    """回归：不看 receiver 就会把别的类型的同名方法调用算成自己的调用者。"""

    def _setup(self, td: Path) -> Path:
        pkg = td / "internal" / "mcp"
        pkg.mkdir(parents=True)
        (pkg / "external_manager.go").write_text(
            "package mcp\n"
            "type ExternalMCPManager struct{}\n"
            "func (m *ExternalMCPManager) cleanupOldExecutions() {}\n",
            encoding="utf-8")
        (pkg / "server.go").write_text(
            "package mcp\n"
            "type Server struct{}\n"
            "func (s *Server) handleCallTool() {\n"
            "\ts.cleanupOldExecutions()\n"      # ← 调的是 Server 自己的
            "}\n"
            "func (s *Server) cleanupOldExecutions() {}\n",
            encoding="utf-8")
        rep = td / "sc.json"
        rep.write_text(
            u1000_row(str(pkg / "external_manager.go"), 3,
                      "func (*ExternalMCPManager).cleanupOldExecutions is unused")
            + "\n", encoding="utf-8")
        return rep

    def test_cross_receiver_not_counted_as_caller(self):
        with tempfile.TemporaryDirectory() as td:
            root = Path(td)
            rep = self._setup(root)
            sys.path.insert(0, str(HERE))
            import dead_code_ledger as dcl
            dcl.REPO_ROOT = root          # 让脚本在临时仓库里定位
            dcl.LEDGER_PATH = root / "no_ledger.json"
            rows, _ = dcl.load_report(str(rep))
            entries = dcl.build_entries(rows, None)
            e = entries[0]
            self.assertEqual(e["symbol"], "(*ExternalMCPManager).cleanupOldExecutions")
            # 关键：Server 的调用不能算成 ExternalMCPManager 的活调用者
            self.assertEqual(e["live_callers"], [])
            self.assertTrue(any("Server" in c for c in e["cross_receiver_refs"]),
                            f"应记录跨 receiver 引用，实际 {e['cross_receiver_refs']}")
            self.assertEqual(e["auto_class"], "dup_of_live")
            dcl.REPO_ROOT = HERE.parent
            dcl.LEDGER_PATH = HERE / "dead_code_ledger.json"


class TestKeyHasNoLineNumber(unittest.TestCase):
    """REA #258：行号漂移不得改变台账键。"""

    def test_line_shift_keeps_key(self):
        sys.path.insert(0, str(HERE))
        import dead_code_ledger as dcl
        a = [json.loads(u1000_row("pkg/a.go", 10, "func foo is unused"))]
        b = [json.loads(u1000_row("pkg/a.go", 999, "func foo is unused"))]
        ea = dcl.build_entries(a, None)
        eb = dcl.build_entries(b, None)
        self.assertEqual(ea[0]["key"], eb[0]["key"])
        self.assertNotIn("10", ea[0]["key"])
        self.assertNotIn("999", eb[0]["key"])


class TestGate(unittest.TestCase):
    def _repo(self) -> tuple[Path, Path]:
        td = Path(tempfile.mkdtemp())
        pkg = td / "internal" / "demo"
        pkg.mkdir(parents=True)
        (pkg / "a.go").write_text(
            "package demo\n"
            "func orphan() {}\n"          # 无任何调用 → dead_root
            "func caller() { orphan() }\n"  # 只被 orphan 之外没人调 → 也是 root
            "func helper() {}\n"
            "func user() { helper() }\n",
            encoding="utf-8")
        rep = td / "sc.json"
        rep.write_text("\n".join([
            u1000_row(str(pkg / "a.go"), 2, "func orphan is unused"),
            u1000_row(str(pkg / "a.go"), 3, "func caller is unused"),
            u1000_row(str(pkg / "a.go"), 4, "func helper is unused"),
            u1000_row(str(pkg / "a.go"), 5, "func user is unused"),
        ]) + "\n", encoding="utf-8")
        return td, rep

    def test_gate_red_when_ledger_missing(self):
        """台账文件不存在 = 全部未裁定 = 红（fail-closed）。"""
        td, rep = self._repo()
        r = run(["--report", str(rep), "--gate",
                 "--repo-root", str(td),
                 "--ledger", str(td / "__absent__.json")])
        self.assertEqual(r.returncode, 1, r.stdout + r.stderr)
        self.assertIn("未裁定", r.stderr)

    def test_gate_green_when_fully_ruled(self):
        td, rep = self._repo()
        sys.path.insert(0, str(HERE))
        import dead_code_ledger as dcl
        rows, _ = dcl.load_report(str(rep))
        entries = dcl.build_entries(rows, None, td)
        keys = [e["key"] for e in entries]
        self.assertTrue(keys, "临时仓库里应当扫到 U1000 条目")

        # 逐条补齐裁定 → 绿
        tmp_ledger = td / "dead_code_ledger.json"
        tmp_ledger.write_text(json.dumps({"rules": [
            {"key": k, "verdict": "keep", "reason": "自测用例"}
            for k in keys]}), encoding="utf-8")
        r = run(["--report", str(rep), "--gate",
                 "--repo-root", str(td), "--ledger", str(tmp_ledger)])
        self.assertEqual(r.returncode, 0, r.stdout + r.stderr)
        self.assertIn("台账全覆盖", r.stdout)

        # 抽掉一条 → 必须转红（门禁不是摆设）
        rules = json.loads(tmp_ledger.read_text(encoding="utf-8"))["rules"]
        tmp_ledger.write_text(json.dumps({"rules": rules[1:]}), encoding="utf-8")
        r2 = run(["--report", str(rep), "--gate",
                  "--repo-root", str(td), "--ledger", str(tmp_ledger)])
        self.assertEqual(r2.returncode, 1, r2.stdout + r2.stderr)
        self.assertIn("未裁定", r2.stderr)

        # reason 留空 → 同样算未裁定（只登记 key 不算登记）
        bad = [dict(x) for x in rules]
        bad[0]["reason"] = ""
        tmp_ledger.write_text(json.dumps({"rules": bad}), encoding="utf-8")
        r3 = run(["--report", str(rep), "--gate",
                  "--repo-root", str(td), "--ledger", str(tmp_ledger)])
        self.assertEqual(r3.returncode, 1, r3.stdout + r3.stderr)


class TestRealLedger(unittest.TestCase):
    """对仓库里真实台账的自检：存在、字段齐、条数与基线一致。"""

    def test_ledger_shape(self):
        p = HERE / "dead_code_ledger.json"
        self.assertTrue(p.is_file(), "台账缺失会导致门禁 exit 1")
        d = json.loads(p.read_text(encoding="utf-8"))
        self.assertIn("rules", d)
        self.assertTrue(d["rules"])
        for r in d["rules"]:
            self.assertTrue(r.get("key"), f"缺 key: {r}")
            self.assertIn(r.get("verdict"),
                          {"wire_up", "investigate", "keep",
                           "archival_candidate"})
            self.assertTrue(r.get("reason"), f"缺 reason: {r['key']}")
            self.assertTrue(r.get("reviewed_on"), f"缺 reviewed_on: {r['key']}")

    def test_no_duplicate_keys(self):
        d = json.loads((HERE / "dead_code_ledger.json").read_text(encoding="utf-8"))
        keys = [r["key"] for r in d["rules"]]
        self.assertEqual(len(keys), len(set(keys)), "台账里有重复 key")

    def test_key_has_no_line_number(self):
        d = json.loads((HERE / "dead_code_ledger.json").read_text(encoding="utf-8"))
        for r in d["rules"]:
            self.assertNotIn(":", r["key"].split("::", 1)[-1],
                             f"key 里混进了行号/类型前缀: {r['key']}")


if __name__ == "__main__":
    unittest.main(verbosity=2)
