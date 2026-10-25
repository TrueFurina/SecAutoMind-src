#!/usr/bin/env python
# -*- coding: utf-8 -*-
"""race_preflight 自测 + 变异验证。

门禁三铁律：① 自身有回归测试 ② 关键判据必须有变异验证（注入错误必须变红）
③ 取不到真值 fail-closed。本文件覆盖 docker_path / dep_versions / skills_parity
三条新增判据的"变红"能力——否则"预检通过"只是恒绿的假安全感。

用法：python scripts/race_preflight_test.py
"""
from __future__ import annotations

import importlib.util
import json
import os
import subprocess
import sys
import tempfile
import time
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
SCRIPTS = ROOT / "scripts"


def _load():
    spec = importlib.util.spec_from_file_location(
        "race_preflight", SCRIPTS / "race_preflight.py")
    m = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(m)
    return m


def _load_sync():
    spec = importlib.util.spec_from_file_location(
        "sync_ctf_agent_skills", SCRIPTS / "sync_ctf_agent_skills.py")
    m = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(m)
    return m


def _verdicts(pf) -> dict:
    return {r["check"]: r["verdict"] for r in pf._results}


class TestDockerPath(unittest.TestCase):
    """事故 #19：交接卡里抄来的 docker 路径根本不存在 → 必须 FAIL。"""

    def test_nonexistent_path_is_fail(self):
        pf = _load()
        pf._results.clear()
        old = os.environ.get("CTF_DOCKER_PATH")
        os.environ["CTF_DOCKER_PATH"] = r"C:\no\such\docker.exe"
        try:
            pf.check_docker_path()
            self.assertEqual(_verdicts(pf).get("docker_path"), "FAIL")
        finally:
            os.environ.pop("CTF_DOCKER_PATH", None)
            if old:
                os.environ["CTF_DOCKER_PATH"] = old

    def test_existing_file_is_pass(self):
        pf = _load()
        pf._results.clear()
        with tempfile.NamedTemporaryFile(suffix=".exe", delete=False) as f:
            p = f.name
        os.environ["CTF_DOCKER_PATH"] = p
        try:
            pf.check_docker_path()
            self.assertEqual(_verdicts(pf).get("docker_path"), "PASS")
        finally:
            os.environ.pop("CTF_DOCKER_PATH", None)
            os.unlink(p)

    def test_unset_falls_back_to_which(self):
        pf = _load()
        pf._results.clear()
        os.environ.pop("CTF_DOCKER_PATH", None)
        pf.check_docker_path()
        self.assertIn(_verdicts(pf).get("docker_path"), ("PASS", "FAIL"))


class TestDepVersions(unittest.TestCase):
    """事故 #19：依赖版本漂移（otel 1.32→1.45）必须被抓到。"""

    def test_drift_is_fail(self):
        pf = _load()
        pf._results.clear()
        real = {"opentelemetry-api": "1.33.1", "logfire": "5.3.0"}
        baseline = {"opentelemetry-api": "1.45.0", "logfire": "5.3.0"}

        pf._installed_versions = lambda py: (real, "")
        with tempfile.TemporaryDirectory() as td:
            pf.DEP_BASELINE = Path(td) / "dep_baseline.json"
            pf.DEP_BASELINE.write_text(json.dumps(baseline), encoding="utf-8")
            pf.check_dep_versions(sys.executable)
            v = _verdicts(pf).get("dep_versions")
            self.assertEqual(v, "FAIL", "版本漂移必须变红")

    def test_consistent_is_pass(self):
        pf = _load()
        pf._results.clear()
        real = {"opentelemetry-api": "1.33.1", "logfire": "5.3.0"}
        pf._installed_versions = lambda py: (real, "")
        with tempfile.TemporaryDirectory() as td:
            pf.DEP_BASELINE = Path(td) / "dep_baseline.json"
            pf.DEP_BASELINE.write_text(json.dumps(real), encoding="utf-8")
            pf.check_dep_versions(sys.executable)
            self.assertEqual(_verdicts(pf).get("dep_versions"), "PASS")

    def test_no_interpreter_is_fail(self):
        pf = _load()
        pf._results.clear()
        pf.check_dep_versions(None)
        self.assertEqual(_verdicts(pf).get("dep_versions"), "FAIL")

    def test_baseline_missing_warns_not_pass(self):
        """没有基线不能假装通过（fail-closed 精神：WARN 而非 PASS）。"""
        pf = _load()
        pf._results.clear()
        pf._installed_versions = lambda py: ({"httpx": "0.28.1"}, "")
        with tempfile.TemporaryDirectory() as td:
            pf.DEP_BASELINE = Path(td) / "nope.json"
            pf.check_dep_versions(sys.executable)
            self.assertEqual(_verdicts(pf).get("dep_versions"), "WARN")


class TestSkillsParity(unittest.TestCase):
    """双写一致性：只放一边 = 赛时引擎看不到新 skill。"""

    def test_diff_detects_missing_and_changed(self):
        sync = _load_sync()
        with tempfile.TemporaryDirectory() as td:
            src = Path(td) / "src"
            dst = Path(td) / "dst"
            src.mkdir()
            dst.mkdir()
            (src / "a.py").write_text("x = 1\n", encoding="utf-8")
            (src / "b.py").write_text("y = 2\n", encoding="utf-8")
            (dst / "a.py").write_text("x = 1\n", encoding="utf-8")
            (dst / "b.py").write_text("y = 999\n", encoding="utf-8")
            st = sync.diff_state(sync.collect(src), sync.collect(dst))
            self.assertFalse(st["in_sync"])
            self.assertEqual(st["only_in_src"], [])
            self.assertEqual(st["changed"], ["b.py"])

    def test_diff_detects_only_in_src(self):
        sync = _load_sync()
        with tempfile.TemporaryDirectory() as td:
            src = Path(td) / "src"
            dst = Path(td) / "dst"
            src.mkdir()
            dst.mkdir()
            (src / "new_skill.py").write_text("z\n", encoding="utf-8")
            st = sync.diff_state(sync.collect(src), sync.collect(dst))
            self.assertEqual(st["only_in_src"], ["new_skill.py"])

    def test_identical_is_in_sync(self):
        sync = _load_sync()
        with tempfile.TemporaryDirectory() as td:
            src = Path(td) / "src"
            dst = Path(td) / "dst"
            src.mkdir()
            dst.mkdir()
            (src / "a.py").write_text("same\n", encoding="utf-8")
            (dst / "a.py").write_text("same\n", encoding="utf-8")
            st = sync.diff_state(sync.collect(src), sync.collect(dst))
            self.assertTrue(st["in_sync"])

    def test_check_mode_exit_codes(self):
        """sync --check：一致 rc=0，缺文件 rc=1。"""
        script = SCRIPTS / "sync_ctf_agent_skills.py"
        with tempfile.TemporaryDirectory() as td:
            dst = Path(td) / "empty_dst"
            dst.mkdir()
            r = subprocess.run([sys.executable, str(script), "--check",
                                "--dst", str(dst)], capture_output=True, text=True,
                               timeout=120)
            self.assertEqual(r.returncode, 1,
                             "真值源有文件而目标为空时 --check 必须 rc=1")

    def test_dst_absent_skips_not_false_red(self):
        """CI/换机上目标目录不存在 = 环境不适用，必须 SKIP(rc=0)，不可假红。"""
        script = SCRIPTS / "sync_ctf_agent_skills.py"
        with tempfile.TemporaryDirectory() as td:
            r = subprocess.run([sys.executable, str(script), "--check",
                                "--dst", str(Path(td) / "nope")],
                               capture_output=True, text=True, timeout=120)
            self.assertEqual(r.returncode, 0, "目标目录不存在时 CI 上不得假红")

    def test_require_dst_makes_absent_fail(self):
        """赛前本机严格模式：目标目录不存在必须 FAIL（fail-closed）。"""
        script = SCRIPTS / "sync_ctf_agent_skills.py"
        with tempfile.TemporaryDirectory() as td:
            r = subprocess.run([sys.executable, str(script), "--check", "--require-dst",
                                "--dst", str(Path(td) / "nope")],
                               capture_output=True, text=True, timeout=120)
            self.assertEqual(r.returncode, 1, "--require-dst 下目标缺失必须 rc=1")


class TestEngineWatch(unittest.TestCase):
    """事故 #19：引擎守护被关掉 / 心跳停滞，必须能被机器抓到（且不能恒红）。"""

    def _run_check(self, root: Path):
        """在伪造的引擎根目录下跑 check_engine_watch，返回 (verdict, detail)。"""
        pf = _load()
        pf._results.clear()
        pf.check_engine_watch(root)
        r = pf._results[-1]
        return r["verdict"], r["detail"]

    def test_nowatch_log_is_fail(self):
        """1024 事故现场：runner_watch.log 末尾写着「未启用看护」→ 必须 FAIL。"""
        with tempfile.TemporaryDirectory() as td:
            root = Path(td) / "engine"
            (root / "logs").mkdir(parents=True)
            (root / "logs" / "runner_watch.log").write_text(
                "[22:30:14] 启动前清理了 1 个旧 runner\n"
                "[22:30:18] 未启用看护（-NoWatch），本脚本退出，runner 继续在后台跑\n",
                encoding="utf-8")
            v, d = self._run_check(root)
            self.assertEqual(v, "FAIL", d)
            self.assertIn("NoWatch", d)

    def test_watch_disabled_heartbeat_is_fail(self):
        """显式 --no-watch 会在心跳里写 WATCH_DISABLED，等同无人值守 → FAIL。"""
        with tempfile.TemporaryDirectory() as td:
            root = Path(td) / "engine"
            (root / "logs").mkdir(parents=True)
            (root / "logs" / "engine_watchdog.log").write_text(
                "[00:00:00] WATCH_DISABLED engine 显式关闭守护\n", encoding="utf-8")
            v, d = self._run_check(root)
            self.assertEqual(v, "FAIL", d)
            self.assertIn("WATCH_DISABLED", d)

    def test_fresh_heartbeat_is_pass(self):
        """负例：守护在跑且心跳新鲜 → PASS（证明判据不是恒红）。"""
        with tempfile.TemporaryDirectory() as td:
            root = Path(td) / "engine"
            (root / "logs").mkdir(parents=True)
            (root / "logs" / "engine_watchdog.log").write_text(
                "[00:00:00] HB engine pid=123 uptime=9s restarts=0/8\n",
                encoding="utf-8")
            v, d = self._run_check(root)
            self.assertEqual(v, "PASS", d)

    def test_stale_heartbeat_is_fail(self):
        """心跳停滞（守护自己死了）→ FAIL，这正是「静默退出无人发现」。"""
        with tempfile.TemporaryDirectory() as td:
            root = Path(td) / "engine"
            (root / "logs").mkdir(parents=True)
            hb = root / "logs" / "engine_watchdog.log"
            hb.write_text("[00:00:00] HB engine pid=123\n", encoding="utf-8")
            old = time.time() - 600
            os.utime(hb, (old, old))
            v, d = self._run_check(root)
            self.assertEqual(v, "FAIL", d)
            self.assertIn("停滞", d)

    def test_no_heartbeat_warns_not_fail(self):
        """无心跳 → WARN 不阻断（赛前还没起引擎属正常），但不能假装 PASS。"""
        with tempfile.TemporaryDirectory() as td:
            root = Path(td) / "engine"
            root.mkdir(parents=True)
            v, d = self._run_check(root)
            self.assertEqual(v, "WARN", d)

    def test_engine_dir_absent_skips(self):
        """CI 上没有引擎目录 → SKIP，不得假红（与 skills_parity 同纪律）。"""
        with tempfile.TemporaryDirectory() as td:
            v, d = self._run_check(Path(td) / "does-not-exist")
            self.assertEqual(v, "SKIP", d)


class TestWatchdog(unittest.TestCase):
    """守护本体：自测必须真通过（含负例），且 --no-watch 退出码可门禁。"""

    def test_selftest_passes(self):
        r = subprocess.run([sys.executable, str(SCRIPTS / "engine_watchdog.py"),
                            "--selftest"],
                           capture_output=True, text=True, timeout=180)
        self.assertEqual(r.returncode, 0, r.stdout[-2000:])
        self.assertIn("OK 全部通过", r.stdout)

    def test_no_watch_exit_code_is_4(self):
        """显式关闭守护必须退出码 4 —— 让外层/预检能抓到，绝不静默。"""
        with tempfile.TemporaryDirectory() as td:
            r = subprocess.run([sys.executable, str(SCRIPTS / "engine_watchdog.py"),
                                "--cmd", "python -c pass",
                                "--cwd", td, "--no-watch"],
                               capture_output=True, text=True, timeout=60)
            self.assertEqual(r.returncode, 4, r.stdout + r.stderr)
            self.assertIn("WATCH_DISABLED", r.stdout)
            hb = Path(td) / "logs" / "engine_watchdog.log"
            self.assertTrue(hb.is_file(), "关闭守护也要留下证据")
            self.assertIn("WATCH_DISABLED", hb.read_text(encoding="utf-8"))


class TestSmoke(unittest.TestCase):
    """脚本本身可运行、结构完整（不跑慢项）。"""

    def test_all_checks_declared(self):
        src = (SCRIPTS / "race_preflight.py").read_text(encoding="utf-8")
        for fn in ("check_docker_path", "check_dep_versions", "check_skills_parity",
                   "check_docker", "check_python_bridge", "check_ctf2",
                   "check_engine_watch"):
            self.assertIn(f"def {fn}(", src)
        for call in ("check_docker_path()", "check_dep_versions(py)",
                     "check_skills_parity()", "check_engine_watch()"):
            self.assertIn(call, src, f"main() 必须调用 {call}")


if __name__ == "__main__":
    unittest.main(verbosity=2)
