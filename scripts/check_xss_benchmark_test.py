#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""check_xss_benchmark_test.py — XSS 基准集自测：回归 + 变异 + 一致性。

纪律（同 audit_benchmark_validity_test.py）：判题器必须**两端都灵**——
  1. 回归：正常靶场 → 3/3 全中（能力真的可测）
  2. 变异：`--safe` 转义靶场 → 0/3（判题器不是"怎么都能过"的空洞绿）
  3. 一致性：`--dump-json` 的 flag_sha256 必须与 xss_benchmark.json 逐项一致

用法：  python scripts/check_xss_benchmark_test.py
"""
import json
import os
import subprocess
import sys
import time
import unittest
from http.client import HTTPConnection

HERE = os.path.dirname(os.path.abspath(__file__))
ROOT = os.path.dirname(HERE)
BENCH = os.path.join(ROOT, "data", "ctf_benchmark")
sys.path.insert(0, BENCH)

import judge_xss  # noqa: E402

PORT = 18196                      # 避开 judge_xss 默认的 18096
RANGE = os.path.join(BENCH, "live_target", "xss_range.py")


def _start_range(extra_args=()):
    proc = subprocess.Popen([sys.executable, RANGE, str(PORT)] + list(extra_args),
                            stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
    deadline = time.time() + 10
    while time.time() < deadline:
        try:
            c = HTTPConnection("127.0.0.1", PORT, timeout=1)
            c.request("GET", "/")
            c.getresponse().read()
            c.close()
            return proc
        except Exception:
            time.sleep(0.1)
    proc.kill()
    proc.wait()
    raise RuntimeError("靶场未就绪")


def _load_bench():
    with open(os.path.join(BENCH, "xss_benchmark.json"), encoding="utf-8") as fh:
        return json.load(fh)["problems"]


class TestXSSBenchmark(unittest.TestCase):
    def _exploit(self, extra_args):
        proc = _start_range(extra_args)
        try:
            return judge_xss.exploit("http://127.0.0.1:%d" % PORT)
        finally:
            proc.kill()
            proc.wait()

    def test_regression_normal_range(self):
        """回归：正常靶场必须 3/3 全中。"""
        bench = _load_bench()
        found = self._exploit(())
        for scene, p in bench.items():
            self.assertIn(p["flag_sha256"], found, "正常靶场未命中 %s" % scene)

    def test_mutation_safe_range(self):
        """变异：--safe 转义后必须 0 命中（证明判题器非空洞绿）。"""
        found = self._exploit(("--safe",))
        self.assertEqual(len(found), 0, "转义靶场仍命中：判题器在瞎猜 -> %r" % found)

    def test_dump_json_matches_benchmark(self):
        """一致性：--dump-json 的 flag_sha256 必须与基准 JSON 一致。"""
        r = subprocess.run([sys.executable, RANGE, "--dump-json"],
                           capture_output=True, text=True)
        self.assertEqual(r.returncode, 0, r.stderr)
        dumped = json.loads(r.stdout)["problems"]
        bench = _load_bench()
        self.assertEqual(sorted(dumped), sorted(bench))
        for k in bench:
            self.assertEqual(dumped[k]["flag_sha256"], bench[k]["flag_sha256"], k)


if __name__ == "__main__":
    unittest.main(verbosity=2)
