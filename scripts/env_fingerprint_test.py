#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""env_fingerprint.py 自测（REA #33 / #239：指纹必须"可写进公开产物"）

指纹最容易出的两种事故：
  1. **泄密**：把环境变量原值、绝对路径写进结果文件，随公开仓库一起发出去；
  2. **装样子**：取不到的项填默认值，让人以为环境已知——这比缺字段更坏。

本文件钉住：字段固定、无绝对路径、无密钥原文、未知项进 unknown、
非 git 目录不猜 HEAD。

运行：python -X utf8 scripts/env_fingerprint_test.py
"""
from __future__ import annotations

import json
import os
import sys
import tempfile
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))

import env_fingerprint as ef  # noqa: E402


class CollectTest(unittest.TestCase):
    def test_required_fields_present(self):
        data = ef.collect()
        for key in ("python", "implementation", "platform", "machine",
                    "git_head", "git_dirty", "deps", "env_fingerprints",
                    "seeds", "captured_at", "unknown"):
            self.assertIn(key, data, f"缺字段 {key}")

    def test_deps_keys_are_stable_even_when_missing(self):
        """未安装的依赖也要保留键（值为 None），否则跨结果对比会错位。"""
        d = ef.deps()
        self.assertEqual(tuple(d), ef._WATCHED_DEPS)
        self.assertTrue(all(v is None or isinstance(v, str) for v in d.values()))

    def test_no_absolute_path_in_payload(self):
        blob = json.dumps(ef.collect(cwd=os.getcwd()), ensure_ascii=False)
        self.assertNotIn(os.path.expanduser("~"), blob, "不得写入用户主目录")
        self.assertNotIn(":\\\\", blob, "不得写入 Windows 绝对路径")
        self.assertNotIn(":\\\\", blob.replace("\\\\", "\\\\"))

    def test_env_values_are_hashed_not_recorded(self):
        os.environ["OMP_NUM_THREADS"] = "7"
        self.addCleanup(os.environ.pop, "OMP_NUM_THREADS", None)
        data = ef.collect()
        blob = json.dumps(data, ensure_ascii=False)
        self.assertNotIn('"7"', blob, "环境变量原值不得出现在指纹里")
        self.assertEqual(len(data["env_fingerprints"]["OMP_NUM_THREADS"]), 12)

    def test_seeds_pass_through(self):
        data = ef.collect(seeds={"seed": 42})
        self.assertEqual(data["seeds"], {"seed": 42})

    def test_unknown_lists_missing_items(self):
        data = ef.collect(cwd=tempfile.gettempdir() + os.sep + "definitely-not-a-repo")
        self.assertIn("git_head", data["unknown"], "非 git 目录必须把 git_head 记为未知")
        self.assertIsNone(data["git_head"])

    def test_stamp_writes_env_into_payload(self):
        payload = {"total": 3}
        out = ef.stamp(payload)
        self.assertIs(out, payload)
        self.assertIn("env", payload)


class GitStateTest(unittest.TestCase):
    def test_non_git_dir_returns_nulls(self):
        d = Path(tempfile.mkdtemp())
        self.addCleanup(lambda: d.rmdir() if d.exists() else None)
        state = ef.git_state(cwd=str(d))
        self.assertIsNone(state["git_head"])
        self.assertIsNone(state["git_dirty"], "取不到不得编 False（那是'干净'的意思）")


if __name__ == "__main__":
    unittest.main(verbosity=2)
