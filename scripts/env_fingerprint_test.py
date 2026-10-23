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
        """未安装的依赖也要保留键（值为 None），否则跨结果对比会错位。

        契约（REA #239 后放宽）：`_WATCHED_DEPS` 必须**全部在位**（固定白名单
        不能因清单变化而消失），且键序对同一仓库是可重复的。清单里声明的包
        追加在其后——早先"键集合恒等于白名单"的写法会锁死这个生长能力。
        """
        d = ef.deps()
        for name in ef._WATCHED_DEPS:
            self.assertIn(name, d, f"固定白名单 {name} 不得从指纹里消失")
        self.assertTrue(all(v is None or isinstance(v, str) for v in d.values()))
        self.assertEqual(tuple(d), tuple(ef.deps()), "同一环境下键序必须可重复")

    def test_deps_grow_from_repo_manifest(self):
        """清单里声明的包必须自动进指纹（否则新增关键依赖指纹不变 = 假齐全）。"""
        d = ef.deps()
        declared = ef.declared_python_deps()
        for name in declared:
            self.assertIn(name, d, f"{name} 在 requirements 里声明却不在指纹里")

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


def _fake_repo(files: dict[str, str]) -> Path:
    root = Path(tempfile.mkdtemp())
    for rel, body in files.items():
        p = root / rel
        p.parent.mkdir(parents=True, exist_ok=True)
        p.write_text(body, encoding="utf-8")
    return root


class ManifestInventoryTest(unittest.TestCase):
    """依赖清单盘点（REA #239）：要能答"锁了没锁""哪些算本项目依赖"。"""

    def test_classify_only_recognizes_known_names(self):
        self.assertEqual(ef._classify_manifest("go.mod"), ("go", "manifest"))
        self.assertEqual(ef._classify_manifest("go.sum"), ("go", "lock"))
        self.assertEqual(ef._classify_manifest("requirements.txt"), ("python", "manifest"))
        self.assertEqual(ef._classify_manifest("requirements.lock.txt"), ("python", "lock"))
        self.assertIsNone(ef._classify_manifest("requirements.in"),
                          "不认识的文件名必须返回 None，不得猜成依赖清单")

    def test_inventory_flags_missing_lock(self):
        """有声明没锁定 = 重装可能装出别的版本，这是本盘点最该看见的信号。"""
        root = _fake_repo({"go.mod": "module x\n", "go.sum": "h1:x\n",
                           "requirements.txt": "requests>=2\n"})
        self.addCleanup(lambda: __import__("shutil").rmtree(root, ignore_errors=True))
        inv = ef.manifest_inventory(root)
        self.assertTrue(inv["scanned"])
        self.assertEqual(inv["ecosystems"], {"go": ["lock", "manifest"],
                                            "python": ["manifest"]})
        self.assertEqual(inv["ecosystems_without_lock"], ["python"])

    def test_inventory_prunes_node_modules(self):
        """node_modules 里几万份 package.json 不是本项目依赖。"""
        root = _fake_repo({"package.json": "{}",
                           "node_modules/x/package.json": "{}",
                           "node_modules/x/y/package.json": "{}"})
        self.addCleanup(lambda: __import__("shutil").rmtree(root, ignore_errors=True))
        inv = ef.manifest_inventory(root)
        self.assertEqual([f["path"] for f in inv["files"]], ["package.json"])

    def test_inventory_paths_are_relative_and_hashed(self):
        root = _fake_repo({"sub/requirements.txt": "requests\n"})
        self.addCleanup(lambda: __import__("shutil").rmtree(root, ignore_errors=True))
        inv = ef.manifest_inventory(root)
        self.assertTrue(inv["root_relative"])
        for f in inv["files"]:
            self.assertFalse(Path(f["path"]).is_absolute())
            self.assertNotIn(str(root), f["path"])
            self.assertEqual(len(f["sha256"]), 16)

    def test_missing_root_is_reported_not_empty(self):
        inv = ef.manifest_inventory(tempfile.gettempdir() + os.sep + "no-such-repo-xyz")
        self.assertFalse(inv["scanned"], "根不存在必须 scanned=false，不能返回空清单当'没有依赖'")
        self.assertIn("未检查", inv["note"])


class RequirementsParseTest(unittest.TestCase):
    def test_skips_comments_options_and_urls(self):
        text = "\n".join([
            "# 注释行不算",
            "",
            "-r other.txt",
            "-e .",
            "--index-url https://example.invalid/simple",
            "git+https://example.invalid/repo.git",
            "requests>=2.32.3",
            "httpx[http2]>=0.27.0        # 行内注释",
            "chardet>=5.2.0,<6",
        ])
        got = dict(ef._parse_requirements(text))
        self.assertEqual(sorted(got), ["chardet", "httpx", "requests"])

    def test_normalizes_dist_names(self):
        self.assertEqual(ef._normalize_dist("Foo_Bar.Baz"), "foo-bar-baz")
        got = ef._parse_requirements("charset_normalizer>=3.3\n")
        self.assertIn("charset-normalizer", got)

    def test_declared_deps_ignore_deep_archives(self):
        """归档提交包里的 requirements 不算本项目依赖（实测仓里就有这种目录）。"""
        root = _fake_repo({"requirements.txt": "requests\n",
                           "submission/01_material/requirements.txt": "evilpkg\n"})
        self.addCleanup(lambda: __import__("shutil").rmtree(root, ignore_errors=True))
        got = ef.declared_python_deps(root)
        self.assertEqual(sorted(got), ["requests"])
        self.assertEqual(ef.declared_source_files(root), ["requirements.txt"])

    def test_declared_deps_include_one_level_subdir(self):
        """py-server/pyproject.toml 这类一级子目录是真实项目根（study-help-pro）。"""
        root = _fake_repo({"py-server/requirements.txt": "fastapi>=0.1\n"})
        self.addCleanup(lambda: __import__("shutil").rmtree(root, ignore_errors=True))
        self.assertEqual(sorted(ef.declared_python_deps(root)), ["fastapi"])

    def test_coverage_reports_uninstalled(self):
        root = _fake_repo({"requirements.txt": "requests\nsurely-not-installed-pkg-xyz\n"})
        self.addCleanup(lambda: __import__("shutil").rmtree(root, ignore_errors=True))
        cov = ef.deps_coverage(root)
        self.assertIn("surely-not-installed-pkg-xyz", cov["declared_not_installed"])
        self.assertEqual(cov["declared_count"], 2)
        self.assertEqual(cov["declared_from"], ["requirements.txt"])

    def test_pyproject_pep621_and_poetry(self):
        """pyproject 是很多项目的唯一 python 清单（study-help-pro 就是），读不出来
        会让 declared_count 显示 0 —— 看起来像"没依赖"，实际是"没读它"。"""
        pep621 = "\n".join([
            "[project]",
            'name = "x"',
            "dependencies = [\"httpx[http2]>=0.27\", \"requests\"]",
            "",
            "[project.optional-dependencies]",
            'dev = ["pytest>=7", "pytest-cov"]',
        ])
        got, reason = ef._parse_pyproject(pep621)
        self.assertIsNone(reason)
        self.assertEqual(sorted(got), ["httpx", "pytest", "pytest-cov", "requests"])

        poetry = "\n".join([
            "[tool.poetry.dependencies]",
            'python = ">=3.11"',
            'fastapi = ">=0.1"',
            "",
            "[tool.poetry.group.dev.dependencies]",
            'pytest = ">=7"',
        ])
        got, reason = ef._parse_pyproject(poetry)
        self.assertIsNone(reason)
        self.assertEqual(sorted(got), ["fastapi", "pytest"],
                         "python 是版本约束不是依赖，不该进依赖集")

    def test_pyproject_without_deps_reports_reason(self):
        got, reason = ef._parse_pyproject('[build-system]\nrequires = ["setuptools"]\n')
        self.assertEqual(got, {})
        self.assertIsNotNone(reason, "读不出依赖名必须给理由，不能只返回空集")

    def test_unparsed_manifests_are_listed(self):
        root = _fake_repo({"pyproject.toml": "[build-system]\nrequires=[]\n",
                           "requirements.txt": "requests\n"})
        self.addCleanup(lambda: __import__("shutil").rmtree(root, ignore_errors=True))
        unparsed = ef.unparsed_manifests(root)
        self.assertEqual([u["path"] for u in unparsed], ["pyproject.toml"])
        self.assertTrue(unparsed[0]["reason"])

    def test_declared_deps_read_pyproject_when_no_requirements(self):
        root = _fake_repo({"pyproject.toml": "[project]\ndependencies=[\"requests\"]\n"})
        self.addCleanup(lambda: __import__("shutil").rmtree(root, ignore_errors=True))
        self.assertEqual(sorted(ef.declared_python_deps(root)), ["requests"])
        self.assertEqual(ef.declared_source_files(root), ["pyproject.toml"])

    def test_collect_embeds_manifest_and_coverage(self):
        data = ef.collect()
        self.assertIn("deps_manifest", data)
        self.assertIn("deps_coverage", data)
        blob = json.dumps(data, ensure_ascii=False)
        self.assertNotIn(os.path.expanduser("~"), blob)


class SamplingContextTest(unittest.TestCase):
    """2026-10-21 事故：用托管 venv 采 study-help-pro，报"langgraph 未装"；
    换成项目自带 py-server/.venv 重采 → 32/32 全装。缺口是**采样环境不对**
    造出来的，不是依赖缺失。指纹必须自证"我是用谁采的"。"""

    def test_sampling_context_has_expected_keys(self):
        ctx = ef.sampling_context()
        self.assertIn("in_venv", ctx)
        self.assertIn("sampled_in_project_venv", ctx)

    def test_foreign_root_is_not_owned_venv(self):
        tmp = tempfile.mkdtemp()
        self.addCleanup(lambda: __import__("shutil").rmtree(tmp, ignore_errors=True))
        ctx = ef.sampling_context(tmp)
        self.assertFalse(ctx["sampled_in_project_venv"],
                         "采样器不在该仓库的 venv 里时不得自称属于它")

    def test_coverage_carries_sampling(self):
        cov = ef.deps_coverage()
        self.assertIn("sampling", cov)
        self.assertIn("sampling_warning", cov)

    def test_missing_deps_outside_project_venv_warns(self):
        """非项目 venv 采出的"未安装"必须带警告——否则会被当成真缺口。"""
        root = _fake_repo({"requirements.txt": "totally-not-installed-pkg-x>=1\n"})
        self.addCleanup(lambda: __import__("shutil").rmtree(root, ignore_errors=True))
        cov = ef.deps_coverage(root)
        self.assertEqual(cov["declared_not_installed"], ["totally-not-installed-pkg-x"])
        if not cov["sampling"]["sampled_in_project_venv"]:
            self.assertTrue(cov["sampling_warning"],
                            "非项目 venv 采集且有缺口时必须给出警告")


if __name__ == "__main__":
    unittest.main(verbosity=2)
