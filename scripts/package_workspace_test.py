#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""package_workspace.py 回归测试：校验 / 清单 / 出包三条路径 + 归档必含关键文件。

不依赖 pytest，直接 python 运行；退出码 0=全过。
"""
import subprocess
import sys
import tarfile
import tempfile
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
SCRIPT = ROOT / "scripts" / "package_workspace.py"


def _run(*args):
    return subprocess.run([sys.executable, str(SCRIPT), *args],
                          capture_output=True, text=True)


def test_check_pass():
    r = _run("--check")
    assert r.returncode == 0, r.stdout + r.stderr
    assert "[PASS] 资产校验通过" in r.stdout


def test_list_contains_core():
    r = _run("--list")
    assert r.returncode == 0, r.stdout + r.stderr
    for token in ("manifest.json", "SOUL.md", "agents/", "roles/", "skills/"):
        assert token in r.stdout, f"--list 缺 {token}"


def test_package_archive():
    with tempfile.TemporaryDirectory() as td:
        out = Path(td) / "ws.tar.gz"
        r = _run("--out", str(out))
        assert r.returncode == 0, r.stdout + r.stderr
        assert out.exists(), "未产出归档"
        with tarfile.open(out) as tf:
            names = tf.getnames()
        assert "manifest.json" in names and "SOUL.md" in names
        assert any(n.startswith("agents/") for n in names)
        assert any(n.startswith("roles/") for n in names)
        assert any(n.startswith("skills/") for n in names)


if __name__ == "__main__":
    test_check_pass()
    test_list_contains_core()
    test_package_archive()
    print("package_workspace_test: OK (3/3)")
