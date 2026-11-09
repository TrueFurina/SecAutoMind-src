# -*- coding: utf-8 -*-
"""解题沙盒容器后端的不变量（无需 docker 也能跑）。

这三条锁的是「防自己」的核心：
1. 挂载白名单里**永远不能**出现 data/questions_real/solutions 这类答案目录
   —— 挂错一层，刚堵的洞原样回来，而外表看起来“我们上容器了”；
2. 默认后端仍是 subprocess（旧行为不变），容器必须显式开启；
3. docker 不可用时**fail-closed**（返回 -4 且带标记），绝不回退到宿主机执行。
"""

import asyncio
import os
import sys

import pytest

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from sandbox import factory  # noqa: E402


def test_app_mounts_never_contain_answer_dirs():
    mounts = factory.app_mounts()
    assert mounts, "代码挂载列表不该为空（否则容器里 import 不到 skills）"
    forbidden = set(factory.NEVER_MOUNT) | {"data", "questions_real", "questions_ext"}
    for host, dest in mounts:
        base = os.path.basename(os.path.normpath(host))
        assert base not in forbidden, f"答案目录被挂进容器: {host} -> {dest}"
        assert dest.startswith("/app/"), f"挂载点必须在 /app 下: {dest}"
        # 挂载目标目录本身不能是答案目录的子路径
        rel = os.path.relpath(host, factory.ctf_root())
        top = rel.replace("\\", "/").split("/")[0]
        assert top not in forbidden, f"挂载落在答案目录里: {host}"


def test_app_subdirs_has_no_answer_dirs():
    for name in factory.APP_SUBDIRS:
        assert name not in factory.NEVER_MOUNT, f"{name} 同时出现在允许与禁止名单里"


def test_default_backend_is_subprocess(monkeypatch):
    monkeypatch.delenv("CTF_SANDBOX_BACKEND", raising=False)
    assert factory.backend() == "subprocess"
    ex = factory.make_executor(workdir=None, default_timeout=30)
    assert type(ex).__name__ == "SubprocessExecutor"


def test_docker_backend_selected_by_env(monkeypatch):
    monkeypatch.setenv("CTF_SANDBOX_BACKEND", "docker")
    ex = factory.make_executor(workdir="/tmp/ctf_probe", default_timeout=30)
    assert type(ex).__name__ == "DockerExecutor"
    assert ex.image
    if os.name != "nt":  # Windows 宿主不支持容器后端（见 docker_executor 注释）
        assert ex._map_text("/tmp/ctf_probe/ciphertext") == "/work/ciphertext"


def test_container_unavailable_is_fail_closed(monkeypatch):
    """docker CLI 不可用 / 平台不支持时，必须报 -4，不许偷偷用宿主机跑。"""
    from sandbox.docker_executor import (CONTAINER_UNAVAILABLE_RC,
                                         UNAVAILABLE_TAG, DockerExecutor)

    monkeypatch.setenv("PATH", "")
    monkeypatch.setenv("CTF_SANDBOX_BACKEND", "docker")
    ex = DockerExecutor(workdir=os.getcwd(), default_timeout=10)
    r = asyncio.run(ex.run("python: print('should-not-run-on-host')", timeout=10))
    assert r.exit_code == CONTAINER_UNAVAILABLE_RC
    assert UNAVAILABLE_TAG in r.stderr
    assert "should-not-run-on-host" not in (r.stdout or "")


@pytest.mark.skipif(os.name == "nt", reason="路径映射只对 POSIX 宿主实现")
def test_path_map_only_touches_workdir():
    from sandbox.docker_executor import DockerExecutor

    ex = DockerExecutor(workdir="/tmp/ctf_probe_x", default_timeout=10)
    code = "open('/tmp/ctf_probe_x/q/a/ciphertext').read() or open('/tmp/ctf_benchmark/ans.json').read()"
    mapped = ex._map_text(code)
    assert "/work/q/a/ciphertext" in mapped
    # 沙盒之外的宿主机路径**故意不映射**：读不到才是对的
    assert "/tmp/ctf_benchmark/ans.json" in mapped
