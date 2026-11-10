# -*- coding: utf-8 -*-
"""解题沙盒容器后端的不变量（无需 docker 也能跑）。

这些锁的是「防自己」的核心：
1. 挂载白名单里**永远不能**出现 data/questions_real/solutions 这类答案目录
   —— 挂错一层，刚堵的洞原样回来，而外表看起来“我们上容器了”；
2. 默认后端仍是 subprocess（旧行为不变），容器必须显式开启；
3. docker 不可用时**fail-closed**（返回 -4 且带标记），绝不回退到宿主机执行；
4. `docker run -e` 注入的环境必须过白名单 + deny，绝不能透传宿主 env。
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


# ── 容器环境变量白名单（2026-11-10）──────────────────────────────────
# 背景：docker_executor 旧注释写「sanitized_env 已剔除 key」，但后端根本没调用
# sanitized_env()；env 是公开构造参数。若有人照注释以为「已脱敏」而传
# os.environ，API Key 会经 `docker run -e` 进容器（还会出现在 inspect/ps）。
# 下面四条把「白名单 + deny + fail-closed」钉成可执行判据。


def test_container_env_allowlist_passes():
    from sandbox.docker_executor import validate_container_env
    assert validate_container_env({"PYTHONPATH": "/app",
                                   "PYTHONIOENCODING": "utf-8",
                                   "LANG": "C.UTF-8"}) is None


def test_container_env_rejects_credential_keys():
    from sandbox.docker_executor import validate_container_env, UNAVAILABLE_TAG
    for k in ("OPENROUTER_API_KEY", "MODELSCOPE_TOKEN", "DB_PASSWORD",
              "AUTH_HEADER", "PRIVATE_KEY"):
        reason = validate_container_env({k: "x"})
        assert reason and UNAVAILABLE_TAG in reason, k


def test_container_env_rejects_unregistered_and_full_environ():
    from sandbox.docker_executor import validate_container_env, UNAVAILABLE_TAG
    reason = validate_container_env({"CTF_SANDBOX_BACKEND": "docker"})
    assert reason and UNAVAILABLE_TAG in reason
    # 模拟「以为已脱敏」而传全量宿主 env：必被拒
    fake_full = {"PATH": "/usr/bin", "LANG": "C.UTF-8",
                 "USERPROFILE": "C:/Users/x", "APPDATA": "C:/x"}
    assert validate_container_env(fake_full)


def test_container_env_fail_closed_no_host_execution():
    from sandbox.docker_executor import (CONTAINER_UNAVAILABLE_RC,
                                         UNAVAILABLE_TAG, DockerExecutor)
    env = {"PATH": "/usr/bin", "PYTHONPATH": "/app", "SOME_APP_TOKEN": "x"}
    ex = DockerExecutor(workdir=os.getcwd(), default_timeout=5, env=env)
    r = asyncio.run(ex.run("python: print('should-not-run-on-host')", timeout=5))
    assert r.exit_code == CONTAINER_UNAVAILABLE_RC
    assert UNAVAILABLE_TAG in r.stderr
    assert "should-not-run-on-host" not in (r.stdout or "")


# ── 孤儿容器回收（2026-11-10）────────────────────────────────────────
# 背景：容器是 `sleep infinity` 常驻 + `--rm`，收尾靠 stop() 里的 docker rm -f。
# 进程被 SIGKILL / OOM / 外部 timeout 杀掉时 stop() 不执行，容器永久驻留。
# 服务器实测：一次 `timeout 600` 杀进程，5 个 ctf-sbx-* 容器 Up 了 10~44 分钟。
# 下面三条锁「只回收同 workdir 前缀且进程已死的」，防误删并行会话的活容器。

PREFIX = "ctf-sbx-deadbeef-"


def test_orphan_reap_takes_only_dead_same_prefix():
    from sandbox.docker_executor import orphan_containers_to_reap
    names = [PREFIX + "111", PREFIX + "222", PREFIX + "333",
             "ctf-sbx-cafebabe-" + "444", "other-container"]
    targets = orphan_containers_to_reap(
        names, PREFIX, self_pid=111, alive=lambda pid: pid == 222)
    # 111 = 自己（交给 stop()）；222 = 还活着（并行会话在用）；444 = 别的工作目录
    assert targets == [PREFIX + "333"], targets


def test_orphan_reap_ignores_prefix_substring_and_garbage():
    """`docker ps --filter name=` 是子串匹配，会把别的名字带进来，必须二次校验。"""
    from sandbox.docker_executor import orphan_containers_to_reap
    names = [PREFIX + "12",           # 短 pid，合法
             "ctf-sbx-deadbeef-12-x",  # 尾部不是纯数字
             "xctf-sbx-deadbeef-12",   # 前缀不对（只差开头）
             "", None]
    targets = orphan_containers_to_reap(names, PREFIX, self_pid=1,
                                        alive=lambda pid: False)
    assert targets == [PREFIX + "12"], targets


def test_pid_alive_is_conservative_on_windows():
    """Windows 上必须判「活着」（⇒ 不删任何容器）。

    理由：`os.kill(pid, 0)` 在 Windows 走 TerminateProcess，signal=0 会真的
    终止目标进程；容器后端在 Windows 本来就 fail-closed，这里再保守一层。
    """
    from sandbox.docker_executor import _pid_alive
    if os.name == "nt":
        assert _pid_alive(999999) is True
    else:
        assert _pid_alive(os.getpid()) is True
        assert _pid_alive(1 << 30) is False
