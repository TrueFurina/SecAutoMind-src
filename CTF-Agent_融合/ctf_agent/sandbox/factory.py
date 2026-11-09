"""沙盒执行器工厂：按开关返回宿主后端或容器后端。

默认仍是 `subprocess`（旧行为一字不变）。容器后端要靠环境变量显式打开：

    CTF_SANDBOX_BACKEND=docker      # 需要 docker CLI + ctf-tools:1 镜像

为什么默认不打开：容器后端依赖宿主机 docker daemon，比赛中 daemon 挂了就是整题
0 分；而宿主后端已经挡住相对路径（`core/solver_sandbox.py`）。所以「更严的隔离」
必须是显式选择，不能悄悄替掉一个能跑的后端。

挂载白名单（唯一入口）
──────────────────────
只挂代码子目录到容器 `/app/<name>`，**绝不挂 `data` / `questions_real` /
`solutions` / 仓库根**。这份名单就是「答案不可能被读」的实现本身；
往这里加一项之前，先问一句：这个目录里有答案吗？
"""

from __future__ import annotations

import os
from typing import List, Optional, Sequence, Tuple

#: 允许进容器的代码子目录（只读挂到 /app/<name>）
APP_SUBDIRS: Sequence[str] = (
    "core", "skills", "tools", "agents", "llm", "eval", "sandbox", "ctfplatform",
)

#: 明确排除、且永远不该出现在挂载列表里的目录（写在这里是给人看的红线）
NEVER_MOUNT: Sequence[str] = ("data", "questions_real", "solutions", "tests", "docs")


def ctf_root() -> str:
    return os.path.dirname(os.path.dirname(os.path.abspath(__file__)))


def app_mounts() -> List[Tuple[str, str]]:
    """构造只读代码挂载列表（宿主机目录, 容器内路径）。"""
    root = ctf_root()
    out: List[Tuple[str, str]] = []
    for name in APP_SUBDIRS:
        host = os.path.join(root, name)
        if os.path.isdir(host):
            out.append((host, f"/app/{name}"))
    return out


def backend() -> str:
    return (os.environ.get("CTF_SANDBOX_BACKEND") or "subprocess").strip().lower()


def make_executor(workdir: Optional[str] = None, default_timeout: int = 30,
                  image: Optional[str] = None, network: str = "none"):
    """返回一个 `run()` 接口一致（→ ExecResult）的执行器。

    Args:
        workdir: 解题沙盒工作目录（None = 继承当前 cwd，旧行为）。
        default_timeout: 默认超时秒数。
        image: 容器镜像，默认取 `CTF_SANDBOX_IMAGE` 或 `ctf-tools:1`。
        network: 容器网络模式，默认 `none`（无外网）。
    """
    if backend() == "docker":
        from .docker_executor import DockerExecutor

        img = image or os.environ.get("CTF_SANDBOX_IMAGE") or "ctf-tools:1"
        return DockerExecutor(
            workdir=workdir or os.getcwd(),
            image=img,
            default_timeout=default_timeout,
            app_mounts=app_mounts(),
            network=network,
            env={"PYTHONPATH": "/app", "PYTHONIOENCODING": "utf-8", "LANG": "C.UTF-8"},
        )

    from .subprocess_executor import SubprocessExecutor

    return SubprocessExecutor(default_timeout=default_timeout, workdir=workdir)
