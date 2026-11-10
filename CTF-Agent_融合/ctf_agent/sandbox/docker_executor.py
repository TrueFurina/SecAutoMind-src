"""容器后端：把解题子进程关进只挂 /work 的容器里。

为什么要这个后端
────────────────
`subprocess_executor.py` 换 cwd 只能挡住**相对路径**。子进程仍是宿主机上的普通
进程，写死绝对路径（`E:\\Program\\SecAutoMind\\...\\data\\ctf_benchmark`）照样能读
——实测 `abs_bench_reachable=True`。要真闭合，必须让那个进程**看不到**那个目录，
唯一可靠的办法是容器只挂载它该看的那一个目录。

挂载设计（这是本模块最要紧的一条）
──────────────────────────────────
- `/work` ← 宿主机的一次性沙盒工作目录（只放本题真实输入），**可写**；
- `/app/<core|skills|tools|agents|llm|eval|sandbox|ctfplatform>` ← 代码树，**只读**；
- **绝不挂 `ctf_agent/data`、`questions_real`、`solutions`、仓库根**。
  挂错一层，刚堵的洞原样回来，而且外表看起来「我们上容器了」。
  `factory.py` 里的白名单是唯一入口，新增挂载必须先问「这目录里有答案吗」。

路径映射
────────
沙盒附件暂存在宿主机 workdir 里，解题脚本拿到的却是宿主机绝对路径
（`C:\\Users\\...\\Temp\\ctf_sbx_xxx\\q\\<qid>\\ciphertext`），在容器内不存在。
因此 `run()` 执行前把 **workdir 前缀**替换成 `/work`，其余宿主机路径一律不动
——不动的那部分正是要被隔离掉的东西，它读不到才是对的。

失败语义（与 docker_session.py 一致）
─────────────────────────────────────
任何 docker 侧问题都返回 `exit_code=-4` + `[CONTAINER_UNAVAILABLE]`，
**绝不回退到宿主机执行**。回退会让「在错误的机器上完成了任务」伪装成成功，
那比直接报错难查一个量级。
"""

from __future__ import annotations

import asyncio
import hashlib
import os
import time
import uuid
from typing import List, Optional, Sequence, Tuple

from .subprocess_executor import (
    ExecResult,
    _check_bash_command,
    _check_cmd_command,
    _looks_like_python,
    validate_python_code,
    _SecurityError,
)

CONTAINER_UNAVAILABLE_RC = -4
UNAVAILABLE_TAG = "[CONTAINER_UNAVAILABLE]"
#: 源码超过这个长度就走文件而不是命令行（与宿主后端同口径）
_CMD_LINE_SRC_LIMIT = 24000

# `docker run -e` 是**新的子进程边界**：注入值会出现在容器环境、
# `docker inspect` / `ps` 里。与 Go 侧 internal/procenv 同款，用
# 「白名单 + deny」双锁，绝不透传宿主 os.environ。
#: 允许注入的键；新增必须显式登记，且不得命中 deny
CONTAINER_ENV_ALLOWLIST = frozenset({
    "PYTHONPATH", "PYTHONIOENCODING", "LANG", "LC_ALL", "PATH", "HOME", "TMPDIR",
})
#: 即便被误登记进白名单，命中这些片段也一律拒绝（双保险）
CONTAINER_ENV_DENY_PARTS = (
    "KEY", "TOKEN", "SECRET", "PASSWORD", "PASSWD", "CREDENTIAL", "AUTH", "PRIVATE",
)


def validate_container_env(env: dict) -> Optional[str]:
    """校验将经 `docker run -e` 注入的环境，返回拒绝原因（None = 放行）。

    🔴 为什么需要运行时锁：factory.make_executor 今天只传 3 项固定白名单，
    但 `DockerExecutor(env=...)` 是公开构造参数；而本文件旧注释曾写
    「sanitized_env 已剔除 key」——实际代码用的是 self.extra_env，**根本没调用**
    sanitized_env()。若有人照注释以为「env 已脱敏」而传 `os.environ`，
    API Key 就会经 `-e` 进容器。故改为白名单 + deny 双锁、fail-closed：
    任何未登记键或疑似凭据键一律拒绝启动容器（返回 -4 + 标记）。
    """
    for k in (env or {}):
        up = str(k).upper()
        if any(p in up for p in CONTAINER_ENV_DENY_PARTS):
            return ("%s 拒绝把疑似凭据键 %r 注入容器（白名单+deny）"
                    % (UNAVAILABLE_TAG, k))
        if up not in CONTAINER_ENV_ALLOWLIST:
            return ("%s 环境变量 %r 未登记在容器白名单里，请显式登记后再用"
                    % (UNAVAILABLE_TAG, k))
    return None


def _pid_alive(pid: int) -> bool:
    """该 pid 现在是否还活着（只用于判断容器是否成了孤儿）。

    POSIX 走 `/proc`（本后端的可用宿主就是 Linux，见 `_platform_block`）。
    **不用** `os.kill(pid, 0)`：Windows 上 `os.kill` 走 TerminateProcess，
    signal=0 会直接**终止**目标进程 —— 一个"检查是否存活"的动作变成杀手，
    实测事故同源（见 AGENTS 第十一条：判活别信 `HasExited`）。
    """
    if pid <= 0:
        return False
    if os.name == "nt":
        # 容器后端在 Windows 宿主 fail-closed，永远不该走到这里；保守判"活着"
        # ⇒ 一个容器都不删。
        return True
    if os.path.isdir("/proc"):
        return os.path.isdir("/proc/%d" % pid)
    try:
        os.kill(pid, 0)
    except ProcessLookupError:
        return False
    except PermissionError:
        return True
    except OSError:
        return False
    return True


def orphan_containers_to_reap(names, prefix: str, self_pid: int,
                              alive=_pid_alive, tail_sep: str = "") -> List[str]:
    """从 `docker ps -a` 给出的容器名里挑出**可回收的孤儿**（纯函数，便于单测）。

    判定四连：名字以 `prefix` 开头 → 尾部 pid 可解析 → pid 不是自己 →
    该 pid 已不存在。**pid 还活着的一律不动**：宁可留一个残留容器，
    也不误删并行会话正在用的那一个（同名脚本误杀是本项目真实事故）。

    Args:
        names: `docker ps -a --format "{{.Names}}"` 的每行（`--filter name=` 是
            子串匹配，可能带进别的名字，故这里再做一次前缀校验）。
        prefix: 全局回收传 `"ctf-sbx-"`（覆盖所有 workdir 的孤儿）；
            按 workdir 精确回收传 `"ctf-sbx-<sha1(workdir)[:8]>-"`。
        self_pid: 当前进程 pid，自身容器交给 `stop()` / atexit 管。
        alive: 判活函数，测试可注入。
        tail_sep: 非空表示 pid 在**最后一个** `tail_sep` 之后
            （全局前缀 `ctf-sbx-` 下的名字形如 `<8hex>-<pid>`）。
    """
    out: List[str] = []
    for raw in names or []:
        nm = (raw or "").strip()
        if not nm.startswith(prefix):
            continue
        tail = nm[len(prefix):]
        if tail_sep:
            if tail_sep not in tail:
                continue
            tail = tail.rsplit(tail_sep, 1)[-1]
        try:
            pid = int(tail)
        except (TypeError, ValueError):
            continue
        if pid <= 0 or pid == self_pid:
            continue
        if alive(pid):
            continue
        out.append(nm)
    return out


def _register_atexit_rm(name: str) -> None:
    """进程退出时兜底删掉自己的容器。

    为什么需要：`docker run -d --rm` 的 `--rm` 只在**容器主进程**退出时触发，
    而容器主进程是 `sleep infinity` —— 它永远不会自己退出。正常批量路径里
    也没有任何地方调用 `DockerExecutor.stop()`（实测 12 道题跑完泄漏 12 个容器）。
    atexit 覆盖「正常退出 / 异常退出 / Ctrl-C」这几种能跑到解释器收尾的场景；
    SIGKILL / OOM 这类跑不到 atexit 的，交给下次 `_sweep_orphans` 按 pid 判活回收。
    """
    import atexit
    import subprocess as _sp

    def _cleanup() -> None:
        try:
            _sp.run(["docker", "rm", "-f", name],
                    stdout=_sp.DEVNULL, stderr=_sp.DEVNULL, timeout=30)
        except Exception:  # noqa: BLE001 - 退出清理不上抛
            pass

    atexit.register(_cleanup)


class DockerExecutor:
    """与 `SubprocessExecutor` 同接口（`run()` → `ExecResult`），后端换成容器。

    Args:
        workdir: 宿主机沙盒工作目录，会被挂到容器 `/work`。
        image: 工具镜像（由 `docker/Dockerfile` 构建，见该文件头注释）。
        app_mounts: `[(宿主机目录, 容器内路径)]` 列表，一律按只读挂载。
        network: 默认 `none`。需要联网取题面资源时才显式放开。
    """

    def __init__(
        self,
        workdir: str,
        image: str = "ctf-tools:1",
        default_timeout: int = 30,
        app_mounts: Optional[Sequence[Tuple[str, str]]] = None,
        network: str = "none",
        env: Optional[dict] = None,
    ) -> None:
        self.workdir = os.path.abspath(workdir) if workdir else os.getcwd()
        self.image = image
        self.default_timeout = default_timeout
        self.app_mounts: List[Tuple[str, str]] = list(app_mounts or [])
        self.network = network
        self.extra_env = dict(env or {})
        # 构造时就锁死：env 不合规 ⇒ fail-closed，绝不带病起容器
        self._env_block = validate_container_env(self.extra_env) or ""
        self._container: Optional[str] = None
        self._start_reason: str = ""
        self._sweep_done: bool = False
        self._lock = asyncio.Lock()
        # 平台限制：Windows 宿主的路径映射（`C:\x` → `/work/x`，剩余分隔符还要转正斜杠）
        # 与"代码里的 \n 等转义"冲突，本轮**不做**。求解本来就在 Linux 服务器上跑
        # （AGENTS 第零条），所以这里 fail-closed，绝不假装支持。
        import platform as _pf
        self._platform_block: str = ""
        if _pf.system() == "Windows":
            self._platform_block = (
                f"{UNAVAILABLE_TAG} 容器后端暂不支持 Windows 宿主（C:\\ → /work 路径映射未实现）；"
                "请在 Linux 服务器（172.16.222.99）上运行"
            )

    # ── 生命周期 ─────────────────────────────────────────

    def _container_name(self) -> str:
        h = hashlib.sha1(self.workdir.encode("utf-8", "ignore")).hexdigest()[:8]
        return f"ctf-sbx-{h}-{os.getpid()}"

    def _mount_args(self) -> List[str]:
        args = ["-v", f"{self.workdir}:/work"]
        for host, dest in self.app_mounts:
            args += ["-v", f"{host}:{dest}:ro"]
        return args

    async def _sweep_orphans(self) -> None:
        """回收**所有 workdir** 下、**进程已死**的孤儿容器（每个实例只做一次）。

        为什么需要：容器是 `sleep infinity` 常驻 + `--rm`，靠 `stop()` 里的
        `docker rm -f` 收尾。而 `stop()` 在正常批量路径里**没人调用**
        （`run.py` / `task_pool` 里没有 stop 钩子，`core/docker_session.py`
        那个 stop 是另一个模块的），进程退出也只会走 `--rm` 的容器主进程
        退出路径 —— 但 `sleep infinity` 不会自己退出 ⇒ 每跑一道题泄漏一个容器。
        实测：服务器上 12 道题跑完，`docker ps -a` 里躺了 12 个 `ctf-sbx-*`。

        所以回收范围是**全局** `ctf-sbx-` 前缀（不再按 workdir hash 收窄，
        否则跨题的孤儿永远清不到），安全边界靠 pid：
        只删尾部 pid 已不存在的容器，pid 还活着的一律不动
        （并行会话正在用的容器绝不能误删 —— 同名脚本误杀是本项目真实事故）。
        """
        if self._sweep_done:
            return
        self._sweep_done = True
        prefix = "ctf-sbx-"
        try:
            proc = await asyncio.create_subprocess_exec(
                "docker", "ps", "-a", "--filter", "name=" + prefix,
                "--format", "{{.Names}}",
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.DEVNULL,
            )
            out, _ = await asyncio.wait_for(proc.communicate(), timeout=30)
        except Exception:  # noqa: BLE001 - 清理是尽力而为，不上抛
            return
        targets = orphan_containers_to_reap(
            out.decode("utf-8", "replace").splitlines(), prefix, os.getpid(),
            tail_sep="-")
        for nm in targets:
            try:
                p = await asyncio.create_subprocess_exec(
                    "docker", "rm", "-f", nm,
                    stdout=asyncio.subprocess.DEVNULL,
                    stderr=asyncio.subprocess.DEVNULL,
                )
                await asyncio.wait_for(p.wait(), timeout=60)
            except Exception:  # noqa: BLE001
                pass

    async def _ensure_container(self) -> Optional[str]:
        """惰性起容器。返回 None 表示可用，否则返回不可用原因。"""
        if self._container:
            return None
        async with self._lock:
            if self._container:
                return None
            await self._sweep_orphans()
            name = self._container_name()
            argv = [
                "docker", "run", "-d", "--rm",
                "--name", name,
                "--network", self.network,
                *self._mount_args(),
                "-w", "/work",
            ]
            # 环境：extra_env 已在构造器经 validate_container_env 白名单+deny 校验
            # （不合规则 _env_block 在 run() 里先返回 -4，走不到这里）。
            # **绝不**透传宿主 os.environ；旧注释称「sanitized_env 已剔除 key」与
            # 代码不符（本后端没调用它），已更正。
            for k, v in self.extra_env.items():
                argv += ["-e", f"{k}={v}"]
            argv += [self.image, "sleep", "infinity"]
            try:
                proc = await asyncio.create_subprocess_exec(
                    *argv,
                    stdout=asyncio.subprocess.PIPE,
                    stderr=asyncio.subprocess.PIPE,
                )
                out, err = await asyncio.wait_for(proc.communicate(), timeout=120)
            except Exception as exc:  # noqa: BLE001 - 启动层不向上抛
                self._start_reason = f"{UNAVAILABLE_TAG} docker run 启动失败: {exc!r}"
                return self._start_reason
            if proc.returncode != 0:
                self._start_reason = (
                    f"{UNAVAILABLE_TAG} docker run rc={proc.returncode}: "
                    f"{err.decode('utf-8', 'replace').strip()[:300]}"
                )
                return self._start_reason
            self._container = name
            _register_atexit_rm(name)
            return None

    async def stop(self) -> None:
        if not self._container:
            return
        name, self._container = self._container, None
        proc = await asyncio.create_subprocess_exec(
            "docker", "rm", "-f", name,
            stdout=asyncio.subprocess.DEVNULL,
            stderr=asyncio.subprocess.DEVNULL,
        )
        try:
            await asyncio.wait_for(proc.wait(), timeout=60)
        except Exception:  # noqa: BLE001 - 清理失败不上抛
            pass

    # ── 路径映射 ─────────────────────────────────────────

    def _map_text(self, text: str) -> str:
        """把宿主机 workdir 前缀替换成 /work（正/反斜杠、大小写都覆盖）。"""
        variants = [
            self.workdir,
            self.workdir.replace("\\", "/"),
            self.workdir.replace("/", "\\"),
            self.workdir.lower(),
            self.workdir.replace("\\", "/").lower(),
        ]
        out = text
        for v in variants:
            out = out.replace(v, "/work")
        return out

    # ── 执行 ────────────────────────────────────────────

    def _build_python_cmd(self, src: str) -> Tuple[List[str], Optional[str], bool]:
        """返回 (容器内 argv, 需清理的宿主机临时文件, 是否写了文件)。"""
        if len(src) <= _CMD_LINE_SRC_LIMIT:
            return ["python3", "-c", src], None, False
        os.makedirs(self.workdir, exist_ok=True)
        tmp_host = os.path.join(self.workdir, f"_src_{uuid.uuid4().hex[:10]}.py")
        with open(tmp_host, "w", encoding="utf-8") as fh:
            fh.write(src)
        return ["python3", f"/work/{os.path.basename(tmp_host)}"], tmp_host, True

    async def run(self, code: str, timeout: Optional[int] = None,
                  task_id: str = "") -> ExecResult:
        if not code or not code.strip():
            return ExecResult(stderr="空代码", exit_code=-1)
        # env 构造错误优先于平台限制：即使 Windows 本来就跑不了，也要把
        # 「有人试图往容器里塞凭据」如实报出来，不能被平台提示盖住。
        if self._env_block:
            return ExecResult(stderr=self._env_block,
                              exit_code=CONTAINER_UNAVAILABLE_RC)
        if self._platform_block:
            return ExecResult(stderr=self._platform_block,
                              exit_code=CONTAINER_UNAVAILABLE_RC)

        timeout = timeout or self.default_timeout
        stripped = code.strip()

        # ── 与宿主后端同一套前置校验（容器是第二层，不是唯一一层）──
        if stripped.startswith(("python: ", "python3: ")):
            python_src = stripped.split(":", 1)[1].strip()
        elif _looks_like_python(stripped):
            python_src = stripped
        else:
            python_src = None

        _tmp_host: Optional[str] = None
        if python_src is not None:
            try:
                validate_python_code(python_src)
            except _SecurityError as exc:
                return ExecResult(stderr=f"[安全拦截] {exc}", exit_code=-2)
            argv, _tmp_host, _ = self._build_python_cmd(python_src)
            inner = argv
        else:
            err = _check_bash_command(code)
            if err:
                return ExecResult(stderr=f"[安全拦截] {err}", exit_code=-2)
            inner = ["sh", "-c", code]

        reason = await self._ensure_container()
        if reason:
            return ExecResult(stderr=reason, exit_code=CONTAINER_UNAVAILABLE_RC)

        # 路径映射：只换 workdir 前缀；其余宿主机路径保持原样（读不到才是对的）
        inner = [self._map_text(a) if os.sep in str(a) or "/" in str(a) else a
                 for a in inner]

        ts = time.strftime("%Y-%m-%d %H:%M:%S")
        exec_argv = ["docker", "exec", "-w", "/work", self._container, *inner]
        timed_out = False
        try:
            proc = await asyncio.create_subprocess_exec(
                *exec_argv,
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE,
            )
            try:
                out_b, err_b = await asyncio.wait_for(proc.communicate(), timeout=timeout)
                rc = proc.returncode if proc.returncode is not None else -1
            except asyncio.TimeoutError:
                timed_out = True
                try:
                    proc.kill()
                except ProcessLookupError:
                    pass
                out_b, err_b = b"", "[超时]".encode("utf-8")
                rc = -1
        except FileNotFoundError:
            return ExecResult(stderr=f"{UNAVAILABLE_TAG} docker CLI 不在 PATH",
                              exit_code=CONTAINER_UNAVAILABLE_RC)
        except Exception as exc:  # noqa: BLE001
            return ExecResult(stderr=f"{UNAVAILABLE_TAG} 执行失败: {exc!r}",
                              exit_code=CONTAINER_UNAVAILABLE_RC)
        finally:
            if _tmp_host and os.path.exists(_tmp_host):
                try:
                    os.remove(_tmp_host)
                except OSError:
                    pass

        stdout = self._map_text(out_b.decode("utf-8", "replace"))
        stderr = self._map_text(err_b.decode("utf-8", "replace"))
        return ExecResult(stdout=stdout, stderr=stderr, exit_code=rc, timed_out=timed_out)

    # 与 SubprocessExecutor 对齐的 no-op 接口（run.py 侧统一调用）
    def watch_run(self, task_id: str, command: str) -> Optional[str]:
        return None

    def watch_reset(self, task_id: str) -> None:
        return None
