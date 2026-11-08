"""在 Docker 长任务执行期间提供存活保障的包装脚本。

背景（2026-10-09 实测，project memory ㉛ 的深化）
──────────────────────────────────────────────
本机 Docker Desktop 的 engine 带一个 **内置 5 分钟 idle 定时器**。日志实证：

    [main.idle] busy -> idle
    [main.idle] timer started (5m0s)
    ...
    [main.idle] initializing idle monitor        ← engine 重启
    [apiproxy] forwarding raw stream from dockerd: The pipe is being closed.
                                                 ← 正在跑的 build/容器连接被掐断

即：**长任务进行到一半、engine 判定 idle 后被关掉，随后有请求时重启 —— 重启过程
把正在进行的连接掐断**。表现为 `docker build` 跑到一半 `unexpected EOF`、
`docker exec` 中途 `npipe ... The system cannot find the file specified`。

这对本项目是硬阻断：一次 bkcrack 已知明文攻击要跑 ~75 分钟，远超 5 分钟窗口。

为什么不能用「后台 sleep 循环」保活
──────────────────────────────────
先试过 `while true; do docker system df; sleep 100; done &`。池子浅：循环若寄生在
被回收的 shell 里，自己先没了，保活对象反而先死。本脚本把**保活与被保活的任务放
进同一个进程**：父进程 Popen 起任务，同时起一条线程周期调 `docker version` 把
idle 计时器踹回去——两者同生共死。

用法
────
    python scripts/_docker_keepalive.py docker build -t ctf-tools:1 docker/
    python scripts/_docker_keepalive.py --interval 30 docker exec ... bkcrack ...

退出码 = 被包裹命令的退出码。超时被杀时返回 -9 对应的 shell 惯例码（137）。

零 LLM 依赖；除 docker CLI 本身外零网络。
"""

from __future__ import annotations

import argparse
import subprocess
import sys
import threading
import time

# idle 定时器是 5m0s；留足一半以上余量，避免一次慢调用就踩线。
DEFAULT_INTERVAL_SECONDS = 60


class KeepAlive(threading.Thread):
    """周期性调用 docker CLI，阻止 Docker Desktop 判定 idle。

    用 `docker version` 而不是更重的命令：目标只是产生一次 API 活动，
    别让保活本身变成负载。任何异常一律吞掉（保活失败不该弄死主任务，
    主任务会自己失败并如实报错）。
    """

    def __init__(self, interval: float, docker_bin: str = "docker") -> None:
        super().__init__(daemon=True)
        self.interval = interval
        self.docker_bin = docker_bin
        # 🔴 2026-10-31 修：原实现命名为 `self._stop`，与 `threading.Thread._stop()`
        # 方法**同名**，把它整个覆盖成了 Event 实例。
        # 后果（仅在 Python ≤3.12 触发）：`Thread.join()` →
        # `_wait_for_tstate_lock()` → `self._stop()` 抛
        # `TypeError: 'Event' object is not callable`，于是 join 永久挂住/报错。
        # 实测对照：
        #   · 3.12.3（服务器）→ 本文件 6 条用例全红，正是该 TypeError；
        #   · 3.13.14（本机）  → 12 条全绿，因为 3.13 移除了 `_wait_for_tstate_lock`，
        #     不再内部调用 `self._stop()` —— 于是这个 bug 被**版本差异静默掩盖**。
        # pyproject 曾声明 requires-python >=3.13，而服务器跑的是 3.12.13 —— 声明高于
        # 生产，导致「只在 3.12 上出现的 bug」被当成不归我们管。2026-11-08 已把声明
        # 放宽到 >=3.12 并给 CI 加了 3.12 腿，理由就是下面这个对照：同一个缺陷，
        # 3.12 全红、3.13 全绿，**版本差异会静默掩盖 bug**，只测高版本等于不测。
        # 改名为 `_stop_evt` 后与基类彻底解耦，两个版本都正确。
        self._stop_evt = threading.Event()
        self.pokes = 0

    def stop(self) -> None:
        self._stop_evt.set()

    def run(self) -> None:
        while not self._stop_evt.wait(self.interval):
            try:
                subprocess.run(
                    [self.docker_bin, "version"],
                    stdout=subprocess.DEVNULL,
                    stderr=subprocess.DEVNULL,
                    timeout=15,
                    shell=False,
                )
                self.pokes += 1
            except Exception:  # noqa: BLE001 - 保活失败不影响主任务判定
                pass


def main(argv: list[str] | None = None) -> int:
    ap = argparse.ArgumentParser(
        prog="_docker_keepalive",
        description="在 Docker 长任务期间踹住 Docker Desktop 的 idle 定时器。",
    )
    ap.add_argument(
        "--interval", type=float, default=DEFAULT_INTERVAL_SECONDS,
        help=f"保活间隔秒数（默认 {DEFAULT_INTERVAL_SECONDS}s；必须显著小于 5 分钟）",
    )
    ap.add_argument(
        "--docker-bin", default="docker",
        help="docker 可执行文件名（可用替身便于测试）",
    )
    ap.add_argument("cmd", nargs=argparse.REMAINDER, help="被包裹的 docker 命令")
    args = ap.parse_args(argv)

    cmd = [c for c in args.cmd if c != "--"]
    if not cmd:
        print("用法: _docker_keepalive.py [--interval N] <docker 命令...>", file=sys.stderr)
        return 2

    if args.interval >= 240:
        # idle 定时器 5m；间隔逼近它等于没保活，宁可直接拒绝也别给用户假的安全感。
        print(f"[keepalive] ✗ 间隔 {args.interval}s 太接近 5 分钟 idle 窗口，拒绝启动",
              file=sys.stderr)
        return 2

    keeper = KeepAlive(args.interval, args.docker_bin)
    keeper.start()
    started = time.time()
    try:
        proc = subprocess.run(cmd, shell=False, check=False)
        rc = proc.returncode
    except KeyboardInterrupt:
        rc = 130
    finally:
        keeper.stop()
        keeper.join(timeout=5)

    dur = time.time() - started
    print(f"[keepalive] 命令结束 rc={rc}，历时 {dur:.1f}s，保活 {keeper.pokes} 次",
          file=sys.stderr)
    return rc


if __name__ == "__main__":
    raise SystemExit(main())
