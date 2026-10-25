#!/usr/bin/env python3
"""引擎守护（process watchdog）—— 进程退出自动重启 + 心跳日志 + 崩溃取证。

为什么要有这个（2026-10-24 快闪赛事故）
----------------------------------------
`final_entry.py` 在赛时**静默退出 3 次**，每次都要人工发现 + 重启。
根因不是"没有守护代码"：`scripts/launch_runner.ps1` 有看护循环，但
  (a) 它只守护 runner_ctf2.py，**不覆盖开赛前的 final_entry.py**；
  (b) `-NoWatch` 开关一加就整个关掉，且**没有任何门禁会报警**（fail-open）；
  (c) `HealthInterval=15s` > 10s 自恢复验收线。

本脚本的三条硬约束（对应上面三条）
------------------------------------
1. 目标可指定任意命令（final_entry / runner / 自研引擎一视同仁）；
2. **默认守护开启**。要关必须显式 `--no-watch`，此时**退出码 = 4 且日志写明
   "WATCH_DISABLED"**，让外层/预检能抓到，绝不静默；
3. 默认 `interval=4s` → 探测+重启实测 < 10s（验收线）。

设计与纪律
----------
- **fail-closed**：超过 `max_restarts` 后停止重启并返回非零退出码，绝不无限重启
  （"死循环"是本项目五宗罪之一）。存活超过 `reset_after` 秒则计数清零，
  避免历史崩溃把额度耗光。
- **崩溃取证**：每次重启记录 exit code、存活时长、stderr 尾部 20 行。
  "启动即退出"（存活 < `boot_grace` 秒）单独标注 —— 那通常不是偶发崩溃，
  是配置/依赖错，重启也没用，必须让人看见。
- **心跳**：每次探活写一行到心跳日志（含 pid / uptime / restarts）。
  其他会话或预检可用**心跳 mtime 判活**，不用猜。
- 零第三方依赖，标准库即可；Windows / Linux 同码。

用法
----
  python scripts/engine_watchdog.py --cmd "python -u final_entry.py" --cwd E:\\Program\\ctf-agent
  python scripts/engine_watchdog.py --config watchdog.json      # 多目标
  python scripts/engine_watchdog.py --status                    # 只查询，不守护
  python scripts/engine_watchdog.py --stop                      # 停掉上一个守护
  python scripts/engine_watchdog.py --selftest                  # 真杀进程验证自恢复

退出码
------
  0 正常（或 --status 时进程存活） / 1 守护放弃（超重启上限） / 2 目标启动即退出且不再试
  3 参数或环境错 / 4 WATCH_DISABLED（显式 --no-watch，故意留的非零码，便于门禁抓）
"""

from __future__ import annotations

import argparse
import json
import os
import subprocess
import sys
import tempfile
import threading
import time
from pathlib import Path

DEFAULT_INTERVAL = 4.0        # 探活间隔（秒）；保证 kill 后 <10s 自恢复
DEFAULT_BOOT_GRACE = 5.0      # 存活短于此 = "启动即退出"，非偶发崩溃
DEFAULT_MAX_RESTARTS = 8
DEFAULT_RESET_AFTER = 120.0   # 稳定运行这么久后，崩溃计数清零
DEFAULT_BACKOFF_CAP = 30.0
HEARTBEAT_MAX_BYTES = 1_000_000
HEARTBEAT_TRUNC_BYTES = 200_000

PIDFILE_NAME = "engine_watchdog.pid"
HEARTBEAT_NAME = "engine_watchdog.log"
CHILD_PID_NAME = "engine_watchdog.child.pid"


# --------------------------------------------------------------------------
# 工具
# --------------------------------------------------------------------------
def _now() -> str:
    return time.strftime("%H:%M:%S")


def _alive(pid: int) -> bool:
    """跨平台存活性判断（不用第三方库）。"""
    if pid <= 0:
        return False
    try:
        if os.name == "nt":
            # Windows 控制台默认 GBK，必须显式声明解码方式；PID 是 ASCII，
            # errors=replace 足以存活判定（本机踩过：默认 utf-8 解码 GBK 直接抛异常）
            r = subprocess.run(
                ["tasklist", "/FI", f"PID eq {pid}"],
                capture_output=True, text=True, timeout=10,
                encoding="utf-8", errors="replace",
            )
            return str(pid) in (r.stdout or "")
        os.kill(pid, 0)
        return True
    except Exception:
        return False


def _terminate(pid: int) -> bool:
    """杀进程树（Windows 用 /T 带子进程，Linux 用进程组）。"""
    try:
        if os.name == "nt":
            subprocess.run(["taskkill", "/PID", str(pid), "/T", "/F"],
                           capture_output=True, timeout=15)
        else:
            try:
                os.killpg(os.getpgid(pid), 15)
            except Exception:
                os.kill(pid, 15)
        return True
    except Exception:
        return False


def _tail(path: Path, n: int = 20) -> str:
    try:
        if not path.is_file():
            return ""
        lines = path.read_text(encoding="utf-8", errors="replace").splitlines()
        return "\n".join(lines[-n:])
    except Exception:
        return ""


def _write_heartbeat(path: Path, line: str) -> None:
    """写心跳；超过体积上限保留尾部，避免赛时跑一晚上把盘写满。"""
    try:
        path.parent.mkdir(parents=True, exist_ok=True)
        if path.is_file() and path.stat().st_size > HEARTBEAT_MAX_BYTES:
            # 先按行保留尾部，若仍然超限（单行超大 / 无换行的巨行）再按字节硬切，
            # 否则"一行 1MB"会让按行截断完全失效 —— 自测第 4 项就是抓这个
            raw = path.read_bytes()
            keep = raw.splitlines()[-200:]
            out = b"\n".join(keep)
            if len(out) > HEARTBEAT_TRUNC_BYTES:
                out = out[-HEARTBEAT_TRUNC_BYTES:]
                nl = out.find(b"\n")
                if nl != -1:
                    out = out[nl + 1:]
            path.write_bytes(out + b"\n")
        with path.open("a", encoding="utf-8") as f:
            f.write(line + "\n")
    except Exception:
        pass


def _tail_err(path: Path) -> str:
    t = _tail(path, 20)
    return (" | stderr尾部: " + t.replace("\n", " ⏎ ")) if t.strip() else ""


# --------------------------------------------------------------------------
# 守护主体
# --------------------------------------------------------------------------
class WatchDog:
    """单目标守护。可在线程里跑（selftest 用）或前台阻塞跑（赛时用）。"""

    def __init__(self, cmd: list[str], cwd: Path | None = None,
                 log_dir: Path | None = None,
                 interval: float = DEFAULT_INTERVAL,
                 boot_grace: float = DEFAULT_BOOT_GRACE,
                 max_restarts: int = DEFAULT_MAX_RESTARTS,
                 reset_after: float = DEFAULT_RESET_AFTER,
                 name: str = "engine",
                 env: dict | None = None,
                 quiet: bool = False):
        self.cmd = cmd
        self.cwd = cwd or Path.cwd()
        self.log_dir = Path(log_dir) if log_dir else (self.cwd / "logs")
        self.interval = max(0.5, float(interval))
        self.boot_grace = float(boot_grace)
        self.max_restarts = int(max_restarts)
        self.reset_after = float(reset_after)
        self.name = name
        self.env = env
        self.quiet = quiet

        self.heartbeat = self.log_dir / HEARTBEAT_NAME
        self.child_pidfile = self.log_dir / CHILD_PID_NAME
        self.proc: subprocess.Popen | None = None
        self.started_at = 0.0
        self.restarts = 0
        self.stopped = threading.Event()
        self.exit_code = 0
        self.out_log = self.log_dir / f"{name}.out"
        self.err_log = self.log_dir / f"{name}.err"

    # -- 子进程生命周期 -----------------------------------------------------
    def _spawn(self) -> subprocess.Popen:
        self.log_dir.mkdir(parents=True, exist_ok=True)
        out = self.out_log.open("a", encoding="utf-8")
        err = self.err_log.open("a", encoding="utf-8")
        # ⚠️ POSIX 必须让子进程自成进程组（setsid），否则 _terminate 里的
        #    os.killpg(os.getpgid(pid)) 会把**守护自己**一起杀掉 —— 同组自杀。
        #    Windows 没有进程组语义，走 taskkill /T，故不加此参数。
        extra = {"start_new_session": True} if os.name != "nt" else {}
        p = subprocess.Popen(self.cmd, cwd=str(self.cwd), stdout=out,
                             stderr=err, env=self.env or None, **extra)
        self.proc = p
        self.started_at = time.time()
        try:
            self.child_pidfile.write_text(str(p.pid), encoding="utf-8")
        except Exception:
            pass
        self._log(f"START {self.name} pid={p.pid} cmd={' '.join(self.cmd)[:120]}")
        return p

    def _log(self, msg: str) -> None:
        line = f"[{_now()}] {msg}"
        if not self.quiet:
            print(line, flush=True)
        _write_heartbeat(self.heartbeat, line)

    # -- 主循环 -------------------------------------------------------------
    def run(self) -> int:
        self._spawn()
        time.sleep(min(1.0, self.boot_grace / 2))
        if self.proc is not None and self.proc.poll() is not None:
            code = self.proc.returncode
            self._log(f"BOOT_FAIL {self.name} 启动即退出 exit={code}"
                      f"{_tail_err(self.err_log)}")
            self._log("不再重试：启动即退出通常是配置/依赖错，重启无效，需人工修")
            self.exit_code = 2
            return self.exit_code

        backoff = 0.0
        while not self.stopped.is_set():
            self.stopped.wait(self.interval)
            if self.stopped.is_set():
                break
            p = self.proc
            if p is None or p.poll() is None:
                # 存活 → 心跳；稳定运行够久则清零崩溃计数
                if time.time() - self.started_at > self.reset_after:
                    self.restarts = 0
                    backoff = 0.0
                self._tick_heartbeat()
                continue

            # ---- 进程已退出 ----
            code = p.returncode
            up = time.time() - self.started_at
            fast = up < self.boot_grace
            self._log(f"EXIT {self.name} pid={p.pid} exit={code} uptime={up:.1f}s"
                      f"{' [启动即退出]' if fast else ''}{_tail_err(self.err_log)}")
            self.restarts += 1
            if self.restarts > self.max_restarts:
                self._log(f"GIVE_UP {self.name} 重启已达上限 {self.max_restarts}"
                          f" 次，停止守护（fail-closed，不无限重启）")
                self.exit_code = 1
                return self.exit_code
            backoff = min(backoff * 2 if backoff else 1.0, 30.0)
            self._log(f"RESTART {self.name} 第 {self.restarts}/{self.max_restarts}"
                      f" 次，退避 {backoff:.0f}s")
            self.stopped.wait(backoff)
            if self.stopped.is_set():
                break
            self._spawn()
            time.sleep(min(1.0, self.boot_grace / 2))
            if self.proc is not None and self.proc.poll() is not None:
                self._log(f"BOOT_FAIL {self.name} 重启后仍启动即退出 exit="
                          f"{self.proc.returncode}{_tail_err(self.err_log)}")
                self.exit_code = 2
                return self.exit_code
        return self.exit_code

    def _tick_heartbeat(self) -> None:
        p = self.proc
        pid = p.pid if p else -1
        up = time.time() - self.started_at
        _write_heartbeat(
            self.heartbeat,
            f"[{_now()}] HB {self.name} pid={pid} uptime={up:.0f}s "
            f"restarts={self.restarts}/{self.max_restarts}",
        )

    def stop(self) -> None:
        self.stopped.set()
        p = self.proc
        if p is not None and p.poll() is None:
            _terminate(p.pid)


# --------------------------------------------------------------------------
# --status / --stop
# --------------------------------------------------------------------------
def cmd_status(args) -> int:
    log_dir = Path(args.log_dir) if args.log_dir else Path(args.cwd) / "logs"
    pf = log_dir / CHILD_PID_NAME
    hb = log_dir / HEARTBEAT_NAME
    info = {
        "log_dir": str(log_dir),
        "child_pidfile": str(pf),
        "child_alive": False,
        "child_pid": None,
        "heartbeat_age_sec": None,
        "verdict": "NO_DATA",
    }
    if pf.is_file():
        try:
            pid = int(pf.read_text(encoding="utf-8").strip())
            info["child_pid"] = pid
            info["child_alive"] = _alive(pid)
        except Exception:
            pass
    if hb.is_file():
        info["heartbeat_age_sec"] = round(time.time() - hb.stat().st_mtime, 1)
    if info["child_alive"]:
        info["verdict"] = "ALIVE"
    elif info["child_pid"]:
        info["verdict"] = "DEAD"
    print(json.dumps(info, ensure_ascii=False, indent=1))
    return 0 if info["child_alive"] else 1


def cmd_stop(args) -> int:
    log_dir = Path(args.log_dir) if args.log_dir else Path(args.cwd) / "logs"
    pf = log_dir / PIDFILE_NAME
    killed = 0
    if pf.is_file():
        try:
            pid = int(pf.read_text(encoding="utf-8").strip())
            if _alive(pid) and _terminate(pid):
                killed += 1
        except Exception:
            pass
        try:
            pf.unlink()
        except Exception:
            pass
    cpf = log_dir / CHILD_PID_NAME
    if cpf.is_file():
        try:
            pid = int(cpf.read_text(encoding="utf-8").strip())
            if _alive(pid) and _terminate(pid):
                killed += 1
        except Exception:
            pass
    print(json.dumps({"stopped": killed, "log_dir": str(log_dir)},
                     ensure_ascii=False))
    return 0


# --------------------------------------------------------------------------
# 自测：真杀进程，断言 10 秒内自恢复（含负例，防恒绿）
# --------------------------------------------------------------------------
def _selftest() -> int:
    failures: list[str] = []

    def check(cond: bool, msg: str) -> None:
        print(("  ok   " if cond else "  FAIL ") + msg, flush=True)
        if not cond:
            failures.append(msg)

    tmp = Path(tempfile.mkdtemp(prefix="wd_selftest_"))
    child = tmp / "child.py"
    child.write_text(
        "import sys, time\n"
        "print('UP', flush=True)\n"
        "sys.stderr.write('UPERR\\\\n')\n"
        "while True:\n"
        "    time.sleep(0.2)\n",
        encoding="utf-8",
    )

    def wait_pid(prev: int | None, timeout: float = 15.0,
                 log_dir: Path | None = None) -> int | None:
        """等子进程 pid 文件出现且与 prev 不同。"""
        pf = (log_dir or (tmp / "logs")) / CHILD_PID_NAME
        end = time.time() + timeout
        while time.time() < end:
            try:
                pid = int(pf.read_text(encoding="utf-8").strip())
                if pid != prev and _alive(pid):
                    return pid
            except Exception:
                pass
            time.sleep(0.05)
        return None

    def wait_hb(log_dir: Path, timeout: float = 15.0) -> bool:
        """等真正的 HB 心跳行出现 —— 不能用固定 sleep 赌时序。

        Linux 上子进程启动快，固定 sleep(1.6) 会在首次心跳（spawn 后约
        2×interval）之前就 kill，导致该项 flaky：Windows 靠启动慢侥幸绿、
        Linux 仿真必红。等真实事件才与平台无关。
        """
        f = log_dir / HEARTBEAT_NAME
        end = time.time() + timeout
        while time.time() < end:
            try:
                if "HB " in f.read_text(encoding="utf-8", errors="replace"):
                    return True
            except Exception:
                pass
            time.sleep(0.05)
        return False

    print("[1] 崩溃自恢复：kill 后必须在 10s 内重新拉起", flush=True)
    wd = WatchDog(cmd=[sys.executable, "-u", str(child)], cwd=tmp,
                  log_dir=tmp / "logs", interval=1.0, boot_grace=2.0,
                  max_restarts=5, reset_after=5.0, name="t1", quiet=True)
    th = threading.Thread(target=wd.run, daemon=True)
    th.start()
    pid1 = wait_pid(None, 15.0)
    check(pid1 is not None, "子进程已拉起")
    if pid1 is None:
        wd.stop()
        return 1
    check(wait_hb(tmp / "logs"), "稳定运行中产生过 HB 心跳行")
    _terminate(pid1)
    t0 = time.time()
    pid2 = wait_pid(pid1, 15.0)
    dt = time.time() - t0
    check(pid2 is not None and pid2 != pid1, f"kill 后被重新拉起（新 pid={pid2}）")
    check(dt < 10.0, f"恢复耗时 {dt:.1f}s < 10s 验收线")
    hb = (tmp / "logs" / HEARTBEAT_NAME)
    hb_txt = hb.read_text(encoding="utf-8") if hb.is_file() else ""
    check("EXIT" in hb_txt and "RESTART" in hb_txt, "心跳日志记录了 EXIT/RESTART")
    check("HB " in hb_txt, "心跳日志含 HB 行（可供外部用 mtime 判活）")
    wd.stop()
    th.join(timeout=10)

    print("[2] 负例：max_restarts=0 时不得无限重启（必须放弃并置失败）", flush=True)
    tmp2 = tmp / "logs2"
    wd2 = WatchDog(cmd=[sys.executable, "-u", str(child)], cwd=tmp,
                   log_dir=tmp2, interval=1.0, boot_grace=2.0,
                   max_restarts=0, reset_after=9999.0, name="t2", quiet=True)
    code_box: list[int] = []
    th2 = threading.Thread(target=lambda: code_box.append(wd2.run()), daemon=True)
    th2.start()
    p1 = wait_pid(None, 15.0, tmp2)
    check(p1 is not None, "负例子进程已拉起")
    if p1 is not None:
        # 必须跨过启动观察窗口（boot_grace/2）再杀，否则命中的是
        # "启动即退出"路径（BOOT_FAIL rc=2）而非"运行中崩溃"路径（GIVE_UP rc=1）。
        # 两条路径各有断言，别混 —— 首版测试就是在这里假红过。
        # 用 wait_hb 等真实心跳事件，不赌固定 sleep（Linux 上会 flaky）。
        wait_hb(tmp2)
        _terminate(p1)
        end = time.time() + 12
        while time.time() < end and not code_box:
            time.sleep(0.1)
        check(bool(code_box), "守护在崩溃后退出（未无限重启）")
        check(code_box and code_box[0] == 1, f"退出码=1（GIVE_UP），实际={code_box}")
        hb2 = tmp2 / HEARTBEAT_NAME
        t2 = hb2.read_text(encoding="utf-8") if hb2.is_file() else ""
        check("GIVE_UP" in t2, "日志含 GIVE_UP（fail-closed 证据）")
        check("RESTART" not in t2, "未发生重启（额度为 0）")
    wd2.stop()
    th2.join(timeout=10)

    print("[3] 启动即退出：必须 BOOT_FAIL 且不再重试", flush=True)
    tmp3 = tmp / "logs3"
    bad = tmp / "boom.py"
    bad.write_text("import sys\nsys.stderr.write('boom\\\\n')\nsys.exit(9)\n",
                   encoding="utf-8")
    wd3 = WatchDog(cmd=[sys.executable, str(bad)], cwd=tmp, log_dir=tmp3,
                   interval=1.0, boot_grace=2.0, max_restarts=5,
                   name="t3", quiet=True)
    rc3 = wd3.run()
    check(rc3 == 2, f"退出码=2（BOOT_FAIL），实际={rc3}")
    t3 = (tmp3 / HEARTBEAT_NAME).read_text(encoding="utf-8") \
        if (tmp3 / HEARTBEAT_NAME).is_file() else ""
    check("BOOT_FAIL" in t3, "日志含 BOOT_FAIL")
    check("boom" in t3, "日志带出 stderr 尾部（崩溃可取证，不是静默退出）")
    check(t3.count("RESTART") == 0, "启动即退出不做无谓重启")

    print("[4] 心跳体积上限：超限后截断而不是无限增长", flush=True)
    tmp4 = tmp / "logs4"
    tmp4.mkdir(parents=True, exist_ok=True)
    hb4 = tmp4 / HEARTBEAT_NAME
    hb4.write_text("x" * (HEARTBEAT_MAX_BYTES + 1000), encoding="utf-8")
    _write_heartbeat(hb4, "[00:00:00] HB tail-kept")
    size = hb4.stat().st_size
    check(size < HEARTBEAT_MAX_BYTES, f"超限时截断（现在 {size}B < 上限）")
    check("tail-kept" in hb4.read_text(encoding="utf-8", errors="replace"),
          "截断后新心跳仍写入")

    print("[5] 进程隔离（POSIX）：子进程不得与守护同进程组", flush=True)
    if os.name == "nt":
        print("  skip Windows 无进程组语义（走 taskkill /T），不适用")
    else:
        wd5 = WatchDog(cmd=[sys.executable, "-u", str(child)], cwd=tmp,
                       log_dir=tmp / "logs5", interval=1.0, boot_grace=2.0,
                       name="t5", quiet=True)
        th5 = threading.Thread(target=wd5.run, daemon=True)
        th5.start()
        p5 = wait_pid(None, 15.0, tmp / "logs5")
        check(p5 is not None, "隔离子进程已拉起")
        if p5 is not None:
            import os as _os
            same = _os.getpgid(p5) == _os.getpgrp()
            check(not same, "子进程自成进程组（killpg 不会误杀守护自身）")
        wd5.stop()
        th5.join(timeout=10)

    print()
    if failures:
        print(f"FAILED {len(failures)}/{len(failures)} 项：")
        for f in failures:
            print("   - " + f)
        return 1
    print("OK 全部通过")
    return 0


# --------------------------------------------------------------------------
# CLI
# --------------------------------------------------------------------------
def _split_cmd(s: str) -> list[str]:
    import shlex
    return shlex.split(s, posix=(os.name != "nt"))


def main() -> int:
    ap = argparse.ArgumentParser(description="引擎守护：退出自动重启 + 心跳 + 取证")
    ap.add_argument("--cmd", help="被守护的命令（字符串，会 shlex 切分）")
    ap.add_argument("--cwd", default=".", help="子进程工作目录")
    ap.add_argument("--log-dir", default=None, help="心跳/stdout 目录（默认 <cwd>/logs）")
    ap.add_argument("--name", default="engine", help="目标名（用于日志文件前缀）")
    ap.add_argument("--interval", type=float, default=DEFAULT_INTERVAL,
                    help=f"探活间隔秒（默认 {DEFAULT_INTERVAL}，保证 <10s 自恢复）")
    ap.add_argument("--boot-grace", type=float, default=DEFAULT_BOOT_GRACE)
    ap.add_argument("--max-restarts", type=int, default=DEFAULT_MAX_RESTARTS)
    ap.add_argument("--reset-after", type=float, default=DEFAULT_RESET_AFTER)
    ap.add_argument("--no-watch", action="store_true",
                    help="显式关闭守护（退出码 4，日志写 WATCH_DISABLED，绝不静默）")
    ap.add_argument("--status", action="store_true", help="只查询子进程存活状态")
    ap.add_argument("--stop", action="store_true", help="停掉守护与其子进程")
    ap.add_argument("--selftest", action="store_true", help="真杀进程验证自恢复")
    ap.add_argument("--deploy", default=None,
                    help="把本脚本复制到指定目录（如 E:\\Program\\ctf-agent\\scripts）")
    args = ap.parse_args()

    if args.selftest:
        return _selftest()
    if args.deploy:
        dst = Path(args.deploy)
        dst.mkdir(parents=True, exist_ok=True)
        target = dst / Path(__file__).name
        target.write_text(Path(__file__).read_text(encoding="utf-8"),
                          encoding="utf-8")
        print(f"deployed -> {target}")
        return 0
    if args.status:
        return cmd_status(args)
    if args.stop:
        return cmd_stop(args)

    cwd = Path(args.cwd).resolve()
    if not cwd.is_dir():
        print(f"ERROR cwd 不存在: {cwd}", file=sys.stderr)
        return 3
    if not args.cmd:
        print("ERROR 需要 --cmd（或改用 --status / --selftest）", file=sys.stderr)
        return 3

    log_dir = Path(args.log_dir) if args.log_dir else cwd / "logs"
    cmd = _split_cmd(args.cmd)

    if args.no_watch:
        _write_heartbeat(
            log_dir / HEARTBEAT_NAME,
            f"[{_now()}] WATCH_DISABLED {args.name} 显式关闭守护 —— "
            f"进程退出将**无人接管**，这是赛时静默退出的已知事故模式",
        )
        print("WATCH_DISABLED: 守护未启用（退出码 4，供门禁/预检抓取）")
        return 4

    log_dir.mkdir(parents=True, exist_ok=True)
    (log_dir / PIDFILE_NAME).write_text(str(os.getpid()), encoding="utf-8")

    wd = WatchDog(cmd=cmd, cwd=cwd, log_dir=log_dir, interval=args.interval,
                  boot_grace=args.boot_grace, max_restarts=args.max_restarts,
                  reset_after=args.reset_after, name=args.name)
    try:
        return wd.run()
    except KeyboardInterrupt:
        wd.stop()
        return 0


if __name__ == "__main__":
    sys.exit(main())
