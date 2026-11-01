#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""CTF 靶场批量回归器 —— 闭环「每次改动 → 全量回归 → 基线对比」。

## 为什么需要它

《决赛升级建议》§五（真题回测闭环）把「升级后必跑分、与基线对比」列为长期竞争力支点。
现有 `ctf_arena.py`（单实例靶场裁判）与 `ycb2026_run.py`（静态题测量）都只产出「本次结果」，
**缺基线对比 / 退化判读那一半**：你跑完一次，没法一眼看出「这次架构改动相比上次退步了哪几题」。
本脚本补上这一半。

## 自包含说明（重要）

本脚本**不依赖**任何未提交的工作树文件：它把靶场裁判原语**内联**进自身
（本地静态模式 = subprocess 捕输出判 flag；服务/pwn 模式 = socket 中继，逻辑等价于 ctf_arena.py）。
这样它能在干净的 main 检出上独立构建、测试、提交，不与并行会话的未跟踪 WIP 纠缠。
若日后 `ctf_arena.py` 并入 main，可将其重构为本脚本的底层依赖。

## 两种判分模式

- `local`（默认）：跑 cmd，捕合并 stdout/stderr，判 flag 明文在不在输出里。
  覆盖 reverse / crypto / misc 等「跑分析脚本、打印 flag」的静态题——也是基准主体。
- `service`：起端口、接受一次连接、把 cmd 当脆弱服务跑、socket 中继、transcript 判分。
  覆盖 pwn / 服务类题（cmd 是脆弱程序，解题者连接它）。

判分纪律（与 ctf_arena 一致）：**只看输出里有没有 flag 明文**，不猜、不看退出码。

## 仪器自检（--self-test，部署后 / 改动后先跑）

用假解题者（cat flag）证明判分确实说 SOLVED、负例（echo nope）说 UNSOLVED、
基线对比逻辑正确。自检不过不得信任真跑结果。

## 用法

```bash
# 仪器自检
python3 ctf_arena_batch.py --self-test

# 真跑：读 manifest（local 模式），写账本 + 存基线
python3 ctf_arena_batch.py --manifest arena_manifest.json \
    --out ledger.jsonl --save-baseline baseline.json

# service 模式（pwn）：每个实例用 service 模式
python3 ctf_arena_batch.py --manifest pwn_manifest.json --mode service ...

# 回归：与基线比，退化 > 0 即闸门红（exit 3）
python3 ctf_arena_batch.py --manifest arena_manifest.json \
    --baseline baseline.json --gate-regression 0
```

退出码：0 = 全绿（或退化在闸门内）；1 = 运行错误（环境/配置，绝不算 UNSOLVED）；
2 = 有题 UNSOLVED（能力层面）；3 = 退化超闸门（能力倒退，最高优先级）。
"""
from __future__ import annotations

import argparse
import json
import os
import socket
import subprocess
import sys
import tempfile
import threading
import time


# ───────────────────────── 内联靶场裁判原语 ─────────────────────────

def _judge_local(cmd: str, cwd: str, flag_value: str | None, timeout: float,
                 log_path: str | None) -> int:
    """本地静态模式：subprocess 捕合并输出，判 flag 明文。无 socket。"""
    if flag_value is not None:
        os.makedirs(cwd, exist_ok=True)
        with open(os.path.join(cwd, "flag"), "w", encoding="utf-8") as fh:
            fh.write(flag_value + "\n")
    try:
        proc = subprocess.run(cmd, shell=True, cwd=cwd, capture_output=True,
                              text=True, timeout=timeout)
        raw = ((proc.stdout or "") + (proc.stderr or "")).encode("utf-8", "replace")
    except subprocess.TimeoutExpired:
        raw = b""
    if log_path:
        with open(log_path, "wb") as fh:
            fh.write(raw)
    if flag_value is None:
        return 1
    return 0 if flag_value.encode() in raw else 2


def _judge_service(cmd: str, cwd: str, port: int, flag_value: str | None,
                   flag_file: str, timeout: float, auto_send: bytes | None,
                   log_path: str | None, flag_path: str | None,
                   bind: str = "127.0.0.1") -> int:
    """服务/pwn 模式：socket 中继 + transcript 判分（等价于 ctf_arena.run_arena）。"""
    if flag_value is not None:
        if flag_path:
            path = flag_path
            os.makedirs(os.path.dirname(path) or ".", exist_ok=True)
        else:
            path = os.path.join(cwd, flag_file)
        with open(path, "w", encoding="utf-8") as fh:
            fh.write(flag_value + "\n")

    srv = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    srv.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    out: list[bytes] = []
    try:
        srv.bind((bind, port))
        srv.listen(1)
        srv.settimeout(timeout)
        conn, _ = srv.accept()
        conn.settimeout(timeout)
        proc = subprocess.Popen(cmd, shell=True, cwd=cwd,
                                stdin=subprocess.PIPE, stdout=subprocess.PIPE,
                                stderr=subprocess.STDOUT, bufsize=0)
        stop = threading.Event()

        def _to_sock():
            try:
                while True:
                    chunk = proc.stdout.read(1)
                    if not chunk:
                        break
                    out.append(chunk)
                    conn.sendall(chunk)
            except Exception:
                pass
            finally:
                stop.set()

        def _from_sock():
            try:
                while not stop.is_set():
                    chunk = conn.recv(4096)
                    if not chunk:
                        break
                    proc.stdin.write(chunk)
                    proc.stdin.flush()
            except Exception:
                pass
            finally:
                try:
                    proc.stdin.close()
                except Exception:
                    pass

        t_out = threading.Thread(target=_to_sock, daemon=True)
        t_out.start()
        if auto_send:
            try:
                proc.stdin.write(auto_send)
                proc.stdin.flush()
            except Exception:
                pass
        t_in = threading.Thread(target=_from_sock, daemon=True)
        t_in.start()

        deadline = time.time() + timeout
        while time.time() < deadline:
            if proc.poll() is not None and stop.is_set():
                break
            time.sleep(0.05)
        if proc.poll() is None:
            proc.kill()
        try:
            proc.wait(timeout=3)
        except Exception:
            pass
        stop.set()
        try:
            conn.close()
        except Exception:
            pass
    except socket.timeout:
        pass
    finally:
        srv.close()

    raw = b"".join(out)
    if log_path:
        with open(log_path, "wb") as fh:
            fh.write(raw)
    if flag_value is None:
        return 1
    return 0 if flag_value.encode() in raw else 2


# ───────────────────────── 批量 / 基线 / 报告 ─────────────────────────

def _run_one(inst: dict, timeout: float) -> dict:
    name = inst.get("name", "?")
    mode = inst.get("mode", "local")
    cwd = inst.get("cwd") or os.getcwd()
    port = int(inst.get("port", 31337))
    flag = inst.get("flag")
    flag_path = inst.get("flag_path")
    auto_hex = inst.get("auto_send_hex")
    log_path = inst.get("log") or os.path.join(
        tempfile.gettempdir(), "arena_%s.log" % name)
    if mode == "service":
        rc = _judge_service(inst["cmd"], cwd, port, flag,
                           inst.get("flag_file", "flag"), timeout,
                           bytes.fromhex(auto_hex) if auto_hex else None,
                           log_path, flag_path)
    else:
        rc = _judge_local(inst["cmd"], cwd, flag, timeout, log_path)
    return {"name": name, "verdict": {0: "SOLVED", 2: "UNSOLVED"}.get(rc, "ERROR"),
            "rc": rc, "elapsed": 0, "log": log_path}


def batch(manifest: list, timeout: float) -> list:
    out = []
    t0 = time.time()
    for inst in manifest:
        r = _run_one(inst, timeout)
        r["elapsed"] = round(time.time() - t0, 2)  # 累计耗时（顺序执行）
        out.append(r)
    return out


def compare(results: list, baseline: dict) -> dict:
    base = {r["name"]: r["verdict"] for r in baseline.get("results", [])}
    rep = {"stable": [], "new_solved": [], "regressed": [], "new_broken": [], "unknown": []}
    for r in results:
        n, v = r["name"], r["verdict"]
        b = base.get(n)
        if b is None:
            rep["unknown"].append(n)
        elif b == v:
            rep["stable"].append(n)
        elif b != "SOLVED" and v == "SOLVED":
            rep["new_solved"].append(n)
        elif b == "SOLVED" and v != "SOLVED":
            rep["regressed"].append(n)
        else:
            rep["new_broken"].append(n)
    return rep


def _self_test_case(name: str, solver_path: str, flag: str, mode: str = "local") -> dict:
    tmp = tempfile.mkdtemp(prefix="arena_selftest_")
    inst = {"name": name, "cmd": '"%s" "%s"' % (sys.executable, solver_path),
            "cwd": tmp, "flag": flag}
    if mode == "service":
        inst["port"] = 32600 + (hash(name) % 1000)
    return _run_one(inst, 5)


def self_test() -> int:
    print("[self-test] 启动仪器自检 ...")
    tmp = tempfile.mkdtemp(prefix="arena_selftest_")
    pos_solver = os.path.join(tmp, "pos_solver.py")
    neg_solver = os.path.join(tmp, "neg_solver.py")
    with open(pos_solver, "w", encoding="utf-8") as fh:
        fh.write("import sys\nsys.stdout.write(open('flag', encoding='utf-8').read())\n")
    with open(neg_solver, "w", encoding="utf-8") as fh:
        fh.write("print('nope')\n")
    pos = _self_test_case("pos", pos_solver, "DASCTF{selftest_pos}")
    neg = _self_test_case("neg", neg_solver, "DASCTF{selftest_neg}")
    base = {"results": [{"name": "pos", "verdict": "SOLVED"},
                        {"name": "neg", "verdict": "UNSOLVED"}]}
    rep = compare([pos, neg], base)
    ok = (pos["verdict"] == "SOLVED"
          and neg["verdict"] == "UNSOLVED"
          and "pos" in rep["stable"]
          and "neg" in rep["stable"]
          and not rep["regressed"]
          and not rep["new_broken"])
    print("[self-test] pos=%s neg=%s compare=%s" % (pos["verdict"], neg["verdict"], rep))
    print("[self-test] %s" % ("PASS" if ok else "FAIL"))
    return 0 if ok else 1


def _report(results: list, rep: dict | None, gate: int) -> int:
    solved = sum(1 for r in results if r["verdict"] == "SOLVED")
    total = len(results)
    print("\n===== 批量回归报告 =====")
    print("实例数=%d  解出=%d  通过率=%.1f%%"
          % (total, solved, 100.0 * solved / total if total else 0))
    for r in results:
        print("  %-20s %s" % (r["name"], r["verdict"]))
    if rep is not None:
        print("-- 基线对比 --")
        print("  stable=%d new_solved=%d regressed=%d new_broken=%d unknown=%d"
              % (len(rep["stable"]), len(rep["new_solved"]), len(rep["regressed"]),
                 len(rep["new_broken"]), len(rep["unknown"])))
        for cat in ("regressed", "new_broken", "new_solved", "unknown"):
            if rep[cat]:
                print("  %s: %s" % (cat, ", ".join(rep[cat])))
    if rep is not None and len(rep["regressed"]) > gate:
        print("✗ 退化超闸门（%d > %d）→ exit 3" % (len(rep["regressed"]), gate))
        return 3
    if any(r["verdict"] == "ERROR" for r in results):
        print("✗ 存在运行错误（环境/配置）→ exit 1")
        return 1
    if any(r["verdict"] == "UNSOLVED" for r in results):
        print("⚠ 存在未解实例（能力层面）→ exit 2")
        return 2
    print("✓ 全绿")
    return 0


def main(argv=None) -> int:
    ap = argparse.ArgumentParser(description="CTF 靶场批量回归器")
    ap.add_argument("--self-test", action="store_true", help="仪器自检（正/负例 + 基线逻辑）")
    ap.add_argument("--manifest", help="实例清单 JSON：[{name,cmd,cwd,mode,port,flag,...}]")
    ap.add_argument("--out", help="JSONL 账本输出路径")
    ap.add_argument("--save-baseline", help="把本次结果存为基线 JSON 的路径")
    ap.add_argument("--baseline", help="历史基线 JSON（与本次对比）")
    ap.add_argument("--mode", default="local", choices=["local", "service"],
                    help="默认判分模式（实例可单条覆盖）")
    ap.add_argument("--gate-regression", type=int, default=0, help="退化容忍上限，超出 → exit 3")
    ap.add_argument("--timeout", type=float, default=20.0, help="单实例超时（秒）")
    args = ap.parse_args(argv)

    if args.self_test:
        return self_test()

    if not args.manifest:
        print("缺少 --manifest（或非 --self-test）", file=sys.stderr)
        return 1
    with open(args.manifest, encoding="utf-8") as fh:
        manifest = json.load(fh)
    if not isinstance(manifest, list) or not manifest:
        print("manifest 必须是非空 list", file=sys.stderr)
        return 1
    # 全局默认 mode 注入到每条实例（实例可覆盖）
    for inst in manifest:
        inst.setdefault("mode", args.mode)

    results = batch(manifest, args.timeout)

    if args.out:
        with open(args.out, "w", encoding="utf-8") as fh:
            for r in results:
                fh.write(json.dumps(r, ensure_ascii=False) + "\n")

    baseline_data = None
    if args.save_baseline:
        baseline_data = {
            "results": results,
            "total": len(results),
            "solved": sum(1 for r in results if r["verdict"] == "SOLVED"),
        }
        with open(args.save_baseline, "w", encoding="utf-8") as fh:
            json.dump(baseline_data, fh, ensure_ascii=False, indent=2)

    rep = None
    if args.baseline:
        with open(args.baseline, encoding="utf-8") as fh:
            baseline_data = json.load(fh)
        rep = compare(results, baseline_data)

    return _report(results, rep, args.gate_regression)


if __name__ == "__main__":
    sys.exit(main())
