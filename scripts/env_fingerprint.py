#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""env_fingerprint.py — 实验/基准产物的环境指纹块（REA #33 / #239）

为什么必须有：一份"准确率 62%"的结果，缺环境指纹就等于不可复现。三个月后
没人知道它跑在哪个 Python、哪个 commit、哪套依赖上；一旦数字对不上，
排查会从"代码改坏了"开始，而真实原因通常是"换了解释器/依赖小版本"。

本模块只做一件事：产出一个**可写进结果文件**的 dict，字段固定、无路径泄漏：

    {
      "python": "3.13.12",
      "implementation": "CPython",
      "platform": "Windows-11-10.0.22631-SP0",
      "machine": "AMD64",
      "git_head": "abc1234",          # 短 SHA；仓库不可用时为 null
      "git_dirty": true,              # 工作区是否脏（脏 = 结果不可精确复现）
      "deps": {"pyyaml": "6.0.1", ...},   # 只记已安装的关键包版本
      "seeds": {...},                 # 由调用方传入
      "captured_at": "2026-10-20T12:00:00+00:00"
    }

纪律：
  * **不写绝对路径**（公开仓库不暴露本机目录结构）；
  * **不写环境变量原值**（可能含密钥）；只允许写"哪些变量被设置过"的 SHA256 指纹；
  * 取不到的项写 `null` 并记入 `unknown`，**不编默认值**——"未检查"不等于"没问题"。
"""
from __future__ import annotations

import hashlib
import os
import platform
import subprocess
import sys
from datetime import datetime, timezone

# 关键依赖：基准/评测结果会受它们影响；缺了就记 null（而不是跳过该项）
_WATCHED_DEPS = ("pyyaml", "requests", "numpy", "pandas", "openai", "httpx")

# 允许记录"是否设置过"的环境变量（值本身不进结果，只进指纹）
_WATCHED_ENV = ("CUDA_VISIBLE_DEVICES", "OMP_NUM_THREADS", "PYTHONHASHSEED", "TZ")


def _git(args: list[str], cwd: str | None = None) -> str | None:
    try:
        out = subprocess.run(["git", *args], cwd=cwd, capture_output=True, text=True,
                             timeout=10)
        return out.stdout.strip() if out.returncode == 0 else None
    except (OSError, subprocess.SubprocessError):
        return None


def git_state(cwd: str | None = None) -> dict:
    """仓库状态：短 HEAD + 是否脏。非 git 目录返回 null（不猜）。"""
    head = _git(["rev-parse", "--short", "HEAD"], cwd)
    status = _git(["status", "--porcelain"], cwd)
    return {
        "git_head": head,
        "git_dirty": (bool(status) if status is not None else None),
    }


def deps() -> dict:
    """关键依赖版本。未安装 = null（不省略键，便于跨结果对比）。"""
    from importlib import metadata

    out: dict[str, str | None] = {}
    for name in _WATCHED_DEPS:
        try:
            out[name] = metadata.version(name)
        except Exception:      # PackageNotFoundError 等
            out[name] = None
    return out


def env_hashes() -> dict:
    """环境变量**是否设置**的指纹（不含值）。设置过 = sha256(名字+值)[:12]。"""
    out: dict[str, str | None] = {}
    for name in _WATCHED_ENV:
        raw = os.environ.get(name)
        out[name] = (hashlib.sha256(f"{name}={raw}".encode("utf-8")).hexdigest()[:12]
                     if raw is not None else None)
    return out


def collect(cwd: str | None = None, seeds: dict | None = None) -> dict:
    """组装指纹。`unknown` 列出取不到的项——下游据此判断可信度，不要静默。"""
    data = {
        "python": platform.python_version(),
        "implementation": platform.python_implementation(),
        "platform": platform.platform(),
        "machine": platform.machine(),
        **git_state(cwd),
        "deps": deps(),
        "env_fingerprints": env_hashes(),
        "seeds": seeds or {},
        "captured_at": datetime.now(timezone.utc).isoformat(timespec="seconds"),
    }
    unknown = [k for k, v in data.items() if v is None]
    unknown += [f"deps.{k}" for k, v in data["deps"].items() if v is None]
    data["unknown"] = sorted(unknown)
    return data


def stamp(payload: dict, cwd: str | None = None, seeds: dict | None = None) -> dict:
    """就地写入 `env` 字段并返回 payload（调用方少写一行）。"""
    payload["env"] = collect(cwd=cwd, seeds=seeds)
    return payload


def main(argv: list[str] | None = None) -> int:
    import argparse
    import json

    ap = argparse.ArgumentParser(description="打印当前环境指纹（JSON）")
    ap.add_argument("--cwd", default=None)
    args = ap.parse_args(argv)
    print(json.dumps(collect(cwd=args.cwd), ensure_ascii=False, indent=2))
    return 0


if __name__ == "__main__":
    sys.exit(main())
