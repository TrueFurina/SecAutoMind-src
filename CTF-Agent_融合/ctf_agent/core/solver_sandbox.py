"""解题沙盒的工作目录（防「AI 解题时读到答案库」，ITEM4-A 的运行层补充）。

纪律（2026-11-09 定）：**防泄露只防自己——解题/训练时 AI 不得读到答案。**
仓库对外是否公开不在防线上；决定成败的是「解题那个进程读不读得到答案」。

做法：
- solver 子进程的 cwd 不再落仓库根 / ctf_agent 根，而是一次性临时目录；
- 只把**本题真实输入附件**（已过 `core.answer_key_filter`）复制进该目录，
  传入路径一并改写成临时目录内的路径；
- 答案库（`data/ctf_benchmark`）与附件同目录的 `flag.txt` 因此都不在相对路径
  射程内，判分真值本身从不进沙盒。

残余（必须记账，不许当成已闭合）：
    同一用户下的子进程没有文件系统 jail，写死绝对路径仍可读到任意目录。
    真正的闭合需要容器化（mount 只挂工作目录）；本模块只负责把「顺手能读到」
    变成「必须先猜到绝对路径」。
"""

from __future__ import annotations

import logging
import os
import shutil
import tempfile
from typing import Iterable, List, Optional

logger = logging.getLogger(__name__)

_CTF_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))  # ctf_agent/

_workdir: Optional[str] = None


def sandbox_workdir() -> str:
    """本进程的解题沙盒工作目录（惰性创建，退出即留在 %TEMP% 下）。"""
    global _workdir
    if _workdir and os.path.isdir(_workdir):
        return _workdir
    _workdir = tempfile.mkdtemp(prefix="ctf_sbx_")
    logger.info("解题沙盒工作目录: %s", _workdir)
    return _workdir


def ctf_root() -> str:
    """ctf_agent/ 根（供沙盒子进程的 PYTHONPATH 用，保证 skills 仍可 import）。"""
    return _CTF_ROOT


def _safe_name(path: str, taken: set) -> str:
    base = os.path.basename(path.rstrip("\\/")) or "attachment"
    stem, ext = os.path.splitext(base)
    name = base
    i = 1
    while name.lower() in taken:
        name = f"{stem}_{i}{ext}"
        i += 1
    taken.add(name.lower())
    return name


def stage_attachments(attachments: Optional[Iterable[str]]) -> List[str]:
    """把真实输入附件复制进沙盒工作目录，返回新路径（解题代码只看得见这些）。

    fail-open：不存在的路径 / 目录型附件原样保留（宁可少隔离，不许把可解输入弄丢）。
    """
    items = [str(a) for a in (attachments or []) if str(a).strip()]
    if not items:
        return []

    wd = sandbox_workdir()
    dest_dir = os.path.join(wd, "input")
    os.makedirs(dest_dir, exist_ok=True)

    taken: set = set()
    out: List[str] = []
    for src in items:
        try:
            if not os.path.exists(src) or os.path.isdir(src):
                # 目录/缺失：不复制（复制整个目录既慢又会把同目录答案带进来）
                logger.warning("附件未暂存（缺失或目录）：%s", src)
                out.append(src)
                continue
            name = _safe_name(src, taken)
            dst = os.path.join(dest_dir, name)
            shutil.copy2(src, dst)
            out.append(dst)
        except Exception as exc:  # noqa: BLE001 - 暂存失败不许中断解题
            logger.warning("附件暂存失败（保留原路径）：%s (%s)", src, exc)
            out.append(src)
    return out


def cleanup() -> None:
    """删掉本次沙盒工作目录（幂等）。"""
    global _workdir
    if _workdir:
        shutil.rmtree(_workdir, ignore_errors=True)
        _workdir = None
