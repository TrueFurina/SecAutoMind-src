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


def stage_attachments(attachments: Optional[Iterable[str]], subdir: str = "input") -> List[str]:
    """把真实输入附件复制进沙盒工作目录，返回新路径（解题代码只看得见这些）。

    fail-open：不存在的路径 / 目录型附件原样保留（宁可少隔离，不许把可解输入弄丢）。
    """
    items = [str(a) for a in (attachments or []) if str(a).strip()]
    if not items:
        return []

    wd = sandbox_workdir()
    dest_dir = os.path.join(wd, subdir)
    os.makedirs(dest_dir, exist_ok=True)

    taken: set = set()
    out: List[str] = []
    kept: List[str] = []
    for src in items:
        try:
            if not os.path.exists(src) or os.path.isdir(src):
                # 目录/缺失：不复制（复制整个目录既慢又会把同目录答案带进来）
                logger.debug("附件未暂存（缺失或目录）：%s", src)
                kept.append(src)
                out.append(src)
                continue
            name = _safe_name(src, taken)
            dst = os.path.join(dest_dir, name)
            shutil.copy2(src, dst)
            out.append(dst)
        except Exception as exc:  # noqa: BLE001 - 暂存失败不许中断解题
            logger.debug("附件暂存失败（保留原路径）：%s (%s)", src, exc)
            kept.append(src)
            out.append(src)
    if kept:
        # 逐条只在 DEBUG；汇总一条 WARNING，避免整库加载时刷屏几百行
        logger.warning("附件未暂存 %d/%d（缺失或目录，已保留原路径）：%s",
                       len(kept), len(items), os.path.basename(kept[0]))
    return out


def cleanup() -> None:
    """删掉本次沙盒工作目录（幂等）。"""
    global _workdir
    if _workdir:
        shutil.rmtree(_workdir, ignore_errors=True)
        _workdir = None


def _resolve_existing(p: str) -> Optional[str]:
    """把题库里的相对附件路径解析成真实存在的绝对路径（口径对齐 eval.corpus）。"""
    if os.path.isabs(p):
        return p if os.path.exists(p) else None
    for cand in (os.path.join(_CTF_ROOT, p), p, os.path.join(os.path.dirname(_CTF_ROOT), p)):
        if os.path.exists(cand):
            return os.path.abspath(cand)
    return None


def _question_subdir(question) -> str:
    """每道题一个独立暂存子目录：防不同题同名附件互相覆盖，也防跨题串看。"""
    qid = str(getattr(question, "id", "") or "q")
    safe = "".join(c if (c.isalnum() or c in "._-") else "_" for c in qid)[:80]
    return os.path.join("q", safe or "q")


def stage_question_attachments(question) -> List[str]:
    """把一道题的附件暂存进沙盒工作目录，返回**绝对**路径列表。

    为什么需要它：本地题库 988 条附件**全是相对 ctf_agent/ 的写法**
    （`data/questions_ext/_attachments/crypto/xxx/ciphertext`）。沙盒 cwd 换到临时
    目录后，这类相对写法一律失效（脚本 open 不到），所以必须在加载层就把真实输入
    复制进来并改成绝对路径。

    两条硬规则：
    - 答案类附件（内容哈希命中题面真值）**不暂存**，保留原路径交 answer_key_filter
      剔除——否则等于把答案复制进沙盒；
    - 复制失败/来源是目录时保留原路径（fail-open，宁可少隔离也不许弄丢可解输入）。
    """
    try:
        from core.answer_key_filter import is_answer_key_attachment
    except Exception:  # noqa: BLE001 - 纯函数缺失不应挡住加载
        is_answer_key_attachment = lambda q, p: False  # type: ignore

    srcs = [str(a) for a in (getattr(question, "attachments", None) or []) if str(a).strip()]
    if not srcs:
        return []

    resolved: List[str] = []
    for s in srcs:
        r = _resolve_existing(s)
        if r is None:
            resolved.append(s)      # 找不到就原样留着，让既有「缺附件」统计照旧暴露
        else:
            resolved.append(r)

    stageable: List[str] = []
    kept: List[str] = []
    for r in resolved:
        try:
            if is_answer_key_attachment(question, r):
                kept.append(r)      # 答案文件不进沙盒
            else:
                stageable.append(r)
        except Exception:  # noqa: BLE001
            kept.append(r)

    staged = stage_attachments(stageable, subdir=_question_subdir(question))
    out: List[str] = staged + kept
    return out

