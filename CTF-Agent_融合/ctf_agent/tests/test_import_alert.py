# -*- coding: utf-8 -*-
"""core/import_alert.py 的行为锁定（2026-11-10）。

共享告警组件要同时满足两个互相拉扯的要求：
  1. 缺 skill/agent 必须**看得见**（否则「能力不存在」又被记成「模型没解出」）；
  2. 跑批时不能每道题刷一条 warning（否则日志淹没，等于没人看）。

所以按「每进程每模块只报一次」实现。本文件锁住首次可见、后续静默、
不同模块各自独立，以及告警文案必须点明错误归因。
"""
from __future__ import annotations

import logging

from core.import_alert import reset_for_test, warn_import_once

_LOGGER = "core.import_alert"


def _warnings(records):
    return [r for r in records if r.levelno == logging.WARNING]


def test_first_failure_is_visible_and_names_the_capability(caplog) -> None:
    """首次失败必须 warning，且点名模块、点明「不是解不出，是能力不存在」。"""
    reset_for_test()
    with caplog.at_level(logging.WARNING, logger=_LOGGER):
        warn_import_once("skills.demo_solver", ImportError("No module named 'demo_solver'"))
    warns = _warnings(caplog.records)
    assert len(warns) == 1, warns
    msg = warns[0].getMessage()
    assert "skills.demo_solver" in msg
    assert "能力不存在" in msg
    assert "不是「解不出」" in msg
    assert "No module named" in msg, "异常原因必须带进日志，否则无法定位缺哪个依赖"


def test_repeated_failures_are_silent(caplog) -> None:
    """同一模块重复失败不得刷屏。"""
    reset_for_test()
    with caplog.at_level(logging.WARNING, logger=_LOGGER):
        for _ in range(6):
            warn_import_once("skills.demo_solver", RuntimeError("again"))
    assert len(_warnings(caplog.records)) == 1


def test_distinct_modules_each_warn_once(caplog) -> None:
    """去重按模块名，不是全局一刀切；缺两个能力要能看见两次。"""
    reset_for_test()
    with caplog.at_level(logging.WARNING, logger=_LOGGER):
        warn_import_once("skills.a", RuntimeError("x"))
        warn_import_once("agents.b", RuntimeError("y"))
        warn_import_once("skills.a", RuntimeError("x again"))
    warns = _warnings(caplog.records)
    assert len(warns) == 2, [r.getMessage() for r in warns]
    assert {"skills.a", "agents.b"} == {
        next(m for m in ("skills.a", "agents.b") if m in r.getMessage())
        for r in warns
    }
