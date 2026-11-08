# -*- coding: utf-8 -*-
"""缺依赖不得静默降级（2026-11-08）。

背景：`skills/rsa_fermat_factor.py` 在缺 gmpy2 时 `run()` 恒返回 None。返回 None 在
本项目的语义是「试过了，没解出」——调用方（`core/presolve.py` 的 L2 RSA 通道、
`agents/crypto_toolkit.py` 十余处 fallback）无法区分「能力不存在」与「模型/算法没解出」。
于是赛时表现为「RSA 解不出」，账记在模型身上，真因是依赖没装。

实测对照：本机（Python 3.14，pip 取不到 gmpy2）12 条 RSA 用例红；服务器（gmpy2 在）同代码全绿。
两处代码一模一样，差的只是环境——这正是「静默降级」最贵的形态：错误归因。

本测试守两件事：
1. 缺依赖时**必须发一次 warning**，措辞明确说明「不是解不出，是能力不存在」；
2. 只发一次（不刷屏），且返回值语义不变（仍是 None）。
"""
import logging

import pytest

from skills import rsa_fermat_factor as skill


def test_missing_deps_warns_loudly_and_only_once(monkeypatch, caplog):
    """缺 gmpy2 时必须告警，且只喊一次——静默降级会把错误记到模型账上。"""
    monkeypatch.setattr(skill, "HAS_DEPS", False)
    monkeypatch.setattr(skill, "_DEPS_WARNED", False)
    monkeypatch.setattr(skill, "_DEP_ERR", "No module named 'gmpy2'")

    with caplog.at_level(logging.WARNING, logger=skill.__name__):
        first = skill.run({"n": 15, "e": 3, "c": 2})
        second = skill.run({"n": 15, "e": 3, "c": 2})

    assert first is None and second is None, "缺依赖时返回值语义必须是 None（调用方已按 None 判）"
    warns = [r for r in caplog.records if r.levelno == logging.WARNING]
    assert len(warns) == 1, f"应只告警一次，实际 {len(warns)} 次：{[r.getMessage() for r in warns]}"
    msg = warns[0].getMessage()
    assert "依赖缺失" in msg and "gmpy2" in msg, f"告警必须点名缺什么：{msg}"
    assert "能力不存在" in msg, "告警必须说明「不是解不出，是能力不存在」——这正是错误归因的根"


def test_dep_flag_is_consistent_with_import():
    """HAS_DEPS 必须与真实可导入性一致（防止有人为了让测试变绿把标志写死 True）。"""
    try:
        import gmpy2  # noqa: F401
        real = True
    except ImportError:
        real = False
    assert skill.HAS_DEPS is real, (
        "HAS_DEPS 与 gmpy2 实际可导入性不一致：写死 True 会让缺依赖时继续跑并抛别的异常，"
        "写死 False 会让有依赖时也不干活")


if __name__ == "__main__":
    raise SystemExit(pytest.main([__file__, "-q"]))
