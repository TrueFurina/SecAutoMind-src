# -*- coding: utf-8 -*-
"""跨模块共用的「导入失败一次性告警」（2026-11-10）。

## 为什么存在

`skills/rsa_fermat_factor.py` 的静默降级（11-08）、
`skills/misc_grid_resample.py` 的不可达守卫（11-10 上午）已经证明：
导入失败若只留一条 debug 日志然后 `return None`，在赛时表现为「模型没解出」，
真因却是 skill/agent 根本没装上——错误归因到模型能力上。

`core/presolve.py` 早有 `_warn_import_once()` 治这个病，但它定义在 presolve
内部，其它模块（`agents/math_engine.py` / `core/fallbacks.py`）没法复用，各自又
写了 `except Exception: return None`。本模块把这条纪律抽成无循环依赖的共享工具：
只依赖标准库 logging，可被 core / agents / skills 任意一方安全导入。

## 语义

- 每进程、每模块**只报一次** warning（跑批时一道题一个 warning 会刷屏）；
- 措辞必须点明「不是「解不出」，是能力不存在」，方便读日志的人立即分辨；
- **不改返回值、不改判分口径**：调用方仍按原来的 `None` / `{}` 处理。
"""
from __future__ import annotations

import logging

_log = logging.getLogger(__name__)
_logged: set[str] = set()


def warn_import_once(module: str, exc: BaseException) -> None:
    """导入 skill/agent 失败：首次 warning，后续静默防刷屏。

    Args:
        module: 被导入的完整模块名（必须精确，日志要能直接定位到缺哪个能力）。
        exc: 捕获到的异常；只取字符串表示，不做任何网络或文件操作。
    """
    if module in _logged:
        return
    _logged.add(module)
    _log.warning(
        "导入 %s 失败（skill/agent 缺失、语法错误或依赖未装）：%s。"
        "这不是「解不出」，是能力不存在。", module, exc)


def reset_for_test() -> None:
    """清空去重集合，仅供测试隔离用；生产代码不调用。"""
    _logged.clear()
