#!/usr/bin/env python3
"""agentic 跑批入口：显式打开 stepfun 的工具能力。

## 为什么需要这个 wrapper

`ctf_stepfun_orchestrator.PROVIDERS["stepfun"]["supports_tools"] = False` 是配置层
的一刀切，而 `solve_one()` 里 `if agentic and cfg.get("supports_tools")` 是硬门槛
⇒ 不加这一行，`--agentic` 对 stepfun 直接退化成 pure_llm，跑批结果会被误读成
「agentic 跑过了」。

## 为什么可以直接开

2026-11-07 实测（一次带 tools 的 chat/completions 请求）：
  model=step-3.5-flash  finish_reason=tool_calls
  tool_calls=1  name=run_python  arguments={"code": "123 * 456"}
模型本身支持 function calling，模型名与端点均未改动。

## 边界（必须与证据一起读）

- 本文件**只**改 `supports_tools` 一个布尔，其余全部透传给 `main()`；
  不改 `verify_flag()`、不改 `run_python_tool()`、不改任何判分或隔离代码。
- 它不提供隔离。隔离由外部 UID + iptables 规则保证（见 docs/evidence/
  private_pool_v1_20261107/agentic_isolation_20261107.json），两者缺一不可：
  wrapper 负责「模型能用工具」，外部规则负责「工具不能出网」。
- 若上游把 `supports_tools` 改成 True，本 patch 变成 no-op（幂等），可安全保留。
"""
import os
import sys

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

import ctf_stepfun_orchestrator as orch  # noqa: E402

PATCH_TARGET = "PROVIDERS['stepfun']['supports_tools']"
_want = True
_had = orch.PROVIDERS["stepfun"].get("supports_tools")
orch.PROVIDERS["stepfun"]["supports_tools"] = _want

# 落一行 stderr：让跑批日志自己证明 patch 真的生效过（不是「声明了但没跑」）
print("[agentic-wrapper] %s: %r -> %r (%s)"
      % (PATCH_TARGET, _had, _want, "no-op" if _had == _want else "patched"),
      file=sys.stderr)

if __name__ == "__main__":
    sys.exit(orch.main())
