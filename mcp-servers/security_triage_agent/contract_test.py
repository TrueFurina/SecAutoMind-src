#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""MCP 出口契约的回归测试 —— 14 项，含变异自检（故意造坏契约，校验必须变红）。

为什么必须有它
--------------
`contract.py` 是**给 LLM 看的自我声明层**。它一旦失效，最危险的失败形态不是
报错，而是**静默通过**：降级的结果照样带一个 `_contract`，只是 `degraded=false`。
那种情况下所有下游测试都是绿的，而调用方拿到的是「看起来成功、实际没做」。

所以本测试分两类：
  · 正向：正常结论必须带齐字段，且原业务字段一个不少（向后兼容）；
  · 变异：伪造 5 种坏契约，`validate()` **必须**逐条报出来——空转的校验器
    比没有校验器更糟，因为它给人已校验的错觉。

跑法：`python contract_test.py`    退出码 0 = 全过
"""
from __future__ import annotations

import json
import sys
from pathlib import Path

HERE = Path(__file__).resolve().parent
if str(HERE) not in sys.path:
    sys.path.insert(0, str(HERE))

from security_agent.mcp import contract as C  # noqa: E402
from security_agent.tools.base import Tool  # noqa: E402
from security_agent.tools.implementations import (  # noqa: E402
    AssetLookupTool,
    CommandExecutionTool,
    FalsePositiveCheckTool,
    HistoryAlertLookupTool,
    HostIsolationSimulatorTool,
    IncidentTriageTool,
    IntelLookupTool,
    IocSearchTool,
    LogLookupTool,
    PlaybookMatcherTool,
    TicketGeneratorTool,
)

ALL_TOOLS = [
    AssetLookupTool(), LogLookupTool(), IntelLookupTool(), HistoryAlertLookupTool(),
    FalsePositiveCheckTool(), IncidentTriageTool(), PlaybookMatcherTool(),
    TicketGeneratorTool(), HostIsolationSimulatorTool(), IocSearchTool(),
    CommandExecutionTool(),
]

_failures: list[str] = []
_checked = 0


def check(cond: bool, msg: str) -> None:
    global _checked
    _checked += 1
    if not cond:
        _failures.append(msg)


# ── T1 常量本身合法 ─────────────────────────────────────────
check(C.SCHEMA_VERSION == "tool-contract/1", "T1 schemaVersion 漂移")
check(len(C.AUTHORITIES) == 4 and "unknown" in C.AUTHORITIES, "T1 权威等级四值不全")
check(set(C.AUTHORITY_MEANING) == set(C.AUTHORITIES), "T1 等级释义与等级列表不同步")

# ── T2 每个工具都声明了合法等级 + 非空固有局限 ─────────────
# 空 limitations 的 observed 工具等于「我保证准确，但不说我只看了一部分」。
for tool in ALL_TOOLS:
    check(isinstance(tool.authority, str) and tool.authority in C.AUTHORITIES,
          f"T2 {tool.name}.authority={tool.authority!r} 非法")
    check(isinstance(tool.limitations, tuple) and len(tool.limitations) > 0,
          f"T2 {tool.name} 未声明固有局限（observed/derived 都必须说明覆盖边界）")

# ── T3 build 基本字段齐全 ───────────────────────────────────
blk = C.build(AssetLookupTool(), {"event": {"id": "E-1"}})
for key in ("schemaVersion", "authority", "coverage", "limitations", "degraded", "evidence"):
    check(key in blk, f"T3 契约缺 {key}")
check(blk["authority"] == "observed", "T3 asset_lookup 应为 observed")
check(blk["degraded"] is False and blk["degradationReason"] is None, "T3 正常结论不应标降级")
check(blk["evidence"]["tool"] == "asset_lookup", "T3 evidence.tool 错")
check(blk["evidence"]["inputDigest"].startswith("sha256:"), "T3 inputDigest 形态错")

# ── T4 非法等级不抛异常，降级为 unknown 并写明 ──────────────
class _Bad(Tool):
    name = "bad_authority"
    authority = "pretty-sure"  # 非法
    limitations = ("夹具",)

bad = C.build(_Bad(), {})
check(bad["authority"] == "unknown", "T4 非法 authority 未降级为 unknown")
check(any("非法" in x for x in bad["limitations"]), "T4 非法 authority 未在 limitations 留痕")

# ── T5 降级强制压到 unknown + partial ─────────────────────
deg = C.build(AssetLookupTool(), {}, degraded=True, degradation_reason="上游不可用")
check(deg["authority"] == "unknown", "T5 降级后 authority 必须 unknown")
check(deg["coverage"]["status"] == "partial", "T5 降级后 coverage 不得为 complete")
check(any("已降级" in x for x in deg["limitations"]), "T5 降级原因未进 limitations")

# ── T6 正常契约通过校验 ───────────────────────────────────
ok = C.attach({"tool_name": "asset_lookup", "summary": "s", "details": []},
              AssetLookupTool(), {"event": {"id": "E-1"}})
check(C.validate(ok) == [], f"T6 正常契约被误判: {C.validate(ok)}")

# ── T7 向后兼容：原业务字段一个不少 ───────────────────────
check(ok["tool_name"] == "asset_lookup" and ok["summary"] == "s" and ok["details"] == [],
      "T7 attach 破坏了原业务字段")

# ── T8 非 dict 结果包成 data ──────────────────────────────
wrapped = C.attach(["hit-1"], IocSearchTool(), {"event": {"id": "E-1"}})
check(wrapped.get("data") == ["hit-1"], "T8 非 dict 结果未包进 data")
check(C.validate(wrapped) == [], "T8 包装后的契约不自洽")

# ── T9~T13 变异自检：坏契约必须被拒 ───────────────────────
def mutated(**kwargs) -> dict:
    base = json.loads(json.dumps(ok))
    for path, value in kwargs.items():
        target = base["_contract"]
        keys = path.split(".")
        for k in keys[:-1]:
            target = target[k]
        target[keys[-1]] = value
    return base

cases = [
    ("T9 缺 _contract", {k: v for k, v in ok.items() if k != "_contract"},
     "缺 _contract"),
    ("T10 degraded 无原因", mutated(degraded=True, authority="unknown", degradationReason=None,
                                    coverage={"status": "partial", "truncated": False, "omittedCount": 0}),
     "degradationReason"),
    ("T11 unavailable 无限制", mutated(**{"coverage.status": "unavailable", "limitations": []}),
     "limitations"),
    ("T12 unknown 无限制", mutated(authority="unknown", limitations=[]), "limitations"),
    ("T13 degraded 仍 complete", mutated(degraded=True, authority="unknown",
                                          degradationReason="x"),
     "complete"),
]
for label, payload, expect in cases:
    errs = C.validate(payload)
    check(bool(errs) and any(expect in e for e in errs), f"{label} 未被校验器拦下: {errs}")

# ── T14 兜底路径必须自报降级（真实触发 IncidentTriageTool 的 except 分支）──
import security_agent.ai.triage as triage_mod  # noqa: E402

_orig = triage_mod.triage_event


def _boom(**kwargs):
    raise RuntimeError("模拟研判模块故障")


triage_mod.triage_event = _boom
try:
    obs = {"summary": "ok", "details": [], "tool_name": "x"}
    fallback = IncidentTriageTool().run(
        event=type("E", (), {"id": "E-1", "title": "t", "behavior": "b"})(),
        asset_observation=type("O", (), {"summary": "s", "details": []})(),
        log_observation=type("O", (), {"summary": "s", "details": []})(),
        intel_observation=type("O", (), {"summary": "s", "details": []})(),
        history_observation=type("O", (), {"summary": "s", "details": []})(),
        false_positive_observation=type("O", (), {"summary": "s", "details": []})(),
    )
finally:
    triage_mod.triage_event = _orig

check(isinstance(fallback, dict) and fallback.get("_degraded") is True,
      "T14 兜底结果未打 _degraded 标（fail-open 伪装复发）")
envelope = C.attach(fallback, IncidentTriageTool(), {"event": {"id": "E-1"}})
check(envelope["_contract"]["degraded"] is True, "T14 兜底未提升为 degraded=True")
check(envelope["_contract"]["authority"] == "unknown", "T14 兜底 authority 必须 unknown")
check(C.validate(envelope) == [], f"T14 兜底契约不自洽: {C.validate(envelope)}")

# ── 汇总 ─────────────────────────────────────────────────
print(f"断言 {_checked} 条，失败 {len(_failures)} 条")
for line in _failures:
    print(f"  [FAIL] {line}")
if _failures:
    print("\n[FAIL] 契约测试未通过")
    raise SystemExit(1)
print("[OK] 契约测试通过：正向字段齐全、向后兼容不破、5 类坏契约全部被拒、兜底自报降级")
raise SystemExit(0)
