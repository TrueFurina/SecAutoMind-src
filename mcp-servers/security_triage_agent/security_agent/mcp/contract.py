"""MCP 工具出口契约：让每条结论自带权威等级、覆盖度与限制（2026-10-19）。

为什么要有这一层
----------------
本项目的工具返回值原本只有 `{tool_name, summary, details}`。这三个字段能表达
「查到了什么」，**表达不了「这条结论有多可信、覆盖到哪、哪里没查到」**。
由此产生三类真实缺陷（均已在代码里留痕）：

  (1) `asset_lookup` 查不到主机时返回 `summary="未找到…"` + `details=[]`，
      与「查到了但字段恰好全空」在结构上不可区分——调用方只能读中文摘要猜；
  (2) `incident_triage` 的兜底分支返回 `confidence="low"` 但 `isError=False`，
      调用方看到的是「研判成功，中等风险」，**实际一步研判都没做**（fail-open 伪装）；
  (3) `ioc_search` 返回空列表既可能是「检索过、未命中」，也可能是「事件四个指标全为空、
      根本没检索」——代码注释承认了这个区分，但没有把它编码进字段。

REA（Reverse Engineer Anything，MIT）用同一套思路解决了同类问题：每个结论挂
`observed / derived / inferred` 三级权威 + 显式 Unknown Ledger + fail-closed。
本模块把这套契约搬进 SecAutoMind 的 MCP 出口，**字段名与语义对齐 REA**，
便于后续把两边的证据包互相引用。

设计约束
--------
1. **零依赖**：只用标准库。本项目的核心链路不允许因 `pip install` 失败而不可用。
2. **不维护第二份清单**：权威等级从 `Tool.authority` 读，本模块**不写**
   「工具名 → 等级」的映射表。清单只允许有一处事实源。
3. **向后兼容**：契约以 `_contract` 键**追加**在原结果旁边，原字段不动。
   老的消费者只读自己认识的键，不会因为多了 `_contract` 而失败。
4. **fail-closed 而不 fail-silent**：降级可以发生（链路不能断），但必须
   在 `_contract.degraded` / `authority="unknown"` 里写明。允许降级，
   不允许**假装没降级**。
"""
from __future__ import annotations

import hashlib
import json
from datetime import datetime, timezone
from typing import Any

#: 契约版本。字段语义变化时递增，便于消费者按版本分支。
SCHEMA_VERSION = "tool-contract/1"

#: 契约在出口 JSON 中的键名。下划线前缀表示「元数据，不是业务字段」。
CONTRACT_KEY = "_contract"

#: 四种权威等级（与 REA 对齐：observed / derived / inferred，另加 unknown）。
AUTHORITIES = ("observed", "derived", "inferred", "unknown")

#: 覆盖度三档。unavailable 表示「这次没查到 / 没做」，不是「结果为空」。
COVERAGE_STATUSES = ("complete", "partial", "unavailable")

#: 工具未声明时的默认权威等级。取 derived 而非 observed，是刻意保守：
#: 宁可低估可信度，也不要让未经审视的工具默认冒充「直接观测」。
DEFAULT_AUTHORITY = "derived"

#: 等级释义随契约一起下发，调用方（LLM 或程序）不必再查文档。
AUTHORITY_MEANING = {
    "observed": "直接读取落盘事实（知识库 / 命令输出），未经推断加工",
    "derived": "由确定性规则从观测结果推导，可复现",
    "inferred": "由模型或启发式推断，存在不确定性",
    "unknown": "本次调用未形成结论（降级 / 异常 / 证据缺失）",
}


def _now_iso() -> str:
    return datetime.now(timezone.utc).replace(microsecond=0).isoformat()


def input_digest(arguments: dict) -> str:
    """入参摘要：只留指纹，不落原文（命令类工具可能含敏感内容）。

    `default=str` 用于兜底不可 JSON 化的对象（如 SecurityEvent 实例）。
    """
    try:
        blob = json.dumps(arguments, sort_keys=True, ensure_ascii=False, default=str)
    except (TypeError, ValueError):  # pragma: no cover - 极端兜底
        blob = repr(sorted(map(str, arguments.keys())))
    return "sha256:" + hashlib.sha256(blob.encode("utf-8")).hexdigest()[:16]


def _from_tool(tool: Any) -> tuple[str, tuple[str, ...]]:
    """从工具对象读取它自己声明的权威等级与固有局限。"""
    authority = getattr(tool, "authority", DEFAULT_AUTHORITY) or DEFAULT_AUTHORITY
    limitations = tuple(getattr(tool, "limitations", ()) or ())
    return authority, limitations


def build(
    tool: Any,
    arguments: dict,
    *,
    authority: str | None = None,
    coverage_status: str = "complete",
    truncated: bool = False,
    omitted_count: int = 0,
    limitations: list[str] | tuple[str, ...] = (),
    degraded: bool = False,
    degradation_reason: str | None = None,
) -> dict:
    """构造一条契约。

    参数全部可覆盖，但默认值来自工具自身声明（`Tool.authority` /
    `Tool.limitations`），出口层不需要认识具体工具。
    """
    tool_authority, tool_limits = _from_tool(tool)
    resolved_authority = authority or tool_authority
    merged_limits = list(tool_limits)

    # 非法取值不抛异常：契约层自身不能成为工具不可用的原因。
    # 降级为 unknown + 显式限制，让问题在出口可见；开发期错误由出口矩阵
    # （`matrix.py` 的「声明合法性」断言）fail-loud 地拦住。
    if resolved_authority not in AUTHORITIES:
        merged_limits.append(
            f"工具声明的权威等级 {resolved_authority!r} 非法（合法值 {AUTHORITIES}），已按 unknown 处理"
        )
        resolved_authority = "unknown"
    if coverage_status not in COVERAGE_STATUSES:
        merged_limits.append(
            f"覆盖度 {coverage_status!r} 非法（合法值 {COVERAGE_STATUSES}），已按 partial 处理"
        )
        coverage_status = "partial"

    # 降级时强制把权威压到 unknown 和 partial：降级的结果不允许再自称
    # observed / complete。这条是硬约束，不接受调用方覆盖。
    if degraded:
        resolved_authority = "unknown"
        if coverage_status == "complete":
            coverage_status = "partial"

    merged_limits = list(dict.fromkeys([*merged_limits, *limitations]))
    if degraded and degradation_reason:
        merged_limits.append(f"本次结果已降级: {degradation_reason}")
    # 空结果与「不可用」不是一回事，但两者都必须说清楚覆盖面。
    if coverage_status == "unavailable" and not merged_limits:
        merged_limits.append("本次调用未覆盖目标对象，结果为空不代表不存在")

    return {
        "schemaVersion": SCHEMA_VERSION,
        "authority": resolved_authority,
        "authorityMeaning": AUTHORITY_MEANING[resolved_authority],
        "coverage": {
            "status": coverage_status,
            "truncated": bool(truncated),
            "omittedCount": int(omitted_count),
        },
        "degraded": bool(degraded),
        "degradationReason": degradation_reason,
        "limitations": merged_limits,
        "evidence": {
            "tool": getattr(tool, "name", "") or "",
            "toolVersion": getattr(tool, "version", "0.1.0"),
            "inputDigest": input_digest(arguments or {}),
            "generatedAt": _now_iso(),
        },
    }


def attach(payload: Any, tool: Any, arguments: dict, **overrides) -> Any:
    """把契约附加到工具返回值上（向后兼容）。

    - `payload` 是 dict：原键全部保留，追加 `_contract`；
    - 其他类型（list / str / 标量）：包成 `{"data": payload, "_contract": …}`。

    工具可在返回 dict 里埋 `_degraded` / `_degradation_reason` 两个私有键来声明
    本次走了降级路径。它们会被提升进契约，**原键保留**（不删，避免破坏消费者）。
    """
    if isinstance(payload, dict):
        body = dict(payload)
        degraded = bool(body.get("_degraded", False))
        reason = body.get("_degradation_reason")
        if degraded and not reason:
            reason = "工具未提供降级原因（属契约缺陷，应为每次降级给出可读理由）"
    else:
        body = {"data": payload}
        degraded, reason = False, None

    overrides.setdefault("degraded", degraded)
    if reason and "degradation_reason" not in overrides:
        overrides["degradation_reason"] = reason

    body[CONTRACT_KEY] = build(tool, arguments, **overrides)
    return body


def validate(payload: Any) -> list[str]:
    """校验一条出口是否带自洽契约。返回错误列表，空列表 = 通过。

    只校验**内部自洽**（字段齐全、语义不矛盾），不校验「等级是否配得上工具」——
    后者由出口矩阵拿 `Tool.authority` 比对，避免本模块持有第二份清单。
    """
    errors: list[str] = []
    if not isinstance(payload, dict):
        return [f"出口不是 dict，无法承载契约（实际 {type(payload).__name__}）"]
    if CONTRACT_KEY not in payload:
        return [f"缺 {CONTRACT_KEY} 字段（工具结论未声明权威等级与覆盖度）"]

    c = payload[CONTRACT_KEY]
    if not isinstance(c, dict):
        return [f"{CONTRACT_KEY} 不是对象"]

    if c.get("schemaVersion") != SCHEMA_VERSION:
        errors.append(f"schemaVersion={c.get('schemaVersion')!r}，期望 {SCHEMA_VERSION!r}")

    authority = c.get("authority")
    if authority not in AUTHORITIES:
        errors.append(f"authority={authority!r} 不在 {AUTHORITIES}")

    cov = c.get("coverage")
    if not isinstance(cov, dict):
        errors.append("coverage 缺失或不是对象")
    else:
        status = cov.get("status")
        if status not in COVERAGE_STATUSES:
            errors.append(f"coverage.status={status!r} 不在 {COVERAGE_STATUSES}")
        if not isinstance(cov.get("truncated"), bool):
            errors.append("coverage.truncated 必须是 bool")
        if not isinstance(cov.get("omittedCount"), int):
            errors.append("coverage.omittedCount 必须是 int")

    limits = c.get("limitations")
    if not isinstance(limits, list):
        errors.append("limitations 必须是列表")
        limits = []

    degraded = c.get("degraded")
    if not isinstance(degraded, bool):
        errors.append("degraded 必须是 bool")
    elif degraded:
        if not c.get("degradationReason"):
            errors.append("degraded=true 但 degradationReason 为空（降级必须给理由）")
        if authority != "unknown":
            errors.append(f"degraded=true 时 authority 必须是 unknown，实际 {authority!r}")
        if isinstance(cov, dict) and cov.get("status") == "complete":
            errors.append("degraded=true 时 coverage.status 不得为 complete")

    if authority == "unknown" and not limits:
        errors.append("authority=unknown 但 limitations 为空（必须说明为何无结论）")
    if isinstance(cov, dict) and cov.get("status") == "unavailable" and not limits:
        errors.append("coverage.status=unavailable 但 limitations 为空")

    ev = c.get("evidence")
    if not isinstance(ev, dict):
        errors.append("evidence 缺失或不是对象")
    else:
        for key in ("tool", "inputDigest", "generatedAt"):
            if not ev.get(key):
                errors.append(f"evidence.{key} 为空")

    return errors
