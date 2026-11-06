#!/usr/bin/env python3
"""ctf_stepfun_orchestrator 的离线回归测试（不联网、不花钱）。

为什么需要它：2026-11-07 往 `call_llm_agentic` 里加统计字段时，把 `len(tcalls)`
写在了 `tcalls = ...` 之前，于是 agentic 路径每题抛 UnboundLocalError，
被 `except Exception` 吞成 `error` 字段 —— **跑批会静默变成全 0，而 summary 里
只有 solved=0，看不出是代码炸了**。这类错误必须有机检，靠人眼复查靠不住。

覆盖：
  1. 正常两轮（第一轮回 tool_calls，第二轮回最终答案）→ 不抛异常、stats 有 2 条
  2. 模型第一轮就不调工具 → stats 1 条、tool_used=False
  3. finish_reason=length 必须被统计成截断（预算耗尽 ≠ 不会）
  4. max_tokens 不超过 4096 的旧行为已修（回归断言）
"""
import importlib.util
import os
import sys

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
SPEC = importlib.util.spec_from_file_location(
    "orch", os.path.join(ROOT, "scripts", "ctf_stepfun_orchestrator.py"))


def load():
    m = importlib.util.module_from_spec(SPEC)
    SPEC.loader.exec_module(m)
    return m


def _body(reasoning="", content="", tool_calls=None, finish="stop", usage=None):
    msg = {"content": content, "reasoning_content": reasoning}
    if tool_calls:
        msg["tool_calls"] = tool_calls
    return {"choices": [{"message": msg, "finish_reason": finish}],
            "usage": usage or {"prompt_tokens": 100, "completion_tokens": 20}}


def main():
    m = load()
    ok = 0
    total = 0

    def ck(label, cond):
        nonlocal ok, total
        total += 1
        ok += int(bool(cond))
        print("%s %s" % ("PASS" if cond else "FAIL", label))

    cfg = dict(m.PROVIDERS["stepfun"])
    cfg["supports_tools"] = True

    # ── 用例 1：两轮，第一轮调工具 ───────────────────────────
    seq = [
        _body(reasoning="think", tool_calls=[{"id": "c1", "type": "function",
                                             "function": {"name": "run_python",
                                                          "arguments": '{"code":"1+1"}'}}],
              finish="tool_calls"),
        _body(content="flag{final_answer}", finish="stop"),
    ]
    calls = {"n": 0}

    def fake_post(url, payload, key, timeout):
        b = seq[min(calls["n"], len(seq) - 1)]
        calls["n"] += 1
        return b

    orig_post, orig_tool = m._post_json, m.run_python_tool
    m._post_json = fake_post
    m.run_python_tool = lambda *a, **k: "2"
    try:
        stats = []
        text, used = m.call_llm_agentic(cfg, "k", "m", "p", 30, max_iter=4,
                                        wall_budget=60, max_tokens=16384, stats=stats)
        ck("两轮正常路径不抛异常", True)
        ck("stats 记录 2 轮", len(stats) == 2)
        ck("stats 含 finish_reason", all("finish_reason" in x for x in stats))
        ck("tool_used=True", used is True)
        ck("最终文本被保留", "flag{final_answer}" in text)
        ck("首轮 finish_reason=tool_calls 被记录", stats[0]["finish_reason"] == "tool_calls")
    except Exception as e:  # noqa: BLE001
        ck("两轮正常路径不抛异常（实际抛了 %s: %s）" % (type(e).__name__, e), False)
        for lbl in ("stats 记录 2 轮", "stats 含 finish_reason", "tool_used=True",
                    "最终文本被保留", "首轮 finish_reason=tool_calls 被记录"):
            ck(lbl, False)

    # ── 用例 2：一轮就收口，不调工具 ─────────────────────────
    seq[:] = [_body(content="I cannot solve this", finish="stop")]
    calls["n"] = 0
    try:
        stats = []
        text, used = m.call_llm_agentic(cfg, "k", "m", "p", 30, max_iter=4,
                                        wall_budget=60, stats=stats)
        ck("不调工具时 stats 1 条", len(stats) == 1)
        ck("不调工具时 tool_used=False", used is False)
    except Exception as e:  # noqa: BLE001
        ck("不调工具路径不抛异常（实际 %s）" % type(e).__name__, False)
        ck("不调工具时 stats 1 条", False)
        ck("不调工具时 tool_used=False", False)

    # ── 用例 3：截断必须可见 ─────────────────────────────────
    seq[:] = [_body(reasoning="x" * 500, finish="length",
                    usage={"prompt_tokens": 10, "completion_tokens": 4096})]
    calls["n"] = 0
    try:
        stats = []
        m.call_llm_agentic(cfg, "k", "m", "p", 30, max_iter=2, wall_budget=60, stats=stats)
        ck("finish_reason=length 被记录（截断可见）",
           stats and stats[0]["finish_reason"] == "length")
        ck("completion_tokens 被记录", stats and stats[0]["completion_tokens"] == 4096)
    except Exception as e:  # noqa: BLE001
        ck("截断路径不抛异常（实际 %s）" % type(e).__name__, False)
        ck("finish_reason=length 被记录（截断可见）", False)
        ck("completion_tokens 被记录", False)

    m._post_json, m.run_python_tool = orig_post, orig_tool

    # ── 用例 4：4096 硬压已解除 ──────────────────────────────
    ck("非推理模型：max_tokens 不再被压到 4096",
       m._token_kwarg(cfg, 16384) == {"max_tokens": 16384})
    ck("默认预算 >= 16384", m.DEFAULT_MAX_TOKENS >= 16384)

    print("\nselftest %d/%d" % (ok, total))
    return 0 if ok == total else 1


if __name__ == "__main__":
    sys.exit(main())
