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

    # ── 用例 3b：API 失败必须可见，不能被吞成「模型没答」─────────
    # 2026-11-07 事故：qwen3.8-max 40 题里 29 题 HTTP 403（额度耗尽），
    # 内层 except 只往文本里塞一行就 break，detail.error 是空的 ⇒
    # 汇总把「额度用完」读成「模型不会」。这条用例钉住这个行为。
    def boom(url, payload, key, timeout):
        raise RuntimeError("HTTP Error 403: Forbidden")

    m._post_json = boom
    try:
        stats = []
        m.call_llm_agentic(cfg, "k", "m", "p", 30, max_iter=2, wall_budget=60, stats=stats)
        ck("API 失败必须落进 stats（不得静默吞掉）", len(stats) == 1)
        ck("API 失败的 finish_reason 标记为 error",
           stats and stats[0].get("finish_reason") == "error")
        ck("API 失败保留错误摘要", "403" in str(stats[0].get("error", "")) if stats else False)
    except Exception as e:  # noqa: BLE001
        ck("API 失败路径不向外抛（实际 %s）" % type(e).__name__, False)
        ck("API 失败必须落进 stats（不得静默吞掉）", False)
        ck("API 失败的 finish_reason 标记为 error", False)
        ck("API 失败保留错误摘要", False)
    m._post_json, m.run_python_tool = orig_post, orig_tool

    # ── 用例 4：4096 硬压已解除 ──────────────────────────────
    ck("非推理模型：max_tokens 不再被压到 4096",
       m._token_kwarg(cfg, 16384) == {"max_tokens": 16384})
    ck("默认预算 >= 16384", m.DEFAULT_MAX_TOKENS >= 16384)

    # ── 用例 5：HTTP 错误必须带原因，且 4xx 不许重试 ──────────
    # 2026-11-07 kimi-k3 八题全 "HTTP Error 400: Bad Request"，没有 body 就没有原因，
    # 只能看出「挂了」看不出「为什么挂」。另外 400 重试 5 次纯属白等。
    import io
    import urllib.error

    def mk_http_err(code, body):
        return urllib.error.HTTPError("http://x", code, "Bad Request", {}, io.BytesIO(body))

    n_calls = {"n": 0}

    def fake_urlopen_400(req, timeout):
        n_calls["n"] += 1
        raise mk_http_err(400, b'{"error":{"message":"tool calls not supported"}}')

    orig_open = m._urlopen_deadline
    m._urlopen_deadline = fake_urlopen_400
    try:
        m._post_json("http://x", {}, "k", 5)
        ck("HTTP 400 必须抛异常", False)
    except RuntimeError as e:
        ck("HTTP 400 错误文本带 body 原因", "tool calls not supported" in str(e))
        ck("HTTP 400 不重试（只发一次）", n_calls["n"] == 1)
    except Exception as e:  # noqa: BLE001
        ck("HTTP 400 抛 RuntimeError（实际 %s）" % type(e).__name__, False)
        ck("HTTP 400 不重试（只发一次）", False)
    finally:
        m._urlopen_deadline = orig_open

    # 429 属于瞬态，必须仍然重试（否则会被上面那条误伤成"一律不重试"）
    n_calls["n"] = 0

    def fake_urlopen_429(req, timeout):
        n_calls["n"] += 1
        raise mk_http_err(429, b'{"error":{"message":"rate limited"}}')

    m._urlopen_deadline = fake_urlopen_429
    try:
        m._post_json("http://x", {}, "k", 5)
    except Exception:  # noqa: BLE001
        pass
    finally:
        m._urlopen_deadline = orig_open
    ck("HTTP 429 仍然重试", n_calls["n"] > 1)

    # ── 用例 6：不接受 temperature 的模型不许多发这个字段 ──────
    # 2026-11-07 kimi-k3 八题全 400，原因就是多塞了 temperature=0.2。
    ck("kimi 系不发送 temperature", m._accepts_temperature("kimi-k3") is False)
    ck("stepfun 系照常发送 temperature", m._accepts_temperature("step-3.5-flash") is True)
    seen = {}

    def fake_post_capture(url, payload, key, timeout):
        seen.update(payload)
        return _body(content="flag{x}", finish="stop")

    m._post_json = fake_post_capture
    m.call_llm_agentic(cfg, "k", "kimi-k3", "p", 30, max_iter=1, wall_budget=60, stats=[])
    ck("kimi 请求体里没有 temperature", "temperature" not in seen)
    seen.clear()
    m.call_llm_agentic(cfg, "k", "step-3.5-flash", "p", 30, max_iter=1, wall_budget=60, stats=[])
    ck("stepfun 请求体里有 temperature", seen.get("temperature") == 0.2)
    m._post_json, m.run_python_tool = orig_post, orig_tool

    # ── 用例：实际执行形态必须自证（2026-11-07 缺陷）──────────
    # 现象：stepfun 的 supports_tools=False，但 `--agentic` 仍写进 summary，
    # 结果文件声称 agentic 而工具调用恒为 0。另一面：dashscope supports_tools=True，
    # 不加 --agentic 也走工具 ⇒ 纯 LLM 对照根本跑不出来。
    cases = [
        (True, False, True, True, "--agentic + 支持工具 ⇒ 走工具"),
        (False, False, True, True, "默认 + 支持工具 ⇒ 走工具（历史行为不变）"),
        (True, False, False, False, "--agentic + 不支持工具 ⇒ 必须降级为纯"),
        (False, False, False, False, "默认 + 不支持工具 ⇒ 纯"),
        (True, True, True, False, "--no-agentic 压过 --agentic"),
        (False, True, True, False, "--no-agentic 压过默认（dashscope 上做消融靠这条）"),
        (False, True, False, False, "--no-agentic + 无工具 ⇒ 纯"),
        (True, True, False, False, "全禁 ⇒ 纯"),
    ]
    for req, noa, sup, exp, desc in cases:
        got_v = m.resolve_agentic(req, noa, sup)
        ck("%s（got=%s）" % (desc, got_v), got_v is exp)

    print("\nselftest %d/%d" % (ok, total))
    return 0 if ok == total else 1


if __name__ == "__main__":
    sys.exit(main())
