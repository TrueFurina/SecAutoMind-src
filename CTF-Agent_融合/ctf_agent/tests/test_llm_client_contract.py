# -*- coding: utf-8 -*-
"""llm/client 契约回归（P1-1 记账重构，2026-08-21 赛后）。

覆盖：
1. ai_chat 返回 str（非 _post_chat 重构后误返回的 tuple）
2. ai_chat_with_usage / ai_chat_json_with_usage 正确返回 (内容, usage)
3. 异步包装 ai_chat_json_async_with_usage 不阻塞事件循环（to_thread）
"""

import asyncio
import os
import sys

import pytest

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))


def test_ai_chat_returns_str_not_tuple(monkeypatch):
    """_post_chat 返回 (content, usage) 后，ai_chat 必须只返回 content 字符串。"""
    from llm import client as llm_client

    _USAGE = {"prompt_tokens": 10, "completion_tokens": 5, "total_tokens": 15}

    def fake_post_chat(messages, temperature, max_tokens, settings):
        return "flag{ok}", dict(_USAGE)

    monkeypatch.setattr(llm_client, "_post_chat", fake_post_chat)
    # 伪装有 key（绕过 fail-open 提前返回）
    monkeypatch.setattr(llm_client, "_resolve_settings",
                        lambda model=None, provider=None: {"api_key": "x", "provider": "baidu",
                                                           "base_url": "https://qianfan.baidubce.com/v2/chat/completions"})
    out = llm_client.ai_chat([{"role": "user", "content": "hi"}])
    assert isinstance(out, str)
    assert out == "flag{ok}"


def test_ai_chat_with_usage_returns_usage(monkeypatch):
    """ai_chat_with_usage 返回 (content, usage)，usage 为真实 token 数。"""
    from llm import client as llm_client

    _USAGE = {"prompt_tokens": 10, "completion_tokens": 5, "total_tokens": 15}

    def fake_post_chat(messages, temperature, max_tokens, settings):
        return "answer", dict(_USAGE)

    monkeypatch.setattr(llm_client, "_post_chat", fake_post_chat)
    monkeypatch.setattr(llm_client, "_resolve_settings",
                        lambda model=None, provider=None: {"api_key": "x", "provider": "baidu",
                                                           "base_url": "https://qianfan.baidubce.com/v2/chat/completions"})
    content, usage = llm_client.ai_chat_with_usage([{"role": "user", "content": "hi"}])
    assert content == "answer"
    assert usage["total_tokens"] == 15


def test_ai_chat_json_async_with_usage_works(monkeypatch):
    """异步包装（to_thread）返回 (json, usage)，事件循环不被同步调用阻塞。"""
    from llm import client as llm_client

    _USAGE = {"prompt_tokens": 2, "completion_tokens": 1, "total_tokens": 3}

    def fake_ai_chat_json_with_usage(messages, system=None, temperature=0.1,
                                     max_tokens=2000, model=None, provider=None,
                                     recover_script=False):
        return {"action": "reason"}, dict(_USAGE)

    monkeypatch.setattr(llm_client, "ai_chat_json_with_usage", fake_ai_chat_json_with_usage)

    async def main():
        obj, usage = await llm_client.ai_chat_json_async_with_usage(
            [{"role": "user", "content": "hi"}])
        return obj, usage

    obj, usage = asyncio.run(main())
    assert obj == {"action": "reason"}
    assert usage["total_tokens"] == 3


# ── 2026-11-02：StepFun JSON 输出约束 + reasoning 超时 ──────────────────
def test_stepfun_gets_json_object_response_format(monkeypatch):
    """stepfun 请求必须带 response_format=json_object（现行行为，保留）。

    2026-11-04 A/B 修正（docs/evidence/stepfun_jsonmode_AB_20261104/）：同题集同模型下
    开/关 json_object 的协议成功率均为 16/16，**零增量**；原"12 题 protocol_fail=248"
    无落盘证据、且与本次实测不符。真实故障是 CoT 吃满输出预算被记成协议失败
    （见 test_stepfun_truncated_cot_*）。该参数保留为无害旁路，不得再宣称其"治病"。
    """
    from llm import client as llm_client

    captured = {}

    class _Resp:
        status_code = 200
        def json(self):
            return {"choices": [{"message": {"content": '{"action":"think"}'}}],
                    "usage": {"prompt_tokens": 1, "completion_tokens": 1,
                              "total_tokens": 2}}
        text = ""

    def fake_post(_url, **kw):
        payload_in = kw.get('json')
        captured["payload"] = payload_in
        captured["url"] = _url
        return _Resp()

    monkeypatch.setattr(llm_client.httpx, "post", fake_post)
    monkeypatch.delenv("CTF_AGENT_JSON_MODE", raising=False)

    llm_client.ai_chat([{"role": "user", "content": "x"}],
                       model="step-3.5-flash", provider="stepfun")
    assert captured["payload"].get("response_format") == {"type": "json_object"}, \
        "stepfun 未带上 response_format=json_object"


def test_non_stepfun_does_not_get_json_mode(monkeypatch):
    """其他 provider 不得被强行加 response_format（有的端点见未知字段直接 400）。"""
    from llm import client as llm_client

    captured = {}

    class _Resp:
        status_code = 200
        def json(self):
            return {"choices": [{"message": {"content": "ok"}}],
                    "usage": {"prompt_tokens": 1, "completion_tokens": 1,
                              "total_tokens": 2}}
        text = ""

    def fake_post(_url, **kw):
        payload_in = kw.get('json')
        captured["payload"] = payload_in
        return _Resp()

    monkeypatch.setattr(llm_client.httpx, "post", fake_post)
    llm_client.ai_chat([{"role": "user", "content": "x"}],
                       model="deepseek-chat", provider="deepseek")
    assert "response_format" not in captured["payload"]


def test_json_mode_can_be_disabled(monkeypatch):
    """CTF_AGENT_JSON_MODE=0 必须能关掉（A/B 对照与端点回归时要用）。"""
    from llm import client as llm_client

    captured = {}

    class _Resp:
        status_code = 200
        def json(self):
            return {"choices": [{"message": {"content": "ok"}}],
                    "usage": {"prompt_tokens": 1, "completion_tokens": 1,
                              "total_tokens": 2}}
        text = ""

    def fake_post(_url, **kw):
        payload_in = kw.get('json')
        captured["payload"] = payload_in
        return _Resp()

    monkeypatch.setattr(llm_client.httpx, "post", fake_post)
    monkeypatch.setenv("CTF_AGENT_JSON_MODE", "0")
    llm_client.ai_chat([{"role": "user", "content": "x"}],
                       model="step-3.5-flash", provider="stepfun")
    assert "response_format" not in captured["payload"]


def test_stepfun_reasoning_gets_extended_timeout():
    """stepfun 全系 reasoning，必须放宽 read timeout 到 300s。

    模型名里没有 reasoner/v4-pro/397b 关键词，靠既有关键词表会漏掉它，
    落在默认超时上被掐断。判定改用 provider，避免新增 step-* 档位再漏一次。
    """
    from llm.client import _resolve_settings
    s = _resolve_settings(None, provider="stepfun")
    assert s["timeout"].read >= 300.0, s["timeout"]


# ── 2026-11-04：CoT 吃预算 / CoT 不得当答案（A/B 实证）─────────────────────
def _mk_resp(content="", reasoning=None, reasoning_content=None, finish_reason="stop"):
    msg = {"content": content}
    if reasoning is not None:
        msg["reasoning"] = reasoning
    if reasoning_content is not None:
        msg["reasoning_content"] = reasoning_content
    body = {"choices": [{"message": msg, "finish_reason": finish_reason}],
            "usage": {"prompt_tokens": 1, "completion_tokens": 1, "total_tokens": 2}}

    class _R:
        status_code = 200
        text = ""

        def raise_for_status(self):
            return None

        def json(self):
            return body

    return _R()


def _sf_settings():
    return {"api_key": "x", "provider": "stepfun", "model": "step-3.5-flash",
            "base_url": "https://api.stepfun.com/v1/chat/completions", "timeout": 300.0}


def test_stepfun_reasoning_only_is_not_answer(monkeypatch):
    """content 空时不得把 stepfun 的思维链当答案（会把截断伪装成成功）。"""
    from llm import client as llm_client

    monkeypatch.setattr(llm_client, "_resolve_settings",
                        lambda model=None, provider=None: _sf_settings())
    monkeypatch.setattr(llm_client.httpx, "post", lambda _url, **kw: _mk_resp(
        content="", reasoning_content='{"action":"flag","flag":"PLACEHOLDER_NOT_A_FLAG"}', finish_reason="stop"))
    out = llm_client.ai_chat([{"role": "user", "content": "x"}],
                             model="step-3.5-flash", provider="stepfun")
    assert out is None, "stepfun 的 CoT 被当成答案了"


def test_stepfun_truncated_cot_retries_once_with_bigger_budget(monkeypatch):
    """finish_reason=length + content 空 → 一次性加倍预算重发，第二次内容才算答案。"""
    from llm import client as llm_client

    calls = []

    def fake_post(_url, **kw):
        calls.append(dict(kw.get("json") or {}))
        if len(calls) == 1:
            return _mk_resp(content="", reasoning_content="思考中……", finish_reason="length")
        return _mk_resp(content='{"action":"think"}', finish_reason="stop")

    monkeypatch.setattr(llm_client, "_resolve_settings",
                        lambda model=None, provider=None: _sf_settings())
    monkeypatch.setattr(llm_client.httpx, "post", fake_post)
    out = llm_client.ai_chat([{"role": "user", "content": "x"}],
                             model="step-3.5-flash", provider="stepfun")
    assert out == '{"action":"think"}'
    assert len(calls) == 2, f"截断未重发（实际 {len(calls)} 次调用）"
    assert calls[1]["max_tokens"] == calls[0]["max_tokens"] * 2


def test_no_retry_when_content_present(monkeypatch):
    """content 有内容时不得重发（省配额）。"""
    from llm import client as llm_client

    calls = []

    def fake_post(_url, **kw):
        calls.append(dict(kw.get("json") or {}))
        return _mk_resp(content='{"action":"reason"}', finish_reason="stop")

    monkeypatch.setattr(llm_client, "_resolve_settings",
                        lambda model=None, provider=None: _sf_settings())
    monkeypatch.setattr(llm_client.httpx, "post", fake_post)
    out = llm_client.ai_chat([{"role": "user", "content": "x"}],
                             model="step-3.5-flash", provider="stepfun")
    assert out == '{"action":"reason"}'
    assert len(calls) == 1


def test_non_stepfun_reasoning_fallback_kept(monkeypatch):
    """非 stepfun 的 reasoning_content 回退行为必须保留（回归保护）。"""
    from llm import client as llm_client

    settings = {"api_key": "x", "provider": "deepseek", "model": "deepseek-chat",
                "base_url": "https://api.deepseek.com/v1/chat/completions", "timeout": 30.0}
    monkeypatch.setattr(llm_client, "_resolve_settings",
                        lambda model=None, provider=None: settings)
    monkeypatch.setattr(llm_client.httpx, "post", lambda _url, **kw: _mk_resp(
        content="", reasoning_content="answer", finish_reason="stop"))
    out = llm_client.ai_chat([{"role": "user", "content": "x"}],
                             model="deepseek-chat", provider="deepseek")
    assert out == "answer"
