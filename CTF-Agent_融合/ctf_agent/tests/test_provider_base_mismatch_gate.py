"""provider / base_url 错配闸门回归测试（2026-11-12）。

事故形态：只设 CTF_AGENT_LLM_BASE_URL 指向某厂商官方端点、不设
CTF_AGENT_LLM_PROVIDER 时，provider 回落 baidu、模型 ernie-*，请求却打到
别家端点。这种错**不会报错**，只会让整批结果静默不可信。

锁住五条：
1. 无 provider + BASE_URL 指向已登记厂商端点 → RuntimeError（fail-closed）；
2. 同上但显式设置了 provider → 放行；
3. BASE_URL 指向本地/自建网关（非登记域名）→ 不拦（避免误伤）；
4. 未设 BASE_URL → 不拦（行为与修复前一致）；
5. 逃生阀 ALLOW_PROVIDER_BASE_MISMATCH=1 → 降级为 warning，仍构造成功。
"""

import pytest

from config import AppConfig, _provider_owning_endpoint

_ENV_KEYS = (
    "CTF_AGENT_LLM_PROVIDER",
    "CTF_AGENT_LLM_BASE_URL",
    "CTF_AGENT_ALLOW_PROVIDER_BASE_MISMATCH",
    "STEP_BASE_URL",
    "CTF_AGENT_LIGHT_MODEL",
    "CTF_AGENT_HEAVY_MODEL",
)


def _clean_env(monkeypatch):
    for k in _ENV_KEYS:
        monkeypatch.delenv(k, raising=False)


# ── 端点反查 ─────────────────────────────────────────────────────────────

def test_owner_lookup_known_vendors():
    assert _provider_owning_endpoint("https://api.deepseek.com/v1") == "deepseek"
    assert _provider_owning_endpoint("https://api.deepseek.com/chat/completions") == "deepseek"
    assert _provider_owning_endpoint("https://dashscope.aliyuncs.com/compatible-mode/v1") == "qwen"


def test_owner_lookup_unknown_or_local_returns_empty():
    assert _provider_owning_endpoint("http://127.0.0.1:18899/v1") == ""
    assert _provider_owning_endpoint("http://localhost:8000/v1") == ""
    assert _provider_owning_endpoint("") == ""
    assert _provider_owning_endpoint("not-a-url") == ""


# ── 闸门行为 ─────────────────────────────────────────────────────────────

def test_no_provider_with_vendor_base_url_raises(monkeypatch):
    _clean_env(monkeypatch)
    monkeypatch.setenv("CTF_AGENT_LLM_BASE_URL", "https://api.deepseek.com/v1")
    with pytest.raises(RuntimeError) as exc:
        AppConfig.from_env()
    assert "CTF_AGENT_LLM_PROVIDER=deepseek" in str(exc.value)


def test_qwen_endpoint_without_provider_also_raises(monkeypatch):
    _clean_env(monkeypatch)
    monkeypatch.setenv("CTF_AGENT_LLM_BASE_URL", "https://dashscope.aliyuncs.com/compatible-mode/v1")
    with pytest.raises(RuntimeError) as exc:
        AppConfig.from_env()
    assert "CTF_AGENT_LLM_PROVIDER=qwen" in str(exc.value)


def test_explicit_provider_with_matching_base_url_ok(monkeypatch):
    _clean_env(monkeypatch)
    monkeypatch.setenv("CTF_AGENT_LLM_PROVIDER", "deepseek")
    monkeypatch.setenv("CTF_AGENT_LLM_BASE_URL", "https://api.deepseek.com/v1")
    cfg = AppConfig.from_env()
    assert cfg.llm_provider == "deepseek"


def test_local_gateway_base_url_not_blocked(monkeypatch):
    _clean_env(monkeypatch)
    monkeypatch.setenv("CTF_AGENT_LLM_BASE_URL", "http://127.0.0.1:18899/v1")
    cfg = AppConfig.from_env()
    assert cfg.llm_provider == "baidu"


def test_no_base_url_not_blocked(monkeypatch):
    _clean_env(monkeypatch)
    cfg = AppConfig.from_env()
    assert cfg.llm_provider == "baidu"


def test_escape_valve_downgrades_to_warning(monkeypatch, caplog):
    _clean_env(monkeypatch)
    monkeypatch.setenv("CTF_AGENT_LLM_BASE_URL", "https://api.deepseek.com/v1")
    monkeypatch.setenv("CTF_AGENT_ALLOW_PROVIDER_BASE_MISMATCH", "1")
    with caplog.at_level("WARNING"):
        cfg = AppConfig.from_env()
    assert cfg.llm_provider == "baidu"
    assert any(
        "ALLOW_PROVIDER_BASE_MISMATCH" in r.getMessage() or "指向 deepseek" in r.getMessage()
        for r in caplog.records
    )
