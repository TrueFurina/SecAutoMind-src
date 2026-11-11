"""配置快照「残留告警」语义回归（2026-11-12）。

原实现「只要变量非空就打 ⚠️ 残留」，把合法显式设置一并污名化：
- provider=deepseek + BASE_URL 指向 deepseek 官方端点（自洽）→ 被报「残留」
- 白名单内、确实生效的 LIGHT_MODEL → 被报「残留」

噪音一多，真问题（父进程塞了个错的 BASE_URL）就没人看了。现按三档判定：
1. 生效且自洽 → 不报；
2. 设了但未生效（被专属变量/白名单回退覆盖）→ 报「未生效」；
3. 生效但 host 不属于当前 provider → 报「疑被改道」。

residue_warnings 键名保留以兼容既有消费方，语义已收窄。
"""

import pytest

from config import print_effective_config_snapshot

_ENV_KEYS = (
    "CTF_AGENT_LLM_PROVIDER",
    "CTF_AGENT_LLM_BASE_URL",
    "CTF_AGENT_LIGHT_MODEL",
    "CTF_AGENT_HEAVY_MODEL",
    "STEP_BASE_URL",
    "CTF_AGENT_ALLOW_PROVIDER_BASE_MISMATCH",
)


def _clean(monkeypatch):
    for k in _ENV_KEYS:
        monkeypatch.delenv(k, raising=False)


def test_self_consistent_base_url_not_warned(monkeypatch):
    """provider=deepseek + 指向 deepseek 官方端点：合法显式设置，不得报残留。"""
    _clean(monkeypatch)
    monkeypatch.setenv("CTF_AGENT_LLM_PROVIDER", "deepseek")
    monkeypatch.setenv("CTF_AGENT_LLM_BASE_URL", "https://api.deepseek.com/v1")
    snap = print_effective_config_snapshot(provider="deepseek")
    assert not any("CTF_AGENT_LLM_BASE_URL" in w for w in snap["residue_warnings"]), \
        snap["residue_warnings"]


def test_allowlisted_light_model_not_warned(monkeypatch):
    """白名单内、确实生效的 LIGHT_MODEL 不得被报成残留。"""
    _clean(monkeypatch)
    monkeypatch.setenv("CTF_AGENT_LLM_PROVIDER", "deepseek")
    monkeypatch.setenv("CTF_AGENT_LIGHT_MODEL", "deepseek-chat")
    snap = print_effective_config_snapshot(provider="deepseek")
    assert snap["light_model"] == "deepseek-chat"
    assert not any("CTF_AGENT_LIGHT_MODEL" in w for w in snap["residue_warnings"]), \
        snap["residue_warnings"]


def test_unknown_host_base_url_still_warned(monkeypatch):
    """生效但 host 不属于当前 provider：端点被改道，必须报。"""
    _clean(monkeypatch)
    monkeypatch.setenv("CTF_AGENT_LLM_BASE_URL", "https://residue.example.com/v1")
    snap = print_effective_config_snapshot(provider="baidu")
    assert any("host 不属于" in w for w in snap["residue_warnings"]), \
        snap["residue_warnings"]


def test_ineffective_base_url_warned_as_ineffective(monkeypatch):
    """BASE_URL 被 provider 专属变量覆盖：报「已设置但未生效」。"""
    _clean(monkeypatch)
    monkeypatch.setenv("CTF_AGENT_LLM_PROVIDER", "stepfun")
    monkeypatch.setenv("STEP_BASE_URL", "https://api.stepfun.com/v1")
    monkeypatch.setenv("CTF_AGENT_LLM_BASE_URL", "https://api.deepseek.com/v1")
    snap = print_effective_config_snapshot(provider="stepfun")
    assert any("已设置但未生效" in w for w in snap["residue_warnings"]), \
        snap["residue_warnings"]


def test_reverted_light_model_warned_as_ineffective(monkeypatch):
    """不在白名单的 LIGHT_MODEL 会被回退 → 报「未生效（被回退）」。"""
    _clean(monkeypatch)
    monkeypatch.setenv("CTF_AGENT_LLM_PROVIDER", "deepseek")
    monkeypatch.setenv("CTF_AGENT_LIGHT_MODEL", "gpt-9-nonexistent")
    snap = print_effective_config_snapshot(provider="deepseek")
    assert any("LIGHT_MODEL" in w and "被回退" in w for w in snap["residue_warnings"]), \
        snap["residue_warnings"]
