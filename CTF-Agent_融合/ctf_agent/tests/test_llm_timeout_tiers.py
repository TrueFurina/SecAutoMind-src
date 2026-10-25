"""D 通道：397B ReadTimeout 治理 + 超时可配置（llm/client.py::_resolve_settings）。

2026-10-25 生产链路实测（腾讯云→ModelScope，TLS 51ms）：
  397B mtok=600 → 26.9s；mtok=1500 → 92.5s/126.0s/26.4s（P50≈92s，方差大）。
60s 统一 read timeout 掐死长 token 调用。治理 = 397B 同 reasoner/v4-pro 式放宽
到 300s + CTF_AGENT_LLM_TIMEOUT_SECONDS 环境覆盖口。
本测试纯 mock（httpx.Timeout 读值断言），零真 token。
"""
import os
import sys
import unittest
from unittest import mock

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

import httpx  # noqa: E402

from llm import client  # noqa: E402


def _resolve(model, **env):
    """带干净 env 的 _resolve_settings（隔离用户环境干扰）。"""
    clean = {k: "" for k in (
        "CTF_AGENT_LLM_TIMEOUT_SECONDS",
        "CTF_AGENT_LLM_API_KEY",
        "CTF_AGENT_LLM_BASE_URL",
        "CTF_AGENT_LIGHT_MODEL",
        "CTF_AGENT_MODELSCOPE_MODEL",
        "CTF_AGENT_MODELSCOPE_API_KEY",
        "CTF_AGENT_ALLOW_OFF_WHITELIST",
    )}
    clean.update(env)
    with mock.patch.dict(os.environ, clean, clear=False):
        # provider=modelscope 需白名单外放行（端点不在 WHITELISTED_ENDPOINTS）
        with mock.patch.dict(os.environ, {"CTF_AGENT_ALLOW_OFF_WHITELIST": "1"}):
            return client._resolve_settings(model, provider="modelscope")


class TestTimeoutTiers(unittest.TestCase):
    def _read_seconds(self, settings):
        t = settings["timeout"]
        self.assertIsInstance(t, httpx.Timeout)
        return t.read

    def test_default_60s(self):
        s = _resolve("Qwen/Qwen3.8-Flash-Next")
        self.assertEqual(self._read_seconds(s), 60)

    def test_397b_raised_to_300(self):
        s = _resolve("Qwen/Qwen3.5-397B-A17B")
        self.assertEqual(self._read_seconds(s), 300)

    def test_reasoner_still_300(self):
        s = _resolve("deepseek-ai/DeepSeek-Reasoner-X")
        self.assertEqual(self._read_seconds(s), 300)

    def test_env_override_wins(self):
        s = _resolve("Qwen/Qwen3.5-397B-A17B",
                     CTF_AGENT_LLM_TIMEOUT_SECONDS="480")
        self.assertEqual(self._read_seconds(s), 480)

    def test_env_override_can_raise_default(self):
        s = _resolve("Qwen/Qwen3.8-Flash-Next",
                     CTF_AGENT_LLM_TIMEOUT_SECONDS="120")
        self.assertEqual(self._read_seconds(s), 120)

    def test_env_invalid_falls_back(self):
        s = _resolve("Qwen/Qwen3.5-397B-A17B",
                     CTF_AGENT_LLM_TIMEOUT_SECONDS="abc")
        self.assertEqual(self._read_seconds(s), 300)  # 非数字视为未设

    def test_env_zero_falls_back(self):
        s = _resolve("Qwen/Qwen3.8-Flash-Next",
                     CTF_AGENT_LLM_TIMEOUT_SECONDS="0")
        self.assertEqual(self._read_seconds(s), 60)


class TestSlowResponseRetry(unittest.TestCase):
    """慢响应行为：397B 档下 126s 真实样本不再被 60s 掐死（间接验证）。

    直接构造 httpx 超时语义：read=300 时 126s 延迟在读窗口内；read=60 时超。
    （完整退避重试链由 client 的既有 retry 机制承担，本组钉住分档值正确。）
    """

    def test_126s_sample_within_397b_window(self):
        s = _resolve("Qwen/Qwen3.5-397B-A17B")
        self.assertGreaterEqual(self._read_sec(s), 126)

    def test_126s_sample_exceeds_default_window(self):
        s = _resolve("Qwen/Qwen3.8-Flash-Next")
        self.assertLess(self._read_sec(s), 126)

    def _read_sec(self, settings):
        return settings["timeout"].read


if __name__ == "__main__":
    unittest.main(verbosity=2)
