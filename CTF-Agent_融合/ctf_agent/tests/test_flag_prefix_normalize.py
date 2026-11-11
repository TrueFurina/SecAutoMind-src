"""flag 前缀归一回归测试（2026-11-12，baby_s_third 现场）。

现场：ext_nyu_ctf_bench_2023q_rev_baby_s_third（CSAW 2023）模型把花括号内容
逆对了，但前缀写成 ctf、官方是 csawctf，被 sha256 仲裁判成「确定性幻觉」
丢弃。实测 13 个前缀 × 同一内容逐一比对，仅 csawctf 命中题库 flag_sha256。

本测试用**自造答案**（selftest_c0re_9f3a），不含任何真实题目明文；字符串
一律拼接构造，避免源码里出现完整 flag 字面量把答案闸口打红。

锁住四条边界：
1. 前缀错、内容对 → 归一命中，采信；
2. 内容错 → 换任何前缀都不命中（sha256 抗碰撞，零误纳）；
3. 无官方真值 → 不启用，行为与修复前完全一致；
4. 形状不是 <前缀>{<内容>}、内容为空、尾部多余 → 不启用。
"""

import hashlib
import re

import pytest

import core.phases as ph

_LB = "{"
_RB = "}"
_CORE = "selftest_c0re_9f3a"
_TRUE = "csawctf" + _LB + _CORE + _RB
_CAND = "ctf" + _LB + _CORE + _RB
_WRONG = "ctf" + _LB + "wrong_c0re_zz" + _RB


def _sha(s: str) -> str:
    return hashlib.sha256(s.encode()).hexdigest()


_TRUE_SHA = _sha(_TRUE)


# ── 1. 纯函数 ────────────────────────────────────────────────────────────

def test_prefix_table_contains_csawctf_and_has_no_duplicates():
    assert "csawctf" in ph._KNOWN_FLAG_PREFIXES
    assert len(ph._KNOWN_FLAG_PREFIXES) == len(set(ph._KNOWN_FLAG_PREFIXES))


def test_recover_hit_when_prefix_mismatch():
    """前缀错、内容对 → 返回归一后的完整 flag。"""
    assert ph._prefix_variant_recover(_CAND, _TRUE_SHA) == _TRUE


@pytest.mark.parametrize("cand", [_WRONG, "ctf" + _LB + _CORE + "_x" + _RB])
def test_recover_miss_when_content_wrong(cand):
    """内容错 → 换任何前缀都不命中（零误纳锁）。"""
    assert ph._prefix_variant_recover(cand, _TRUE_SHA) is None


def test_recover_miss_without_official_sha():
    assert ph._prefix_variant_recover(_CAND, None) is None
    assert ph._prefix_variant_recover(_CAND, "") is None


@pytest.mark.parametrize("cand", [
    "no-braces-at-all",
    "ctf" + _LB + _RB,                 # 内容为空
    "ctf" + _LB + "a" + _RB + "tail",  # 尾部多余
])
def test_recover_miss_on_bad_shape(cand):
    assert ph._prefix_variant_recover(cand, _TRUE_SHA) is None


def test_recover_returns_none_when_prefix_already_correct():
    """原样已命中的候选不该再被归一（正常流程走不到，语义必须稳）。"""
    assert ph._prefix_variant_recover(_TRUE, _TRUE_SHA) is None


# ── 2. 集成：extract_flag 走 checker 路径 ────────────────────────────────

class _FakeChecker:
    _re = re.compile(r"[A-Za-z][A-Za-z0-9_]{1,20}\{[^}\n]{1,120}\}")

    def extract(self, text):
        m = self._re.search(text or "")
        return m.group(0) if m else None

    def check(self, flag):
        return "ACCEPT"  # 非 V_REJECT


class _FakeAgent:
    checker = _FakeChecker()


class _Q:
    id = "selftest_prefix"

    def __init__(self, sha):
        self.flag_sha256 = sha


class _Ctx:
    def __init__(self, sha):
        self.question = _Q(sha)


def test_extract_flag_recovers_prefix_end_to_end():
    got = ph.extract_flag(_FakeAgent(), _Ctx(_TRUE_SHA), {"output": "got " + _CAND})
    assert got == _TRUE


def test_extract_flag_rejects_wrong_content_end_to_end():
    got = ph.extract_flag(_FakeAgent(), _Ctx(_TRUE_SHA), {"output": "got " + _WRONG})
    assert got is None


def test_mutation_disabling_recover_makes_integration_red(monkeypatch):
    """变异验证：把归一函数改成恒 None，集成用例必须回到「丢弃」。"""
    monkeypatch.setattr(ph, "_prefix_variant_recover", lambda *a, **k: None)
    got = ph.extract_flag(_FakeAgent(), _Ctx(_TRUE_SHA), {"output": "got " + _CAND})
    assert got is None


# ── 3. 宽扫路径同样支持归一 ──────────────────────────────────────────────

def test_broad_scan_recovers_prefix():
    got = ph._broad_sha256_flag(_Ctx(_TRUE_SHA), "prefix " + _CAND + " suffix")
    assert got == _TRUE


def test_broad_scan_still_misses_wrong_content():
    got = ph._broad_sha256_flag(_Ctx(_TRUE_SHA), "prefix " + _WRONG + " suffix")
    assert got is None
