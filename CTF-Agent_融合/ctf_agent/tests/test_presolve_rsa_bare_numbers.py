"""presolve RSA 参数提取：无标签「每行一个数字」形态（2026-11-12 修复）。

病根：_try_rsa_factor 只认 `n = <数字>` 标签形式。题目直接给 n / e / c 三行
十进制（pycryptodome 打印、sagemath 输出都是这个形态）时，整条 RSA 确定性链
被静默跳过——表现上是「presolve 没解出」，实质是「能力不存在」。

本文件锁两件事：
1. 三行裸数字必须被读取并解出（主场景）；
2. 其它形态（行数不对、含说明文字、e 位宽异常）不得被误采用。

测试用的 p/q 由 gmpy2.next_prime 生成、相差约 230，费马一步命中；
n 需足够大，才能让 int(b"flag{...}") 落在 n 以内（60 bit 的 n 装不下明文，
那会让测试误报「解不出」——2026-11-12 首版就踩了）。
"""

import asyncio
from types import SimpleNamespace

import pytest

gmpy2 = pytest.importorskip("gmpy2")

from core import presolve as P

_P = int(gmpy2.next_prime(10 ** 38))
_Q = int(gmpy2.next_prime(_P + 200))
_N = _P * _Q
_E = 65537
_MSG = b"flag{bare_rsa}"
_M = int.from_bytes(_MSG, "big")
assert _M < _N, "测试夹具自检：明文必须落在模数内"
_C = pow(_M, _E, _N)


def _q(path, cat="crypto"):
    return SimpleNamespace(id="bare_rsa", category=cat, attachments=[path], extra={})


def test_bare_three_line_is_read(tmp_path):
    """三行裸数字（n / e / c）必须被读取并解出。"""
    p = tmp_path / "challenge.txt"
    p.write_text("%d\n%d\n%d\n" % (_N, _E, _C), encoding="utf-8")
    flag = asyncio.run(P._try_rsa_factor(_q(str(p))))
    assert flag is not None, "三行裸数字未被读取，RSA 确定性链被静默跳过"
    assert flag == "flag{bare_rsa}", flag


def test_labeled_form_still_works(tmp_path):
    """回归：原标签形式（n = ... / e = ... / c = ...）不能被这次改动破坏。"""
    p = tmp_path / "challenge.txt"
    p.write_text("n = %d\ne = %d\nc = %d\n" % (_N, _E, _C), encoding="utf-8")
    flag = asyncio.run(P._try_rsa_factor(_q(str(p))))
    assert flag == "flag{bare_rsa}", flag


@pytest.mark.parametrize("body", [
    "1234\n65537\n5678\n9999\n",                              # 4 行
    "1234\n5678\n",                                            # 2 行
    "notice: this is a rsa challenge\n1234\n65537\n5678\n",    # 含说明文字
    "1234567890123456789012\n999999999999999999999\n5678\n",   # 第 2 行 21 位（e 不可能）
])
def test_non_bare_shapes_not_taken(tmp_path, body):
    """保守护栏：不满足形态的一律不采用，宁可漏也不误命中说明文本。"""
    p = tmp_path / "challenge.txt"
    p.write_text(body, encoding="utf-8")
    assert asyncio.run(P._try_rsa_factor(_q(str(p)))) is None
