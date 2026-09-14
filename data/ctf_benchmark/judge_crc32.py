#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
CRC32 伪造攻击 · 双语言镜像 (Python 侧, 纯标准库)

与 Go 侧 internal/ctfplatform/crc32_forge.go 独立实现、互相印证：
- crc32_std：标准 CRC32（反射多项式 0xEDB88320，init/final xor）
- forge_suffix：由 crc32(m‖0000) ⊕ target 得到 d，解 32×32 GF(2) 线性方程组 L(X)=d
- 全基准集中只存 flag_sha256，绝不存明文

运行：
    python judge_crc32.py                 # 校验 crc32_benchmark.json
    python judge_crc32.py --selfcheck    # 与 zlib.crc32 交叉验证 + 伪造自检
"""
import argparse
import hashlib
import json
import os
import re
import sys
import zlib

HERE = os.path.dirname(os.path.abspath(__file__))
BENCH = os.path.join(HERE, "crc32_benchmark.json")

_RE_SIGNAL = re.compile(r'(?i)\bcrc[-_]?32\b')
_RE_MSGHEX = re.compile(r'(?i)message\s*(?:\(hex\))?\s*[:=]\s*([0-9a-fA-F]{2,})')
_RE_TARGET = re.compile(r'(?i)target\s*(?:crc32)?\s*(?:value)?\s*[:=]\s*(?:0x)?([0-9a-fA-F]{8})')


def _table():
    t = []
    for i in range(256):
        c = i
        for _ in range(8):
            c = (0xEDB88320 ^ (c >> 1)) if (c & 1) else (c >> 1)
        t.append(c & 0xFFFFFFFF)
    return t


_TABLE = _table()


def crc32_std(data):
    r = 0xFFFFFFFF
    for b in data:
        r = (r >> 8) ^ _TABLE[(r ^ b) & 0xFF]
    return r ^ 0xFFFFFFFF


def _solve_gf2(cols, rhs):
    """解 32 未知 GF(2) 方程组：sum x_j·cols[j] = rhs。返回 x(32bit) 或 None。"""
    rows = []
    for bit in range(32):
        coef = 0
        for j, v in enumerate(cols):
            if (v >> bit) & 1:
                coef |= (1 << j)
        rows.append(coef | (((rhs >> bit) & 1) << 32))
    pivot = {}
    r = 0
    for col in range(32):
        sel = -1
        for i in range(r, 32):
            if (rows[i] >> col) & 1:
                sel = i
                break
        if sel < 0:
            continue
        rows[r], rows[sel] = rows[sel], rows[r]
        for i in range(32):
            if i != r and (rows[i] >> col) & 1:
                rows[i] ^= rows[r]
        pivot[col] = r
        r += 1
    for i in range(r, 32):
        if rows[i] == (1 << 32):
            return None
    x = 0
    for col, pr in pivot.items():
        if (rows[pr] >> 32) & 1:
            x |= (1 << col)
    return x


def forge_suffix(msg, target):
    """返回 4 字节后缀 X（bytes），使 crc32(msg‖X)==target；无解返回 None。"""
    base = crc32_std(bytes(msg) + b"\x00\x00\x00\x00")
    d = base ^ target
    cols = []
    for i in range(4):
        for b in range(8):
            buf = bytearray(4)
            buf[i] = (1 << b) & 0xFF
            r = 0
            for by in buf:
                r = (r >> 8) ^ _TABLE[(r ^ by) & 0xFF]
            cols.append(r)
    x = _solve_gf2(cols, d)
    if x is None:
        return None
    out = bytes([x & 0xFF, (x >> 8) & 0xFF, (x >> 16) & 0xFF, (x >> 24) & 0xFF])
    if crc32_std(bytes(msg) + out) != target:
        return None
    return out


def solve_from_text(text):
    """从题目描述解析并伪造，返回 [flag] 或 []。"""
    if not _RE_SIGNAL.search(text):
        return []
    mm = _RE_MSGHEX.search(text)
    tm = _RE_TARGET.search(text)
    if not mm or not tm:
        return []
    try:
        msg = bytes.fromhex(mm.group(1))
    except ValueError:
        return []
    if not msg:
        return []
    target = int(tm.group(1), 16) & 0xFFFFFFFF
    x = forge_suffix(msg, target)
    if x is None:
        return []
    return ["flag{%s}" % x.hex()]


def run():
    with open(BENCH, 'r', encoding='utf-8') as f:
        data = json.load(f)
    total = len(data['problems'])
    hit = 0
    for name, p in data['problems'].items():
        cands = solve_from_text(p['description'])
        want = p['flag_sha256'].lower()
        ok = any(hashlib.sha256(c.encode()).hexdigest() == want for c in cands)
        print(('HIT  ' if ok else 'MISS ') + name)
        hit += 1 if ok else 0
    print('CRC32 %d/%d' % (hit, total))
    return total, hit


def selfcheck():
    # 1) crc32_std 与 zlib.crc32 交叉验证
    for m in (b"", b"a", b"hello", b"The quick brown fox", bytes(range(65))):
        assert crc32_std(m) == (zlib.crc32(m) & 0xFFFFFFFF), "crc32 mismatch %r" % m
    # 2) 伪造：任意目标都可命中，且唯一
    for m in (b"amount=100&to=alice", b"admin=0", b"", b"session=deadbeefcafe"):
        for tg in (0x00000000, 0xDEADBEEF, 0xFFFFFFFF, 0x12345678, 0x0BADF00D):
            x = forge_suffix(m, tg)
            assert x is not None and len(x) == 4, "forge failed %r %08x" % (m, tg)
            assert crc32_std(m + x) == tg, "forge mismatch %r %08x" % (m, tg)
            assert forge_suffix(m, tg) == x, "forge not unique"
    # 3) 解析路径
    m = b"user=guest&admin=0"
    tg = 0x1A2B3C4D
    d = ("Integrity is protected with a CRC32 checksum (not a MAC).\n"
         "message (hex) = %s\ncrc32 = %08x\ntarget = %08x\n"
         "Append 4 bytes as flag{<8 hex>}.\n" % (m.hex(), crc32_std(m), tg))
    x = forge_suffix(m, tg)
    assert solve_from_text(d) == ["flag{%s}" % x.hex()], "解析失败"
    # 4) 反误报
    assert solve_from_text("firmware protected by a CRC32 checksum over the header.") == []
    assert solve_from_text("message (hex) = deadbeef\ntarget = 12345678\nfoo") == []
    print('SELFCHECK PASS (CRC32 stdlib cross-check / forge uniqueness / parse / no-FP)')


if __name__ == '__main__':
    ap = argparse.ArgumentParser()
    ap.add_argument('--selfcheck', action='store_true')
    args = ap.parse_args()
    if args.selfcheck:
        selfcheck()
        sys.exit(0)
    run()
