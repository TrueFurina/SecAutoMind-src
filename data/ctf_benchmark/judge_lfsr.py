#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
LFSR 流预测攻击（Berlekamp–Massey）· 双语言镜像 (Python 侧, 纯标准库)

与 Go 侧 internal/ctfplatform/lfsr_predict.go 独立实现、互相印证：
- 观察到 >= 2L 个连续输出比特（L = 序列最小线性复杂度）
- Berlekamp–Massey 在 GF(2) 上恢复最小连接多项式
- s[k] = Σ_{i=1..L} C[i]·s[k-i] 逐位前推 → 预测后续 16 位
- 无需知道 LFSR 抽头与初态，纯位运算，零外部依赖
- 全基准集中只存 flag_sha256，绝不存明文

运行：
    python judge_lfsr.py                 # 校验 lfsr_benchmark.json
    python judge_lfsr.py --selfcheck    # 前向 Fibonacci LFSR 交叉验证预测正确性
"""
import argparse
import hashlib
import json
import os
import re
import sys

HERE = os.path.dirname(os.path.abspath(__file__))
BENCH = os.path.join(HERE, "lfsr_benchmark.json")

PREDICT = 16
_RE_SIGNAL = re.compile(r'(?i)\b(lfsr|linear[_\s-]?feedback[_\s-]?shift[_\s-]?register|'
                        r'berlekamp[_\s-]?massey|shift[_\s-]?register)\b')
_RE_BITS = re.compile(r'(?i)\b([01]{48,})\b')


def berlekamp_massey(seq):
    """GF(2) 上恢复最小连接多项式。返回 (C, L)：C[0]=1，
    递推 s[k] = Σ_{i=1..L} C[i]·s[k-i]。seq 为 0/1 列表。"""
    B = [1]
    C = [1]
    L = 0
    m = 1
    for n in range(len(seq)):
        d = seq[n]
        for i in range(1, L + 1):
            if i < len(C):
                d ^= C[i] & seq[n - i]
        if d == 0:
            m += 1
            continue
        if 2 * L <= n:
            T = C[:]
            while len(C) < m + len(B):
                C.append(0)
            for i in range(len(B)):
                C[i + m] ^= B[i]
            L = n + 1 - L
            B = T
            m = 1
        else:
            while len(C) < m + len(B):
                C.append(0)
            for i in range(len(B)):
                C[i + m] ^= B[i]
            m += 1
    return C, L


def predict_next(bits, k=PREDICT):
    """由已观察比特 bits 预测随后 k 位。返回 0/1 列表。"""
    C, L = berlekamp_massey(bits)
    seq = list(bits)
    while len(seq) < len(bits) + k:
        nxt = 0
        for i in range(1, L + 1):
            if i < len(C) and len(seq) - i >= 0:
                nxt ^= C[i] & seq[len(seq) - i]
        seq.append(nxt)
    return seq[len(bits):]


def solve_from_text(text):
    """从题目描述解析比特流并预测，返回 [str(flag)] 或 []。"""
    if not _RE_SIGNAL.search(text):
        return []
    m = _RE_BITS.search(text)
    if not m:
        return []
    raw = m.group(1)
    bits = [1 if c == '1' else 0 for c in raw]
    nxt = predict_next(bits)
    if len(nxt) < PREDICT:
        return []
    val = 0
    for b in nxt:
        val = (val << 1) | b
    return ["flag{%d}" % val]


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
    print('LFSR %d/%d' % (hit, total))
    return total, hit


# ── 前向 Fibonacci LFSR（仅用于 selfcheck 真值比对） ──
def _fib_lfsr(init, taps):
    reg = list(init)

    def nxt():
        out = reg[0]
        fb = 0
        for t in taps:
            fb ^= reg[t]
        reg.append(fb)
        del reg[0]
        return out

    return nxt


def selfcheck():
    cases = [
        (16, [15, 6, 1, 0], [1] * 16),
        (24, [23, 6, 4, 0], [1] * 24),
        (32, [31, 22, 2, 1], [1] * 32),
    ]
    for degree, taps, init in cases:
        gen = _fib_lfsr(init, taps)
        leak = [gen() for _ in range(2 * degree + 16)]
        true_next = [gen() for _ in range(PREDICT)]
        got = predict_next(leak)
        assert got == true_next, \
            "selfcheck failed degree=%d: got %r want %r" % (degree, got, true_next)
        desc = ("LFSR keystream prediction challenge.\n"
                "bits = %s\n" % ''.join(str(x) for x in leak))
        cands = solve_from_text(desc)
        want = 0
        for b in true_next:
            want = (want << 1) | b
        assert cands == ["flag{%d}" % want], "parse path failed degree=%d: %r" % (degree, cands)
    print('SELFCHECK PASS (Berlekamp–Massey LFSR prediction, 3 degrees)')


if __name__ == '__main__':
    ap = argparse.ArgumentParser()
    ap.add_argument('--selfcheck', action='store_true')
    args = ap.parse_args()
    if args.selfcheck:
        selfcheck()
        sys.exit(0)
    run()
