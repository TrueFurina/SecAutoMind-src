#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
MT19937 状态恢复攻击 · 双语言镜像 (Python 侧, 纯标准库)

与 Go 侧 internal/ctfplatform/mt19937_recover.go 独立实现、互相印证：
- 泄露 624 个连续 32-bit 输出 → 由输出反解内部状态（untemper，可逆双射）
- 推进一轮 twist（与生成器内部完全一致）
- 预测第 625 个输出 = 下一个"随机"值 = temper(state'[0])
- 全程无需种子、无需任何外部依赖，纯位运算
- 全基准集中只存 flag_sha256，绝不存明文

运行：
    python judge_mt19937.py                 # 校验 mt19937_benchmark.json
    python judge_mt19937.py --selfcheck    # 用标准 MT19937 前向生成器交叉验证预测正确性
"""
import argparse
import hashlib
import json
import os
import re
import sys

HERE = os.path.dirname(os.path.abspath(__file__))
BENCH = os.path.join(HERE, "mt19937_benchmark.json")

N = 624
M = 397
MATRIX_A = 0x9908b0df
UPPER = 0x80000000
LOWER = 0x7fffffff

_RE_SIGNAL = re.compile(r'(?i)\b(mersenne[_\s-]?twister|mt[_\s-]?19937|mt19937)\b')
_RE_INT = re.compile(r'0x[0-9a-fA-F]+|\d+')


def temper(y):
    y ^= y >> 11
    y ^= (y << 7) & 0x9d2c5680
    y ^= (y << 15) & 0xefc60000
    y ^= y >> 18
    return y & 0xffffffff


def untemper(y):
    y = _undo_rshift(y, 18)
    y = _undo_lshift(y, 15, 0xefc60000)
    y = _undo_lshift(y, 7, 0x9d2c5680)
    y = _undo_rshift(y, 11)
    return y & 0xffffffff


def _undo_rshift(y, shift):
    # 前向 o[p] = x[p] ^ x[p+shift]，故 x[p] = o[p] ^ x[p+shift]，自高位向低位递推。
    x = 0
    for p in range(31, -1, -1):
        bit = (y >> p) & 1
        if p + shift < 32:
            bit ^= (x >> (p + shift)) & 1
        if bit:
            x |= (1 << p)
    return x


def _undo_lshift(y, shift, mask):
    x = 0
    for p in range(32):
        bit = (y >> p) & 1
        if ((mask >> p) & 1) and p >= shift:
            bit ^= (x >> (p - shift)) & 1
        if bit:
            x |= (1 << p)
    return x


def twist(state):
    for i in range(N):
        y = (state[i] & UPPER) | (state[(i + 1) % N] & LOWER)
        state[i] = state[(i + M) % N] ^ (y >> 1)
        if y & 1:
            state[i] ^= MATRIX_A
        state[i] &= 0xffffffff


def predict_next(outputs):
    if len(outputs) < N:
        return None
    state = [untemper(o) for o in outputs[:N]]
    twist(state)
    return temper(state[0])


def parse_uint32s(s):
    out = []
    for m in _RE_INT.findall(s):
        try:
            v = int(m, 16) if m.lower().startswith('0x') else int(m, 10)
        except ValueError:
            continue
        if 0 <= v <= 0xffffffff:
            out.append(v)
    return out


def extract_outputs(text):
    i = text.find('[')
    if i >= 0:
        j = text.find(']', i)
        if j > 0:
            seg = text[i + 1:j]
            ints = parse_uint32s(seg)
            if len(ints) >= N:
                return ints
    return parse_uint32s(text)


def solve_from_text(text):
    """从题目描述解析并预测下一个输出，返回 [str(flag)] 或 []。"""
    if not _RE_SIGNAL.search(text):
        return []
    outputs = extract_outputs(text)
    if len(outputs) < N:
        return []
    nxt = predict_next(outputs)
    if nxt is None:
        return []
    return ["flag{%d}" % nxt]


def run():
    with open(BENCH, 'r', encoding='utf-8') as f:
        data = json.load(f)
    total = len(data['problems'])
    hit = 0
    for name, p in data['problems'].items():
        cands = solve_from_text(p['description'])
        want = p['flag_sha256'].lower()
        ok = False
        for c in cands:
            if hashlib.sha256(c.encode()).hexdigest() == want:
                ok = True
                break
        print(('HIT  ' if ok else 'MISS ') + name)
        hit += 1 if ok else 0
    print('MT19937 %d/%d' % (hit, total))
    return total, hit


# ── 标准 MT19937 前向生成器（仅用于 selfcheck 真值比对） ──
def _forward_mt(seed):
    state = [0] * N
    state[0] = seed & 0xffffffff
    for i in range(1, N):
        state[i] = (1812433253 * (state[i - 1] ^ (state[i - 1] >> 30)) + i) & 0xffffffff
    idx = [0]

    def nxt():
        if idx[0] >= N:
            twist(state)
            idx[0] = 0
        y = temper(state[idx[0]])
        idx[0] += 1
        return y

    return nxt


def selfcheck():
    for seed in (1, 19650218, 0xCAFEBABE, 0x1234567):
        gen = _forward_mt(seed)
        outputs = [gen() for _ in range(N)]
        true_next = gen()
        got = predict_next(outputs)
        assert got == true_next, "selfcheck failed seed=%d: got %r want %r" % (seed, got, true_next)
        # 解析路径也验证一遍
        desc = ("Mersenne Twister MT19937 prediction.\n"
                "outputs = [%s]\n" % ", ".join(str(x) for x in outputs))
        cands = solve_from_text(desc)
        assert cands == ["flag{%d}" % true_next], "parse path failed seed=%d: %r" % (seed, cands)
    print('SELFCHECK PASS (MT19937 state recovery, 4 seeds)')


if __name__ == '__main__':
    ap = argparse.ArgumentParser()
    ap.add_argument('--selfcheck', action='store_true')
    args = ap.parse_args()
    if args.selfcheck:
        selfcheck()
        sys.exit(0)
    run()
