#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
LCG 线性同余预测攻击 · 双语言镜像 (Python 侧, 纯标准库)

与 Go 侧 internal/ctfplatform/lcg_predict.go 独立实现、互相印证：
- 形态①：参数全知（a,c,m,seed）→ 二进制倍增求 K 步后状态
- 形态②：模数已知 + 连续输出 → a=(x2-x1)/(x1-x0) mod m，c=x1-a·x0 mod m
- 形态③：模数未知 + >=6 连续输出 → gcd 恢复 m（m | t_{i+1}·t_{i-1} - t_i²），再走形态②
- 全基准集中只存 flag_sha256，绝不存明文

运行：
    python judge_lcg.py                 # 校验 lcg_benchmark.json
    python judge_lcg.py --selfcheck    # 三形态前向交叉验证
"""
import argparse
import hashlib
import json
import os
import re
import sys
from math import gcd

HERE = os.path.dirname(os.path.abspath(__file__))
BENCH = os.path.join(HERE, "lcg_benchmark.json")

_RE_SIGNAL = re.compile(r'(?i)\b(lcg|linear[_\s-]?congruential)\b')
_RE_OUTPUTS = re.compile(r'(?i)\b(?:outputs?|states?|values?)\s*[:=]\s*\[([0-9,\s]+)\]')
_RE_MOD = re.compile(r'(?i)\b(?:modulus|modulo|mod|m)\s*[:=]\s*(\d+)')
_RE_MULT = re.compile(r'(?i)\b(?:multiplier|\ba)\s*[:=]\s*(\d+)')
_RE_INCR = re.compile(r'(?i)\b(?:increment|\bc)\s*[:=]\s*(\d+)')
_RE_SEED = re.compile(r'(?i)\bseed\s*[:=]\s*(\d+)')
_RE_STEPS = re.compile(r'(?i)\bafter\s+(\d+)\s+steps?')


def _first(rx, s):
    m = rx.search(s)
    return int(m.group(1)) if m else None


def step(x, a, c, m):
    return (a * x + c) % m


def advance(seed, a, c, m, steps):
    """二进制倍增：O(log steps)。仿射复合 (A,C)∘(A2,C2)=(A·A2, A·C2+C)。"""
    A, C = 1 % m, 0 % m
    for i in range(steps.bit_length() - 1, -1, -1):
        A, C = (A * A) % m, (A * C + C) % m
        if (steps >> i) & 1:
            A, C = (A * a) % m, (A * c + C) % m
    return (A * seed + C) % m


def recover_ac(outs, m):
    """由连续输出与模数反解 (a,c)，并用全序列验证；失败返回 None。"""
    if len(outs) < 3 or m <= 0:
        return None
    d0 = (outs[1] - outs[0]) % m
    d1 = (outs[2] - outs[1]) % m
    try:
        inv = pow(d0, -1, m)
    except ValueError:
        return None
    a = (d1 * inv) % m
    c = (outs[1] - a * outs[0]) % m
    cur = outs[0]
    for i in range(1, len(outs)):
        cur = step(cur, a, c, m)
        if cur != outs[i]:
            return None
    return a, c


def recover_modulus(outs):
    """由 >=6 连续输出经 gcd 恢复模数（可能为其倍数）。"""
    if len(outs) < 6:
        return None
    t = [outs[i + 1] - outs[i] for i in range(len(outs) - 1)]
    g = 0
    for i in range(1, len(t) - 1):
        d = t[i + 1] * t[i - 1] - t[i] * t[i]
        g = gcd(g, abs(d))
        if g == 0:
            return None
    return g if g > 1 else None


def modulus_candidates(g):
    out = []
    for p in (2, 3, 5, 7, 11, 13, 17, 19, 23, 29, 31, 37, 41, 43, 47):
        if g % p == 0:
            out.append(g // p)
    out.append(g)
    return out


def solve_from_text(text):
    """从题目描述解析并预测，返回 [str(flag)] 或 []。"""
    if not _RE_SIGNAL.search(text):
        return []
    outs = []
    mo = _RE_OUTPUTS.search(text)
    if mo:
        for p in mo.group(1).split(','):
            p = p.strip()
            if p:
                outs.append(int(p))

    mod = _first(_RE_MOD, text)
    mult = _first(_RE_MULT, text)
    incr = _first(_RE_INCR, text)
    seed = _first(_RE_SEED, text)
    steps = _first(_RE_STEPS, text)

    if None not in (mod, mult, incr, seed, steps):
        return ["flag{%d}" % advance(seed, mult, incr, mod, steps)]
    if mod is not None and len(outs) >= 3:
        r = recover_ac(outs, mod)
        if r:
            return ["flag{%d}" % step(outs[-1], r[0], r[1], mod)]
        return []
    if len(outs) >= 6:
        g = recover_modulus(outs)
        if g is None:
            return []
        for cand in modulus_candidates(g):
            r = recover_ac(outs, cand)
            if r:
                return ["flag{%d}" % step(outs[-1], r[0], r[1], cand)]
    return []


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
    print('LCG %d/%d' % (hit, total))
    return total, hit


# ── 前向 LCG（仅用于 selfcheck 真值比对） ──
def _gen(seed, a, c, m, n):
    out = []
    cur = seed
    for _ in range(n):
        out.append(cur)
        cur = step(cur, a, c, m)
    return out


def selfcheck():
    a = 6364136223846793005
    c = 1442695040888963407
    m = 1 << 64
    seed = 20260914

    # 形态①：倍增 vs 朴素迭代
    for k in (0, 1, 2, 7, 100, 1000, 999999):
        cur = seed
        for _ in range(k):
            cur = step(cur, a, c, m)
        assert advance(seed, a, c, m, k) == cur, "advance mismatch k=%d" % k

    # 形态②：已知模数反解 a,c
    outs = _gen(seed, a, c, m, 5)
    r = recover_ac(outs, m)
    assert r == (a, c), "recover_ac mismatch: %r" % (r,)

    # 形态③：未知模数 gcd 恢复（选参数使 gcd 恰为 m）
    m3, a3, c3, s3 = 2147483647, 48271, 11, 999
    outs3 = _gen(s3, a3, c3, m3, 8)
    g = recover_modulus(outs3)
    assert g is not None and g % m3 == 0, "gcd 未含真实 m: g=%r m=%r" % (g, m3)
    hit3 = False
    for cand in modulus_candidates(g):
        rr = recover_ac(outs3, cand)
        if rr:
            assert cand == m3 and step(outs3[-1], rr[0], rr[1], cand) == step(outs3[-1], a3, c3, m3), \
                "形态③ 预测错 cand=%r" % (cand,)
            hit3 = True
            break
    assert hit3, "形态③ 未命中"

    # 解析路径（三形态 description）
    d1 = ("An LCG service.\nmodulus = %d\nmultiplier = %d\nincrement = %d\nseed = %d\n"
          "Predict the state after 1000 steps as flag{value}.\n" % (m, a, c, seed))
    want1 = advance(seed, a, c, m, 1000)
    assert solve_from_text(d1) == ["flag{%d}" % want1], "解析①失败"
    d2 = ("An LCG with known modulus = %d leaked consecutive outputs = [%s].\n"
          "Predict the next as flag{value}.\n" % (m3, ', '.join(map(str, _gen(1, 48271, 0, m3, 5)))))
    outs2 = _gen(1, 48271, 0, m3, 5)
    assert solve_from_text(d2) == ["flag{%d}" % step(outs2[-1], 48271, 0, m3)], "解析②失败"
    d3 = ("The LCG parameters are unknown. Leaked consecutive outputs = [%s].\n"
          "Predict the next as flag{value}.\n" % ', '.join(map(str, outs3)))
    assert solve_from_text(d3) == ["flag{%d}" % step(outs3[-1], a3, c3, m3)], "解析③失败"

    print('SELFCHECK PASS (LCG advance/recover_ac/recover_modulus, 3 forms)')


if __name__ == '__main__':
    ap = argparse.ArgumentParser()
    ap.add_argument('--selfcheck', action='store_true')
    args = ap.parse_args()
    if args.selfcheck:
        selfcheck()
        sys.exit(0)
    run()
