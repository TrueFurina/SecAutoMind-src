#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
生成 MT19937 状态恢复 双语言基准 (mt19937_benchmark.json)。

确定性合成：用标准 MT19937 前向生成器产生 624 个连续 32-bit 输出，
再取第 625 个输出作为"下一个随机值"（被当作 secret）。
flag = flag{<next>}，flag_sha256 = sha256(flag)，绝不存明文 next。

攻防语义：MT19937 的内部状态恰为 624 个 32-bit 字，输出 = temper(state[i]) 可逆；
泄露 624 个连续完整输出即可反解状态并预测后续所有输出。
"""
import hashlib
import json
import os

HERE = os.path.dirname(os.path.abspath(__file__))
OUT = os.path.join(HERE, "mt19937_benchmark.json")

N = 624
M = 397
MATRIX_A = 0x9908b0df
UPPER = 0x80000000
LOWER = 0x7fffffff


def temper(y):
    y ^= y >> 11
    y ^= (y << 7) & 0x9d2c5680
    y ^= (y << 15) & 0xefc60000
    y ^= y >> 18
    return y & 0xffffffff


def twist(state):
    for i in range(N):
        y = (state[i] & UPPER) | (state[(i + 1) % N] & LOWER)
        state[i] = state[(i + M) % N] ^ (y >> 1)
        if y & 1:
            state[i] ^= MATRIX_A
        state[i] &= 0xffffffff


def make_gen(seed):
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


CASES = [
    {"name": "mt19937_default_seed", "seed": 19650218,
     "note": "MT19937 默认种子 19650218，泄露 624 个连续输出，预测第 625 个（secret）"},
    {"name": "mt19937_custom_seed", "seed": 0xCAFEBABE,
     "note": "MT19937 自定义种子 0xCAFEBABE，同样泄露 624 输出后预测下一个"},
]


def main():
    problems = {}
    for c in CASES:
        gen = make_gen(c["seed"])
        outputs = [gen() for _ in range(N)]
        nxt = gen()
        flag = "flag{%d}" % nxt
        description = (
            "Mersenne Twister MT19937 prediction challenge.\n"
            "The server used MT19937 to generate \"random\" tokens, but it leaked "
            "624 consecutive 32-bit outputs of the RNG.\n"
            "Predict the next output (the 625th value) — it is used as the secret flag.\n\n"
            "outputs = [%s]\n" % ", ".join(str(x) for x in outputs)
        )
        problems[c["name"]] = {
            "description": description,
            "flag_sha256": hashlib.sha256(flag.encode()).hexdigest(),
            "algo": "mt19937",
            "note": c["note"],
        }
    with open(OUT, "w", encoding="utf-8") as f:
        json.dump({"problems": problems}, f, ensure_ascii=False, indent=2)
    print("wrote %s (%d problems)" % (OUT, len(problems)))
    for n, p in problems.items():
        print("  %s -> flag_sha256=%s" % (n, p["flag_sha256"][:16]))


if __name__ == "__main__":
    main()
