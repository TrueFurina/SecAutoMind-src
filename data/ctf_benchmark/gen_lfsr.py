#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
生成 LFSR 流预测 双语言基准 (lfsr_benchmark.json)。

确定性合成：用 Fibonacci 型 LFSR 前向生成器产生 2*degree+16 位输出（degree=寄存器
级数），泄露前 2*degree 位…实际描述给出全部 (2*degree+16) 位并"要求预测紧随的
16 位"。flag = flag{<16 位二进制的十进制值>}，flag_sha256 = sha256(flag)，绝不存明文。

攻防语义：输出比特是 LFSR 状态的线性函数，观察长度 >= 2L（L=最小线性复杂度）即可用
Berlekamp–Massey 恢复线性递推并预测后续比特（无需寄存器抽头/初态）。
生成后立即用 BM 自检：预测结果必须与真值一致，否则换种子重来（保证入库基准可复现）。
"""
import hashlib
import json
import os

HERE = os.path.dirname(os.path.abspath(__file__))
OUT = os.path.join(HERE, "lfsr_benchmark.json")

PREDICT = 16


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


def _berlekamp_massey(seq):
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


def _predict(bits):
    C, L = _berlekamp_massey(bits)
    seq = list(bits)
    while len(seq) < len(bits) + PREDICT:
        nxt = 0
        for i in range(1, L + 1):
            if i < len(C) and len(seq) - i >= 0:
                nxt ^= C[i] & seq[len(seq) - i]
        seq.append(nxt)
    return seq[len(bits):]


CASES = [
    {"name": "lfsr_deg24", "degree": 24,
     "taps": [23, 6, 4, 0], "seed_shift": 0,
     "note": "24 级 Fibonacci LFSR 密钥流：泄露 64 位，预测随后 16 位"},
    {"name": "lfsr_deg32", "degree": 32,
     "taps": [31, 22, 2, 1], "seed_shift": 1,
     "note": "32 级 Fibonacci LFSR 密钥流：泄露 80 位，预测随后 16 位"},
]


def main():
    problems = {}
    for c in CASES:
        degree = c["degree"]
        init = [1] * degree  # 初态全 1，避免退化
        gen = _fib_lfsr(init, c["taps"])
        # 共需 2L+16（泄露）+ 16（预测目标）位
        total_bits = 2 * degree + 2 * PREDICT
        bits = [gen() for _ in range(total_bits)]
        leak = bits[:2 * degree + PREDICT]
        true_next = bits[2 * degree + PREDICT:]
        # 生成后自检（保证入库基准可复现、可被 BM 预测）
        got = _predict(leak)
        assert got == true_next, "BM selfcheck failed for %s" % c["name"]
        val = 0
        for b in true_next:
            val = (val << 1) | b
        flag = "flag{%d}" % val
        leak_str = ''.join(str(x) for x in leak)
        description = (
            "A server generates a keystream with a linear feedback shift register (LFSR), "
            "but it leaked %d consecutive output bits of the LFSR keystream.\n"
            "Predict the next %d bits (the secret) with Berlekamp-Massey.\n\n"
            "bits = %s\n" % (len(leak), PREDICT, leak_str)
        )
        problems[c["name"]] = {
            "description": description,
            "flag_sha256": hashlib.sha256(flag.encode()).hexdigest(),
            "algo": "lfsr",
            "note": c["note"],
        }
    with open(OUT, "w", encoding="utf-8") as f:
        json.dump({"problems": problems}, f, ensure_ascii=False, indent=2)
    print("wrote %s (%d problems)" % (OUT, len(problems)))
    for n, p in problems.items():
        print("  %s -> flag_sha256=%s" % (n, p["flag_sha256"][:16]))


if __name__ == "__main__":
    main()
