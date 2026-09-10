#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""生成 ECDSA nonce 复用攻击基准集 ecdsa_benchmark.json（secp256k1）。

两签名共享同一 nonce k 的离线私钥恢复（经典 nonce-reuse）：
    k = (z1 - z2) * (s1 - s2)^-1 mod n
    d = (s1*k - z1) * r^-1        mod n
flag = flag{<hex(d)>}，基准集仅存 sha256(flag)（不存明文）。

与 Go tryECDSANonceReuse / TestECDSANonceReuseAgainstBenchmark 双语言镜像：
描述文本严格采用 Go 侧正则可解析的 `r = ...`（十进制）格式，
flag 格式 `flag{<hex(d)>}`（小写最小长度十六进制），确保两侧还原同一 d 与同一 flag。
"""
import hashlib
import json
import os
import random

# secp256k1 曲线参数
P = 0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEFFFFFC2F
A = 0
B = 7
GX = 0x79BE667EF9DCBBAC55A06295CE870B07029BFCDB2DCE28D959F2815B16F81798
GY = 0x483ADA7726A3C4655DA4FBFC0E1108A8FD17B448A68554199C47D08FFB10D4B8
N = 0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEBAAEDCE6AF48A03BBFD25E8CD0364141


def inv(x, m):
    return pow(x % m, -1, m)


def ec_add(p1, p2):
    if p1 is None:
        return p2
    if p2 is None:
        return p1
    x1, y1 = p1
    x2, y2 = p2
    if x1 == x2 and (y1 + y2) % P == 0:
        return None
    if p1 == p2:
        lam = (3 * x1 * x1 + A) * inv(2 * y1, P) % P
    else:
        lam = (y2 - y1) * inv((x2 - x1) % P, P) % P
    x3 = (lam * lam - x1 - x2) % P
    y3 = (lam * (x1 - x3) - y1) % P
    return (x3, y3)


def ec_mul(k, pt):
    r = None
    k = k % N
    while k > 0:
        if k & 1:
            r = ec_add(r, pt)
        pt = ec_add(pt, pt)
        k >>= 1
    return r


def make_problem(seed):
    rng = random.Random(seed)
    d = rng.randrange(1, N - 1)
    k = rng.randrange(1, N - 1)
    R = ec_mul(k, (GX, GY))
    r = R[0] % N
    while r == 0:  # N 为素数，r!=0 即可逆
        k = rng.randrange(1, N - 1)
        R = ec_mul(k, (GX, GY))
        r = R[0] % N
    msg1 = ("ECDSA nonce reuse challenge message one (alpha) %d" % seed).encode()
    msg2 = ("ECDSA nonce reuse challenge message two (beta) %d" % seed).encode()
    z1 = int.from_bytes(hashlib.sha256(msg1).digest(), "big") % N
    z2 = int.from_bytes(hashlib.sha256(msg2).digest(), "big") % N
    kinv = inv(k, N)
    s1 = (kinv * (z1 + r * d)) % N
    s2 = (kinv * (z2 + r * d)) % N
    # 自洽校验：离线还原必须得到原 d
    krec = (z1 - z2) * inv((s1 - s2) % N, N) % N
    drec = ((s1 * krec - z1) * inv(r, N)) % N
    assert drec == d, "recovery mismatch (generator math bug)"
    dhex = format(d, "x")
    flag = "flag{" + dhex + "}"
    desc = (
        "ECDSA nonce reuse. Two signatures share the same nonce k.\n"
        "n  = %d\n"
        "r  = %d\n"
        "s1 = %d\n"
        "z1 = %d\n"
        "s2 = %d\n"
        "z2 = %d\n"
        "Recover d, flag=flag{<hex(d)>}.\n"
    ) % (N, r, s1, z1, s2, z2)
    return {
        "ecdsa_nonce_reuse_01": {
            "description": desc,
            "flag_sha256": hashlib.sha256(flag.encode()).hexdigest(),
            "note": "ECDSA 同 nonce 两签名(r 相同) → k=(z1-z2)/(s1-s2) → d=(s1*k-z1)/r mod n，"
                    "离线还原私钥 d，flag=flag{<hex(d)>}（纯大数运算，无在线 oracle）。",
        }
    }


HERE = os.path.dirname(os.path.abspath(__file__))
OUT = os.path.join(HERE, "ecdsa_benchmark.json")


def main():
    probs = make_problem(20260903)
    doc = {"problems": probs}
    json.dump(doc, open(OUT, "w", encoding="utf-8"), indent=2, ensure_ascii=False)
    for pid, p in probs.items():
        print("  %s | sha256:%s" % (pid, p["flag_sha256"]))
    print("写入 %s" % OUT)


if __name__ == "__main__":
    main()
