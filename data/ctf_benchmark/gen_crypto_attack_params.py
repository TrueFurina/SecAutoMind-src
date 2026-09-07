# -*- coding: utf-8 -*-
"""合成 crypto 经典攻击三题的参数并自验数学（共模/Hastad 广播/Wiener）。"""
import hashlib
import json
import random
from math import gcd

random.seed(20260908)


def gen_prime(bits):
    while True:
        p = random.getrandbits(bits) | (1 << (bits - 1)) | 1
        if all(p % d for d in (3, 5, 7, 11, 13, 17, 19, 23, 29, 31, 37)):
            # 简易确定性 Miller-Rabin（小基数足够 512-bit 演示）
            d = p - 1
            r = 0
            while d % 2 == 0:
                d //= 2
                r += 1
            ok = True
            for a in (2, 3, 5, 7, 11, 13, 17, 19, 23, 29, 31, 37):
                x = pow(a, d, p)
                if x in (1, p - 1):
                    continue
                for _ in range(r - 1):
                    x = x * x % p
                    if x == p - 1:
                        break
                else:
                    ok = False
                    break
            if ok:
                return p


FLAG_CM = "flag{c0mm0n_m0dulus_1s_f4t4l}"
FLAG_HB = "flag{h4st4d_br04dc4st_cr7}"
FLAG_WN = "flag{w13n3r_c0nt1nu3d_fr4ct10ns}"

out = {}

# ── 1. 共模攻击：同 n 不同 e ──
m = int.from_bytes(FLAG_CM.encode(), "big")
p, q = gen_prime(256), gen_prime(256)
n = p * q
phi = (p - 1) * (q - 1)
e1, e2 = 65537, 17
assert gcd(e1, e2) == 1
c1, c2 = pow(m, e1, n), pow(m, e2, n)
# 自验：egcd 还原
def egcd(a, b):
    if b == 0:
        return (a, 1, 0)
    g, x, y = egcd(b, a % b)
    return (g, y, x - (a // b) * y)
g, s, t = egcd(e1, e2)
mm = (pow(c1, s, n) * pow(c2, t, n)) % n
assert mm == m, "共模自验失败"
out["common_modulus"] = {"n": n, "e1": e1, "e2": e2, "c1": c1, "c2": c2,
                         "flag": FLAG_CM, "sha256": hashlib.sha256(FLAG_CM.encode()).hexdigest()}

# ── 2. Hastad 广播：e=3，3 组不同 n ──
m2 = int.from_bytes(FLAG_HB.encode(), "big")
ns, cs = [], []
for _ in range(3):
    pi, qi = gen_prime(256), gen_prime(256)
    ni = pi * qi
    assert m2 < ni
    ns.append(ni)
    cs.append(pow(m2, 3, ni))
# 自验：CRT 合成 + 开立方
N = ns[0] * ns[1] * ns[2]
M = 0
for ni, ci in zip(ns, cs):
    Ni = N // ni
    M += ci * Ni * pow(Ni, -1, ni)
M %= N
lo, hi = 0, 1 << ((M.bit_length() // 3) + 2)
while lo < hi:  # 整数立方根二分
    mid = (lo + hi) // 2
    if mid ** 3 < M:
        lo = mid + 1
    else:
        hi = mid
assert lo ** 3 == M and lo == m2, "Hastad 自验失败"
out["hastad_broadcast"] = {"n1": ns[0], "n2": ns[1], "n3": ns[2], "c1": cs[0], "c2": cs[1], "c3": cs[2], "e": 3,
                           "flag": FLAG_HB, "sha256": hashlib.sha256(FLAG_HB.encode()).hexdigest()}

# ── 3. Wiener：小 d ──
m3 = int.from_bytes(FLAG_WN.encode(), "big")
p3, q3 = gen_prime(256), gen_prime(256)
n3 = p3 * q3
phi3 = (p3 - 1) * (q3 - 1)
d = random.getrandbits(100) | 1  # d < n^0.25/3 ≈ 2^126
while gcd(d, phi3) != 1:
    d += 2
e3 = pow(d, -1, phi3)
assert pow(pow(m3, e3, n3), d, n3) == m3
c3 = pow(m3, e3, n3)
# 自验：连分数攻击
def cf_expand(a, b):
    while b:
        q = a // b
        yield q
        a, b = b, a - q * b
convs = []
h0, h1, k0, k1 = 0, 1, 1, 0
for qv in cf_expand(e3, n3):
    h0, h1 = h1, qv * h1 + h0
    k0, k1 = k1, qv * k1 + k0
    convs.append((h1, k1))  # (k, d) 候选
found = False
for k, dcand in convs:
    if k == 0:
        continue
    if (e3 * dcand - 1) % k != 0:
        continue
    phi_c = (e3 * dcand - 1) // k
    # 用小指数验证 m^e mod n == pow(m, e mod phi_c, n)？直接验证 d：m^(e*d mod phi)
    dd = e3 * dcand - 1
    if pow(m3, e3, n3) == m3:
        pass
    x = pow(c3, dcand, n3)
    if x == m3:
        found = True
        break
assert found, "Wiener 自验失败"
out["wiener"] = {"n": n3, "e": e3, "c": c3,
                 "flag": FLAG_WN, "sha256": hashlib.sha256(FLAG_WN.encode()).hexdigest()}

json.dump(out, open("data/ctf_benchmark/crypto_attack_params.json", "w", encoding="utf-8"),
          indent=1, ensure_ascii=False)
print("三题合成+自验全部通过")
for k, v in out.items():
    print(" ", k, "| n bits:", v["n"].bit_length() if isinstance(v.get("n"), int) else v["n1"].bit_length(),
          "| sha256:", v["sha256"][:16])
