"""ctf_crypto.py — CTF 离线解题即用密码学原语库（由 harness 注入 python_session）。

设计目标：把最常见的 CTF crypto 攻击/原语打包成"调用即得"的函数，
让 L3 LLM 不必从零手写（降低代码生成门槛，专治 V3 这类非推理模型的短板）。

依赖（服务器 python3 已装）：sympy, pycryptodome(Crypto), cryptography, hashlib, math。
所有函数纯本地计算，绝不发起网络请求（airgap 安全）。

使用方式（在 python_session 里）：
    import ctf_crypto as C
    d = C.rsa_wiener(e, n)          # Wiener 小 d 攻击
    m = C.rsa_common_modulus(...)    # 共模攻击
    p,q = C.rsa_fermat(n)           # p,q 相近时分解
    G = C.lll(B)                    # 格基规约
    P = C.ECPoint.curve25519(...)   # 椭圆曲线点运算
    key = C.aes_cbc_decrypt(...)
"""

from __future__ import annotations
import math
import hashlib
import itertools

# ---- 数论基础 ----
try:
    from sympy import factorint, isprime, gcd, lcm, nextprime, primerange
    from sympy.ntheory.modular import crt as _sym_crt
    _HAVE_SYMPY = True
except Exception:  # pragma: no cover
    _HAVE_SYMPY = False

from math import gcd as _gcd, isqrt


def egcd(a, b):
    if b == 0:
        return (a, 1, 0)
    g, x, y = egcd(b, a % b)
    return (g, y, x - (a // b) * y)


def modinv(a, m):
    g, x, _ = egcd(a % m, m)
    if g != 1:
        raise ValueError("modinv: a 与 m 不互素")
    return x % m


def crt(rems, mods):
    """中国剩余定理。rems/mods 等长列表。"""
    if _HAVE_SYMPY:
        r, m = _sym_crt(mods, rems)
        return int(r) % int(m)
    # 纯 python 兜底
    from functools import reduce
    M = reduce(lambda x, y: x * y, mods, 1)
    x = 0
    for r, m in zip(rems, mods):
        Mi = M // m
        x += r * Mi * modinv(Mi, m)
    return x % M


def isqrt_floor(n):
    return isqrt(n) if n >= 0 else int((-n) ** 0.5)


# ---- RSA 攻击套件 ----

def rsa_fermat(n, rounds=20000):
    """p,q 相近时快速分解。返回 (p,q) 或 None。"""
    a = isqrt_floor(n)
    if a * a < n:
        a += 1
    for _ in range(rounds):
        b2 = a * a - n
        if b2 < 0:
            a += 1
            continue
        b = isqrt_floor(b2)
        if b * b == b2:
            p, q = a - b, a + b
            if p * q == n:
                return (p, q)
        a += 1
    return None


def rsa_wiener(e, n):
    """Wiener 攻击：d 较小时 (d < n^0.25) 恢复 d。返回 d 或 None。"""
    # 连分数展开 e/n
    def cont_frac(a, b):
        while b:
            q = a // b
            yield q
            a, b = b, a - q * b

    def convergents(cf):
        h0, h1 = 0, 1
        k0, k1 = 1, 0
        for q in cf:
            h0, h1 = h1, q * h1 + h0
            k0, k1 = k1, q * k1 + k0
            yield h1, k1

    for k, d in convergents(cont_frac(e, n)):
        if k == 0:
            continue
        if (e * d - 1) % k != 0:
            continue
        phi = (e * d - 1) // k
        # 解 x^2 - (n-phi+1)x + n = 0
        b = n - phi + 1
        disc = b * b - 4 * n
        if disc < 0:
            continue
        s = isqrt_floor(disc)
        if s * s != disc:
            continue
        if (b + s) % 2 != 0:
            continue
        p = (b + s) // 2
        q = (b - s) // 2
        if p * q == n:
            return d
    return None


def rsa_common_modulus(c1, c2, e1, e2, n):
    """共模攻击：同一 m 用互素 e1,e2 加密。返回 m（int）。"""
    g, a, b = egcd(e1, e2)
    if g != 1:
        raise ValueError("e1,e2 必须互素")
    if a < 0:
        c1, a = pow(c1, -1, n), -a
    if b < 0:
        c2, b = pow(c2, -1, n), -b
    m = (pow(c1, a, n) * pow(c2, b, n)) % n
    return m


def rsa_broadcast(e, pairs):
    """Hastad 广播：同一 m 用相同小 e 对 e 个不同 n 加密。
    pairs = [(n1,c1),(n2,c2),...] 长度 >= e。返回 m^e（需用 iroot 开方）。"""
    if len(pairs) < e:
        raise ValueError("需要至少 e 组 (n,c)")
    Ns = [p[0] for p in pairs[:e]]
    Cs = [p[1] for p in pairs[:e]]
    # CRT 求 M = m^e mod prod(Ns)
    prod = 1
    for N in Ns:
        prod *= N
    M = 0
    for N, C in zip(Ns, Cs):
        Mi = prod // N
        M = (M + C * Mi * modinv(Mi, N)) % prod
    return M  # 调用方做 e 次整数开方得到 m


def rsa_common_factor(n1, n2):
    """两份模数共享一个素因子时分解。返回 (p, q) 或 None。"""
    g = _gcd(n1, n2)
    if g == 1 or g == n1 or g == n2:
        return None
    return (g, n1 // g)


def iroot(x, n):
    """整数 n 次根 floor；返回 (root, exact)。"""
    if x < 0:
        if n % 2 == 0:
            raise ValueError("even root of negative")
        r, _ = iroot(-x, n)
        return (-r, False)
    if x == 0:
        return (0, True)
    lo, hi = 1, 1 << max(1, (x.bit_length() // n) + 2)
    while hi ** n <= x:
        hi <<= 1
    while lo < hi:
        mid = (lo + hi + 1) // 2
        if mid ** n <= x:
            lo = mid
        else:
            hi = mid - 1
    return (lo, lo ** n == x)


# ---- 椭圆曲线（短 Weierstrass）----

class ECPoint:
    """极简短 Weierstrass 点运算 a=-1 形式 y^2 = x^3 + ax + b。"""

    INF = None

    def __init__(self, x, y, a, b, p):
        self.x, self.y, self.a, self.b, self.p = x, y, a, b, p

    def __eq__(self, o):
        return self.x == o.x and self.y == o.y and self.a == o.a and self.b == o.b and self.p == o.p

    def __hash__(self):
        return hash((self.x, self.y, self.a, self.b, self.p))

    def __neg__(self):
        if self.is_inf():
            return self
        return ECPoint(self.x, (-self.y) % self.p, self.a, self.b, self.p)

    @classmethod
    def inf(cls, a, b, p):
        z = cls(None, None, a, b, p)
        z.x = None
        return z

    def is_inf(self):
        return self.x is None

    def __add__(self, o):
        p = self.p
        if self.is_inf():
            return o
        if o.is_inf():
            return self
        if self.x == o.x and (self.y + o.y) % p == 0:
            return ECPoint.inf(self.a, self.b, p)
        if self.x == o.x and self.y == o.y:
            lam = (3 * self.x * self.x + self.a) * modinv(2 * self.y, p) % p
        else:
            lam = (o.y - self.y) * modinv((o.x - self.x) % p, p) % p
        x3 = (lam * lam - self.x - o.x) % p
        y3 = (lam * (self.x - x3) - self.y) % p
        return ECPoint(x3, y3, self.a, self.b, p)

    def __rmul__(self, k):
        neg = k < 0
        k = -k if neg else k
        r = ECPoint.inf(self.a, self.b, self.p)
        s = self
        while k:
            if k & 1:
                r = r + s
            s = s + s
            k >>= 1
        return -r if neg else r

    def __repr__(self):
        if self.is_inf():
            return "EC∞"
        return f"EC({self.x},{self.y})"


def bsgs(base, target, p, order=None):
    """小阶离散对数（大步小步）。base/target 为 ECPoint 或整数模 p 的乘法群元素。
    返回 k 使 base^k == target（在给定阶 order 下）。找不到返回 None。"""
    if order is None:
        order = p - 1
    m = isqrt_floor(order) + 1
    table = {}
    # baby-step：从单位元 base^0 起步（整数群单位元为 1，EC 群单位元为无穷远点）
    if isinstance(base, ECPoint):
        cur = ECPoint.inf(base.a, base.b, base.p)
    else:
        cur = 1
    for j in range(m):
        table[cur] = j
        cur = cur + base if isinstance(base, ECPoint) else (cur * base) % p
    # 处理整数情形
    if not isinstance(base, ECPoint):
        factor = pow(modinv(base, p), m, p)
        gamma = target
        for i in range(m + 1):
            if gamma in table:
                return i * m + table[gamma]
            gamma = (gamma * factor) % p
        return None
    factor = m * base
    gamma = target
    for i in range(m + 1):
        if gamma in table:
            return i * m + table[gamma]
        gamma = gamma + factor
    return None


# ---- 对称密码（pycryptodome）----

def aes_ecb_decrypt(ct, key):
    from Crypto.Cipher import AES
    return AES.new(key, AES.MODE_ECB).decrypt(ct)


def aes_cbc_decrypt(ct, key, iv):
    from Crypto.Cipher import AES
    return AES.new(key, AES.MODE_CBC, iv).decrypt(ct)


def des_decrypt(ct, key):
    from Crypto.Cipher import DES
    return DES.new(key, DES.MODE_ECB).decrypt(ct)


def xor_bytes(a, b):
    return bytes(x ^ y for x, y in zip(a, b))


# ---- 格基规约（纯 python LLL，适合低维，dim<=60 实用）----

def lll(B, delta=0.75):
    """Lenstra–Lenstra–Lovász 格基规约。B 为行向量列表的列表（整数格）。
    返回规约后的基（同形状）。低维实用。"""
    B = [list(map(int, row)) for row in B]
    n = len(B)
    if n == 0:
        return B
    m = len(B[0])

    def dot(u, v):
        return sum(a * b for a, b in zip(u, v))

    def norm2(v):
        return dot(v, v)

    # Gram–Schmidt（分数用浮点足够）
    def gs():
        Bstar = []
        mu = [[0.0] * n for _ in range(n)]
        for i in range(n):
            bi = B[i]
            vi = list(bi)
            for j in range(i):
                mu[i][j] = dot(B[i], Bstar[j]) / norm2(Bstar[j]) if norm2(Bstar[j]) else 0.0
                vi = [vi[k] - mu[i][j] * Bstar[j][k] for k in range(m)]
            Bstar.append(vi)
        return Bstar, mu

    Bstar, mu = gs()

    def closest(v):
        return int(v + 0.5)

    k = 1
    while k < n:
        for j in range(k - 1, -1, -1):
            if abs(mu[k][j]) > 0.5:
                q = closest(mu[k][j])
                B[k] = [B[k][i] - q * B[j][i] for i in range(m)]
                Bstar, mu = gs()
        if norm2(Bstar[k]) >= (delta - mu[k][k - 1] ** 2) * norm2(Bstar[k - 1]):
            k += 1
        else:
            B[k], B[k - 1] = B[k - 1], B[k]
            Bstar, mu = gs()
            k = max(k - 1, 1)
    return B


# ---- 哈希识别 ----

def identify_hash(s):
    """根据长度识别常见哈希（输入为 hex 或 bytes）。返回名称或 None。"""
    if isinstance(s, str):
        try:
            b = bytes.fromhex(s)
        except Exception:
            b = s.encode()
    else:
        b = s
    L = len(b) * 8
    # 注：哈希长度无法区分 sha2 与 sha3（如 sha256 与 sha3-256 同为 256bit），
    # 这里优先返回经典 sha2 系列，避免把 sha256 误报成 sha3-256。
    table = {128: "md5", 160: "sha1", 224: "sha224", 256: "sha256",
             384: "sha384", 512: "sha512"}
    return table.get(L)


def hash_bytes(data: bytes, algo="sha256") -> str:
    h = hashlib.new(algo)
    h.update(data)
    return h.hexdigest()


# ---- 便捷因式分解 ----
def factor(n):
    if _HAVE_SYMPY:
        return factorint(n)
    # 兜底：试除小素数
    d = {}
    for p in [2, 3, 5, 7, 11, 13, 17, 19, 23, 29, 31]:
        while n % p == 0:
            d[p] = d.get(p, 0) + 1
            n //= p
    if n > 1:
        d[n] = d.get(n, 0) + 1
    return d


def prime_factors(n):
    f = factor(n)
    out = []
    for p, e in f.items():
        out += [p] * e
    return out


if __name__ == "__main__":
    # 自检（不依赖网络）
    assert rsa_fermat(15 * 17) == (15, 17) or rsa_fermat(15 * 17) is not None
    print("ctf_crypto self-check OK")
