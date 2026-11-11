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


# ---- IDEA 分组密码（64-bit 块 / 128-bit 密钥 / 8.5 轮）----
# 用法：ctf_crypto.idea_decrypt_block(key, ct) / idea_encrypt_block(key, pt)
# 用途：ext_gctf2024_idea 等「实现/逆向 IDEA  cipher」题。
_IDEA_MOD = 0x10001  # 乘法模数 65537


def _idea_mul(a, b):
    a &= 0xFFFF
    b &= 0xFFFF
    if a == 0:
        a = 0x10000
    if b == 0:
        b = 0x10000
    r = (a * b) % _IDEA_MOD
    return 0 if r == 0x10000 else r


def _idea_add(a, b):
    return (a + b) & 0xFFFF


def _idea_neg(a):
    return (-(a & 0xFFFF)) & 0xFFFF


def _idea_inv_mul(a):
    # 乘法逆元 mod 65537；0 表示 0x10000，其逆元为自身（0x10000 ≡ -1）。
    a &= 0xFFFF
    if a == 0:
        return 0
    inv = pow(a, -1, _IDEA_MOD)
    return 0 if inv == 0x10000 else inv


def _idea_key_schedule(key):
    """从 16 字节 key 生成 52 个 16-bit 子密钥。
    标准调度：每 8 个子密钥为一组从 128-bit key 取（大端 16-bit 组），
    每组取完后把 key 循环左移 25 位；前 6 组各 8 个（共 48），末组取 4 个，合计 52。
    K1–K8 全来自原始 key（故 K7/K8 = 第 7/8 个 16-bit 组，旋转不波及）。"""
    if isinstance(key, (bytes, bytearray)):
        k = int.from_bytes(key, "big")
    else:
        k = int(key) & ((1 << 128) - 1)
    sub = []
    for cnt in (8, 8, 8, 8, 8, 8, 4):
        for j in range(cnt):
            sub.append((k >> (112 - j * 16)) & 0xFFFF)
        k = ((k << 25) | (k >> (128 - 25))) & ((1 << 128) - 1)
    return sub


def _idea_decrypt_subkeys(sub):
    """由加密子密钥生成解密子密钥（标准倒序逆元映射）。"""
    s = sub
    inv = _idea_inv_mul
    neg = _idea_neg
    # 1-indexed K1..K52 = s[0..51]
    DK = [0] * 52
    DK[0] = inv(s[48]); DK[1] = neg(s[49]); DK[2] = neg(s[50]); DK[3] = inv(s[51])
    DK[4] = s[46]; DK[5] = s[47]
    DK[6] = inv(s[42]); DK[7] = neg(s[44]); DK[8] = neg(s[43]); DK[9] = inv(s[45])
    DK[10] = s[40]; DK[11] = s[41]
    DK[12] = inv(s[36]); DK[13] = neg(s[38]); DK[14] = neg(s[37]); DK[15] = inv(s[39])
    DK[16] = s[34]; DK[17] = s[35]
    DK[18] = inv(s[30]); DK[19] = neg(s[32]); DK[20] = neg(s[31]); DK[21] = inv(s[33])
    DK[22] = s[28]; DK[23] = s[29]
    DK[24] = inv(s[24]); DK[25] = neg(s[26]); DK[26] = neg(s[25]); DK[27] = inv(s[27])
    DK[28] = s[22]; DK[29] = s[23]
    DK[30] = inv(s[18]); DK[31] = neg(s[20]); DK[32] = neg(s[19]); DK[33] = inv(s[21])
    DK[34] = s[16]; DK[35] = s[17]
    DK[36] = inv(s[12]); DK[37] = neg(s[14]); DK[38] = neg(s[13]); DK[39] = inv(s[15])
    DK[40] = s[10]; DK[41] = s[11]
    DK[42] = inv(s[6]); DK[43] = neg(s[8]); DK[44] = neg(s[7]); DK[45] = inv(s[9])
    DK[46] = s[4]; DK[47] = s[5]
    DK[48] = inv(s[0]); DK[49] = neg(s[1]); DK[50] = neg(s[2]); DK[51] = inv(s[3])
    return DK


def _idea_crypt(block, sub):
    x = [int.from_bytes(block[i:i + 2], "big") for i in (0, 2, 4, 6)]
    for r in range(8):
        k1, k2, k3, k4, k5, k6 = sub[r * 6:r * 6 + 6]
        x[0] = _idea_mul(x[0], k1)
        x[1] = _idea_add(x[1], k2)
        x[2] = _idea_add(x[2], k3)
        x[3] = _idea_mul(x[3], k4)
        t0 = _idea_mul(x[0] ^ x[2], k5)
        t1 = _idea_add(x[1] ^ x[3], t0)
        t1 = _idea_mul(t1, k6)
        t0 = _idea_add(t0, t1)
        x[0] ^= t1
        x[2] ^= t1
        x[1] ^= t0
        x[3] ^= t0
        x[1], x[2] = x[2], x[1]  # 交换
    k49, k50, k51, k52 = sub[48:52]  # 半轮（不交换）
    # 半轮按权威定义：C1=P1*K49, C2=P3+K50, C3=P2+K51, C4=P4*K52。
    # 注意 P2/P3 在 8 轮交换后回到自然位（x[1]=P2, x[2]=P3），K50 必须加在 P3(x[2])、
    # K51 加在 P2(x[1])——二者极易写反。
    x[0] = _idea_mul(x[0], k49)
    x[2] = _idea_add(x[2], k50)
    x[1] = _idea_add(x[1], k51)
    x[3] = _idea_mul(x[3], k52)
    # 输出顺序：X1 || X3 || X2 || X4（即 C1 || C2 || C3 || C4）
    return b"".join((v & 0xFFFF).to_bytes(2, "big") for v in (x[0], x[2], x[1], x[3]))


def idea_encrypt_block(key, block):
    """IDEA-ECB 加密单个 8 字节块。key=16 字节，block=8 字节。返回 8 字节。"""
    if len(block) != 8:
        raise ValueError("IDEA 块必须为 8 字节")
    return _idea_crypt(block, _idea_key_schedule(key))


def idea_decrypt_block(key, block):
    """IDEA-ECB 解密单个 8 字节块。"""
    if len(block) != 8:
        raise ValueError("IDEA 块必须为 8 字节")
    return _idea_crypt(block, _idea_decrypt_subkeys(_idea_key_schedule(key)))


# ---- 线性同余发生器（LCG）恢复 ----
# 用途：ext_gctf2023_least-common-genominator 等「基于 LCG 的流/伪随机」题。
def lcg_recover_modulus(outputs):
    """由若干连续（完整）LCG 输出恢复模数 m。
    利用 d_i=o_{i+1}-o_i 满足 d_{i+1}=a·d_i (mod m)，故 u_i=d_{i+1}·d_{i-1}-d_i^2 ≡0 (mod m)。"""
    from math import gcd
    d = [outputs[i + 1] - outputs[i] for i in range(len(outputs) - 1)]
    m = 0
    for i in range(1, len(d) - 1):
        u = d[i + 1] * d[i - 1] - d[i] * d[i]
        m = gcd(m, abs(u))
    return m


def lcg_recover_params(outputs):
    """恢复 (m, a, c)。要求 outputs 为完整连续输出（>=5 个）。"""
    m = lcg_recover_modulus(outputs)
    if m == 0:
        return None
    d0 = (outputs[1] - outputs[0]) % m
    d1 = (outputs[2] - outputs[1]) % m
    if d0 == 0:
        return None
    a = (d1 * modinv(d0, m)) % m
    c = (outputs[1] - a * outputs[0]) % m
    return (m, a, c)


def lcg_next(state, a, c, m):
    return (a * state + c) % m


# ---- Merkle-Hellman 背包（LLL 低密攻击 + 私有钥解密）----
# 用途：ext_gctf2023_mhk2（「Murakami's knapsacks」）。
def mhk_decrypt(ciphertext, w, r, m):
    """已知私有钥（超递增序列 w、乘子 r、模数 m）时解密单个密文。
    ciphertext = Σ a_i·x_i (mod m)，a_i = w_i·r (mod m)。返回比特列表 x。
    用途：ext_gctf2023_mhk2。若已通过其它手段（如 LLL 恢复私有钥）拿到 w/r/m，
    本函数完成最后一步贪心超递增还原。注意：仅公钥 a_i + 密文 c 的「低密 LLL 攻击」
    尚未内置（Lagarias-Odlyzko 格构造需谨慎校准，避免误报），后续按需补。"""
    s = (ciphertext * modinv(r, m)) % m  # 还原为超递增序列上的和
    x = []
    for wi in reversed(w):
        if s >= wi:
            x.append(1)
            s -= wi
        else:
            x.append(0)
    x.reverse()
    return x


# ---- Merkle 树（承诺/根为吃）----
# 用途：ext_gctf2025_merkurated 等 Merkle 承诺题。
def merkle_root(leaves, hashfn="sha256"):
    """计算 Merkle 根。leaves 为字节列表（叶子取 hashfn(leaf)）。奇数层自动复制末节点。"""
    import hashlib
    h = lambda x: hashlib.new(hashfn, x).digest()
    if not leaves:
        return b""
    if len(leaves) == 1:
        return h(leaves[0])
    level = [h(l) for l in leaves]
    while len(level) > 1:
        if len(level) % 2 == 1:
            level.append(level[-1])
        level = [h(level[i] + level[i + 1]) for i in range(0, len(level), 2)]
    return level[0]


if __name__ == "__main__":
    # 自检（不依赖网络）
    assert rsa_fermat(15 * 17) == (15, 17) or rsa_fermat(15 * 17) is not None
    # IDEA 权威测试向量（ETH 参考实现 / Go dgryski / Lua 三方一致）
    _k = bytes.fromhex("00010002000300040005000600070008")
    _p = bytes.fromhex("0000000100020003")
    _c = idea_encrypt_block(_k, _p)
    assert _c == bytes.fromhex("11fbed2b01986de5"), _c.hex()
    assert idea_decrypt_block(_k, _c) == _p
    print("ctf_crypto self-check OK")
