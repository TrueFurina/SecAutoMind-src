"""ctf_crypto.py 离线单测（不发起任何网络请求，不依赖 LLM）。

运行：
    python3 test_ctf_crypto.py
AES/DES 用例依赖 pycryptodome，若缺失则自动跳过（服务器有该依赖，会在 harness 跑时覆盖）。
"""
import math
import os
import sys
import unittest

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import ctf_crypto as C  # noqa: E402


# ---- 确定性素性判定（base 集合对 < 2^81 确定性），供 Wiener 用例自造 RSA ----
_MRB = [2, 3, 5, 7, 11, 13, 17, 19, 23, 29, 31, 37]


def _is_prime(n):
    if n < 2:
        return False
    for p in _MRB:
        if n % p == 0:
            return n == p
    d, r = n - 1, 0
    while d % 2 == 0:
        d //= 2
        r += 1
    for a in _MRB:
        x = pow(a, d, n)
        if x in (1, n - 1):
            continue
        ok = False
        for _ in range(r - 1):
            x = (x * x) % n
            if x == n - 1:
                ok = True
                break
        if not ok:
            return False
    return True


def _gen_prime(bits):
    import random
    while True:
        cand = random.randrange(1 << (bits - 1), 1 << bits) | 1
        if _is_prime(cand):
            return cand


class TestNumberTheory(unittest.TestCase):
    def test_modinv(self):
        self.assertEqual(C.modinv(17, 3120), 2753)
        self.assertEqual((C.modinv(7, 100) * 7) % 100, 1)
        self.assertRaises(ValueError, C.modinv, 4, 8)  # 不互素

    def test_crt(self):
        # x ≡ 2 (mod 3), 3 (mod 5), 2 (mod 7) -> 23
        self.assertEqual(C.crt([2, 3, 2], [3, 5, 7]), 23)

    def test_iroot(self):
        self.assertEqual(C.iroot(27, 3), (3, True))
        self.assertEqual(C.iroot(80, 3), (4, False))
        self.assertEqual(C.iroot(2 ** 20, 20), (2, True))
        self.assertEqual(C.iroot(2 ** 40, 20), (4, True))
        self.assertEqual(C.iroot(0, 5), (0, True))


class TestRSA(unittest.TestCase):
    def test_rsa_fermat(self):
        p, q = 10007, 10009  # 相近
        n = p * q
        self.assertEqual(set(C.rsa_fermat(n)), {p, q})
        self.assertIsNone(C.rsa_fermat(2 * 3 * 5 * 7 * 11 * 13))  # 差距大，应失败

    def test_rsa_wiener(self):
        p, q = _gen_prime(40), _gen_prime(40)
        while p == q:
            q = _gen_prime(40)
        n = p * q
        phi = (p - 1) * (q - 1)
        # 选 d 落在 Wiener 界内：d < n^0.25 / 3，且 (d, phi)=1
        bound = int(n ** 0.25 // 3)
        cands = [3, 5, 7, 11, 13, 17, 19, 23, 29, 31, 37, 41, 43, 47, 53, 59,
                 61, 67, 71, 73, 79, 83, 89, 97, 101, 257, 65537]
        d = next(c for c in cands if math.gcd(c, phi) == 1 and c < bound)
        e = C.modinv(d, phi)
        self.assertEqual(C.rsa_wiener(e, n), d)

    def test_rsa_common_modulus(self):
        p, q = 104729, 104723
        n = p * q
        phi = (p - 1) * (q - 1)
        e1, e2 = 17, 65537
        self.assertEqual(math.gcd(e1, e2), 1)
        self.assertEqual(math.gcd(e1, phi), 1)
        self.assertEqual(math.gcd(e2, phi), 1)
        m = 12345678901234567890
        c1 = pow(m, e1, n)
        c2 = pow(m, e2, n)
        self.assertEqual(C.rsa_common_modulus(c1, c2, e1, e2, n) % n, m % n)

    def test_rsa_common_factor(self):
        p = 999983
        q1 = 1000033
        q2 = 1000037
        n1 = p * q1
        n2 = p * q2
        res = C.rsa_common_factor(n1, n2)
        self.assertIsNotNone(res)
        self.assertEqual(set(res), {p, q1})

    def test_rsa_broadcast(self):
        # 三个不同 n，相同 e=3，同一 m（m 必须小于每个 n，且 m^e < prod）
        e = 3
        ns = [104729, 104723, 104717]
        m = 12345
        self.assertLess(m, min(ns))
        pairs = [(n, pow(m, e, n)) for n in ns]
        M = C.rsa_broadcast(e, pairs)
        self.assertEqual(C.iroot(M, e), (m, True))


class TestECC(unittest.TestCase):
    def test_point_add_double(self):
        # 曲线 y^2 = x^3 + x + 1 (a=1,b=1) mod 13，点 P=(0,1)
        P = C.ECPoint(0, 1, 1, 1, 13)
        twoP = P + P
        self.assertEqual((twoP.x, twoP.y), (10, 7))
        self.assertEqual((P + C.ECPoint.inf(1, 1, 13)).x, 0)
        self.assertTrue((P + (-1 * P)).is_inf())

    def test_scalar_mul(self):
        P = C.ECPoint(0, 1, 1, 1, 13)
        self.assertTrue((5 * P).is_inf() is False)
        # 5P 应等于 (P+P)+(P+P)+P
        self.assertEqual(5 * P, (P + P) + (P + P) + P)


class TestBSGS(unittest.TestCase):
    def test_multiplicative(self):
        # mod 23，base=5，求 log_5(20)
        # 5^5 = 20 (mod 23)
        self.assertEqual(C.bsgs(5, 20, 23, order=22), 5)

    def test_ecdlp_small(self):
        # 在小曲线上用 bsgs 解 ECDLP：先暴力求 P 的阶，再验证能还原已知 k
        P = C.ECPoint(0, 1, 1, 1, 13)
        cur = C.ECPoint.inf(1, 1, 13)
        order = None
        for i in range(1, 200):
            cur = cur + P
            if cur.is_inf():
                order = i
                break
        self.assertIsNotNone(order, "未能求出 P 的阶")
        k = 5
        Q = k * P
        res = C.bsgs(P, Q, 13, order=order)
        self.assertEqual(res, k)
        self.assertEqual(res * P, Q)


class TestSymmetric(unittest.TestCase):
    def test_aes_ecb_roundtrip(self):
        try:
            from Crypto.Cipher import AES
        except Exception:
            self.skipTest("pycryptodome 不可用")
        key = b"0" * 16
        pt = b"0123456789abcdef"
        ct = C.aes_ecb_decrypt(C.aes_ecb_decrypt(pt, key), key)  # 两次解密=恒等? 不，需加密
        # 用库解密函数配一个自造密文：先加密再解密应还原
        enc = AES.new(key, AES.MODE_ECB).encrypt(pt)
        self.assertEqual(C.aes_ecb_decrypt(enc, key), pt)

    def test_aes_cbc_roundtrip(self):
        try:
            from Crypto.Cipher import AES
        except Exception:
            self.skipTest("pycryptodome 不可用")
        key = b"1" * 16
        iv = b"2" * 16
        pt = b"abcdef0123456789"
        enc = AES.new(key, AES.MODE_CBC, iv).encrypt(pt)
        self.assertEqual(C.aes_cbc_decrypt(enc, key, iv), pt)

    def test_des_roundtrip(self):
        try:
            from Crypto.Cipher import DES
        except Exception:
            self.skipTest("pycryptodome 不可用")
        key = b"12345678"
        pt = b"abcdefgh"
        enc = DES.new(key, DES.MODE_ECB).encrypt(pt)
        self.assertEqual(C.des_decrypt(enc, key), pt)

    def test_xor(self):
        self.assertEqual(C.xor_bytes(b"\x01\x02", b"\x03\x01"), b"\x02\x03")


class TestLattice(unittest.TestCase):
    def _det(self, M):
        # 2x2 / 3x3 行列式
        n = len(M)
        if n == 2:
            return M[0][0] * M[1][1] - M[0][1] * M[1][0]
        if n == 3:
            a, b, c = M[0]
            return (a * (M[1][1] * M[2][2] - M[1][2] * M[2][1])
                    - b * (M[1][0] * M[2][2] - M[1][2] * M[2][0])
                    + c * (M[1][0] * M[2][1] - M[1][1] * M[2][0]))
        raise ValueError

    def test_lll_preserves_lattice(self):
        B = [[100, 0], [99, 1]]
        R = C.lll(B)
        self.assertEqual(len(R), 2)
        self.assertEqual(len(R[0]), 2)
        # 幺模变换保持 |det|
        self.assertEqual(abs(self._det(R)), abs(self._det(B)))
        # 规约应让首个向量显著变短（原 (100,0) 长 100）
        self.assertLess(math.isqrt(R[0][0] ** 2 + R[0][1] ** 2), 100)

    def test_lll_3x3(self):
        B = [[1, 1, 1], [-1, 0, 2], [3, 5, 6]]
        R = C.lll(B)
        self.assertEqual(abs(self._det(R)), abs(self._det(B)))


class TestHashes(unittest.TestCase):
    def test_identify_hash(self):
        self.assertEqual(C.identify_hash(bytes(16)), "md5")
        self.assertEqual(C.identify_hash(bytes(20)), "sha1")
        self.assertEqual(C.identify_hash(bytes(32)), "sha256")
        self.assertEqual(C.identify_hash(bytes(64)), "sha512")
        # 不应误判为 sha3
        self.assertNotEqual(C.identify_hash(bytes(32)), "sha3-256")

    def test_hash_bytes(self):
        import hashlib
        self.assertEqual(C.hash_bytes(b"abc"), hashlib.sha256(b"abc").hexdigest())


class TestFactor(unittest.TestCase):
    def test_factor(self):
        f = C.factor(360)
        prod = 1
        for p, e in f.items():
            prod *= p ** e
        self.assertEqual(prod, 360)


if __name__ == "__main__":
    unittest.main(verbosity=2)
