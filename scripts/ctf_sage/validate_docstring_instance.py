"""validate_docstring_instance.py — 能力边界验证（非自测，服务器专用，约 2 分钟）。

验证 README 的核心声明：纯 Python LLL 在 Sage 规范参数下完整复现
SageMath small_roots docstring 的 513-bit RSA 实例。

权威实例（Sage 官方文档 small_roots docstring，2026-10-24 逐字核对）：
  sage: Nbits, Kbits = 512, 56
  sage: e = 3
  sage: p = 2^256 + 2^8 + 2^5 + 2^3 + 1
  sage: q = 2^256 + 2^8 + 2^5 + 2^3 + 2^2 + 1
  sage: N = p*q
  sage: K = ZZ.random_element(0, 2^Kbits)
  sage: M = [0]*Kbits + [1]*(Nbits-Kbits); M[i] = Kdigits[i]; M = ZZ(M, 2)
  sage: C = ZmodN(M)^e
  sage: f = (2^Nbits - 2^Kbits + x)^e - C
  sage: Kbar = f.small_roots()[0]; K == Kbar  → True

即 a = 2^512 - 2^56（已知高 456 位全 1），C = (a+K)^3 mod N，
f(x) = (x+a)^3 - C，根 x0 = K（f(K) = M^3 - C = N*floor(M^3/N) ≡ 0 mod N 精确成立）。
Sage 默认参数：beta=1, epsilon=beta/8 ⇒ m=3, t=0, dim=9, X=ceil(0.5*N^{5/24})。

2026-10-24 实测结果（服务器 venv_ctf，numpy 2.5.4 / python 3.12.3）：
  对照组 256-bit（同模式缩小）：dim-9 命中 row0，44.5s，||b1|| 低于 det^(1/9) 6.3bit
  全规模 513-bit（docstring verbatim）：dim-9 命中 row0，82.9s，
      ||b1|| 低于 det^(1/9) 23bit；同格本机 512.9s（服务器约 6 倍速）
  自检：LLL 规约条件满足（is_lll_reduced）、||b1|| 贴 Hermite 界 2^{(n-1)/4}·det^{1/n}
      ⇒ 「未恢复」若发生，可判定为数学固有（目标不在格中），非实现缺陷。

⚠️ 作废历史（勿重犯）：2026-10-23 首版实验用 poly=[-C,3M^2,3M,1] 且 M 含未知
低位 K，即 (x+M)^3-(C+M^3)——该多项式不含目标根，「K 未恢复」不构成任何证据，
据此得出的「大 N 纯 Python LLL 不可靠」结论已作废。本脚本第一步即实例健全性
断言 f(K) ≡ 0 mod N，构造错误当场失败，不会产出假阴性结论。

用法（服务器）：
  cd ~/ctf_sage && ~/venv_ctf/bin/python -u validate_docstring_instance.py
本机跑约 9 分钟（512.9s 那格）——按项目政策，重活一律上服务器。
"""
import sys
import time
import random
from fractions import Fraction
from math import log2

sys.path.insert(0, '.')
from t1_coppersmith import _build_lattice, _params, _horner
from common import lll_reduce, is_lll_reduced


def _log2_int(x) -> float:
    if isinstance(x, Fraction):
        return _log2_int(x.numerator) - _log2_int(x.denominator)
    x = abs(int(x))
    if x == 0:
        return float("-inf")
    bl = x.bit_length()
    return (bl - 1) + log2(x / (1 << (bl - 1)))


def _is_prime(n: int) -> bool:
    if n < 2:
        return False
    for p in (2, 3, 5, 7, 11, 13, 17, 19, 23, 29, 31, 37):
        if n % p == 0:
            return n == p
    d, s = n - 1, 0
    while d % 2 == 0:
        d //= 2
        s += 1
    for a in (2, 3, 5, 7, 11, 13, 17, 19, 23, 29, 31, 37):
        x = pow(a, d, n)
        if x in (1, n - 1):
            continue
        for _ in range(s - 1):
            x = x * x % n
            if x == n - 1:
                break
        else:
            return False
    return True


def run_instance(name, Nbits, Kbits, p, q, seed, max_m=5, wall_cap=2400):
    e = 3
    N = p * q
    assert _is_prime(p) and _is_prime(q), "p/q 必须为素数"
    rng = random.Random(seed)
    K = rng.randrange(1 << Kbits)
    a = (1 << Nbits) - (1 << Kbits)          # 已知高位（全 1）
    M = a + K                                # 真实消息
    C = pow(M, e, N)
    # f(x) = (x+a)^3 - C mod N（升序系数）
    poly = [(a ** 3 - C) % N, (3 * a * a) % N, (3 * a) % N, 1]

    print(f"\n===== {name}: N={N.bit_length()}bit Kbits={Kbits} e={e} =====", flush=True)
    # 1. 实例健全性：f(K) ≡ 0 mod N（不满足直接放弃——构造错了跑什么都没意义）
    fk = _horner(poly, K) % N
    print(f"实例健全性 f(K) mod N == 0: {fk == 0}（K={K}）", flush=True)
    if fk != 0:
        print("!! 实例构造错误，终止本实例", flush=True)
        return False

    m0, t0, X = _params(3, N, Fraction(1), None, None)
    print(f"Sage 规范参数: m={m0} t={t0} X=2^{X.bit_length()}", flush=True)

    for m in range(m0, max_m + 1):
        t = int(3 * m * (1 - 1))  # beta=1 ⇒ t=0（与 Sage 公式一致）
        dim = m * 3 + t
        rows = _build_lattice(poly, N, m, t, 3, X)
        bits = max(max(abs(x).bit_length() for x in r) for r in rows)
        print(f"[{name}] m={m} dim={dim} 条目 {bits}bit —— LLL 开始 "
              f"(预估 ~{dim*dim*bits*bits*3e-7:.0f}s)", flush=True)
        t0 = time.time()
        red = lll_reduce(rows)
        dt = time.time() - t0
        print(f"[{name}] m={m} LLL 完成 {dt:.1f}s", flush=True)

        ok_lll = is_lll_reduced(red)
        n = len(rows)
        log2_det = sum(_log2_int(rows[r][r]) for r in range(n))
        b1sq = sum(x * x for x in red[0])
        log2_b1 = _log2_int(b1sq) / 2
        log2_bound = (n - 1) / 4 + log2_det / n
        print(f"[{name}] m={m} 规约条件自检: {ok_lll}; "
              f"det^(1/{n})=2^{log2_det/n:.1f} 理论界=2^{log2_bound:.1f} "
              f"||b1||=2^{log2_b1:.1f} (<=界: {log2_b1 <= log2_bound + 1e-9})", flush=True)

        hit = None
        for i, v in enumerate(red):
            G, ok = [], True
            for k in range(len(v)):
                xk = X ** k
                if v[k] % xk != 0:
                    ok = False
                    break
                G.append(v[k] // xk)
            if ok and _horner(G, K) == 0:
                hit = i
                break
        print(f"[{name}] m={m} K 恢复: {hit is not None}"
              + (f"（row{hit}）" if hit is not None else ""), flush=True)
        if hit is not None:
            return True
        if dt > wall_cap:
            print(f"[{name}] 单步超墙钟上限 {wall_cap}s，停止升 m", flush=True)
            break
    return False


def main():
    # 对照组：128-bit 素数、Nbits=256、Kbits=28（docstring 模式缩小）
    rng = random.Random(20261024)

    def gen_prime(bits):
        while True:
            v = rng.getrandbits(bits) | (1 << (bits - 1)) | 1
            if _is_prime(v):
                return v

    pc = gen_prime(128)
    qc = gen_prime(128)
    ok_ctrl = run_instance("对照组-256bit", 256, 28, pc, qc, seed=20261024, max_m=4)

    # 全规模：docstring verbatim 的 p, q
    p = 2**256 + 2**8 + 2**5 + 2**3 + 1
    q = 2**256 + 2**8 + 2**5 + 2**3 + 2**2 + 1
    ok_full = run_instance("全规模-512bit(docstring)", 512, 56, p, q, seed=20261023,
                           max_m=5, wall_cap=2400)

    print(f"\n===== 总结: 对照组={ok_ctrl} 全规模={ok_full} =====", flush=True)
    sys.exit(0 if (ok_ctrl and ok_full) else 1)


if __name__ == "__main__":
    main()
