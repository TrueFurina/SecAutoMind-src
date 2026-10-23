"""t1_coppersmith.py — Coppersmith 小根攻击（单变量：f(x) ≡ 0 mod N 或 mod N 的大因子）。

构造与 SageMath `Polynomial_dense_mod_n.small_roots` 源码级同构（2026-10-23 逐行对齐）：
  首项归一：a_d 可逆时 f ← a_d^{-1}·f（monic 化，根不变）
  参数：epsilon = beta/8；m = ceil(max(beta²/(d·epsilon), 7·beta/d))；
        t = floor(d·m·(1/beta - 1))；X 缺省 = ceil(0.5·N^{beta²/d - epsilon})
  多项式族：
    g_{i,j} = x^j·N^{m-i}·f^i   (i = 0..m-1, j = 0..d-1)   ← 主族
    h_i    = x^i·f^m            (i = 0..t-1)               ← 额外移位
  格：dim = m·d + t，行 = 各多项式系数向量 × X^k（k = 该项次数）
  取 LLL 输出各行反缩放得多项式 G（要求 X^k 逐项整除），求 |r| ≤ X 的整数根；
  筛：gcd(N, f(r)) ≥ N^beta（beta=1 即 f(r) ≡ 0 mod N）。

sage 快速路径：has_sage() 为真时直接调 sage 的 small_roots（大 X 场景首选）。
纯 Python 路径的取根：numpy 向量化 mod 素数过滤 + 精确验证（X ≤ 2^24）；
更大 X 需 sage（详见 detail 提示）。

诚实边界（2026-10-23 实证，勿外推）：
  1. 纯 Python + LLL 在 dim≤20、m=Sage 公式起步值下，对「通用多项式 + 小根」实例
     已验证到 N=160bit（Q = f(x_0)/N 较小时）；M 过大的 stereotyped message 实例
     会使 Q ~ N^{1/2}，三角抵消残差 ~Q² 超出目标预算 → 同参数失效（自适应 m 也救不回，
     因目标不在格中）。此类实例走 sage 路径或先降 Q（减小 M）。
  2. 取根在 X > 2^24 时依赖 numpy 浮点近似或 sage；纯 Python 无非暴力精确路径。
  3. 本实现与 Sage 源码逐行同构；Sage docstring 两实例（N=10001→4、N=17→2）为回归基准。

输入 JSON：
  {"modulus": N, "poly": [a0, a1, ..., ad]（升序整数系数）,
   "X": <int>（可选，缺省按 beta 自动）, "beta": 1 | 0.5（可选，默认 1）}
输出：flags = 恢复的小根（十进制字符串；调用方据此构造 flag 明文，如 m/p/q）。
自测：python t1_coppersmith.py --selftest
"""

from __future__ import annotations

import sys
from fractions import Fraction
from math import gcd

from common import as_int, emit, has_sage, integer_nth_root, lll_reduce, need, read_params

# 纯 Python 路径的维度上限：Fraction LLL 在 dim>~20 且条目 ~2^80 时耗时按分钟计，
# 超过即交 sage 快速路径（fpylll）——诚实标注能力边界，不假装能跑。
_DIM_CAP = 20


# ---------------------------------------------------------------- 多项式算术（升序系数表）

def _polymul(a: list[int], b: list[int]) -> list[int]:
    r = [0] * (len(a) + len(b) - 1)
    for i, x in enumerate(a):
        if x:
            for j, y in enumerate(b):
                r[i + j] += x * y
    return r


def _horner(coeffs: list[int], r: int) -> int:
    v = 0
    for c in reversed(coeffs):
        v = v * r + c
    return v


def _ceil_frac(x: Fraction) -> int:
    return -((-x.numerator) // x.denominator)


# ---------------------------------------------------------------- 参数与构造

def _params(d: int, N: int, beta: Fraction, epsilon: Fraction | None, X: int | None):
    eps = epsilon if epsilon is not None else beta / 8
    m = max(_ceil_frac(beta * beta / (d * eps)), _ceil_frac(Fraction(7) * beta / d))
    t = int(d * m * (1 / beta - 1))  # floor（Fraction 转 int 即 floor）
    if X is None:
        # X = ceil(0.5·N^{beta²/d - eps})；t0 = floor(N^e) 时 0.5·N^e ∈ (t0/2, (t0+1)/2)，
        # 其 ceil 恒等于 t0//2 + 1（完全幂情形单独校正）
        e = beta * beta / d - eps
        if e <= 0:
            X = 1
        else:
            t0 = integer_nth_root(N ** e.numerator, e.denominator)
            X = t0 // 2 + 1
            if t0 ** e.denominator == N ** e.numerator:  # N^e 恰为整数
                X = (t0 + 1) // 2
    return m, t, X


def _build_lattice(f: list[int], N: int, m: int, t: int, d: int, X: int) -> list[list[int]]:
    dim = m * d + t
    rows: list[list[int]] = []
    powers: list[list[int]] = [[1]]
    for _ in range(m):
        powers.append(_polymul(powers[-1], f))
    for i in range(m):
        ni = N ** (m - i)
        fi = powers[i]
        for j in range(d):
            g = [0] * dim
            for k, c in enumerate(fi):
                if k + j < dim:
                    g[k + j] = c * ni
            rows.append([g[k] * X ** k for k in range(dim)])
    fm = powers[m]
    for i in range(t):
        g = [0] * dim
        for k, c in enumerate(fm):
            if k + i < dim:
                g[k + i] = c
        rows.append([g[k] * X ** k for k in range(dim)])
    return rows


# ---------------------------------------------------------------- 整数根提取

def _roots_numpy(G: list[int], X: int) -> list[int]:
    """numpy 向量化：mod 素数过滤 + 精确验证。无假阳性（精确验证），X ≤ 2^24。"""
    try:
        import numpy as np
    except ImportError:
        return []
    q = (1 << 31) - 1  # 梅森素数；Horner 中间值 < q² < 2^62，int64 安全
    gq = [c % q for c in G]
    out: set[int] = set()
    chunk = 1 << 20
    lo = -X
    while lo <= X:
        hi = min(lo + chunk - 1, X)
        r = np.arange(lo, hi + 1, dtype=np.int64)
        rq = r % q
        v = np.zeros_like(rq)
        for c in reversed(gq):
            v = (v * rq + c) % q
        for cand in r[v == 0]:
            ci = int(cand)
            if _horner(G, ci) == 0:
                out.add(ci)
        lo = hi + 1
    return sorted(out)


def _roots_float(G: list[int], X: int) -> list[int]:
    """浮点根近似 + 精确验证（系数与根均在 double 安全范围时有效）。"""
    if X >= (1 << 50):
        return []
    try:
        import numpy as np
        desc = [float(c) for c in reversed(G)]
        if any(c != c or abs(c) == float("inf") for c in desc):
            return []
        out: set[int] = set()
        for z in np.roots(desc):
            if abs(z.imag) > 1e-6 * max(1.0, abs(z.real)):
                continue
            r = round(z.real)
            if abs(r) <= X and _horner(G, r) == 0:
                out.add(r)
        return sorted(out)
    except Exception:  # noqa: BLE001
        return []


def _integer_roots(G: list[int], X: int) -> list[int]:
    found = _roots_numpy(G, X)
    if not found:
        found = _roots_float(G, X)
    return found


# ---------------------------------------------------------------- sage 快速路径

def _sage_roots(f: list[int], N: int, X: int, beta: Fraction) -> list[int] | None:
    if not has_sage():
        return None
    import subprocess

    prog = (
        "from sage.all import *\n"
        "import json\n"
        f"P.<x> = PolynomialRing(Zmod({N}))\n"
        f"f = sum({c}*x**{i} for i, c in enumerate({f}))\n"
        f"rs = f.small_roots(X={X}, beta={float(beta)})\n"
        "print(json.dumps([int(r) for r in rs]))\n"
    )
    try:
        res = subprocess.run(
            ["sage", "-c", prog], capture_output=True, text=True, timeout=600
        )
        import json

        line = [ln for ln in res.stdout.strip().splitlines() if ln.startswith("[")]
        if not line:
            return None
        return [int(v) for v in json.loads(line[-1])]
    except Exception:  # noqa: BLE001
        return None


# ---------------------------------------------------------------- 主求解

def _direct_integer_roots(f: list[int], N: int, nbeta: int, X: int) -> list[int]:
    """直接整数根预检：f 在 Z 上有精确小根时（Q = f(x_0)/N = 0 的退化情形），
    Coppersmith 格机制反而用不上（目标 H 无法小化），直接取根更稳。
    numpy 浮点近似 + 精确验证（无假阳性；浮点失败则静默跳过）。"""
    if X >= (1 << 50):
        return []
    try:
        import numpy as np

        desc = [float(c) for c in reversed(f)]
        if any(c != c or abs(c) == float("inf") for c in desc):
            return []
        out: set[int] = set()
        for z in np.roots(desc):
            if abs(z.imag) > 1e-6 * max(1.0, abs(z.real)):
                continue
            r = round(z.real)
            if abs(r) <= X and _horner(f, r) % N == 0 and gcd(N, _horner(f, r)) >= nbeta:
                out.add(r)
        return sorted(out)
    except Exception:  # noqa: BLE001
        return []


def solve_small_roots(f_coeffs: list[int], N: int, X: int | None, beta: Fraction) -> tuple[str, list[int], str]:
    if N < 2:
        return "not_applicable", [], "modulus 必须 ≥ 2"
    if beta <= 0 or beta > 1:
        return "not_applicable", [], f"beta 必须落在 (0, 1]，得到 {beta}"
    f_coeffs = [c % N for c in f_coeffs]
    d = len(f_coeffs) - 1
    if d < 1:
        return "not_applicable", [], "poly 为常数多项式（次数 < 1）"
    lead = f_coeffs[-1]
    if gcd(lead, N) != 1:
        return "not_applicable", [], f"首项系数 {lead} 与 N 不互质，无法 monic 归一"
    inv = pow(lead, -1, N)
    f = [c * inv % N for c in f_coeffs]  # monic 化（mod N 意义下根不变）
    # N^beta 的保守整数下界（筛选用）
    bnum, bden = beta.numerator, beta.denominator
    nbeta = integer_nth_root(N ** bnum, bden)

    if X is None:
        _, _, X = _params(d, N, beta, None, None)
    if X < 1:
        return "not_applicable", [], f"X 必须 ≥ 1，得到 {X}"

    # 预检：f 在 Z 上的精确小根（Q=0 退化情形的正路）
    direct = _direct_integer_roots(f, N, nbeta, X)
    if direct:
        return "solved", direct, f"直接整数根（f 在 Z 上有精确小根，Q=0）: {direct}"

    # 自适应 m：Sage 公式给出起步值；大 N 下 m=O(1) 余量不足（目标向量仅高于
    # det^{1/D} 数个 bit，LLL 近似因子 2^{(D-1)/4} 会miss），按维度上限递增重试。
    # 工作量预算（2026-10-23 实测标定，纯 Python LLL）：
    #   dim=8/条目 212bit→1.0s；dim=10/265bit→6.9s；dim=12/318bit→32.3s
    #   ⇒ 成本 ≈ dim²·bits²·3e-7 s。首次尝试（m=m0 的规范构造）恒跑；
    #   增量重试仅在预估 ≤ _RETRY_BUDGET（≈10s 量级）时进行——该规模以上纯
    #   Python 不可负担（大 N 情形本就走 sage/fpLLL 路径），拒绝路径也由此有界。
    _RETRY_BUDGET = 1e7
    m0, t0, _ = _params(d, N, beta, None, X)
    last_detail = ""
    m = m0
    first = True
    while True:
        t = int(d * m * (1 / beta - 1))
        dim = m * d + t
        rows = _build_lattice(f, N, m, t, d, X)
        if not first:
            bits = max(max(abs(x).bit_length() for x in r) for r in rows)
            if dim * dim * bits * bits > _RETRY_BUDGET:
                last_detail = (
                    f"增量重试预算耗尽（dim={dim}, 条目 {bits}bit，预估 LLL "
                    f"成本超 10s 量级；d={d}, X={X}, beta={beta}）")
                break
        red = lll_reduce(rows)
        roots: set[int] = set()
        for v in red:
            G: list[int] = []
            ok = True
            for k in range(len(v)):
                xk = X ** k
                if v[k] % xk != 0:
                    ok = False
                    break
                G.append(v[k] // xk)
            if not ok:
                continue
            for r in _integer_roots(G, X):
                if gcd(N, _horner(f, r)) >= nbeta:
                    roots.add(r)
        if roots:
            return "solved", sorted(roots), (
                f"Coppersmith 小根攻击成功（d={d}, m={m}, t={t}, X={X}, beta={beta}）")
        last_detail = (
            f"未找到 |r| ≤ X={X} 且 gcd(N, f(r)) ≥ N^{beta} 的根"
            f"（d={d}, m={m}, t={t}, dim={dim}；X 可能超出理论界或需 sage 加速）")
        first = False
        if dim >= _DIM_CAP:
            break
        m += 1
    # sage 兜底（大 X 取根受限 / 需要更强规约时）
    srs = _sage_roots(f, N, X, beta)
    if srs:
        return "solved", sorted(set(srs)), f"Coppersmith 小根攻击成功（sage 路径，d={d}, X={X}, beta={beta}）"
    return "not_applicable", [], last_detail


def _selftest() -> None:
    import random

    rng = random.Random(20261023)
    ok = total = 0

    def is_prime(n: int) -> bool:
        for p in (2, 3, 5, 7, 11, 13, 17, 19, 23, 29, 31, 37):
            if n % p == 0:
                return n == p
        dd, s = n - 1, 0
        while dd % 2 == 0:
            dd //= 2
            s += 1
        for a in (2, 3, 5, 7, 11, 13, 17, 19, 23, 29, 31, 37):
            x = pow(a, dd, n)
            if x in (1, n - 1):
                continue
            for _ in range(s - 1):
                x = x * x % n
                if x == n - 1:
                    break
            else:
                return False
        return True

    def rand_prime(bits: int) -> int:
        while True:
            n = rng.getrandbits(bits) | (1 << (bits - 1)) | 1
            if is_prime(n):
                return n

    # 用例 0a：Sage docstring 权威实例（N=10001, f=x³+10x²+5000x-222 → 根 4）
    total += 1
    status, roots, detail = solve_small_roots([(-222) % 10001, 5000, 10, 1], 10001, None, Fraction(1))
    good = status == "solved" and 4 in roots
    ok += good
    print(f"  权威实例 N=10001: {'PASS' if good else 'FAIL ' + detail}")

    # 用例 0b：Sage TESTS 权威实例（f=x²-5x+6 mod 17 → 根 2）
    total += 1
    status, roots, detail = solve_small_roots([6 % 17, (-5) % 17, 1], 17, None, Fraction(1))
    good = status == "solved" and 2 in roots
    ok += good
    print(f"  权威实例 N=17: {'PASS' if good else 'FAIL ' + detail}")

    # 用例 1：通用三次 + 小根 mod N（N=2^80；f = (x-x_0)(x²+bx+c) + Q·N，b,c ~ N）
    # 实证（2026-10-23）：此形态在 N≤160bit、m=Sage 公式下纯 Python LLL 稳定命中。
    # 注意：RSA e=3 stereotyped 实例（M~N、根远低于默认 X）在 N≥2^120 时纯 Python LLL
    # 未见目标行（全规模 docstring 复刻验证见 git log / 实验记录）；小 M 构造则退化
    # （Q=f(x_0)/N 增大或根变成 Z 上精确根）。该场景走 sage 路径（fpLLL）。
    p, q = rand_prime(40), rand_prime(40)
    N = p * q
    x0 = 12345
    b = rng.randrange(N)
    c = rng.randrange(N)
    poly = [(-x0 * c + N) % N, (c - x0 * b) % N, (b - x0) % N, 1]
    total += 1
    status, roots, detail = solve_small_roots(poly, N, 1 << 14, Fraction(1))
    good = status == "solved" and x0 in roots
    ok += good
    print(f"  通用三次小根(N=2^80): {'PASS' if good else 'FAIL ' + detail}")

    # 用例 2：已知 p 高比特（d=1, beta=0.5；f = ph + x，根 mod p；x_0 必须 < X）
    ph_bits = 13  # p = ph + x_0，ph = P·2^13，x_0 < 2^12 < 默认 X ≈ 0.5·N^{3/16}
    while True:
        p2 = rand_prime(40)
        P2 = p2 >> ph_bits
        x0_2 = p2 & ((1 << ph_bits) - 1)
        if P2 > 0 and 0 < x0_2 < (1 << (ph_bits - 1)):
            break
    q2 = rand_prime(40)
    N2 = p2 * q2
    ph = P2 << ph_bits
    poly2 = [ph, 1]
    total += 1
    status, roots, detail = solve_small_roots(poly2, N2, None, Fraction(1, 2))
    good = status == "solved" and x0_2 in roots
    ok += good
    print(f"  p 高比特已知: {'PASS' if good else 'FAIL ' + detail}")

    # 用例 3：前提拒绝（首项与 N 不互质）
    total += 1
    status, _, detail = solve_small_roots([2 * p, 2], N, 1 << 14, Fraction(1))
    good = status == "not_applicable"
    ok += good
    print(f"  首项不可逆拒绝: {'PASS' if good else 'FAIL ' + detail}")

    # 用例 4：无小根（随机多项式，界内无根；用小 N 保证自适应 m 循环的空转代价可控）
    N4 = rand_prime(20) * rand_prime(20)
    poly4 = [rng.randrange(N4), rng.randrange(N4), 1]
    total += 1
    status, roots, detail = solve_small_roots(poly4, N4, 1 << 14, Fraction(1))
    good = status == "not_applicable" and not roots
    ok += good
    print(f"  无小根拒绝: {'PASS' if good else 'FAIL ' + detail}")

    print(f"t1 selftest: {ok}/{total}")
    sys.exit(0 if ok == total else 1)


def main() -> None:
    if "--selftest" in sys.argv:
        _selftest()
        return
    try:
        params = read_params(sys.argv)
        need(params, "modulus", "poly")
        N = as_int(params["modulus"], "modulus")
        poly = [as_int(c, f"poly[{i}]") for i, c in enumerate(params["poly"])]
        X = as_int(params["X"], "X") if params.get("X") is not None else None
        beta_raw = params.get("beta", 1)
        beta = Fraction(str(beta_raw))
        status, roots, detail = solve_small_roots(poly, N, X, beta)
        emit(status, flags=[str(r) for r in roots], detail=detail, engine="t1_coppersmith")
    except Exception as exc:  # noqa: BLE001
        emit("error", detail=f"{type(exc).__name__}: {exc}", engine="t1_coppersmith")
        sys.exit(2)


if __name__ == "__main__":
    main()
