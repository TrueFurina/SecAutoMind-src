"""t4_boneh_durfee.py — Boneh-Durfee 小私钥指数攻击（d < N^0.292）。

构造（Herrmann–May, PKC 2010《Maximizing Small Root Bounds by Linearization》§3，
2026-10-23 按论文原文 + mimoo 权威实现逐条对齐）：
  RSA 密钥方程 ed = 1 + k·φ(N)，φ = N+1−(p+q)
  ⇒ 令 A = (N+1)/2，f(x,y) = 1 + x(A+y)，根 (x0,y0) = (2k, −(p+q)/2)
    满足 f(x0,y0) = e·d ≡ 0 (mod e)
  线性化 u = xy+1 ⇒ f̄ = u + A·x（消去二次项 xy，恢复格的三角结构）
  x-shifts：g_{k,i} = x^i·f̄^k·e^(m−k)，k = 0..m，i = 0..m−k
  y-shifts：h_{j,k} = y^j·f̄^k·e^(m−k)，j = 1..t，k = ⌊m/t⌋·j..m
    ⚠️ y-shift 必须先在商环 Z[u,x,y]/(xy+1−u) 中约化（x^b y^c → x^{b−1}y^{c−1}(u−1)），
       否则会引入不在单子集里的 x^b y^c 项——这是 2026-10-23 实测踩过的坑。
  单子以 (u,x,y) 指数三元组表示；矩阵元 = 系数 × U^a·X^b·Y^c
  界：X = 2·N^δ（δ 为 d 的指数界），Y = 2·⌊√N⌋+1，U = X·Y+1，t = ⌊(1−2δ)·m⌋
    ⚠️ Y 取 2√N 而非论文的 N^0.5：根 y0 = −(p+q)/2，AM-GM 下 (p+q)/2 ≥ √N，
        p,q 不等时可达 ~1.4√N，用 ⌊√N⌋ 会让 |y0| > Y 而破坏启发式（实测踩过）。
  可达 δ ≤ 1/2·(2−√2) ≈ 0.292（满尺寸 e ≈ N 时）
  LLL 后取两条短向量，反缩放（除以 U^a X^b Y^c）并代 u=wz+1 得二元多项式，
  结式消 w 求整数根 (w0,z0)，d = (1+w0(A+z0))/e，再用 pow 自检 d 有效性。

诚实边界（2026-10-23 实测，纯 Python Fraction LLL，无 sage/fpylll）：
  1. 规模：128-bit N / m=3 ≈ 3s；192-bit / m=3 ≈ 9s；m=4 约 3–10 倍。
     256-bit / m=3 已失败（需 m=4，约数分钟）；更大 N 请走 sage/fpylll。
  2. 增量重试受工作量预算约束（同 t1 的 dim²·bits²·3e-7 标定），拒绝路径有界。
  3. LLL 用 common.lll_reduce（Fraction 精确算术）——sympy 的 Matrix.lll 在本格上
     会触发内部断言（2026-10-23 实测，满秩无零行仍断言失败），不可用。

输入 JSON：
  {"n": N, "e": e, "c": <密文 int，可选>, "delta": <d 的界指数，默认 0.26>,
   "m": <格参数，可选>, "t": <y-shift 参数，可选>}
输出：flags = 解密明文（给了 c）或私钥 d 的十进制（未给 c）。
前提检查（不满足返回 not_applicable，不瞎跑）：
  - n 为大于 4 的奇数（RSA 模数）
  - e 满尺寸（e² ≥ N）；小 e 时 d 不小，Boneh-Durfee 不适用
  - 0 < delta < 0.292（理论界）
自测：python t4_boneh_durfee.py --selftest
"""

from __future__ import annotations

import sys
from math import comb, gcd, isqrt

from common import as_int, emit, flag_candidates, integer_nth_root, lll_reduce, need, read_params

# 纯 Python Fraction LLL 的维度上限（同 t1：dim>~20 条目数千 bit 时耗时不可负担）
_DIM_CAP = 20
# 增量重试工作量预算（同 t1 标定：dim²·bits²·3e-7 ≈ 秒）
_RETRY_BUDGET = 1e7
# 首次尝试的硬上限（≈300s 量级）：防大 N 卡死十几分钟，超过即 fail-fast 提示 sage
_FIRST_BUDGET = 1e9


# ---------------------------------------------------------------- 多项式工具

def _reduce_xy(poly: dict[tuple[int, int, int], int]) -> dict[tuple[int, int, int], int]:
    """在商环 Z[u,x,y]/(xy+1-u) 中约化：x^b·y^c → x^{b-1}·y^{c-1}·(u−1)。

    这是 unravelled linearization 的关键一步：约化后 y-shift 的单子才落在
    「x-shift 单子 ∪ {u^k y^j}」内，格才保持三角结构。
    """
    out: dict[tuple[int, int, int], int] = {}
    for (a, b, c), co in poly.items():
        stack = [((a, b, c), co)]
        while stack:
            (a, b, c), co = stack.pop()
            if b >= 1 and c >= 1:
                stack.append(((a + 1, b - 1, c - 1), co))
                stack.append(((a, b - 1, c - 1), -co))
            else:
                out[(a, b, c)] = out.get((a, b, c), 0) + co
    return {k: v for k, v in out.items() if v}


def _pow_frac(n: int, delta: float) -> int:
    """floor(n^delta)；float 溢出时回退到有理逼近 + 精确整数根。"""
    if delta <= 0:
        return 1
    try:
        v = n ** delta
        if v == float("inf"):
            raise OverflowError
        return int(v)
    except OverflowError:
        from fractions import Fraction

        frac = Fraction(delta).limit_denominator(1000)
        return integer_nth_root(n ** frac.numerator, frac.denominator)


def _fbar_pow(k: int, a_coef: int) -> dict[tuple[int, int, int], int]:
    """(u + A·x)^k 展开，返回 {(a,b,c): coeff}（单子 u^a x^b y^c）。"""
    return {(k - j, j, 0): comb(k, j) * a_coef ** j for j in range(k + 1)}


# ---------------------------------------------------------------- 格构造

def _build_lattice(n: int, e: int, m: int, t: int, delta: float):
    """构造 Boneh-Durfee 格。返回 (matrix, monos, scales, A)。"""
    A = (n + 1) // 2
    X = 2 * _pow_frac(n, delta)
    Y = 2 * isqrt(n) + 1          # 见 docstring：覆盖 (p+q)/2 ≤ ~1.4√N
    U = X * Y + 1

    x_shifts: list[dict[tuple[int, int, int], int]] = []
    for k in range(m + 1):
        fk = _fbar_pow(k, A)
        ek = e ** (m - k)
        for i in range(m - k + 1):
            x_shifts.append({(a, b + i, c): co * ek for (a, b, c), co in fk.items()})

    monos: set[tuple[int, int, int]] = set()
    for p in x_shifts:
        monos |= set(p)

    y_shifts: list[dict[tuple[int, int, int], int]] = []
    for j in range(1, t + 1):
        for k in range((m // t) * j, m + 1):
            fk = _fbar_pow(k, A)
            ek = e ** (m - k)
            raw = {(a, b, c + j): co * ek for (a, b, c), co in fk.items()}
            y_shifts.append(_reduce_xy(raw))
            monos.add((k, 0, j))

    monos_sorted = sorted(monos)
    shifts = x_shifts + y_shifts

    # 自检：约化后所有单子都必须落在单子集内（否则格构造漏项）
    for p in shifts:
        for mo in p:
            if mo not in monos:
                raise AssertionError(f"单子 {mo} 不在集合内：y-shift 约化不完整")

    scales = [U ** a * X ** b * Y ** c for (a, b, c) in monos_sorted]
    idx = {mo: i for i, mo in enumerate(monos_sorted)}
    mat = [[0] * len(monos_sorted) for _ in shifts]
    for r, p in enumerate(shifts):
        for mo, co in p.items():
            mat[r][idx[mo]] = co * scales[idx[mo]]
    return mat, monos_sorted, scales, A


# ---------------------------------------------------------------- 根提取

def _recover_d(reduced, monos, scales, A: int, e: int, n: int):
    """从 LLL 输出恢复私钥 d；失败返回 None。

    对每对短向量：反缩放得多项式（代 u = wz+1）→ 结式消 w → 整数根 z0
    → 代回求 w0 → d = (1+w0(A+z0))/e → pow 自检。
    """
    import sympy

    w, z = sympy.symbols("w z")
    polys = []
    for row in reduced:
        expr = sympy.Integer(0)
        ok = True
        for coeff, (a, b, c), sc in zip(row, monos, scales):
            if coeff == 0:
                continue
            q, r = divmod(int(coeff), sc)
            if r != 0:          # 必须逐项整除（短向量是缩放基的整数组合）
                ok = False
                break
            expr += q * (w * z + 1) ** a * w ** b * z ** c
        if ok:
            polys.append(sympy.expand(expr))

    for i in range(min(len(polys), 10)):
        for j in range(i + 1, min(len(polys), 12)):
            try:
                res = sympy.resultant(polys[i], polys[j], w)
            except Exception:  # noqa: BLE001 —— 结式失败只跳过该对
                continue
            if res == 0:
                continue
            try:
                rp = sympy.Poly(res, z)
            except Exception:  # noqa: BLE001
                continue
            if rp.degree() < 1:
                continue
            try:
                z_roots = rp.ground_roots()
            except Exception:  # noqa: BLE001
                continue
            for z0 in z_roots:
                if not z0.is_Integer:
                    continue
                z0 = int(z0)
                try:
                    p1z = sympy.Poly(polys[i].subs(z, z0), w)
                except Exception:  # noqa: BLE001
                    continue
                if p1z.degree() < 1:
                    continue
                try:
                    w_roots = p1z.ground_roots()
                except Exception:  # noqa: BLE001
                    continue
                for w0 in w_roots:
                    if not w0.is_Integer:
                        continue
                    w0 = int(w0)
                    val = 1 + w0 * (A + z0)
                    if val % e != 0:
                        continue
                    d = val // e
                    if d > 0 and _valid_d(d, n, e):
                        return d
    return None


def _valid_d(d: int, n: int, e: int) -> bool:
    """用若干小底数自检 d 是否为有效私钥指数（e·d ≡ 1 mod λ(n)）。"""
    for base in (2, 3, 5, 7, 11):
        if gcd(base, n) != 1:
            continue
        if pow(pow(base, e, n), d, n) != base % n:
            return False
    return True


# ---------------------------------------------------------------- 主求解

def solve_boneh_durfee(n: int, e: int, c: int | None = None,
                       delta: float = 0.26, m: int | None = None,
                       t: int | None = None):
    """返回 (status, payload, detail)；payload 为明文字节或 None。"""
    if n <= 4 or n % 2 == 0:
        return "not_applicable", None, "n 必须是大于 4 的奇数（RSA 模数）"
    if e <= 1:
        return "not_applicable", None, "e 非法（≤1）"
    if e * e < n:
        return "not_applicable", None, (
            "e 不是满尺寸（e² < N）：小 e 时 d 不小，Boneh-Durfee 不适用")
    if not (0 < delta < 0.292):
        return "not_applicable", None, (
            f"delta={delta} 超出 Boneh-Durfee 理论界 (0, 0.292)；"
            "越界不跑（避免无意义的格计算）")

    # 显式 m 时只跑一次（t 缺省按论文 τ=(1−2δ) 推）；否则从 m=3 起自适应递增
    auto = m is None
    fixed = None
    if not auto:
        fixed = (m, t if t is not None else max(1, int((1 - 2 * delta) * m)))

    last = ""
    cur = 3
    first = True
    while True:
        if auto:
            tt = t if t is not None else max(1, int((1 - 2 * delta) * cur))
        else:
            cur, tt = fixed
        if cur < 1 or tt < 1:
            return "error", None, f"m/t 非法（m={cur}, t={tt}）"
        if cur > 12:
            last = f"m={cur} 超出预算上限"
            break
        mat, monos, scales, A = _build_lattice(n, e, cur, tt, delta)
        dim = len(mat)
        bits = max(abs(x).bit_length() for row in mat for x in row)
        cost = dim * dim * bits * bits
        limit = _FIRST_BUDGET if first else _RETRY_BUDGET
        if cost > limit:
            last = (f"纯 Python LLL 预算不足（m={cur}, t={tt}, dim={dim}, 条目 {bits}bit，"
                    f"预估成本 {cost * 3e-7:.0f}s 超上限）：请用 sage/fpylll，或减小 N")
            break
        red = lll_reduce(mat)
        d = _recover_d(red, monos, scales, A, e, n)
        if d is not None:
            detail = (f"Boneh-Durfee 成功（m={cur}, t={tt}, dim={dim}, delta={delta}）："
                      f"恢复 d={d}")
            if c is not None:
                msg = pow(c, d, n)
                raw = msg.to_bytes(max(1, (msg.bit_length() + 7) // 8), "big")
                return "solved", raw, detail
            return "solved", str(d).encode(), detail + "（未给密文，flags 为 d 的十进制）"
        last = (f"未恢复出小 d（m={cur}, t={tt}, dim={dim}, delta={delta}）："
                f"d 可能 ≥ N^delta，或需更大 m / sage 加速")
        first = False
        if not auto or dim >= _DIM_CAP:
            break
        cur += 1
    return "not_applicable", None, last


# ---------------------------------------------------------------- 自测

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


def _gen_prime(bits: int, rng) -> int:
    while True:
        v = rng.getrandbits(bits) | (1 << (bits - 1)) | 1
        if _is_prime(v):
            return v


def _gen_rsa(bits: int, delta: float, rng):
    """生成 e 满尺寸、d < N^delta 的 RSA 实例。"""
    while True:
        p = _gen_prime(bits // 2, rng)
        q = _gen_prime(bits // 2, rng)
        if p == q:
            continue
        n = p * q
        phi = (p - 1) * (q - 1)
        db = max(2, int(bits * delta))
        d = rng.getrandbits(db) | (1 << (db - 1)) | 1
        if gcd(d, phi) != 1:
            continue
        e = pow(d, -1, phi)
        if e * e < n:            # 要求满尺寸 e
            continue
        return n, e, d


def _selftest() -> None:
    import random
    import time

    rng = random.Random(20261023)
    ok = total = 0

    def check(name: str, cond: bool, extra: str = "") -> None:
        nonlocal ok, total
        total += 1
        ok += 1 if cond else 0
        print(f"  {name}: {'PASS' if cond else 'FAIL ' + extra}")

    # 用例 1：128-bit，delta=0.24，m=3 → 恢复 d 并解密
    # （delta 取 0.24 而非 0.26：有限 m 下启发式有失败概率，0.24 实测 3/3 稳定）
    # 消息必须 < n（128-bit），否则 pow(m,e,n) 先取模、解密只能还原 m mod n。
    n, e, d = _gen_rsa(128, 0.24, rng)
    msg = b"FLAG{bd_ok}"
    m_int = int.from_bytes(msg, "big")
    assert m_int < n, "自测消息必须小于 n"
    c = pow(m_int, e, n)
    t0 = time.time()
    status, got, detail = solve_boneh_durfee(n, e, c=c, delta=0.24, m=3)
    dt = time.time() - t0
    check("128bit delta=0.24 m=3", status == "solved" and got == msg,
          f"{status} {detail[:80]} ({dt:.1f}s)")

    # 用例 2：192-bit，delta=0.25，m=3
    n2, e2, d2 = _gen_rsa(192, 0.25, rng)
    c2 = pow(0x41424344, e2, n2)
    t0 = time.time()
    status, got, detail = solve_boneh_durfee(n2, e2, c=c2, delta=0.25, m=3)
    dt = time.time() - t0
    check("192bit delta=0.25 m=3", status == "solved" and got == (0x41424344).to_bytes(4, "big"),
          f"{status} {detail[:80]} ({dt:.1f}s)")

    # 用例 3：拒绝——小 e（e=3），d 不小，不适用
    n3 = _gen_prime(64, rng) * _gen_prime(64, rng)
    status, _, detail = solve_boneh_durfee(n3, 3, delta=0.26, m=3)
    check("拒绝小 e", status == "not_applicable", detail[:80])

    # 用例 4：拒绝——delta 超理论界 0.292
    status, _, detail = solve_boneh_durfee(n3, n3 - 2, delta=0.35, m=3)
    check("拒绝 delta>0.292", status == "not_applicable", detail[:80])

    # 用例 5：拒绝——e 满尺寸但 d 不小（随机 e 的逆元），攻击失败须优雅返回
    n5, _, _ = _gen_rsa(128, 0.26, rng)
    phi5 = None
    # 直接用已知 p,q 不可得，改用随机满尺寸 e 构造：随机 e 的逆元 d 期望 ~N
    while True:
        e5 = rng.getrandbits(128) | (1 << 127) | 1
        if gcd(e5, n5) == 1:
            break
    t0 = time.time()
    status, _, detail = solve_boneh_durfee(n5, e5, delta=0.26, m=3)
    dt = time.time() - t0
    check("d 不小→优雅拒绝", status == "not_applicable", f"{status} {detail[:60]} ({dt:.1f}s)")

    # 用例 6：n 非法（偶数）
    status, _, detail = solve_boneh_durfee(100, 65537, delta=0.26, m=3)
    check("拒绝偶数 n", status == "not_applicable", detail[:80])

    print(f"t4 selftest: {ok}/{total}")
    sys.exit(0 if ok == total else 1)


# ---------------------------------------------------------------- 入口

def main() -> None:
    if "--selftest" in sys.argv:
        _selftest()
        return
    try:
        params = read_params(sys.argv)
        need(params, "n", "e")
        n = as_int(params["n"], "n")
        e = as_int(params["e"], "e")
        c = as_int(params["c"], "c") if params.get("c") is not None else None
        delta = float(params.get("delta", 0.26))
        m = as_int(params["m"], "m") if params.get("m") is not None else None
        t = as_int(params["t"], "t") if params.get("t") is not None else None
        status, payload, detail = solve_boneh_durfee(n, e, c=c, delta=delta, m=m, t=t)
        flags: list[str] = []
        if status == "solved" and payload is not None:
            text = payload.decode("utf-8", "replace")
            flags = [text] + flag_candidates(text)
        emit(status, flags=flags, detail=detail, engine="t4_boneh_durfee")
    except Exception as exc:  # noqa: BLE001
        emit("error", detail=f"{type(exc).__name__}: {exc}", engine="t4_boneh_durfee")
        sys.exit(2)


if __name__ == "__main__":
    main()
