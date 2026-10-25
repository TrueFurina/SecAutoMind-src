"""t5_dlp_bsgs_ph.py — 离散对数求解：Pohlig-Hellman（光滑阶）+ BSGS（素数阶子群）。

输入 JSON：
  {"g": <生成元 int>, "h": <目标 int>, "p": <模数 int>, "order": <群阶 int, 可选>}
  语义：求 x 使 g^x ≡ h (mod p)。order 缺省时用 sympy.factorint 分解 p-1 试探。

前提检查（不满足返回 not_applicable）：
  - g 在模 p 下可逆（gcd(g,p)==1）
  - order 给出时，h 的阶必须整除 order（h^(order/pi) 类校验简化：直接做 PH 分解）
  - BSGS 子问题阶 ≤ 2^48（纯 Python 内存/时间边界，超过建议 sage/pari）

自测：python t5_dlp_bsgs_ph.py --selftest
"""

from __future__ import annotations

import json
import math
import sys

from common import as_int, emit, need, read_params


def _baby_step_giant_step(g: int, h: int, p: int, order: int) -> int | None:
    """素数阶 order 子群上的 BSGS：O(sqrt(order)) 时间、O(sqrt(order)) 空间。"""
    m = math.isqrt(order)
    if m == 0:
        return 0 if h % p == 1 % p else None
    if m > (1 << 24):  # 1677 万条目，纯 Python 字典边界
        raise ValueError(f"BSGS 子群阶 {order} 超出纯 Python 边界（>{1<<24}），请用 sage/pari")
    table: dict[int, int] = {}
    e = 1
    for j in range(m):
        table.setdefault(e, j)
        e = e * g % p
    factor = pow(g, -m, p) if m else 1
    gamma = h % p
    # 巨步必须覆盖 i ∈ [0, ceil(order/m)]：旧代码 range(m+1) 在 m·(m+1) < order 时
    # 漏解——最小反例 order=3（m=1，只覆盖 d∈{0,1}，d=2 永远找不到）。
    # 2026-10-25 p=1009(order=1008=2^4·3^2·7) 冒烟实测抓出：PH 数位 d=2 全挂。
    # 任何命中都满足 d ≡ x (mod order)（群同态），故直接 % order 返回即真解。
    steps = (order + m - 1) // m
    for i in range(steps + 1):
        if gamma in table:
            return (i * m + table[gamma]) % order
        gamma = gamma * factor % p
    return None


def _factor_order(n: int) -> dict[int, int]:
    """小因子试除 + 剩余部分整体作为一个大因子（PH 需要完全分解；不完全时如实报告）。"""
    factors: dict[int, int] = {}
    d = 2
    while d * d <= n and d < 100000:
        while n % d == 0:
            factors[d] = factors.get(d, 0) + 1
            n //= d
        d += 1 if d == 2 else 2
    if n > 1:
        factors[n] = factors.get(n, 0) + 1
    return factors


def solve_dlp(g: int, h: int, p: int, order: int | None = None) -> tuple[str, int | None, str]:
    if math.gcd(g, p) != 1:
        return "not_applicable", None, f"g 与 p 不互质（gcd={math.gcd(g, p)}），非乘法群 DLP"
    if order is None:
        order = p - 1  # 常见默认：乘法群；子群场景必须显式给 order
    if order <= 0 or h % p == 0:
        return "not_applicable", None, "order 非正或 h≡0，无解/输入非法"
    if pow(h, order, p) != 1:
        return "not_applicable", None, "h^order ≢ 1 (mod p)：h 不在 order 阶子群内"

    factors = _factor_order(order)
    unfactored = [q for q in factors if q > (1 << 40)]
    if unfactored:
        return "not_applicable", None, f"order 含大素因子 {unfactored[:3]}…，纯 Python PH 不可行（需 sage/pari ECM）"

    residues, moduli = [], []
    for q, e in factors.items():
        pe = q**e
        # 数位剥离（digit-by-digit）：每位 d_k ∈ [0, q)。
        # 关键：hk = (h·g^(-x_k))^(order/q^(k+1)) 落在 **阶 q 的子群**里
        # （x-x_k ≡ d_k·q^k mod q^(k+1) ⇒ hk = (g^(order/q))^{d_k}），
        # 所以 BSGS 的生成元必须是 gamma_q = g^(order/q)（阶 q），不是 g^(order/pe)。
        # 2026-10-25 修真 bug：旧代码用 g^(order/pe)，e=1 时两者巧合相同故自测全过，
        # q^e（e≥2，如 order=100=2²·5² 的 p=101）时 BSGS 在错误子群里必然找不到 d_k。
        # 回归：p=101, g=2, h=8 → x=3（旧代码报「PH 子步失败 q=2 k=0」）。
        gamma_q = pow(g, order // q, p)
        xk = 0
        for k in range(e):
            hk = (pow(pow(g, xk, p), -1, p) * h) % p
            hk = pow(hk, order // (q ** (k + 1)), p)
            d = _baby_step_giant_step(gamma_q, hk, p, q)
            if d is None:
                return "error", None, f"PH 子步失败：q={q}, k={k}（子群结构异常）"
            xk += d * q**k
        residues.append(xk % pe)
        moduli.append(pe)

    # CRT 合并
    x, M = 0, 1
    for r, m in zip(residues, moduli):
        g_ = math.gcd(M, m)
        if (r - x) % g_ != 0:
            return "error", None, "CRT 不相容（子群假设被破坏）"
        lcm = M // g_ * m
        t = ((r - x) // g_) * pow(M // g_, -1, m // g_) % (m // g_)
        x = (x + M * t) % lcm
        M = lcm
    if pow(g, x, p) != h % p:
        return "error", None, "求解结果校验失败（g^x ≢ h）"
    return "solved", x, f"PH+BSGS 成功（order 分解 {factors}）"


def _selftest() -> None:
    import random

    rng = random.Random(20261023)
    ok = 0
    total = 0
    # 用例 1：光滑阶大群（p-1 全小因子合成）
    p = 2 * 3 * 5 * 7 * 11 * 13 * 17 + 1  # 510511，非素数也能跑子群逻辑
    # 构造真素数光滑阶群
    p = 2 * 3**2 * 5 * 7 * 11 * 13 + 1
    while not _is_prime(p):
        p += 2
    order = p - 1
    for _ in range(5):
        x = rng.randrange(order)
        g = _find_generator(p)
        h = pow(g, x, p)
        total += 1
        status, got, detail = solve_dlp(g, h, p, order)
        good = status == "solved" and got == x
        ok += good
        print(f"  光滑阶: x={x} got={got} {'PASS' if good else 'FAIL ' + detail}")
    # 用例 2：大素数阶子群（BSGS 主战场）
    p = _next_prime(1 << 40)
    q = _next_prime(1 << 20)  # 子群阶 ~1e6，BSGS 秒级
    while (p - 1) % q:
        p = _next_prime(p + 1)
        q = _next_prime(1 << 20)
    g = pow(_find_generator(p), (p - 1) // q, p)
    for _ in range(3):
        x = rng.randrange(q)
        h = pow(g, x, p)
        total += 1
        status, got, detail = solve_dlp(g, h, p, q)
        good = status == "solved" and got == x
        ok += good
        print(f"  素数阶子群: x={x} got={got} {'PASS' if good else 'FAIL ' + detail}")
    # 用例 3：前提不满足必须 not_applicable（不许瞎跑）
    status, got, detail = solve_dlp(2, 3, 4, None)
    total += 1
    good = status == "not_applicable"
    ok += good
    print(f"  前提拒绝: status={status} {'PASS' if good else 'FAIL'}")
    # 用例 4：重复素因子阶（e≥2 数位剥离）——2026-10-25 服务器冒烟试出的真 bug 回归：
    # 旧实现 BSGS 生成元误用 g^(order/pe)，q^e（e≥2）场景必报「PH 子步失败」。
    # p=101: order=100=2²·5²，g=2 是生成元，h=8=2³ → x=3。
    for p_, g_, h_, expect in [(101, 2, 8, 3)]:
        total += 1
        status, got, detail = solve_dlp(g_, h_, p_, None)
        good = status == "solved" and got == expect
        ok += good
        print(f"  重复素因子(order={p_-1}=2^2*5^2): x={expect} got={got} {'PASS' if good else 'FAIL ' + str(detail)}")
    # p=1009: order=1008=2^4·3^2·7 —— 4 位 + 2 位 + 1 位混合剥离
    p4 = 1009
    while not _is_prime(p4):
        p4 += 2
    g4 = _find_generator(p4)
    for x in (0, 1, 7, 123, 1007):
        h4 = pow(g4, x, p4)
        total += 1
        status, got, detail = solve_dlp(g4, h4, p4, p4 - 1)
        good = status == "solved" and got == x
        ok += good
        print(f"  多位剥离(order={p4-1}): x={x} got={got} {'PASS' if good else 'FAIL ' + str(detail)}")
    # 显式子群 order=3²（e=2，子群+多位组合）
    g9 = pow(g4, (p4 - 1) // 9, p4)
    for x in (0, 1, 4, 8):
        h9 = pow(g9, x, p4)
        total += 1
        status, got, detail = solve_dlp(g9, h9, p4, 9)
        good = status == "solved" and got == x
        ok += good
        print(f"  子群9(order=3^2): x={x} got={got} {'PASS' if good else 'FAIL ' + str(detail)}")
    print(f"t5 selftest: {ok}/{total}")
    sys.exit(0 if ok == total else 1)


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


def _next_prime(n: int) -> int:
    if n % 2 == 0:
        n += 1
    while not _is_prime(n):
        n += 2
    return n


def _find_generator(p: int) -> int:
    for g in range(2, min(p, 1000)):
        if _is_primitive_root(g, p):
            return g
    raise RuntimeError("未找到生成元")


def _is_primitive_root(g: int, p: int) -> bool:
    if math.gcd(g, p) != 1:
        return False
    order = p - 1
    for q in set(_factor_order(order)):
        if pow(g, order // q, p) == 1:
            return False
    return True


def main() -> None:
    if "--selftest" in sys.argv:
        _selftest()
        return
    try:
        params = read_params(sys.argv)
        need(params, "g", "h", "p")
        order = as_int(params["order"], "order") if params.get("order") is not None else None
        status, x, detail = solve_dlp(as_int(params["g"], "g"), as_int(params["h"], "h"),
                                       as_int(params["p"], "p"), order)
        flags = [str(x)] if status == "solved" and x is not None else []
        emit(status, flags=flags, detail=detail, engine="t5_dlp_bsgs_ph")
    except Exception as exc:  # noqa: BLE001 —— 契约：任何异常转 error，不裸崩
        emit("error", detail=f"{type(exc).__name__}: {exc}", engine="t5_dlp_bsgs_ph")
        sys.exit(2)


if __name__ == "__main__":
    main()
