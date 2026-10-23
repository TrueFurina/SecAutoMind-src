"""t6_hastad_broadcast.py — Håstad 广播攻击：同一消息 m、同一小指数 e、多接收者。

场景：c_i = m^e mod n_i（i=1..k，k≥e），所有 n_i 两两互质（不同 RSA 密钥对）。
攻击：CRT 合并 C ≡ m^e (mod N)，若 m^e < N 则 C == m^e，直接开 e 次整数根。

输入 JSON：
  {"e": <指数 int>, "pairs": [{"n": int, "c": int}, ...]}    # k ≥ e 组
前提检查（不满足返回 not_applicable）：
  - 组数 k ≥ e
  - n_i 两两互质（gcd 校验）
  - 合并后 C 恰为 e 次完全幂（integer_nth_root 精确验证）；不是 → 消息不够小/假设不成立

自测：python t6_hastad_broadcast.py --selftest
"""

from __future__ import annotations

import sys

from common import as_int, emit, integer_nth_root, need, read_params


def _crt(residues: list[int], moduli: list[int]) -> int:
    x, M = 0, 1
    for r, m in zip(residues, moduli):
        g = _gcd(M, m)
        if (r - x) % g != 0:
            raise ValueError("CRT 不相容：n_i 不两两互质")
        lcm = M // g * m
        t = ((r - x) // g) * pow(M // g, -1, m // g) % (m // g)
        x = (x + M * t) % lcm
        M = lcm
    return x % M


def _gcd(a: int, b: int) -> int:
    while b:
        a, b = b, a % b
    return a


def solve_hastad(e: int, pairs: list[tuple[int, int]]) -> tuple[str, bytes | None, str]:
    if e < 2:
        return "not_applicable", None, "e<2 无广播攻击意义（e=1 直接解）"
    if len(pairs) < e:
        return "not_applicable", None, f"组数 {len(pairs)} < e={e}：Håstad 需要至少 e 个接收者"
    for n, _ in pairs:
        if n <= 0:
            return "not_applicable", None, "存在非正模数"
    for i in range(len(pairs)):
        for j in range(i + 1, len(pairs)):
            if _gcd(pairs[i][0], pairs[j][0]) != 1:
                return "not_applicable", None, f"n_{i} 与 n_{j} 不互质，CRT 合并前提破"
    try:
        C = _crt([c for _, c in pairs], [n for n, _ in pairs])
    except ValueError as exc:
        return "not_applicable", None, str(exc)
    root = integer_nth_root(C, e)
    if root**e != C:
        return "not_applicable", None, "CRT 合并值不是 e 次完全幂：消息 m^e ≥ N（消息不够小或假设不成立）"
    return "solved", root.to_bytes((root.bit_length() + 7) // 8, "big"), f"Håstad 成功（e={e}, k={len(pairs)}）"


def _selftest() -> None:
    import random

    rng = random.Random(20261023)
    ok = total = 0

    def mk_rsa(bits: int):
        while True:
            p = _gen_prime(bits, rng)
            q = _gen_prime(bits, rng)
            if p != q:
                return p * q, p, q

    # 用例 1：e=3 三接收者（教科书场景）
    e = 3
    m = b"FLAG{hastad_broadcast_demo}"
    m_int = int.from_bytes(m, "big")
    ns = []
    while len(ns) < e:
        n, _, _ = mk_rsa(512)
        if m_int**e < n:
            ns.append(n)
    # 保证 m^e < N（三个 512-bit n 相乘 ≈ 1536bit > 24bit 消息的 3 次方 ≈ 72bit，天然满足）
    pairs = [(n, pow(m_int, e, n)) for n in ns]
    total += 1
    status, got, detail = solve_hastad(e, pairs)
    good = status == "solved" and got == m
    ok += good
    print(f"  e=3 广播: {'PASS' if good else 'FAIL ' + detail}")
    # 用例 2：前提拒绝——只有 2 组却声称 e=3
    total += 1
    status, _, detail = solve_hastad(3, pairs[:2])
    good = status == "not_applicable"
    ok += good
    print(f"  组数不足拒绝: {'PASS' if good else 'FAIL'}")
    # 用例 3：前提拒绝——消息太大（m^e ≥ N 时合并值非完全幂）
    big = int.from_bytes(b"A" * 200, "big")  # 1600bit 消息，e=3 → 4800bit > 3×512bit
    pairs_big = [(n, pow(big, e, n)) for n in ns]
    total += 1
    status, _, detail = solve_hastad(e, pairs_big)
    good = status == "not_applicable"
    ok += good
    print(f"  消息过大拒绝: {'PASS' if good else 'FAIL: ' + detail}")
    # 用例 4：e=2 两接收者
    e2 = 2
    m2_raw = b"FLAG{e2}"
    m2 = int.from_bytes(m2_raw, "big")
    ns2 = []
    while len(ns2) < e2:
        n, _, _ = mk_rsa(512)
        ns2.append(n)
    pairs2 = [(n, pow(m2, e2, n)) for n in ns2]
    total += 1
    status, got, detail = solve_hastad(e2, pairs2)
    good = status == "solved" and got == m2_raw
    ok += good
    print(f"  e=2 广播: {'PASS' if good else 'FAIL ' + detail}")
    print(f"t6 selftest: {ok}/{total}")
    sys.exit(0 if ok == total else 1)


def _gen_prime(bits: int, rng) -> int:
    from common import integer_nth_root  # noqa: F401 —— 保持 common 单一导入点风格

    while True:
        n = rng.getrandbits(bits) | (1 << (bits - 1)) | 1
        if _is_prime(n):
            return n


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


def main() -> None:
    if "--selftest" in sys.argv:
        _selftest()
        return
    try:
        params = read_params(sys.argv)
        need(params, "e", "pairs")
        e = as_int(params["e"], "e")
        pairs = []
        for i, item in enumerate(params["pairs"]):
            need(item, "n", "c")
            pairs.append((as_int(item["n"], f"pairs[{i}].n"), as_int(item["c"], f"pairs[{i}].c")))
        status, got, detail = solve_hastad(e, pairs)
        flags = []
        if status == "solved" and got is not None:
            flags = [got.decode("utf-8", "replace")]
            flags += _extract_flags(got)
        emit(status, flags=flags, detail=detail, engine="t6_hastad_broadcast")
    except Exception as exc:  # noqa: BLE001
        emit("error", detail=f"{type(exc).__name__}: {exc}", engine="t6_hastad_broadcast")
        sys.exit(2)


def _extract_flags(raw: bytes) -> list[str]:
    from common import flag_candidates

    return flag_candidates(raw.decode("utf-8", "replace"))


if __name__ == "__main__":
    main()
