"""t2_ecdsa_hnp.py — ECDSA 私钥恢复：nonce 复用（精确代数）+ 偏差 nonce（HNP 格攻击）。

模式 A（nonce_reuse）：两条签名共用同一 nonce k → k=(z1-z2)/(s1-s2)，d=(s1·k-z1)/r。纯代数，精确。
模式 B（hnp）：nonce 有小偏差（k_i < 2^b，如高位已知/MSB 泄露）→ HNP 格攻击。
  格构造（本模板自推导 + 数值实证）：
    签名方程 k_i = t_i + a_i·d - n·q_i（a_i = r_i·s_i^{-1} mod n，t_i = s_i^{-1}·z_i mod n）
    ⇒ 目标向量 K = (k_0, ..., k_{m-1}) ∈ Z^m 落在格 L 的陪集 t + L 中：
      L = {c·a + n·q : c ∈ Z, q ∈ Z^m}，det(L) = n^{m-1}（a 随机 mod n）
    ⇒ CVP：求 -t 在 L 中的最近向量。用 Kannan 嵌入化归 SVP：
      Λ = (L×{0}) + ⟨(t, K_anchor)⟩ ⊂ Z^{m+1}，K_anchor ≈ √m·B
      (K, K_anchor) = (K - t, 0) + (t, K_anchor) ∈ Λ，且是唯一短向量
      （教训：①不能把 d 作为坐标——d 全尺寸 ~n/2，目标不再短；
             ②不能把 t 直接并入 Z^m 基——det 被稀释成 n^{m-2}，同等参数下攻击失效）

输入 JSON：
  {"mode": "nonce_reuse" | "hnp",
   "n": <曲线阶 int>, "curve": "secp256k1"|"自定义(需给 Gx,Gy,a,p)", ...}
  nonce_reuse: {"r": int, "s1": int, "z1": int, "s2": int, "z2": int}
  hnp:         {"sigs": [{"r": int, "s": int, "z": int}, ...], "nonce_bits": int（b, k_i < 2^b）}

自测：python t2_ecdsa_hnp.py --selftest
"""

from __future__ import annotations

import sys
from math import gcd, isqrt

from common import as_int, emit, lll_reduce, need, read_params

# 内置曲线（阶 n、生成元）；测试用 64 位玩具曲线 + secp256k1 参数
CURVES = {
    # secp256k1
    "secp256k1": {
        "p": 0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEFFFFFC2F,
        "a": 0, "b": 7,
        "gx": 0x79BE667EF9DCBBAC55A06295CE870B07029BFCDB2DCE28D959F2815B16F81798,
        "gy": 0x483ADA7726A3C4655DA4FBFC0E1108A8FD17B448A68554199C47D08FFB10D4B8,
        "n": 0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEBAAEDCE6AF48A03BBFD25E8CD0364141,
    },
}


# ---------------------------------------------------------------- 曲线运算

def _ec_add(P, Q, a, p):
    if P is None:
        return Q
    if Q is None:
        return P
    x1, y1 = P
    x2, y2 = Q
    if x1 == x2 and (y1 + y2) % p == 0:
        return None
    if P == Q:
        lam = (3 * x1 * x1 + a) * pow(2 * y1, -1, p) % p
    else:
        lam = (y2 - y1) * pow(x2 - x1, -1, p) % p
    x3 = (lam * lam - x1 - x2) % p
    y3 = (lam * (x1 - x3) - y1) % p
    return (x3, y3)


def _ec_mul(k: int, P, a, p):
    R = None
    while k:
        if k & 1:
            R = _ec_add(R, P, a, p)
        P = _ec_add(P, P, a, p)
        k >>= 1
    return R


def _center(v: int, n: int) -> int:
    """取模 n 的居中表示（-n/2, n/2]，控制格基条目规模。"""
    v %= n
    return v - n if v > n // 2 else v


def _log2_ceil(x: int) -> float:
    """≥log2(x) 的最小整数，用于安全余量的保守估计。"""
    b = x.bit_length()
    return float(b - 1 if (1 << (b - 1)) == x else b)


# ---------------------------------------------------------------- 模式 A：nonce 复用

def solve_nonce_reuse(r: int, s1: int, z1: int, s2: int, z2: int, n: int) -> tuple[str, list[int], str]:
    if (s1 - s2) % n == 0:
        return "not_applicable", [], "s1 ≡ s2 (mod n)：两条签名同 nonce 且同 z，无法分离"
    k = (z1 - z2) * pow((s1 - s2) % n, -1, n) % n
    if r % n == 0:
        return "not_applicable", [], "r ≡ 0 (mod n)：签名非法"
    d = (s1 * k - z1) * pow(r, -1, n) % n
    # 自校验：用 d 重签验证
    if (pow(k, -1, n) * (z1 + r * d)) % n != s1 % n:
        return "error", [], "恢复结果校验失败"
    return "solved", [d], f"nonce 复用恢复成功（k={k}）"


# ---------------------------------------------------------------- 模式 B：HNP 格攻击

def solve_hnp(sigs: list[tuple[int, int, int]], n: int, nonce_bits: int) -> tuple[str, list[int], str]:
    if nonce_bits <= 0:
        return "not_applicable", [], "nonce_bits 必须为正（k_i < 2^nonce_bits）"
    m_all = len(sigs)
    if m_all < 2:
        return "not_applicable", [], "HNP 至少需要 2 条签名"
    B = 1 << nonce_bits
    # 过滤不可逆签名（gcd(s_i,n)≠1 或 gcd(r_i,n)≠1 的签名无信息量）
    usable = [(r, s, z) for r, s, z in sigs if gcd(s, n) == 1 and gcd(r, n) == 1]
    m = len(usable)
    if m < 2:
        return "not_applicable", [], "可逆签名不足 2 条（存在 s_i 或 r_i 与 n 不互质）"
    # 前提粗验：CVP 解距 ~√m·B 必须显著小于 det(L)^{1/m} = n^{(m-1)/m}，否则观测无信息量
    margin = (m - 1) * n.bit_length() / m - nonce_bits - 0.5 * _log2_ceil(m)
    if margin <= 2:
        return "not_applicable", [], (
            f"维度不匹配：n 仅 {n.bit_length()} 位、nonce_bits={nonce_bits}、m={m} —— "
            "格攻击要求 n^{(m-1)/m} >> √m·2^b（安全余量不足 2 bit）")
    a = [_center(r * pow(s, -1, n) % n, n) for r, s, _ in usable]
    t = [_center(pow(s, -1, n) * z % n, n) for _, s, z in usable]
    # Kannan 嵌入：L = {c·a + n·q} ⊂ Z^m（det(L) = n^{m-1}），目标 K=(k_0..k_{m-1}) ∈ t + L。
    # Λ = (L×{0}) + ⟨(t, K_anchor)⟩ ⊂ Z^{m+1}，K_anchor ≈ √m·B；
    # LLL 后取末坐标 =±K_anchor 的短向量恢复 K（不能把 d 作坐标——d 全尺寸，且不能把 t
    # 直接并作 Z^m 基行——那会把 det 稀释成 n^{m-2}，攻击失效）。
    K_anchor = B * isqrt(m) + B
    rows: list[list[int]] = []
    for i in range(m):
        row = [0] * (m + 1)
        row[i] = n
        rows.append(row)
    rows.append(a + [0])
    rows.append(t + [K_anchor])
    red = lll_reduce(rows)
    for v in red:
        if abs(v[m]) != K_anchor:
            continue
        ks = v[:m]
        if not all(0 <= x < B for x in ks):
            continue
        d_cand = (ks[0] - t[0]) * pow(a[0], -1, n) % n
        if d_cand == 0:
            continue
        ok = True
        for i, (r, s, z) in enumerate(usable):
            if (pow(s, -1, n) * (z + r * d_cand) - ks[i]) % n != 0:
                ok = False
                break
        if ok:
            return "solved", [d_cand], f"HNP 格攻击成功（m={m}, nonce_bits={nonce_bits}）"
    return "not_applicable", [], "格攻击未恢复：偏差可能不足或签名数不够（可增加签名重试）"


def _selftest() -> None:
    import random

    rng = random.Random(20261023)
    ok = total = 0

    # 玩具曲线（64 位素数域）——HNP 自测速度关键
    p = (1 << 61) - 1  # 梅森素数
    a = 3
    G = (2, 3)  # 需验证在曲线上；下面动态找一个
    # y^2 = x^3 + a*x + b mod p，取 b 使 G 在曲线上
    b = (G[1] * G[1] - G[0] ** 3 - a * G[0]) % p
    # 曲线阶（玩具曲线直接暴力数点太慢，改用大随机阶近似）——
    # 自测策略：不依赖真实曲线阶，用「群由 G 生成、阶为某 L」的模拟方式验证代数正确性
    # 更简单：直接构造合成签名数据验证两条求解路径的代数/格逻辑（不依赖 EC 点运算）
    n_toy = (1 << 62) - 57  # 模拟曲线阶（自测只验证代数层）

    # 用例 1：nonce 复用（代数）
    d = rng.randrange(1, n_toy)
    k = rng.randrange(1, n_toy)
    r = rng.randrange(1, n_toy)
    z1, z2 = rng.randrange(n_toy), rng.randrange(n_toy)
    s1 = pow(k, -1, n_toy) * (z1 + r * d) % n_toy
    s2 = pow(k, -1, n_toy) * (z2 + r * d) % n_toy
    total += 1
    status, flags, detail = solve_nonce_reuse(r, s1, z1, s2, z2, n_toy)
    good = status == "solved" and flags and flags[0] == d
    ok += good
    print(f"  nonce 复用: {'PASS' if good else 'FAIL ' + detail}")

    # 用例 2：nonce 复用前提拒绝（s1==s2 且 z1!=z2 时 k 无定义）
    total += 1
    status, _, detail = solve_nonce_reuse(r, s1, z1, s1, z1, n_toy)
    good = status == "not_applicable"
    ok += good
    print(f"  同签名拒绝: {'PASS' if good else 'FAIL'}")

    # 用例 3：HNP 格攻击（nonce 高位已知：k_i = K_i + 低位随机，k_i < 2^40，n ~ 2^62）
    nonce_bits = 40
    sigs = []
    for _ in range(6):
        k_i = rng.randrange(1 << nonce_bits)
        r_i = rng.randrange(1, n_toy)
        z_i = rng.randrange(n_toy)
        s_i = pow(k_i, -1, n_toy) * (z_i + r_i * d) % n_toy
        sigs.append((r_i, s_i, z_i))
    total += 1
    status, flags, detail = solve_hnp(sigs, n_toy, nonce_bits)
    good = status == "solved" and flags and flags[0] == d
    ok += good
    print(f"  HNP 格攻击: {'PASS' if good else 'FAIL ' + detail}")

    # 用例 4：HNP 前提拒绝（nonce_bits 太大，观测无信息量）
    total += 1
    status, _, detail = solve_hnp(sigs, n_toy, 61)
    good = status == "not_applicable"
    ok += good
    print(f"  无信息量拒绝: {'PASS' if good else 'FAIL'}")

    print(f"t2 selftest: {ok}/{total}")
    sys.exit(0 if ok == total else 1)


def main() -> None:
    if "--selftest" in sys.argv:
        _selftest()
        return
    try:
        params = read_params(sys.argv)
        need(params, "mode", "n")
        n = as_int(params["n"], "n")
        mode = str(params["mode"]).strip().lower()
        if mode == "nonce_reuse":
            need(params, "r", "s1", "z1", "s2", "z2")
            status, ds, detail = solve_nonce_reuse(
                as_int(params["r"], "r"), as_int(params["s1"], "s1"),
                as_int(params["z1"], "z1"), as_int(params["s2"], "s2"),
                as_int(params["z2"], "z2"), n)
        elif mode == "hnp":
            need(params, "sigs", "nonce_bits")
            sigs = []
            for i, sg in enumerate(params["sigs"]):
                need(sg, "r", "s", "z")
                sigs.append((as_int(sg["r"], f"sigs[{i}].r"), as_int(sg["s"], f"sigs[{i}].s"),
                             as_int(sg["z"], f"sigs[{i}].z")))
            status, ds, detail = solve_hnp(sigs, n, as_int(params["nonce_bits"], "nonce_bits"))
        else:
            status, ds, detail = "error", [], f"未知 mode: {mode}"
        emit(status, flags=[str(x) for x in ds], detail=detail, engine="t2_ecdsa_hnp")
    except Exception as exc:  # noqa: BLE001
        emit("error", detail=f"{type(exc).__name__}: {exc}", engine="t2_ecdsa_hnp")
        sys.exit(2)


if __name__ == "__main__":
    main()
