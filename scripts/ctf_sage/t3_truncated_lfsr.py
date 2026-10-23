"""t3_truncated_lfsr.py — LFSR 状态/递推恢复：full（转移方程解 taps）+ truncated（已知 taps 解状态）。

结构约定（Fibonacci 型，与多数 CTF 题一致）：
  输出字 w_t = 状态快照；演化：fb = XOR_{p in taps} bit_p(w_t)；w_{t+1} = (w_t >> 1) | (fb << (width-1))。

full 模式（taps 未知）：
  每个相邻对给一条 GF(2) 线性方程 bit31(w_{t+1}) = XOR_p f_p·bit_p(w_t)（32 未知 f_p）。
  收集 ≥width 条独立方程解出 taps → 回放验证 → 预测后续输出。
  随机序列必然方程组冲突 → not_applicable（不硬凑）。

truncated 模式（taps 由调用方提供，或先跑 full）：
  每个输出的高 known_high_bits 位已知 → 每位是初始状态的一条 GF(2) 线性方程
  （XOR 按位无进位，高位方程不受低位影响）→ 高斯消元解初始状态 → 生成完整序列。

输入 JSON：
  {"mode": "full" | "truncated",
   "outputs": [<int>, ...],
   "bits_per_output": <int>,
   "predict_count": <int, 可选>,          # full：预测后续多少个输出
   "taps": [<int>, ...],                  # truncated：递推位置（full 模式的输出会带上）
   "known_high_bits": <int>}              # truncated：每字已知高位宽度

自测：python t3_truncated_lfsr.py --selftest
"""

from __future__ import annotations

import sys

from common import as_int, emit, flag_candidates, need, read_params


# ---------------------------------------------------------------- GF(2) 线性代数

def _solve_gf2(equations: list[tuple[int, int]], n: int) -> list[int] | None:
    """解 GF(2) 线性方程组：equations = [(mask, rhs)]，mask 第 j 位为未知数 j 的系数。
    返回唯一解（n 位整数）；欠定或冲突返回 None。
    结构：消元后每行主元=最高位（上三角）→ 回代按主元位置升序。"""
    pivot_of: dict[int, tuple[int, int]] = {}
    for m, r in equations:
        cm, cr = m, r
        while cm:
            p = cm.bit_length() - 1
            if p in pivot_of:
                pm, pr = pivot_of[p]
                cm ^= pm
                cr ^= pr
            else:
                pivot_of[p] = (cm, cr)
                break
        else:
            if cr != 0:
                return None  # 0 = 1：冲突
    if len(pivot_of) < n or max(pivot_of) >= n:
        return None  # 欠定（或主元越界：mask 宽度超过未知数个数）
    sol = 0
    for p in sorted(pivot_of):  # 升序：行内引用变量位置均低于主元
        m, r = pivot_of[p]
        val = r
        rest = m & ~(1 << p)
        while rest:
            b = rest & -rest
            val ^= (sol >> (b.bit_length() - 1)) & 1
            rest ^= b
        if val:
            sol |= 1 << p
    return sol


# ---------------------------------------------------------------- LFSR 引擎

def lfsr_step(w: int, taps: list[int], width: int) -> int:
    fb = 0
    for p in taps:
        fb ^= (w >> p) & 1
    return (w >> 1) | (fb << (width - 1))


def _contribution_masks(taps: list[int], width: int, steps: int) -> list[list[int]]:
    """contrib[t][j] = 初始状态第 j 位对第 t 步状态的贡献掩码（GF(2) 线性性）。"""
    out = []
    for t in range(steps):
        per_init = []
        for j in range(width):
            s = 1 << j
            for _ in range(t):
                s = lfsr_step(s, taps, width)
            per_init.append(s)
        out.append(per_init)
    return out


# ---------------------------------------------------------------- 求解

def solve_full(outputs: list[int], width: int, predict_count: int) -> tuple[str, list[int], str, list[int]]:
    if len(outputs) < width // 8 + 4:
        return "not_applicable", [], f"输出不足：{len(outputs)} 字（至少需 ~width/8+4 条独立方程）", []
    equations = []
    for t in range(len(outputs) - 1):
        w, wn = outputs[t], outputs[t + 1]
        mask = w & ((1 << width) - 1)
        rhs = (wn >> (width - 1)) & 1
        equations.append((mask, rhs))
    f = _solve_gf2(equations, width)
    if f is None:
        return "not_applicable", [], "GF(2) 方程组无唯一解：观测不足或序列非该型 LFSR", []
    taps = [p for p in range(width) if (f >> p) & 1]
    if not taps:
        return "not_applicable", [], "递推全零：序列为常量/无反馈", []
    # 回放验证（方程来自同一关系，仍显式验，防实现 bug）
    cur = outputs[0]
    for w in outputs[1:]:
        cur = lfsr_step(cur, taps, width)
        if cur != w:
            return "not_applicable", [], "回放验证失败：非 LFSR 结构", []
    preds = []
    for _ in range(predict_count):
        cur = lfsr_step(cur, taps, width)
        preds.append(cur)
    return "solved", preds, f"taps 恢复成功（taps={taps}），预测 {predict_count} 步", taps


def solve_truncated(outputs: list[int], width: int, known_high: int, taps: list[int]) -> tuple[str, list[int], str]:
    if known_high <= 0 or known_high >= width:
        return "not_applicable", [], f"known_high_bits={known_high} 非法（需 0<k<{width}）"
    if not taps:
        return "not_applicable", [], "taps 未提供：截断模式需递推位置（先用 full 模式求得）"
    need_eq = width
    if len(outputs) * known_high < need_eq:
        return "not_applicable", [], f"观测不足：{len(outputs)}字×{known_high}位 < {width} 位状态"
    contrib = _contribution_masks(taps, width, len(outputs))
    shift = width - known_high  # 截断输入是「原词高 known_high 位」构成的数
    equations = []
    for t, w in enumerate(outputs):
        for j in range(shift, width):  # 已知高位 j（原词坐标）
            mask = 0
            for init_j in range(width):
                if (contrib[t][init_j] >> j) & 1:
                    mask |= 1 << init_j
            equations.append((mask, (w >> (j - shift)) & 1))
    state0 = _solve_gf2(equations, width)
    if state0 is None:
        return "not_applicable", [], "状态方程组无唯一解：观测不足/相关或 taps 不符"
    # 生成完整序列并验证已知高位一致
    full = []
    cur = state0
    for t in range(len(outputs)):
        full.append(cur)
        cur = lfsr_step(cur, taps, width)
    for t, w in enumerate(outputs):
        if w != (full[t] >> shift):
            return "not_applicable", [], "生成序列与观测高位不一致：taps 或观测有误"
    return "solved", full, f"状态恢复成功（taps={taps}），生成 {len(full)} 个完整输出字"


def _selftest() -> None:
    ok = total = 0

    width = 32
    taps = [31, 22, 2, 1, 0]
    state0 = 0xACE1ACE1 & ((1 << width) - 1)
    seq = [state0]
    for _ in range(80):
        seq.append(lfsr_step(seq[-1], taps, width))
    seq = seq[1:]  # 第一个输出就是初始状态快照

    # 用例 1：full 模式——恢复 taps 并预测未来
    total += 1
    status, preds, detail, got_taps = solve_full(seq[:60], width, 20)
    good = status == "solved" and preds == seq[60:80] and sorted(got_taps) == sorted(taps)
    ok += good
    print(f"  full 预测+taps: {'PASS' if good else 'FAIL ' + detail}")

    # 用例 2：full 模式——随机序列必须拒绝
    import random

    rng = random.Random(42)
    junk = [rng.getrandbits(width) for _ in range(80)]
    total += 1
    status, _, detail, _ = solve_full(junk, width, 5)
    good = status == "not_applicable"
    ok += good
    print(f"  随机序列拒绝: {'PASS' if good else 'FAIL: ' + detail}")

    # 用例 3：full 模式——观测太少必须拒绝
    total += 1
    status, _, detail, _ = solve_full(seq[:3], width, 5)
    good = status == "not_applicable"
    ok += good
    print(f"  短序列拒绝: {'PASS' if good else 'FAIL'}")

    # 用例 4：truncated 模式——已知 taps，只给高 24 位，恢复完整序列
    trunc = [w >> 8 for w in seq[:40]]
    total += 1
    status, full, detail = solve_truncated(trunc, width, 24, taps)
    good = status == "solved" and full == seq[:40]
    ok += good
    print(f"  truncated 恢复: {'PASS' if good else 'FAIL ' + detail}")

    # 用例 5：truncated 模式——taps 错误必须拒绝（不硬凑）
    total += 1
    status, _, detail = solve_truncated(trunc, width, 24, [31, 5, 3])
    good = status == "not_applicable"
    ok += good
    print(f"  错 taps 拒绝: {'PASS' if good else 'FAIL: ' + detail}")

    # 用例 6：truncated 模式——不给 taps 必须拒绝
    total += 1
    status, _, detail = solve_truncated(trunc, width, 24, [])
    good = status == "not_applicable"
    ok += good
    print(f"  缺 taps 拒绝: {'PASS' if good else 'FAIL'}")

    print(f"t3 selftest: {ok}/{total}")
    sys.exit(0 if ok == total else 1)


def main() -> None:
    if "--selftest" in sys.argv:
        _selftest()
        return
    try:
        params = read_params(sys.argv)
        need(params, "mode", "outputs", "bits_per_output")
        mode = str(params["mode"]).strip().lower()
        width = as_int(params["bits_per_output"], "bits_per_output")
        outputs = [as_int(w, f"outputs[{i}]") for i, w in enumerate(params["outputs"])]
        if mode == "full":
            predict = as_int(params.get("predict_count", 1), "predict_count")
            status, preds, detail, taps = solve_full(outputs, width, predict)
            flags = flag_candidates(" ".join(hex(p) for p in preds))
        elif mode == "truncated":
            known = as_int(params["known_high_bits"], "known_high_bits")
            taps = [as_int(t, f"taps[{i}]") for i, t in enumerate(params.get("taps") or [])]
            status, full, detail = solve_truncated(outputs, width, known, taps)
            flags = flag_candidates(" ".join(hex(p) for p in full))
        else:
            status, detail, flags = "error", f"未知 mode: {mode}", []
        emit(status, flags=flags, detail=detail, engine="t3_truncated_lfsr")
    except Exception as exc:  # noqa: BLE001
        emit("error", detail=f"{type(exc).__name__}: {exc}", engine="t3_truncated_lfsr")
        sys.exit(2)


if __name__ == "__main__":
    main()
