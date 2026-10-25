"""ctf_sage_t1_coppersmith — Coppersmith 小根模板 skill 适配层（P0-1，2026-10-25）。

数学实现全在 scripts/ctf_sage/t1_coppersmith.py（纯 Python，与 Sage small_roots
源码同构；docstring 513-bit 实例实测可恢复）。本文件只做 params → solve_small_roots
的映射与结果整形，**不含任何攻击逻辑**——改数学请改模板库并跑其 --selftest。

skill 入参（execute_python 的 params 字段，LLM 从题干提取）：
  modulus   : int，模数 N（必需）
  poly      : [a0, a1, ..., ad] 升序整数系数（必需）
  X         : int，根的上界（可选；缺省按 beta 自动推）
  beta      : "1" 或 "0.5"（可选，默认 1）
  candidates: [r1, ...] 候选根列表（可选；O(1) 精确验证，无需格计算）
返回：{"ok", "status", "roots", "note"}；status=not_applicable 表示前提不满足。
"""

import os
import sys


def _sage_dir() -> str:
    env = os.environ.get("CTF_SAGE_DIR")
    if env:
        return env
    # 仓库根相对：CTF-Agent_融合/ctf_agent/skills/ → 上溯三级 → scripts/ctf_sage
    here = os.path.dirname(os.path.abspath(__file__))
    return os.path.abspath(os.path.join(here, "..", "..", "..", "scripts", "ctf_sage"))


def run(params):
    try:
        sys.path.insert(0, _sage_dir())
        from fractions import Fraction

        import t1_coppersmith as t1
    except Exception as exc:  # noqa: BLE001
        return {"ok": False, "note": f"模板库不可用: {type(exc).__name__}: {exc}"}

    try:
        n = int(params["modulus"])
        poly = [int(c) for c in params["poly"]]
        x = int(params["X"]) if params.get("X") is not None else None
        beta = Fraction(str(params.get("beta", "1")))
        raw_cands = params.get("candidates")
        cands = [int(c) for c in raw_cands] if raw_cands else None
    except Exception as exc:  # noqa: BLE001
        return {"ok": False, "note": f"参数错误: {type(exc).__name__}: {exc}"}

    status, roots, detail = t1.solve_small_roots(poly, n, x, beta, candidates=cands)
    out = {"ok": status == "solved", "status": status, "roots": roots, "note": detail}
    if status == "solved" and roots:
        out["result"] = f"小根 x0 = {roots[0]}"
    return out
