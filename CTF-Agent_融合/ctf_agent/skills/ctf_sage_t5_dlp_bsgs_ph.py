"""ctf_sage_t5_dlp_bsgs_ph — 离散对数 BSGS + Pohlig-Hellman 模板适配层（P0-1）。

数学实现全在 scripts/ctf_sage/t5_dlp_bsgs_ph.py（纯 Python）。
本文件只做 params → solve_dlp 的映射与结果整形，不含攻击逻辑。

skill 入参（execute_python 的 params 字段）：
  g     : int，生成元（必需）
  h     : int，目标值（必需）
  p     : int，素数模数（必需）
  order : int，g 的阶（可选；缺省按 p-1 处理，光滑时自动走 Pohlig-Hellman）
返回：{"ok", "status", "x", "note"}；status=not_applicable = 前提不满足
（g 与 p 不互质 / 阶太光滑不了且 BSGS 预算超限等）。
"""

import os
import sys


def _sage_dir() -> str:
    env = os.environ.get("CTF_SAGE_DIR")
    if env:
        return env
    here = os.path.dirname(os.path.abspath(__file__))
    return os.path.abspath(os.path.join(here, "..", "..", "..", "scripts", "ctf_sage"))


def run(params):
    try:
        sys.path.insert(0, _sage_dir())
        import t5_dlp_bsgs_ph as t5
    except Exception as exc:  # noqa: BLE001
        return {"ok": False, "note": f"模板库不可用: {type(exc).__name__}: {exc}"}

    try:
        g = int(params["g"])
        h = int(params["h"])
        p = int(params["p"])
        order = int(params["order"]) if params.get("order") is not None else None
    except Exception as exc:  # noqa: BLE001
        return {"ok": False, "note": f"参数错误: {type(exc).__name__}: {exc}"}

    status, x, detail = t5.solve_dlp(g, h, p, order)
    out = {"ok": status == "solved", "status": status, "note": detail}
    if status == "solved" and x is not None:
        out["x"] = x
        out["result"] = f"离散对数 x = {x}"
    return out
