"""ctf_sage_t2_ecdsa_hnp — ECDSA nonce 复用 / HNP 格恢复私钥模板适配层（P0-1）。

数学实现全在 scripts/ctf_sage/t2_ecdsa_hnp.py（Kannan 嵌入 + LLL，纯 Python）。
本文件只做 params → solve_* 的映射与结果整形，不含攻击逻辑。

skill 入参（execute_python 的 params 字段）：
  mode="nonce_reuse": n, r, s1, z1, s2, z2（两条签名共用同一 nonce：r 相同）
  mode="hnp":         n, nonce_bits, sigs=[{"r":..,"s":..,"z":..}, ...]（≥8 条独立签名）
返回：{"ok", "status", "d", "note"}；status=not_applicable = 前提不满足（如签名不足）。
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
        import t2_ecdsa_hnp as t2
    except Exception as exc:  # noqa: BLE001
        return {"ok": False, "note": f"模板库不可用: {type(exc).__name__}: {exc}"}

    try:
        n = int(params["n"])
        mode = str(params.get("mode", "")).strip().lower()
        if mode == "nonce_reuse":
            status, ds, detail = t2.solve_nonce_reuse(
                int(params["r"]), int(params["s1"]), int(params["z1"]),
                int(params["s2"]), int(params["z2"]), n)
        elif mode == "hnp":
            sigs = [(int(sg["r"]), int(sg["s"]), int(sg["z"])) for sg in params["sigs"]]
            status, ds, detail = t2.solve_hnp(sigs, n, int(params["nonce_bits"]))
        else:
            return {"ok": False, "note": f"未知 mode: {mode!r}（应为 nonce_reuse 或 hnp）"}
    except Exception as exc:  # noqa: BLE001
        return {"ok": False, "note": f"参数错误: {type(exc).__name__}: {exc}"}

    out = {"ok": status == "solved", "status": status, "note": detail}
    if status == "solved" and ds:
        out["d"] = ds[0]
        out["d_all"] = ds
        out["result"] = f"ECDSA 私钥 d = {ds[0]}"
    return out
