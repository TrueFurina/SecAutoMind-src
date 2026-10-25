"""ctf_sage_t4_boneh_durfee — RSA 私指数 d < N^0.292 模板适配层（P0-1）。

数学实现全在 scripts/ctf_sage/t4_boneh_durfee.py（Herrmann-May unravelled
linearization，纯 Python）。本文件只做 params → solve_boneh_durfee 的映射与
结果整形，不含攻击逻辑。

skill 入参（execute_python 的 params 字段）：
  n    : int，RSA 模数（必需）
  e    : int，公指数（必需；须满尺寸 e² ≥ N）
  c    : int，密文（可选；给了就直接解出明文）
  delta: float，d ≈ N^delta 的估计（可选，默认 0.26；须 < 0.292）
返回：{"ok", "status", "d", "plaintext", "note"}；status=not_applicable = 前提不满足
（偶数 n / 小 e / delta 越界等——这是模板的正常回答，据此换路）。
"""

import os
import sys


def _sage_dir() -> str:
    env = os.environ.get("CTF_SAGE_DIR")
    if env:
        return env
    here = os.path.dirname(os.path.abspath(__file__))
    return os.path.abspath(os.path.join(here, "..", "..", "..", "scripts", "ctf_sage"))


def _render_plaintext(payload) -> str:
    """明文字节 → 可读文本（utf-8 失败给 hex，不丢信息）。"""
    if payload is None:
        return ""
    if isinstance(payload, str):
        return payload
    try:
        return payload.decode("utf-8")
    except UnicodeDecodeError:
        return payload.hex()


def run(params):
    try:
        sys.path.insert(0, _sage_dir())
        import t4_boneh_durfee as t4
    except Exception as exc:  # noqa: BLE001
        return {"ok": False, "note": f"模板库不可用: {type(exc).__name__}: {exc}"}

    try:
        n = int(params["n"])
        e = int(params["e"])
        c = int(params["c"]) if params.get("c") is not None else None
        delta = float(params.get("delta", 0.26))
        m = int(params["m"]) if params.get("m") is not None else None
        t = int(params["t"]) if params.get("t") is not None else None
    except Exception as exc:  # noqa: BLE001
        return {"ok": False, "note": f"参数错误: {type(exc).__name__}: {exc}"}

    status, payload, detail = t4.solve_boneh_durfee(n, e, c, delta=delta, m=m, t=t)
    out = {"ok": status == "solved", "status": status, "note": detail}
    if status == "solved":
        text = _render_plaintext(payload)
        if text:
            out["plaintext"] = text
            out["result"] = f"明文 = {text}"
    return out
