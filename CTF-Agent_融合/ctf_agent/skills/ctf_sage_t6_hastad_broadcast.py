"""ctf_sage_t6_hastad_broadcast — 同明文低指数广播攻击模板适配层（P0-1）。

数学实现全在 scripts/ctf_sage/t6_hastad_broadcast.py（Håstad + CRT + 开 e 次方，纯 Python）。
本文件只做 params → solve_hastad 的映射与结果整形，不含攻击逻辑。

skill 入参（execute_python 的 params 字段）：
  e    : int，公指数（必需；≥2）
  pairs: [[n1, c1], [n2, c2], ...]（必需；组数 ≥ e，同一明文用同一 e 广播加密）
返回：{"ok", "status", "plaintext", "note"}；status=not_applicable = 前提不满足
（组数 < e 等）。明文通常是 flag 本体——先过形态校验再当候选。
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
        import t6_hastad_broadcast as t6
    except Exception as exc:  # noqa: BLE001
        return {"ok": False, "note": f"模板库不可用: {type(exc).__name__}: {exc}"}

    try:
        e = int(params["e"])
        pairs = [(int(n), int(c)) for n, c in params["pairs"]]
    except Exception as exc:  # noqa: BLE001
        return {"ok": False, "note": f"参数错误: {type(exc).__name__}: {exc}"}

    status, payload, detail = t6.solve_hastad(e, pairs)
    out = {"ok": status == "solved", "status": status, "note": detail}
    if status == "solved":
        text = _render_plaintext(payload)
        if text:
            out["plaintext"] = text
            out["result"] = f"明文 = {text}"
    return out
