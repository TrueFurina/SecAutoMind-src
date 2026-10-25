"""ctf_sage_t3_truncated_lfsr — LFSR 全输出 / 截断恢复模板适配层（P0-1）。

数学实现全在 scripts/ctf_sage/t3_truncated_lfsr.py（Berlekamp-Massey + 格，纯 Python）。
本文件只做 params → solve_* 的映射与结果整形，不含攻击逻辑。

skill 入参（execute_python 的 params 字段）：
  mode="full":      outputs（连续输出序列）, width（寄存器位宽）, predict_count（预测条数）
  mode="truncated": outputs, width, known_high（已知高位比特数）, taps（反馈多项式抽头）
返回：{"ok", "status", "state", "predict", "note"}；status=not_applicable = 前提不满足。
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
        import t3_truncated_lfsr as t3
    except Exception as exc:  # noqa: BLE001
        return {"ok": False, "note": f"模板库不可用: {type(exc).__name__}: {exc}"}

    try:
        outputs = [int(v) for v in params["outputs"]]
        width = int(params["width"])
        mode = str(params.get("mode", "full")).strip().lower()
        if mode == "full":
            status, state, detail, predict = t3.solve_full(
                outputs, width, int(params.get("predict_count", 8)))
        elif mode == "truncated":
            taps = [int(t) for t in params.get("taps", [])]
            status, state, detail = t3.solve_truncated(
                outputs, width, int(params["known_high"]), taps)
            predict = []
        else:
            return {"ok": False, "note": f"未知 mode: {mode!r}（应为 full 或 truncated）"}
    except Exception as exc:  # noqa: BLE001
        return {"ok": False, "note": f"参数错误: {type(exc).__name__}: {exc}"}

    out = {"ok": status == "solved", "status": status, "note": detail}
    if status == "solved" and state:
        out["state"] = state
        out["result"] = f"LFSR 状态 = {state}"
    if predict:
        out["predict"] = predict
    return out
