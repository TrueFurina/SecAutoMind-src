#!/usr/bin/env python3
"""summarize_external_runs.py 的离线回归（不联网、不花钱、秒级）。

为什么值得单测：这个脚本决定「哪张表给谁看」。它出错的三种方式都不是崩，
而是**安静地出一张看起来正常的错表**：

  ① 接口失败被算成「模型答错」→ 假的能力边界（2026-11-07 qwen 403 事故）；
  ② `--run` 声明的模型与结果文件里跑的不是同一个 → 假的多模型对照；
  ③ 分母算错（把污染/硬不可用/接口失败的题留在分母里）→ 假的 rate。

所以这里测的是「会不会出错的表」，不是「能不能跑」。

用例：
  1. 干净三轮：rc=0，表里 rate 与解出数对得上
  2. 声明模型 ≠ models_used：rc=2（判红，不出表）
  3. `api_error_rounds>0` 的题必须进「API失败」列，且从可计分分母里剔除
  4. 旧结果（无 `api_error_rounds` 字段）靠 `raw_head` 里的 `(llm_error:` 认出接口失败
  5. 硬不可用的题不进可计分分母

用法：python scripts/test_summarize_external_runs.py
"""
import json
import os
import subprocess
import sys
import tempfile

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
SCRIPT = os.path.join(ROOT, "scripts", "summarize_external_runs.py")
PY = sys.executable or "python3"

CASES = []


def ck(name, cond, extra=""):
    CASES.append((name, bool(cond), extra))


def _write(path, obj):
    with open(path, "w", encoding="utf-8") as f:
        json.dump(obj, f, ensure_ascii=False)
    return path


def make_pool(tmp, ids):
    probs = {}
    for pid in ids:
        probs[pid] = {"id": pid, "category": "crypto", "title": pid, "flag_sha256": "0" * 64}
    return _write(os.path.join(tmp, "pool.json"),
                  {"version": "test", "problems": probs})


def make_audit(tmp, contam=(), hard=(), soft=()):
    tiers = {"A_static_complete": [], "B_needs_oracle": [], "C_contaminated": list(contam),
             "D_hard_unavailable": list(hard), "E_soft_constrained": list(soft)}
    return _write(os.path.join(tmp, "audit.json"),
                  {"pool": "test", "total": None, "counts": {}, "tiers": tiers,
                   "admissible_denominator": 0, "details": {}})


def row(pid, **kw):
    base = {"id": pid, "solved": False, "tool_calls": 3, "latency": 10.0,
            "llm_rounds": [{"finish_reason": "tool_calls"}], "got": "", "error": ""}
    base.update(kw)
    return base


def run(args):
    p = subprocess.run([PY, SCRIPT] + args, capture_output=True, text=True,
                       encoding="utf-8", errors="replace",
                       env={**os.environ, "PYTHONIOENCODING": "utf-8"})
    return p.returncode, (p.stdout or "") + (p.stderr or "")


def main():
    ids = ["q_ok", "q_api", "q_hard", "q_solved"]
    with tempfile.TemporaryDirectory() as tmp:
        pool = make_pool(tmp, ids)
        audit = make_audit(tmp, hard=["q_hard"])

        # 干净一轮：1 题解出、1 题正常未解、1 题接口失败、1 题硬不可用
        clean = _write(os.path.join(tmp, "clean.json"), {
            "summary": {"model": "m-A", "models_used": ["m-A"]},
            "details": [
                row("q_ok"),
                row("q_solved", solved=True, got="flag{x}", hit_mode="exact"),
                row("q_api", api_error_rounds=1, timeout_rounds=0,
                    api_error_first="HTTP Error 403: Forbidden",
                    llm_rounds=[{"finish_reason": "error"}]),
                row("q_hard"),
            ]})
        rc, out = run(["--pool", pool, "--audit", audit, "--run", "r1:m-A:" + clean])
        ck("干净一轮 rc=0", rc == 0, "rc=%s" % rc)
        ck("干净一轮：解出 1/4", "| r1 | m-A | 1/4 |" in out, out[:400])
        # 可计分分母 = 4 - 1 硬不可用 - 1 接口失败 = 2 ⇒ 1/2 = 0.500
        ck("可计分 rate 剔除了 API失败与硬不可用", "| 0.500 |" in out, "未见到 0.500")
        ck("API 失败单列", "API失败" in out and "| 1 |" in out, "缺 API失败列")
        # 硬不可用题不得进 EMPTY（会被读成「模型空答」）
        ck("硬不可用题标 NOT_ADMISSIBLE 而非 EMPTY",
           "NOT_ADMISSIBLE 1" in out and "EMPTY 1" in out, out[:600])

        # 模型误标：声明 m-B，文件里是 m-A ⇒ 判红
        rc, out = run(["--pool", pool, "--audit", audit, "--run", "r2:m-B:" + clean])
        ck("声明模型与 models_used 不符必须判红", rc == 2, "rc=%s out=%s" % (rc, out[:200]))

        # 旧结果回退：没有 api_error_rounds，只有 raw_head 里的标记
        legacy = _write(os.path.join(tmp, "legacy.json"), {
            "summary": {"model": "m-A"},
            "details": [row("q_ok", raw_head="(llm_error: HTTP Error 403)"),
                        row("q_solved")]})
        rc, out = run(["--pool", pool, "--audit", audit, "--run", "r3:m-A:" + legacy])
        ck("旧结果靠 raw_head 认出接口失败", rc == 0 and "| 1 |" in out, out[:300])

        # 变异验证：把接口失败的字段拿掉，同一行必须变回「普通未解」而不是 API_ERROR
        mutated = _write(os.path.join(tmp, "mut.json"), {
            "summary": {"model": "m-A", "models_used": ["m-A"]},
            "details": [row("q_ok")]})
        rc, out = run(["--pool", pool, "--audit", audit, "--run", "r4:m-A:" + mutated])
        ck("变异：无失败字段时不算 API_ERROR", rc == 0 and "| 0 |" in out, out[:300])

    ok = sum(1 for _, c, _ in CASES if c)
    for name, cond, extra in CASES:
        print("%s %s%s" % ("PASS" if cond else "FAIL", name,
                           "" if cond else "  ← " + str(extra)))
    print("\nselftest %d/%d" % (ok, len(CASES)))
    return 0 if ok == len(CASES) else 1


if __name__ == "__main__":
    sys.exit(main())
