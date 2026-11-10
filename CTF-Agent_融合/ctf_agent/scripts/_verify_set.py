"""内部可复现验证集一键复跑。

配套清单：data/questions_real/_audit/verify_set_20261111.json（core_set 6 道）

为什么存在
----------
2026-10-12 incident 之后 questions_real 93 道里 80 道附件残缺，10-01 那批
大分母审计结论已无法复现。本脚本把「附件齐全 + 判分口径无争议」的 6 道
圈成最小集合，任何人可在服务器上当场复跑，作为对外可交代的能力凭证。

口径
----
纯 LLM：确定性预解全部关闭。每题日志必须同时满足
  ① 出现 "SKIP_PRESOLVE True"
  ② 出现 "内部预扫已按 CTF_AGENT_INTERNAL_PRESOLVE=off 关闭"
  ③ "[presolve:" 标记数为 0
否则该次作废（防止 presolve 悄悄污染结果）。任一题不满足即整体判 FAIL。

用法
----
    # 服务器上，key 已就绪（. /tmp/ds_run.env 或已 export CTF_AGENT_LLM_API_KEY）
    python scripts/_verify_set.py
    python scripts/_verify_set.py --json /tmp/vset_result.json
    python scripts/_verify_set.py --only real_crypto_ezrsa

不要在本机跑（AGENTS.md 第零条：跑实验一律在 172.16.222.99）。
"""
from __future__ import annotations

import argparse
import json
import os
import re
import subprocess
import sys
import time
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
MANIFEST = ROOT / "data" / "questions_real" / "_audit" / "verify_set_20261111.json"
SINGLE = ROOT / "run_single.py"

# 纯 LLM 口径必设项（缺一即污染，见 verify_set_20261111.json reproduce.env_required）
ENV_BASE = {
    "CTF_AGENT_LLM_PROVIDER": "deepseek",
    "CTF_AGENT_USE_REAL_LLM": "1",
    "PYTHONUNBUFFERED": "1",
    "CTF_AGENT_LLM_BASE_URL": "https://api.deepseek.com/v1",
    "CTF_AGENT_LIGHT_MODEL": "deepseek-chat",
    "CTF_AGENT_HEAVY_MODEL": "deepseek-chat",
    "CTF_AGENT_MID_MODEL": "deepseek-chat",
    "CTF_SANDBOX_BACKEND": "docker",
    "CTF_AGENT_PER_Q_BUDGET": "200000",
    "CTF_AGENT_PER_Q_WALLCLOCK": "300",
    "CTF_AGENT_EASY_WALLCLOCK": "300",
    "CTF_AGENT_PRELOAD_ATTACHMENTS": "1",
    "CTF_AGENT_SKIP_PRESOLVE": "1",
    "CTF_AGENT_INTERNAL_PRESOLVE": "off",
    "CTF_AGENT_LAST_CHANCE_PRESOLVE": "0",
}
# 显式清空：这两个一旦被外部 shell 设置，步数就不是默认 max_retries=3 的真实状态
ENV_UNSET = ("CTF_AGENT_MAX_RETRIES", "CTF_AGENT_LLM_CALL_BUDGET")


def _grab(pat: str, text: str) -> str:
    m = re.search(pat, text, re.MULTILINE)
    return m.group(1).strip() if m else ""


def run_one(qid: str, log_dir: Path, timeout: int) -> dict:
    env = dict(os.environ)
    env.update(ENV_BASE)
    for k in ENV_UNSET:
        env.pop(k, None)
    t0 = time.time()
    try:
        proc = subprocess.run(
            [sys.executable, str(SINGLE), qid],
            cwd=str(ROOT), env=env, capture_output=True, text=True, timeout=timeout,
        )
        out = (proc.stdout or "") + (proc.stderr or "")
        rc = proc.returncode
    except subprocess.TimeoutExpired as exc:
        out = ((exc.stdout or b"").decode("utf-8", "ignore") if isinstance(exc.stdout, bytes) else (exc.stdout or ""))
        out += ((exc.stderr or b"").decode("utf-8", "ignore") if isinstance(exc.stderr, bytes) else (exc.stderr or ""))
        rc = -9
    elapsed = round(time.time() - t0, 1)

    log_dir.mkdir(parents=True, exist_ok=True)
    (log_dir / f"{qid}.log").write_text(out, encoding="utf-8", errors="ignore")

    anchor_skip = "SKIP_PRESOLVE True" in out
    anchor_internal = "内部预扫已按 CTF_AGENT_INTERNAL_PRESOLVE=off 关闭" in out
    presolve_marks = len(re.findall(r"\[presolve:", out))

    return {
        "id": qid,
        "rc": rc,
        "elapsed_s": elapsed,
        "flag": _grab(r"^FLAG (.*)$", out) or None,
        "match": _grab(r"^MATCH (.*)$", out) or None,
        "error_category": _grab(r'"category": "([a-z_]+)"', out) or None,
        "caliber_ok": bool(anchor_skip and anchor_internal and presolve_marks == 0),
        "anchor": {"skip_presolve": anchor_skip, "internal_off": anchor_internal,
                   "presolve_marks": presolve_marks},
    }


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--json", help="把结果写到该路径")
    ap.add_argument("--only", help="只跑单题 id")
    ap.add_argument("--timeout", type=int, default=600, help="单题硬超时（秒）")
    args = ap.parse_args()

    if not MANIFEST.exists():
        print(f"清单不存在: {MANIFEST}")
        return 2
    manifest = json.loads(MANIFEST.read_text(encoding="utf-8"))
    cases = manifest["core_set"]["cases"]
    if args.only:
        cases = [c for c in cases if c["id"] == args.only]
        if not cases:
            print(f"清单里没有 {args.only}")
            return 2

    log_dir = Path("/tmp/vset_logs")
    rows = []
    for c in cases:
        print(f"-> {c['id']}", flush=True)
        r = run_one(c["id"], log_dir, args.timeout)
        rows.append(r)
        mark = "OK " if r["match"] == "True" else "MISS"
        print(f"   {mark} {r['elapsed_s']}s flag={r['flag']} "
              f"caliber_ok={r['caliber_ok']} err={r['error_category']}", flush=True)

    ok = [r for r in rows if r["match"] == "True"]
    caliber_bad = [r["id"] for r in rows if not r["caliber_ok"]]
    print("\n" + "=" * 62)
    print(f"解出 {len(ok)}/{len(rows)} = {len(ok)/max(len(rows),1):.1%}")
    if caliber_bad:
        print(f"口径污染（结果作废）: {caliber_bad}")
        verdict = "FAIL_CALIBER"
    else:
        print("口径锚点全部通过：SKIP_PRESOLVE True + 内部预扫已关闭 + presolve 标记 0")
        verdict = "PASS"
    print(f"VERDICT={verdict}")
    print(f"日志目录 {log_dir}")

    if args.json:
        Path(args.json).write_text(json.dumps(
            {"ran_at": time.strftime("%Y-%m-%dT%H:%M:%S"),
             "verdict": verdict, "solved": len(ok), "total": len(rows), "rows": rows},
            ensure_ascii=False, indent=2), encoding="utf-8")
        print(f"已写 {args.json}")

    return 0 if verdict == "PASS" else 1


if __name__ == "__main__":
    raise SystemExit(main())
