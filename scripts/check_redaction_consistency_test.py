#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""`check_redaction_consistency.py` 的回归自测：每条判据一个正例 + 一个变异反例。

为什么必须带变异：本仓教训反复出现「门禁写好但从没证明它会红」。
这里每条规则都用「注入缺陷 → 必须 exit 1」证明判定力，而不是只测正例。
"""

from __future__ import annotations

import json
import shutil
import sys
import tempfile
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))
import check_redaction_consistency as C  # noqa: E402

RESULTS: list[tuple[str, bool, str]] = []


def _write(root: Path, rel: str, obj) -> None:
    p = root / rel
    p.parent.mkdir(parents=True, exist_ok=True)
    p.write_text(json.dumps(obj, ensure_ascii=False, indent=2) + "\n", encoding="utf-8")


def make_repo(tmp: Path, *, redacted: bool = True, manifest_flag: str | None = None,
              status: str = "synced", declared: bool = True, residual: bool = False,
              expires: str | None = None, baseline_min_hit: int = 20,
              baseline_impact=None, dangling_entry: bool = False,
              extra_entry: bool = False) -> Path:
    """造一个最小仓库形态。

    manifest_flag=None → 判分口径与脱敏串一致（synced 场景）；
    否则写入该值（用来制造「判分仍用原 flag」的未同步场景）。
    """
    desc = "flag{REDACTED_web_xss}" if redacted else "flag{real_answer_here}"
    if residual:
        desc = "flag{REDACTED_web_xss} 另有 flag{leak_me}"
    prob = {"description": desc, "name": "web_xss"}
    if declared:
        prob["prompt_answer_redacted"] = True
        prob["prompt_answer_redacted_fields"] = ["description"]
    _write(tmp, "data/ctf_benchmark/benchmark.json",
           {"version": 1, "problems": {"web_xss": prob}})
    man = []
    if manifest_flag is not None:
        man = [{"name": "web_xss", "mode": "local", "cmd": "x", "flag": manifest_flag}]
    _write(tmp, "scripts/arena_manifest.json", man)
    _write(tmp, "docs/benchmark_baseline.json", {"suites": {"static": {"min_hit": baseline_min_hit}}})
    entries = [{
        "file": "data/ctf_benchmark/benchmark.json",
        "problem": "web_xss",
        "redacted_fields": ["description"],
        "judge_synced": manifest_flag is None,
        "status": status,
        "owner": "unassigned",
        "expires": expires,
        "reason": "自测夹具",
        "baseline_impact": baseline_impact,
    }]
    if dangling_entry:
        entries.append({
            "file": "data/ctf_benchmark/benchmark.json", "problem": "ghost",
            "redacted_fields": ["description"], "judge_synced": True,
            "status": "synced", "owner": "-", "expires": None, "reason": "悬空夹具",
            "baseline_impact": None,
        })
    if extra_entry:
        entries.append({
            "file": "data/ctf_benchmark/benchmark.json", "problem": "web_xss_dup",
            "redacted_fields": ["description"], "judge_synced": True,
            "status": "synced", "owner": "-", "expires": None, "reason": "重复夹具",
            "baseline_impact": None,
        })
    _write(tmp, "data/ctf_benchmark/redaction_ledger.json", {"schema": 1, "entries": entries})
    return tmp


def run_case(title: str, expect: int, **kw) -> None:
    tmp = Path(tempfile.mkdtemp(prefix="rl_"))
    try:
        root = make_repo(tmp, **kw)
        code, lines = C.check(root)
        ok = code == expect
        detail = lines[-1] if lines else "(无输出)"
        RESULTS.append((title, ok, "RC=%d 期望 %d ｜ %s" % (code, expect, detail)))
    finally:
        shutil.rmtree(tmp, ignore_errors=True)


def main() -> int:
    # T1 正例：题面脱敏，判分口径也已同步（manifest 期望就是脱敏串）
    run_case("T1 脱敏与判分口径一致 → PASS", 0,
             manifest_flag="flag{REDACTED_web_xss}", status="synced")
    # T2 正例：判分未同步，但已显式登记为债务 → PASS（债被看见）
    run_case("T2 未同步但登记为债务 → PASS", 0,
             manifest_flag="flag{real_answer_here}", status="accepted_debt")
    # T3 变异：新增脱敏未入账（台账里没有这条）—— 这里靠「台账悬空」反向触发不了，
    #        改为直接不给台账文件
    tmp = Path(tempfile.mkdtemp(prefix="rl_"))
    try:
        make_repo(tmp, manifest_flag=None)
        (tmp / C.LEDGER_REL).unlink()
        code, lines = C.check(tmp)
        RESULTS.append(("T3 没有台账 → 未登记的新增脱敏必须红", code == 1,
                        "RC=%d ｜ %s" % (code, lines[-1] if lines else "")))
    finally:
        shutil.rmtree(tmp, ignore_errors=True)
    # T4 变异：判分未同步却写 status=synced
    run_case("T4 未同步却写 synced → FAIL", 1,
             manifest_flag="flag{real_answer_here}", status="synced")
    # T5 变异：台账悬空（登记了语料里不存在的题）
    run_case("T5 台账悬空 → FAIL", 1, dangling_entry=True)
    # T6 变异：同一题残留非脱敏 flag 形态（脱敏漏了）
    run_case("T6 残留明文 → FAIL", 1, residual=True, manifest_flag=None)
    # T7 变异：没声明脱敏字段
    run_case("T7 缺 prompt_answer_redacted_fields → FAIL", 1,
             declared=False, manifest_flag=None)
    # T8 变异：债务已过期
    run_case("T8 债务过期 → FAIL", 1,
             manifest_flag="flag{real_answer_here}", status="accepted_debt",
             expires="2026-01-01")
    # T9 变异：声明了 baseline_impact 但地板既不是 from 也不是 to
    run_case("T9 地板未联动 → FAIL", 1,
             manifest_flag=None, status="synced",
             baseline_min_hit=99,
             baseline_impact={"suite": "static", "from": 20, "to": 16})
    # T10 正例：地板仍是 from 且登记为债务 → PASS
    run_case("T10 地板暂留 from 但有债务登记 → PASS", 0,
             manifest_flag="flag{real_answer_here}", status="accepted_debt",
             baseline_min_hit=20,
             baseline_impact={"suite": "static", "from": 20, "to": 16})

    bad = 0
    for title, ok, detail in RESULTS:
        print("  [%s] %s" % ("PASS" if ok else "FAIL", title))
        if not ok:
            print("        %s" % detail)
            bad += 1
    total = len(RESULTS)
    print("\n结论：%s —— %d/%d 通过" % ("PASS" if bad == 0 else "FAIL", total - bad, total))
    return 0 if bad == 0 else 1


if __name__ == "__main__":
    sys.exit(main())
