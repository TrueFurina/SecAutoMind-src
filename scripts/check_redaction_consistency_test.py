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


def make_repo(tmp: Path, *, declared: bool = True, residual: bool = False,
              status: str = "synced", expires: str | None = None,
              baseline_min_hit: int = 20, baseline_impact=None,
              dangling_entry: bool = False, consumer: str = "synced") -> Path:
    """造一个最小仓库形态。

    consumer 四种形态：
      synced      —— 判分已标 expect=not_attemptable（不再要求答案）
      answer      —— 判分仍要求答案，但只存哈希（flag_sha256）
      plain       —— 判分仍要求答案，且以明文 flag 存（R7 泄密）
      service_env —— service 模式明文 flag + 声明 flag_from_env（R7 允许的例外）
    """
    desc = "flag{REDACTED_web_xss}"
    if residual:
        desc = "flag{REDACTED_web_xss} 另有 flag{leak_me}"
    prob = {"description": desc, "name": "web_xss"}
    if declared:
        prob["prompt_answer_redacted"] = True
        prob["prompt_answer_redacted_fields"] = ["description"]
    _write(tmp, "data/ctf_benchmark/benchmark.json",
           {"version": 1, "problems": {"web_xss": prob}})

    man = []
    if consumer == "synced":
        man = [{"name": "web_xss", "mode": "local", "cmd": "x",
                "expect": "not_attemptable",
                "not_attemptable_reason": "题面已脱敏，密文不在语料里"}]
    elif consumer == "answer":
        man = [{"name": "web_xss", "mode": "local", "cmd": "x",
                "flag_sha256": "0" * 64}]
    elif consumer == "plain":
        man = [{"name": "web_xss", "mode": "local", "cmd": "x", "flag": "flag{old_answer}"}]
    elif consumer == "service_env":
        man = [{"name": "web_xss", "mode": "service", "cmd": "x",
                "flag": "flag{svc}", "flag_from_env": True}]
    _write(tmp, "scripts/arena_manifest.json", man)
    _write(tmp, "docs/benchmark_baseline.json", {"suites": {"static": {"min_hit": baseline_min_hit}}})
    entries = [{
        "file": "data/ctf_benchmark/benchmark.json",
        "problem": "web_xss",
        "redacted_fields": ["description"],
        "judge_synced": consumer == "synced",
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
    _write(tmp, "data/ctf_benchmark/redaction_ledger.json", {"schema": 1, "entries": entries})
    return tmp


def run_case(title: str, expect: int, **kw) -> None:
    tmp = Path(tempfile.mkdtemp(prefix="rl_"))
    try:
        root = make_repo(tmp, **kw)
        code, lines = C.check(root)
        ok = code == expect
        detail = lines[-1] if lines else "(无输出)"
        if not ok:
            detail += " ｜ 失败项：" + " ; ".join(l for l in lines if "[FAIL]" in l)[:600]
        RESULTS.append((title, ok, detail))
    finally:
        shutil.rmtree(tmp, ignore_errors=True)


def main() -> int:
    # T1 正例：判分已标不可判，台账 synced
    run_case("T1 判分已标不可判 + synced → PASS", 0, consumer="synced", status="synced")
    # T2 正例：判分仍要求答案，但已登记为债务 → PASS（债被看见）
    run_case("T2 仍要求答案但登记为债务 → PASS", 0, consumer="answer", status="accepted_debt")
    # T3 变异：台账文件缺失 → 新增脱敏未登记必须红
    tmp = Path(tempfile.mkdtemp(prefix="rl_"))
    try:
        make_repo(tmp, consumer="synced")
        (tmp / C.LEDGER_REL).unlink()
        code, lines = C.check(tmp)
        RESULTS.append(("T3 没有台账 → 未登记的新增脱敏必须红", code == 1,
                        "RC=%d ｜ %s" % (code, lines[-1] if lines else "")))
    finally:
        shutil.rmtree(tmp, ignore_errors=True)
    # T4 变异：仍要求答案却写 synced（等于声称已同步）
    run_case("T4 仍要求答案却写 synced → FAIL", 1, consumer="answer", status="synced")
    # T5 变异：台账悬空
    run_case("T5 台账悬空 → FAIL", 1, dangling_entry=True, consumer="synced")
    # T6 变异：同一题残留非脱敏 flag 形态
    run_case("T6 残留明文 → FAIL", 1, residual=True, consumer="synced")
    # T7 变异：没声明脱敏字段
    run_case("T7 缺 prompt_answer_redacted_fields → FAIL", 1, declared=False, consumer="synced")
    # T8 变异：债务已过期
    run_case("T8 债务过期 → FAIL", 1, consumer="answer", status="accepted_debt",
             expires="2026-01-01")
    # T9 变异：声明了 baseline_impact 但地板既不是 from 也不是 to
    run_case("T9 地板未联动 → FAIL", 1, consumer="synced", status="synced",
             baseline_min_hit=99, baseline_impact={"suite": "static", "from": 20, "to": 16})
    # T10 正例：地板仍是 from 且登记为债务
    run_case("T10 地板暂留 from 但有债务登记 → PASS", 0,
             consumer="answer", status="accepted_debt", baseline_min_hit=20,
             baseline_impact={"suite": "static", "from": 20, "to": 16})
    # T11 变异：判分清单仍存明文答案（泄密）；判分口径本身也已同步
    run_case("T11 manifest 明文 flag → FAIL（答案表泄密）", 1,
             consumer="plain", status="synced")
    # T12 正例：service 模式明文 flag 且声明来自环境变量 → 不算泄密
    run_case("T12 service 模式 flag_from_env 例外 → PASS", 0,
             consumer="service_env", status="accepted_debt")

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
