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
from datetime import date, timedelta
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))
import check_redaction_consistency as C  # noqa: E402

RESULTS: list[tuple[str, bool, str]] = []
# 夹具默认的「合规」记账值：R8 要求有人负责 + 到期日在 365 天内且未过期。
DEFAULT_OWNER = "agent"
DEFAULT_EXPIRES = (date.today() + timedelta(days=180)).isoformat()


def _write(root: Path, rel: str, obj) -> None:
    p = root / rel
    p.parent.mkdir(parents=True, exist_ok=True)
    p.write_text(json.dumps(obj, ensure_ascii=False, indent=2) + "\n", encoding="utf-8")


def make_repo(tmp: Path, *, declared: bool = True, residual: bool = False,
              status: str = "synced", expires: str | None = DEFAULT_EXPIRES,
              owner: str = DEFAULT_OWNER, renewals=None,
              baseline_min_hit: int = 20, baseline_impact=None,
              dangling_entry: bool = False, consumer: str = "synced",
              answer_leak: bool = False, exempt=None) -> Path:
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
        "owner": owner,
        "expires": expires,
        "reason": "自测夹具",
        "baseline_impact": baseline_impact,
    }]
    if renewals is not None:
        entries[0]["renewals"] = renewals
    if dangling_entry:
        entries.append({
            "file": "data/ctf_benchmark/benchmark.json", "problem": "ghost",
            "redacted_fields": ["description"], "judge_synced": True,
            "status": "synced", "owner": "-", "expires": None, "reason": "悬空夹具",
            "baseline_impact": None,
        })
    _write(tmp, "data/ctf_benchmark/redaction_ledger.json", {"schema": 1, "entries": entries})
    # R9 夹具：在入仓位置放一条「可被直接抄走」的答案明文，并让题目真值指向它
    if answer_leak:
        import hashlib
        leak = "flag{fixture_leak_0001}"
        prob["flag_sha256"] = hashlib.sha256(leak.encode("utf-8")).hexdigest()
        _write(tmp, "data/ctf_benchmark/benchmark.json",
               {"version": 1, "problems": {"web_xss": prob}})
        leak_p = tmp / "scripts" / "leaky_fixture.py"
        leak_p.parent.mkdir(parents=True, exist_ok=True)
        leak_p.write_text('# 夹具：答案明文躺在这里\nLEAK = "%s"\n' % leak, encoding="utf-8")
    if exempt is not None:
        _write(tmp, C.EXEMPT_REL, {"schema": 1, "entries": exempt})
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
    # ---- R8 记账三件套（2026-11-04 补：负责人=agent / 有到期日 / 续期须留痕）----
    # T13 变异：owner 仍是占位符 unassigned（「没人负责」）
    run_case("T13 owner=unassigned → FAIL（无人负责）", 1, consumer="synced",
             status="synced", owner="unassigned")
    # T14 变异：expires 为空（「永不复查」）
    run_case("T14 expires 为空 → FAIL", 1, consumer="synced", status="synced",
             expires=None)
    # T15 变异：synced 条目也已过期（旧版只校验债务，synced 逃检）
    run_case("T15 synced 但已过期 → FAIL", 1, consumer="synced", status="synced",
             expires="2020-01-01")
    # T16 变异：到期日超过 365 天上限（「填个很久以后」= 把记账做空）
    run_case("T16 expires 超上限 → FAIL", 1, consumer="synced", status="synced",
             expires=(date.today() + timedelta(days=400)).isoformat())
    # T17 变异：手改 expires 却不留续期记录（renewals 最后一条 to 对不上）
    run_case("T17 手改过期日留痕不符 → FAIL", 1, consumer="synced", status="synced",
             expires=DEFAULT_EXPIRES,
             renewals=[{"date": "2026-01-01", "by": "agent",
                        "from": "2026-01-01", "to": "2027-01-01", "reason": "手改"}])
    # T18 正例：续期记录完整且与 expires 一致
    run_case("T18 续期留痕一致 → PASS", 0, consumer="synced", status="synced",
             expires=DEFAULT_EXPIRES,
             renewals=[{"date": date.today().isoformat(), "by": "agent",
                        "from": "2026-01-01", "to": DEFAULT_EXPIRES,
                        "reason": "复核后延期"}])
    # ---- R9 全域答案明文（2026-11-04 补：判分只用哈希，明文在任何入仓文件里都是白送）----
    # T19 变异：入仓文件里躺着可直接抄的答案明文
    run_case("T19 入仓文件含答案明文 → FAIL", 1, consumer="synced", status="synced",
             answer_leak=True)
    # T20 正例：同一命中，但该文件在豁免表里且豁免本身合规
    run_case("T20 明文中豁免且豁免合规 → PASS", 0, consumer="synced", status="synced",
             answer_leak=True,
             exempt=[{"file": "scripts/leaky_fixture.py", "reason": "生成器必须知道明文",
                      "owner": "agent", "expires": DEFAULT_EXPIRES}])
    # T21 变异：豁免表里挂着一条已无命中的条目（豁免变防腐堆）
    run_case("T21 豁免悬空 → FAIL", 1, consumer="synced", status="synced",
             exempt=[{"file": "scripts/leaky_fixture.py", "reason": "已无用",
                      "owner": "agent", "expires": DEFAULT_EXPIRES}])
    # T22 变异：豁免无人负责（等于开了个没有人管的洞）
    run_case("T22 豁免 owner=unassigned → FAIL", 1, consumer="synced", status="synced",
             answer_leak=True,
             exempt=[{"file": "scripts/leaky_fixture.py", "reason": "生成器必须知道明文",
                      "owner": "unassigned", "expires": DEFAULT_EXPIRES}])

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
