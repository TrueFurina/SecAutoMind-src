#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""合规能力评测入口：前置守卫 → 跑批 → 自动证据 → 判分仲裁。

为什么要有这个入口（评审 §12）：
  - 上一版判据的 evidence.json **由人填**，填假仍会误判（§11.4 已承认的边界）；
  - 启动器 `_run_purellm_176.py` 没有任何开关前置，三条件全缺照跑；
  - 因此把「开关 + 池指纹 + 门禁 + 判据」收进同一个不可绕过的入口，
    证据由入口从 env / 源码 / 指纹自动生成，而不是事后手写。

口径（必须写清，否则证据自相矛盾）：
  - airgap 的「零外网」指**解题子进程**（python_session / skill / 流式 shell）经
    syscall 隔离；**LLM API 通道本身必须联网**，不在隔离范围内，否则无法调用模型。
  - 判闸门是否生效**只能用 IP 直连证明**（DNS 失败与没配 DNS 同形），所以要求
    `--airgap-proof` 里 ip_direct_blocked=true 且 af_unix_ok=true。
  - temperature：orchestrator 两处请求体硬编码 0.2 ⇒ 随机源「显式固定」代码级可证；
    但这**不等于逐位可复现**（provider 采样/版本会变），判据只要求显式固定值。

用法：
  python scripts/run_capability_eval.py --preflight
  python scripts/run_capability_eval.py --adjudicate <result.json>
  python scripts/run_capability_eval.py --run --result <result.json> -- <cmd...>
退出码：前置不通过 = 2；判分不可归因 = 1；全绿 = 0。
"""
from __future__ import annotations

import argparse
import datetime
import hashlib
import json
import os
import re
import subprocess
import sys

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from check_benchmark_plaintext_answer import analyze, violations  # noqa: E402
from check_pure_llm_caliber import (EVIDENCE_KEYS, PURE_LLM_EVIDENCE_KEYS,  # noqa: E402
                                   evidence_keys, judge_run, load_leak_ids,
                                   load_questions, load_trained_ids,
                                   prove_pure_llm_path, selftest)

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
POOL = os.path.join(ROOT, "data", "ctf_benchmark", "purellm_clean_benchmark.json")
MANIFEST = os.path.join(ROOT, "data", "ctf_benchmark", "purellm_clean_benchmark.manifest.json")
LEAK = os.path.join(ROOT, ".workbuddy", "tmp", "rev_leak.out")
ORCH = os.path.join(ROOT, "scripts", "ctf_stepfun_orchestrator.py")
WORKDIR = os.path.join(ROOT, ".workbuddy", "tmp", "capability_eval")
EVIDENCE_PATH = os.path.join(WORKDIR, "evidence.auto.json")


def _sha256(path):
    h = hashlib.sha256()
    with open(path, "rb") as f:
        for chunk in iter(lambda: f.read(65536), b""):
            h.update(chunk)
    return h.hexdigest()


def _fixed_temperature_proven():
    """代码级证据：orchestrator 请求体是否显式固定 temperature。"""
    if not os.path.isfile(ORCH):
        return False, "orchestrator 不存在"
    src = open(ORCH, encoding="utf-8", errors="replace").read()
    vals = re.findall(r'["\']temperature["\']\s*:\s*([0-9.]+)', src)
    if len(vals) >= 2 and len(set(vals)) == 1:
        return True, "请求体显式固定 temperature=%s（%d 处），非 provider 默认" % (vals[0], len(vals))
    return False, "请求体未显式固定 temperature（vals=%r）" % vals


def preflight(args):
    """真实检查，不模拟、不伪造。返回 (ok, checks, evidence)。

    §13 修正：Go runner 的三个开关与 IP 直连 proof 只在 **agentic 路径**
    （有 python_session 解题子进程）才适用。pure_llm 路径模型没有代码执行
    出口，这些开关在 orchestrator 里全树无消费者 ⇒ 标 N/A，不参与放行判定，
    改由判分时用 prove_pure_llm_path() 从结果+源码自动生成内生证据。
    """
    checks = []
    mode = args.mode

    def chk(name, ok, note, na=False, warn=False):
        checks.append({"item": name, "ok": bool(ok), "note": str(note),
                       "na": bool(na), "warn": bool(warn)})

    na_note = ("N/A：该开关的消费者全在 Go 侧（cmd/llmbench / cmd/runner / internal/airgap "
               "/ py_session.go），ctf_stepfun_orchestrator.py 无消费者；设了也不证明本路径任何性质")
    if mode == "agentic":
        chk("CTF_AIRGAP=1", os.environ.get("CTF_AIRGAP") == "1",
            "env CTF_AIRGAP=%r" % os.environ.get("CTF_AIRGAP"))
        chk("RUNNER_LLM_NO_FALLBACK=1", os.environ.get("RUNNER_LLM_NO_FALLBACK") == "1",
            "env RUNNER_LLM_NO_FALLBACK=%r" % os.environ.get("RUNNER_LLM_NO_FALLBACK"))
        chk("CTF_AGENT_INTERNAL_PRESOLVE=off",
            os.environ.get("CTF_AGENT_INTERNAL_PRESOLVE") == "off",
            "env CTF_AGENT_INTERNAL_PRESOLVE=%r" % os.environ.get("CTF_AGENT_INTERNAL_PRESOLVE"))
    else:
        chk("CTF_AIRGAP=1", True, na_note, na=True)
        chk("RUNNER_LLM_NO_FALLBACK=1", True, na_note, na=True)
        chk("CTF_AGENT_INTERNAL_PRESOLVE=off", True, na_note, na=True)

    proof = {}
    proof_ok = False
    if args.airgap_proof and os.path.isfile(args.airgap_proof):
        try:
            proof = json.load(open(args.airgap_proof, encoding="utf-8"))
            proof_ok = proof.get("ip_direct_blocked") is True and proof.get("af_unix_ok") is True
        except Exception as exc:
            proof = {"parse_error": str(exc)}
    if mode == "agentic":
        chk("airgap IP 直连证据", proof_ok,
            "需 ip_direct_blocked=true 且 af_unix_ok=true；实得 %s" % json.dumps(proof, ensure_ascii=False)[:180])
    else:
        chk("airgap IP 直连证据", True,
            "N/A：pure_llm 无解题子进程，seccomp 拦的是 Go 侧 python_session", na=True)
        proof_ok = True

    pool_ok, pool_sha = False, ""
    if os.path.isfile(POOL) and os.path.isfile(MANIFEST):
        mf = json.load(open(MANIFEST, encoding="utf-8"))
        pool_sha = _sha256(POOL)
        pool_ok = pool_sha == mf.get("out_sha256")
    chk("题池指纹与 manifest 一致", pool_ok, "actual=%s" % pool_sha[:16])

    rows = analyze(ROOT)
    scanned = any(r["file"] == os.path.basename(POOL) for r in rows)
    gate_ok = scanned and not violations(rows)
    chk("明文答案门禁覆盖新池且零违规", gate_ok,
        "扫到 %d 集，新池在扫描内=%s，violations=%d" % (len(rows), scanned, len(violations(rows))))

    temp_ok, temp_note = _fixed_temperature_proven()
    chk("随机源代码级固定", temp_ok, temp_note)

    if mode == "pure_llm":
        try:
            osrc = open(ORCH, encoding="utf-8", errors="replace").read()
        except Exception:
            osrc = ""
        shape_ok = (re.search(r"if\s+agentic\s+and\s+cfg\.get\(\s*[\"']supports_tools[\"']\s*\)", osrc) is not None
                    and re.search(r'["\']tool_calls["\']\s*:\s*0', osrc) is not None
                    and "run_python_tool(" in osrc)
        chk("源码：非 agentic 分支写死 tool_calls=0 且工具受门控", shape_ok,
            "orchestrator 源码正则形状（完整 AST 证明在判分时由 prove_pure_llm_path 补齐）")
        cmd_args = [x for x in args.command if x != "--"]
        cmd_ok = not cmd_args or ("--agentic" not in cmd_args and "--artifact-dir" not in cmd_args)
        chk("跑批命令未启用 --agentic / --artifact-dir", cmd_ok,
            "command=%r" % " ".join(cmd_args)[:150])

    # 题池入库状态：必须真的出现在 git 历史里（clone 下来的评委能拿到题）。
    # 只用 git ls-files 会把「git add 后未 commit」也算成入库 —— 那是第三个假绿。
    tracked = False
    try:
        r = subprocess.run(["git", "log", "-1", "--format=%H", "--",
                            os.path.relpath(POOL, ROOT).replace("\\", "/")],
                           cwd=ROOT, capture_output=True, text=True, timeout=10)
        tracked = r.returncode == 0 and bool(r.stdout.strip())
    except Exception:
        tracked = False
    chk("题池已纳入 git 历史（对外可引用性）", tracked,
        "in_history=%s；须显式 git add -f 且 commit，仅 staged 不算" % tracked,
        warn=True)
    pool_tracked = tracked

    ok = all(c["ok"] for c in checks if not c.get("na") and not c.get("warn"))
    ev = {
        "run_id": "capability_eval_%s" % datetime.datetime.now().strftime("%Y%m%dT%H%M%S"),
        "generated_by": "scripts/run_capability_eval.py (自动生成，非人工填写)",
        "generated_at": datetime.datetime.now().isoformat(timespec="seconds"),
        "eval_path": mode,
        "evidence_contract": [k for k, _ in evidence_keys({"eval_path": mode})],
        "temperature_fixed": temp_ok,
        "temperature_basis": temp_note,
        # pool_tracked_and_clean 由判据按下面三个子键重算，这里不自行发绿。
        "pool_fingerprint_ok": pool_ok,
        "pool_gate_ok": gate_ok,
        "pool_sha256": pool_sha,
        "pool_path": os.path.relpath(POOL, ROOT).replace("\\", "/"),
        "pool_in_version_control": pool_tracked,
        "caveats": [
            "pool_tracked_and_clean 只证明「指纹一致+门禁覆盖」，不等于题池入库；对外引用前须入库",
            "temperature 显式固定 ≠ 逐位可复现；provider 采样与版本仍会带来方差",
            "pure_llm 无工具出口 ≠ 无先验知识，模型记忆与公开 writeup 无法由本链路排除",
        ],
        "preflight_passed": ok,
        "_usage": "preflight_passed=false 时本证据只能用于「把历史批次判为不可归因」，禁止用于放行任何新跑批",
        "preflight_checks": checks,
    }
    if mode == "agentic":
        ev.update({
            "airgap_active": os.environ.get("CTF_AIRGAP") == "1",
            "airgap_zero_egress_proven": proof_ok,
            "airgap_scope": "解题子进程 python_session/skill/流式shell；LLM API 通道不在隔离范围（否则无法调用模型）",
            "airgap_proof": proof,
            "no_fallback_proven": os.environ.get("RUNNER_LLM_NO_FALLBACK") == "1",
            "channel_attribution_proven": os.environ.get("RUNNER_LLM_NO_FALLBACK") == "1",
            "channel_basis": "入口固定单一 --provider；Python orchestrator 不走 Go 侧 fallback 链",
            "presolve_off_proven": os.environ.get("CTF_AGENT_INTERNAL_PRESOLVE") == "off",
        })
    else:
        # 不写 agentic 键，避免证据里出现「零外网已证明=True」这种与路径无关的假信号。
        ev["not_applicable_switches"] = {
            "CTF_AIRGAP / RUNNER_LLM_NO_FALLBACK / CTF_AGENT_INTERNAL_PRESOLVE / IP直连proof":
                "消费者全在 Go 侧（cmd/llmbench/cmd/runner/internal/airgap/py_session.go），"
                "pure_llm 路径无解题子进程；改用 prove_pure_llm_path 的结果+源码内生证据",
        }
        ev["_pending"] = "结果级内生证据在 --adjudicate 时自动生成并覆盖本证据"
    return ok, checks, ev


def adjudicate(result_path, ev, out_path, mode="pure_llm", command=None, auto_prove=True):
    result = json.load(open(result_path, encoding="utf-8"))
    os.makedirs(WORKDIR, exist_ok=True)
    if mode == "pure_llm" and auto_prove:
        # 跑完再验：结果里只要出现任何 tool_calls != 0 / audit 非空，
        # 自动证明立刻把 no_model_egress_proven 置 False → 整批不可归因。
        frag, proof = prove_pure_llm_path(result, ORCH, command)
        merged = dict(ev)
        merged.update(frag)
        merged["caveats"] = list(ev.get("caveats", [])) + list(frag.get("caveats", []))
        ev = merged
        proof_path = os.path.join(WORKDIR, "%s.proof.json" % ev.get("run_id", "run"))
        with open(proof_path, "w", encoding="utf-8") as f:
            json.dump(proof, f, ensure_ascii=False, indent=2)
        ev["proof_report_path"] = os.path.relpath(proof_path, ROOT).replace("\\", "/")
    questions, _ = load_questions(POOL)
    leak_ids, leak_ok = load_leak_ids(LEAK)
    trained, trained_ok = load_trained_ids(ROOT)
    v = judge_run(result, questions, ev, leak_ids, leak_ok, trained, trained_ok)
    os.makedirs(os.path.dirname(out_path), exist_ok=True)
    with open(out_path, "w", encoding="utf-8") as f:
        json.dump(v, f, ensure_ascii=False, indent=2)
    return v


def pipeline_selftest():
    """链路自测：判据层 + 入口层都能在合规条件下给出正向结论。

    明确边界：这里用**合成数据**验证代码路径，不是评测结果，不产出可引用分数。
    """
    print("=== A. 判据层变异验证 ===")
    rc = selftest()
    print("=== B. 入口层正向链路（合成数据，非评测）===")
    questions, _ = load_questions(POOL)
    ids = [k for k, v in questions.items() if not v.get("requires_airgap")][:2]
    ev = {k: True for k, _ in PURE_LLM_EVIDENCE_KEYS}
    ev["eval_path"] = "pure_llm"
    ev["pool_sha256"] = "f" * 64
    ev["result_pool_sha256"] = "f" * 64
    ev.update({"pool_fingerprint_ok": True, "pool_gate_ok": True,
               "pool_in_version_control": True})
    result = {"details": [
        {"id": ids[0], "solved": True, "hit_mode": "exact", "latency": 10.0, "error": ""},
        {"id": ids[1], "solved": False, "hit_mode": "", "latency": 11.0, "error": ""},
    ]}
    leak, leak_ok = load_leak_ids(LEAK)
    trained, trained_ok = load_trained_ids(ROOT)
    v = judge_run(result, questions, ev, leak, leak_ok, trained, trained_ok)
    want = {"LLM_SOLVED": 1, "CLEAN_FAIL": 1, "NOT_ATTRIBUTABLE": 0}
    ok = (v["verdicts"] == want and v["capability_rate"] == 0.5 and v["claimable"])
    print("  %s 合成 2 题：verdicts=%s rate=%s claimable=%s（期望 %s / 0.5 / True）"
          % ("PASS" if ok else "FAIL", v["verdicts"], v["capability_rate"], v["claimable"], want))
    print("链路自测：%s" % ("PASS" if rc == 0 and ok else "FAIL"))
    return 0 if rc == 0 and ok else 1


def main():
    ap = argparse.ArgumentParser(description="合规能力评测入口（前置守卫+自动证据+判分）")
    ap.add_argument("--mode", choices=("pure_llm", "agentic"), default="pure_llm",
                    help="评测路径：pure_llm=无工具出口(默认)，agentic=有解题子进程需 seccomp/IP 直连证明")
    ap.add_argument("--preflight", action="store_true", help="只验前置并写 evidence.auto.json")
    ap.add_argument("--adjudicate", metavar="RESULT_JSON", help="用已有跑批结果判分")
    ap.add_argument("--run", action="store_true", help="前置通过后执行 -- 之后的跑批命令")
    ap.add_argument("--result", help="跑批输出路径（--run 时用于判分）")
    ap.add_argument("--airgap-proof", help="IP 直连探测结果 json")
    ap.add_argument("--legacy-evidence", help="历史批次自带证据（归因旧结果时用，不冒充新评测）")
    ap.add_argument("--out", default=os.path.join(WORKDIR, "verdict.auto.json"))
    ap.add_argument("--selftest", action="store_true",
                    help="链路自测：判据变异验证 + 合成合规批次的正向结论（不是评测结果）")
    ap.add_argument("command", nargs=argparse.REMAINDER, help="-- 之后的跑批命令")
    args = ap.parse_args()

    if args.selftest:
        return pipeline_selftest()

    ok, checks, ev = preflight(args)
    print("=== 前置守卫 ===")
    for c in checks:
        tag = ("N/A " if c.get("na") else
               "WARN" if c.get("warn") and not c["ok"] else
               "OK " if c["ok"] else "FAIL")
        print("  %s %-38s %s" % (tag, c["item"], c["note"]))
    os.makedirs(WORKDIR, exist_ok=True)
    with open(EVIDENCE_PATH, "w", encoding="utf-8") as f:
        json.dump(ev, f, ensure_ascii=False, indent=2)
    print("自动证据：%s" % os.path.relpath(EVIDENCE_PATH, ROOT))

    if args.preflight:
        if not ok:
            print("前置未通过 → 拒绝跑批（fail-closed）。缺项必须先补齐，不放行任何能力率。")
            return 2
        print("前置通过。可以执行 --run 或 --adjudicate。")
        return 0

    def report(v):
        print("=== 判分仲裁 ===")
        print("有效开跑 %d / 原始命中 %d / LLM_SOLVED %d / CLEAN_FAIL %d / NOT_ATTRIBUTABLE %d"
              % (v["effective_runs"], v["raw_solved_hits"], v["verdicts"]["LLM_SOLVED"],
                 v["verdicts"]["CLEAN_FAIL"], v["verdicts"]["NOT_ATTRIBUTABLE"]))
        print("可引用=%s 能力率=%s 逐题明细=%s"
              % (v["claimable"], v["capability_rate"], os.path.relpath(args.out, ROOT)))
        return 0 if v["claimable"] else 1

    # 历史批次归因：不受前置失败阻挡 —— 判据的价值正是把不合格批次判成不可归因。
    # 用自动证据（含 preflight_passed=false）或该批次自带的 legacy 证据，绝不冒充新评测。
    if args.adjudicate and not args.run:
        ev_use = ev
        if args.legacy_evidence:
            ev_use = json.load(open(args.legacy_evidence, encoding="utf-8"))
            ev_use["_mode"] = "legacy_attribution"
        else:
            ev_use["_mode"] = "auto_evidence(preflight_passed=%s)" % ok
        return report(adjudicate(args.adjudicate, ev_use, args.out, args.mode,
                                 auto_prove=not args.legacy_evidence))

    if not ok:
        print("前置未通过 → 拒绝跑批（fail-closed）。缺项必须先补齐，不放行任何能力率。")
        return 2
    if args.run:
        cmd = [x for x in args.command if x != "--"]
        if not cmd:
            print("--run 需要 -- 之后的命令", file=sys.stderr)
            return 2
        # 防洗白：把本批次实际使用的题池指纹写进证据，判分时由判据内部比对重算。
        bench = None
        for i, x in enumerate(cmd):
            if x == "--benchmark" and i + 1 < len(cmd):
                bench = cmd[i + 1]
                break
        bp = bench and (bench if os.path.isabs(bench) else os.path.join(ROOT, bench))
        ev["result_pool_sha256"] = _sha256(bp) if bp and os.path.isfile(bp) else None
        print("绑定结果题池：%s sha=%s" % (bench, str(ev["result_pool_sha256"])[:16]))
        print("执行跑批：%s" % " ".join(cmd))
        rc = subprocess.call(cmd, cwd=ROOT)
        print("跑批 rc=%d" % rc)
        if not args.result:
            return rc
        return report(adjudicate(args.result, ev, args.out, args.mode, cmd))
    return 0


if __name__ == "__main__":
    sys.exit(main())
