#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""纯 LLM 能力率归因判据 —— 唯一源（fail-closed）。

2026-11-05 补实：本文件此前**只存在于文档与记忆里**：
  - MEMORY_DETAIL.md 三处写「引用能力率前必跑 scripts/check_pure_llm_caliber.py」；
  - 规划_下一步_20261026.md 写「✅ 完成，4 项变异测试通过」；
  但 `git log --all`（含 --diff-filter=D）与全树 find 均为 0 命中 —— 一条指向
  不存在文件的强制纪律。本实现把该纪律变成可执行代码，不改写历史记载。

设计契约（三条，不可放宽）：
  1. **fail-closed**：每个证据项必须显式为 True；缺失 / None / False 一律不可归因。
     「没查到坏」不等于「证明是好的」——这是本项目判据被翻盘过多次的根因。
  2. **防空洞绿**：空跑、分母 0、白名单读不到、泄漏集读不到，全部判不可归因。
     不复刻 verify_evidence.py 曾出现的「0+0==0 也报绿」事故。
  3. **sha256 命中只是候选**：`solved=True` 不等于 LLM_SOLVED。必须同时满足
     零外网 + 无官方仓库可抄 + 题面无明文答案 + 有效开跑 + 通道归属 + 非 presolve
     + 非训练白名单，才允许计入分子。不可归因时 capability_rate 输出 **null**，
     绝不输出 0.0（0.0 会被读成「测出来是 0 分」，而真相是「没测出可引用分数」）。

用法：
  python scripts/check_pure_llm_caliber.py <result.json> \
      --questions <pool.json> --evidence <run_evidence.json> \
      --leak-set <audit_public_flag_leak 输出.txt> [--out verdict.json] [--json]
  python scripts/check_pure_llm_caliber.py --selftest

退出码：0 = 本批可归因（可引用分母）；1 = 不可归因（契约与历史记载一致）。

接线点（给持有跑批权的会话，本轮不单方改他人 WIP 文件）：
  在 ctf_stepfun_orchestrator.py 的 solve_one() 返回体里加 claim_ok 三元组，
  并调用本模块的 judge_one(detail, prob, ctx)；命中但 verdict != LLM_SOLVED 时
  写 NOT_ATTRIBUTABLE 而不是 solved。判据在报告层，不改 verify_flag() 的 sha256 仲裁。
"""
from __future__ import annotations

import argparse
import ast
import hashlib
import json
import os
import re
import sys

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
try:
    from check_benchmark_plaintext_answer import answer_is_in_statement
    _CHECKER_ERR = None
except Exception as exc:  # pragma: no cover - 缺依赖必须让判据 fail-closed
    answer_is_in_statement = None
    _CHECKER_ERR = str(exc)

LLM_SOLVED = "LLM_SOLVED"
CLEAN_FAIL = "CLEAN_FAIL"
NOT_ATTRIBUTABLE = "NOT_ATTRIBUTABLE"

# 证据项：键 -> 人类可读标签。全部必须显式 True。
#
# 2026-11-05 §13 路径感知修正：此前把 Go runner 的 seccomp 开关
# (CTF_AIRGAP / RUNNER_LLM_NO_FALLBACK / CTF_AGENT_INTERNAL_PRESOLVE)
# 无差别套到 Python orchestrator 的 pure_llm 路径上，但全树 grep 证实
# CTF_AIRGAP 的消费者只在 cmd/llmbench、cmd/runner、internal/airgap、
# py_session.go 等 Go 侧；ctf_stepfun_orchestrator.py 一个都没有。
# pure_llm 路径里 solve_one() 非 agentic 分支写死 tool_calls=0，
# 模型没有代码执行/网络出口 ⇒ 威胁不是「联网抄 flag」，而是
# 「模型记忆 / 题面明文答案 / 通道归属伪造」。
# 因此两条路径各自的证据契约不同；eval_path 缺失时取最严的 agentic 契约
# （fail-closed：不声明路径就按最严格判）。
AGENTIC_EVIDENCE_KEYS = (
    ("airgap_active", "隔离机制已启用"),
    ("airgap_zero_egress_proven", "该题执行期零外网访问已留痕"),
    ("no_fallback_proven", "已禁备用通道降级，归属不被冒充"),
    ("channel_attribution_proven", "实际执行通道与报告标注一致"),
    ("presolve_off_proven", "确定性预解已关闭"),
    ("temperature_fixed", "请求体显式固定随机源（代码级可证）"),
    ("pool_tracked_and_clean", "题池入库且经质量门禁背书"),
    ("result_pool_matches_proven", "结果实际所用题池与证据指纹一致"),
)

PURE_LLM_EVIDENCE_KEYS = (
    ("no_model_egress_proven", "模型无代码执行/网络出口（结果+源码双证）"),
    ("single_channel_proven", "单一 provider 且源码无自动降级链"),
    ("channel_attribution_proven", "实际执行通道与报告标注一致"),
    ("no_presolve_proven", "判分只读 sha256，该路径无 presolve"),
    ("temperature_fixed", "请求体显式固定随机源（代码级可证）"),
    ("pool_tracked_and_clean", "题池入库且经质量门禁背书"),
    # §13 防洗白：旧脏池批次不能靠「拿新干净池重新归因」变成可引用。
    # 该键由 judge_run 内部按指纹重算并覆盖，不接受 evidence 里人工填的 True。
    ("result_pool_matches_proven", "结果实际所用题池与证据指纹一致"),
)

# 兼容既有 import：未声明路径时按最严契约判。
EVIDENCE_KEYS = AGENTIC_EVIDENCE_KEYS


def evidence_keys(evidence):
    """按 eval_path 选契约；未知/缺失一律取最严的 agentic 契约（fail-closed）。"""
    path = (evidence or {}).get("eval_path")
    if path == "pure_llm":
        return PURE_LLM_EVIDENCE_KEYS
    return AGENTIC_EVIDENCE_KEYS

# 泄漏集 ID 的宽松匹配：覆盖 ext_gctf2021_* / real_* 等形态。
_LEAK_ID_RE = re.compile(r"\b(?:ext|real)_[A-Za-z0-9_-]{3,}\b")
_ANTIFRAUD_REL = os.path.join("CTF-Agent_融合", "ctf_agent", "scripts", "_antifraud.py")


def _load_json(path):
    with open(path, encoding="utf-8", errors="replace") as f:
        return json.load(f)


def load_leak_ids(path):
    """从 audit_public_flag_leak.py 的文本输出解析可下载官方 flag 的题 ID。

    返回 (set, available)。空集 / 文件缺失一律 available=False —— 否则
    「没解析到泄漏题」会被误当成「没有泄漏题」，正是 fail-closed 要防的形态。
    """
    if not path or not os.path.isfile(path):
        return set(), False
    text = open(path, encoding="utf-8", errors="replace").read()
    # 权威行优先：审计脚本的 "  LEAK: <id> -> <path>" 才是已确认命中；
    # 表格区可能含「疑似但未确认」的题（实测 24 vs 23），混进来会扩大封杀面。
    ids = set(re.findall(r"LEAK:\s*(\S+)\s*->", text))
    if not ids:  # 回退：无 LEAK: 行时按表格首列解析
        ids = set(_LEAK_ID_RE.findall(text))
        ids = {i for i in ids if "benchmark" not in i and "summary" not in i}
    return ids, len(ids) > 0


def load_trained_ids(repo_root):
    """AST 解析反注水白名单，不 import 目标模块（避免其模块级副作用）。

    AUTHORIZED_KPI_SOLVES = frozenset(BASE | set(PROMOTION_EVIDENCE.keys()))
    直接 literal_eval 不了，故分别取两个常量的字面量再合并。
    """
    path = os.path.join(repo_root, _ANTIFRAUD_REL)
    if not os.path.isfile(path):
        return set(), False
    try:
        tree = ast.parse(open(path, encoding="utf-8", errors="replace").read())
    except Exception:
        return set(), False

    def literal_of(varname):
        for node in tree.body:
            if not isinstance(node, ast.Assign):
                continue
            if not any(isinstance(t, ast.Name) and t.id == varname for t in node.targets):
                continue
            val = node.value
            if isinstance(val, ast.Call) and val.args:  # frozenset({...}) / set([...])
                val = val.args[0]
            try:
                obj = ast.literal_eval(val)
            except Exception:
                return None
            if isinstance(obj, dict):
                return set(obj.keys())
            if isinstance(obj, (set, frozenset, list, tuple)):
                return set(obj)
            return None
        return None

    base = literal_of("BASE_AUTHORIZED_KPI_SOLVES")
    promo = literal_of("PROMOTION_EVIDENCE")
    if base is None or promo is None:
        return set(), False
    return set(base) | set(promo), True


def load_questions(path):
    """题池 problems 可能是 dict（key->题）或 list，统一成 id->题。"""
    if not path or not os.path.isfile(path):
        return {}, False
    try:
        d = _load_json(path)
    except Exception:
        return {}, False
    probs = d.get("problems", d) if isinstance(d, dict) else d
    if isinstance(probs, dict):
        out = {}
        for k, v in probs.items():
            if isinstance(v, dict):
                out[str(k)] = v
                out.setdefault(str(v.get("id", k)), v)
        return out, len(out) > 0
    if isinstance(probs, list):
        out = {str(v.get("id", i)): v for i, v in enumerate(probs) if isinstance(v, dict)}
        return out, len(out) > 0
    return {}, False


#: 调用层面的失败关键字。命中即说明「模型没被真正问到」，不是答错。
_API_FAIL_MARKS = (
    "no available channel", "cooldown", "quota", "403", "429",
    # 2026-11-08 实证：402 是余额不足，不是限流。旧表里没有它，于是
    # 「全批一次调用都没成功」被判成 CLEAN_FAIL、rate=0.0、claimable=True。
    "402", "payment required", "insufficient", "余额不足", "额度",
    "401", "unauthorized", "invalid api key", "authentication",
)


def api_call_failed(detail):
    """这一次调用有没有**成功过任何一轮**模型调用。单一实现，两处调用方共用。

    只认**正面证据**，字段缺失一律返回 False（= 无法判定，不当成"失败"）。
    理由：`docs/evidence/private_pool_v1_20261107` 与 `private_pool_v2_20261107`
    的结果文件整份没有 `llm_rounds`；若把"缺字段"读成"没有成功轮次"，88.3% 那批
    会被自己的判据判废。缺字段是**不知道**，不是**否定**。

    返回 True 的三种情形，都要求证据在设计上不可能由"答错"产生：
      ① 生产侧直接声明 `all_rounds_api_failed=True`；
      ② `llm_rounds` 非空，且**每一轮**的 finish_reason 都是 error/timeout；
      ③ **没有**轮次明细时，`api_error_first` 命中调用层失败关键字。

    🔴 ③ 必须限定在"没有轮次明细"。有明细就以结构为准 —— 否则「第 2 轮 402、
    第 3 轮成功」会被文本判成调用失败，把一次真实尝试剔出分母。这个分叉我第一版
    就写错了（`analyze_retry_recoverability.is_api_failed` 无条件读文本），
    自测里那条「有一轮成功的行不算调用失败」当场转红才发现。
    """
    if detail.get("all_rounds_api_failed") is True:
        return True
    rounds = detail.get("llm_rounds")
    if isinstance(rounds, list) and rounds:
        good = [r for r in rounds if isinstance(r, dict)
                and str(r.get("finish_reason") or "") not in ("error", "timeout", "")]
        return not good
    first = str(detail.get("api_error_first") or "")
    if first and any(k in first.lower() for k in _API_FAIL_MARKS):
        n_err = detail.get("api_error_rounds")
        return isinstance(n_err, int) and n_err > 0
    return False


# 兼容旧名（本文件内多处以 `_rounds_all_failed` 引用）。
def _rounds_all_failed(detail):
    return api_call_failed(detail)


def _effective(detail):
    """有效开跑：有模型响应、且不是一次都没问到。

    判据（全部满足才算分母）：
      · `latency`/`seconds` > 0（0 秒空跑不算）
      · `error` 不是调用层失败（限额/鉴权/限流，见 `_API_FAIL_MARKS`）
      · 不是 `api_call_failed()`（全轮 error/timeout，或只有文本证据）
    """
    if not isinstance(detail, dict):
        return False
    secs = detail.get("latency", detail.get("seconds"))
    if not isinstance(secs, (int, float)) or secs <= 0:
        return False
    err = str(detail.get("error") or "")
    if err and any(k in err.lower() for k in _API_FAIL_MARKS):
        return False
    # 生产侧（ctf_stepfun_orchestrator）过去把 `error` 无条件写成 ""：
    # 全部轮次都在 API 层失败时，`error` 仍是空串，失败只留在
    # `llm_rounds[].error` / `api_error_first` 里 ⇒ 上面那行永远不命中。
    return not api_call_failed(detail)


def judge_one(detail, prob, ctx):
    """纯函数：返回 (verdict, reasons)。无 IO，便于单测与变异验证。"""
    reasons = []
    pid = str(detail.get("id", ""))
    solved = bool(detail.get("solved"))

    if not _effective(detail):
        # 区分两种"没跑成"：0 秒空跑 vs 调用层失败。后者的 rate 若被算进分母，
        # 就是把「余额不足」当成「模型不会」—— 一句 rate=0.0 里藏着一个假红。
        reasons.append("api_call_failed_no_successful_round" if api_call_failed(detail)
                       else "ineffective_run")
    for key, label in ctx.get("evidence_keys") or AGENTIC_EVIDENCE_KEYS:
        if ctx["evidence"].get(key) is not True:
            reasons.append("missing_evidence:%s(%s)" % (key, label))
    if not ctx.get("leak_set_available"):
        reasons.append("leak_set_unavailable")
    elif pid in ctx["leak_ids"]:
        reasons.append("official_flag_downloadable")
    if not ctx.get("trained_ids_available"):
        reasons.append("trained_whitelist_unavailable")
    elif pid in ctx["trained_ids"]:
        reasons.append("authorized_trained_solve")
    if prob is None:
        reasons.append("question_not_found")
    elif answer_is_in_statement is None:
        reasons.append("plaintext_checker_unavailable:%s" % _CHECKER_ERR)
    else:
        try:
            plaintext, _ = answer_is_in_statement(prob)
        except Exception as exc:
            plaintext, reasons = True, reasons + ["plaintext_check_failed:%s" % exc]
        if plaintext:
            reasons.append("answer_plaintext_in_statement")
    if str(detail.get("hit_mode") or "") == "presolve":
        reasons.append("presolve_hit")

    if reasons:
        return NOT_ATTRIBUTABLE, reasons
    return (LLM_SOLVED if solved else CLEAN_FAIL), []


def judge_run(result, questions, evidence, leak_ids, leak_available,
              trained_ids, trained_available):
    """跑批级仲裁：产出可引用/不可引用的明确结论。"""
    details = result.get("details") or []
    # 防洗白：题池绑定键一律内部重算，忽略证据文件里人工填写的值。
    ev_work = dict(evidence or {})
    used_sha, claimed_sha = ev_work.get("result_pool_sha256"), ev_work.get("pool_sha256")
    ev_work["result_pool_matches_proven"] = bool(
        isinstance(used_sha, str) and isinstance(claimed_sha, str)
        and used_sha and used_sha == claimed_sha)
    # 题池「可引用性」同样由代码重算，不接受证据里人工填的 True：
    # 指纹一致 + 质量门禁零违规 + 版本控制可查，三者缺一即不可对外引用。
    # 只满足前两条时文件仍在 .gitignore 里，评委拿不到题 ⇒ 不能发绿。
    ev_work["pool_tracked_and_clean"] = bool(
        ev_work.get("pool_fingerprint_ok") is True
        and ev_work.get("pool_gate_ok") is True
        and ev_work.get("pool_in_version_control") is True)
    evidence = ev_work
    keys = evidence_keys(evidence)
    ctx = {
        "evidence": evidence,
        "evidence_keys": keys,
        "leak_ids": leak_ids or set(),
        "leak_set_available": bool(leak_available),
        "trained_ids": trained_ids or set(),
        "trained_ids_available": bool(trained_available),
    }
    verdicts = {LLM_SOLVED: 0, CLEAN_FAIL: 0, NOT_ATTRIBUTABLE: 0}
    rows = []
    for d in details:
        pid = str(d.get("id", ""))
        v, why = judge_one(d, questions.get(pid), ctx)
        verdicts[v] += 1
        rows.append({"id": pid, "solved_raw": bool(d.get("solved")),
                     "verdict": v, "reasons": why})

    # 全局证据齐备 + 分母有效，才允许给出能力率。缺一即 null。
    all_evidence = all(evidence.get(k) is True for k, _ in keys)
    effective = sum(1 for d in details if _effective(d))
    # 🔴 2026-11-08：全批一次调用都没成功的批次不得给读数。
    # 实测：v2 池 2 题在 stepfun / tokenrhythm 上都返回 HTTP 402（余额不足），
    # 每题的 `error` 都被生产者写成 ""，失败只留在 `api_error_first`。
    # 旧判据把它们判成 CLEAN_FAIL ⇒ `rate=0.0 / claimable=True / blocking=[]`。
    # 这不是"保守的坏消息"，是把一次没问出口的调用印成 0% 解出率 ——
    # 与「换池洗白」同源，只是方向相反：分母被塞进了从未发生的尝试。
    api_failed = [d for d in details if api_call_failed(d)]
    # 分母只含「可归因」题：NOT_ATTRIBUTABLE 的题必须剔除，不能混进能力率。
    attributable = verdicts[LLM_SOLVED] + verdicts[CLEAN_FAIL]
    claimable = bool(details) and effective > 0 and attributable > 0 and all_evidence \
        and leak_available and trained_available and answer_is_in_statement is not None \
        and len(api_failed) < len(details)

    blocking = []
    for k, label in keys:
        if evidence.get(k) is not True:
            blocking.append("%s: 未证明" % label)
    if not leak_available:
        blocking.append("官方 flag 可下载题集未加载")
    if not trained_available:
        blocking.append("训练白名单未加载")
    if not details or effective == 0:
        blocking.append("有效分母为 0（空跑批次）")
    if details and len(api_failed) == len(details):
        blocking.append("全批 LLM 调用均在 API 层失败（%d/%d 题），"
                        "本次不产生能力读数" % (len(api_failed), len(details)))

    hits = [r for r in rows if r["solved_raw"]]
    # 分母被"调用失败"缩小时必须自己说出来。部分失败仍是合法读数（那些题确实没被问到），
    # 但如果只写在 effective_runs 里，读的人得自己做减法才知道分母为什么变小。
    notes = []
    if details and 0 < len(api_failed) < len(details):
        notes.append("分母提示：%d/%d 题因调用层失败（余额/限流/鉴权）被剔出，"
                     "本文 rate 的分母是 %d" % (len(api_failed), len(details), attributable))
    return {
        "run_id": evidence.get("run_id") or result.get("summary", {}).get("slice") or "unknown",
        "contract": "fail-closed / sha256命中仅为候选 / 不可归因时rate为null",
        "eval_path": (evidence or {}).get("eval_path") or "agentic(未声明路径，按最严)",
        "evidence_contract": [k for k, _ in keys],
        "total": len(details),
        "effective_runs": effective,
        # 调用层失败的题数：可见即可审计。为 0 才说明这批题"真的被问过"。
        "api_call_failed_runs": len(api_failed),
        "verdicts": verdicts,
        "raw_solved_hits": len(hits),
        "hits": hits,
        "claimable": claimable,
        "claimable_denominator": attributable if claimable else 0,
        "attributable_runs": attributable,
        "excluded_not_attributable": verdicts[NOT_ATTRIBUTABLE],
        "capability_rate": (round(verdicts[LLM_SOLVED] / attributable, 6)
                            if claimable and attributable else None),
        "blocking_reasons": blocking,
        "notes": notes,
        "evidence": evidence,
        "rows": rows,
    }


def prove_pure_llm_path(result, orch_path, run_command=None):
    """自动生成 pure_llm 路径的内生证据（不读 Go 侧 env，不接受人工填写的布尔）。

    为什么必须路径内生：CTF_AIRGAP / RUNNER_LLM_NO_FALLBACK /
    CTF_AGENT_INTERNAL_PRESOLVE 全是 Go runner 或 CTF-Agent 侧开关，
    ctf_stepfun_orchestrator.py 全树无消费者；设了它们不能证明这条路径的任何性质。
    本函数改从「结果文件的实际形态 + orchestrator 源码结构」取证。

    返回 (evidence_fragment, proof_report)。fragment 只含本函数能证明的键；
    temperature_fixed / pool_tracked_and_clean 由评测入口另行补齐。
    """
    summary = result.get("summary") or {}
    details = result.get("details") or []
    checks = []

    def add(name, ok, basis):
        checks.append({"check": name, "ok": bool(ok), "basis": str(basis)[:240]})

    add("summary.agentic is False", summary.get("agentic") is False,
        "summary.agentic=%r" % summary.get("agentic"))
    add("summary.tool_calls_total == 0", summary.get("tool_calls_total") == 0,
        "tool_calls_total=%r" % summary.get("tool_calls_total"))
    bad = [str(d.get("id")) for d in details if d.get("tool_calls") != 0]
    add("每题 tool_calls 显式为 0", bool(details) and not bad, "异常题=%r" % bad[:5])
    bad_audit = [str(d.get("id")) for d in details if d.get("audit")]
    add("每题 audit 留痕为空", not bad_audit, "有审计留痕题=%r" % bad_audit[:5])
    if run_command:
        add("跑批命令未启用 --agentic / 未挂工件目录",
            "--agentic" not in run_command and "--artifact-dir" not in run_command,
            "command=%r" % " ".join(run_command)[:160])

    code = {}
    try:
        src = open(orch_path, encoding="utf-8", errors="replace").read()
        tree = ast.parse(src)

        def fn(name):
            return next((n for n in tree.body
                         if isinstance(n, ast.FunctionDef) and n.name == name), None)

        solve, verify, agentic = fn("solve_one"), fn("verify_flag"), fn("call_llm_agentic")

        def calls_in(node, fname):
            if node is None:
                return []
            return [n for n in ast.walk(node) if isinstance(n, ast.Call)
                    and isinstance(n.func, ast.Name) and n.func.id == fname]

        in_solve = len(calls_in(solve, "run_python_tool"))
        in_agentic = len(calls_in(agentic, "run_python_tool"))
        zero_written = re.search(r'["\']tool_calls["\']\s*:\s*0', src) is not None
        gated = re.search(r"if\s+agentic\s+and\s+cfg\.get\(\s*[\"']supports_tools[\"']\s*\)", src) is not None
        loadkey_calls = len(calls_in(tree, "load_key"))
        resolve_calls = [n for n in ast.walk(tree) if isinstance(n, ast.Call)
                         and ((isinstance(n.func, ast.Name) and n.func.id == "Resolve")
                              or (isinstance(n.func, ast.Attribute) and n.func.attr == "Resolve"))]
        verify_src = ast.get_source_segment(src, verify) or "" if verify else ""
        presolve_in_verify = "presolve" in verify_src.lower()
        presolve_hits = [str(d.get("id")) for d in details
                         if str(d.get("hit_mode") or "") == "presolve"]

        code = {
            "functions_present": bool(solve and verify and agentic),
            "run_python_tool_callers": {"solve_one": in_solve, "call_llm_agentic": in_agentic},
            "non_agentic_writes_tool_calls_0": zero_written,
            "agentic_gate_present": gated,
            "load_key_call_sites": loadkey_calls,
            "resolve_fallback_call_sites": len(resolve_calls),
            "presolve_in_verify_flag": presolve_in_verify,
            "presolve_hits_in_result": presolve_hits[:5],
        }
    except Exception as exc:
        code = {"error": "%s: %s" % (type(exc).__name__, exc)}

    egress_src_ok = (code.get("functions_present") is True
                     and code.get("run_python_tool_callers", {}).get("solve_one") == 0
                     and code.get("run_python_tool_callers", {}).get("call_llm_agentic", 0) > 0
                     and code.get("non_agentic_writes_tool_calls_0") is True
                     and code.get("agentic_gate_present") is True)
    add("源码：工具执行仅在 agentic 分支可达", egress_src_ok, json.dumps(code, ensure_ascii=False))

    single_ok = (code.get("load_key_call_sites") == 1
                 and code.get("resolve_fallback_call_sites") == 0
                 and isinstance(summary.get("provider"), str) and bool(summary.get("provider")))
    add("源码：单一 provider 且无自动降级链", single_ok,
        "provider=%r load_key=%r Resolve=%r" % (summary.get("provider"),
        code.get("load_key_call_sites"), code.get("resolve_fallback_call_sites")))

    no_presolve_ok = (code.get("presolve_in_verify_flag") is False
                      and not code.get("presolve_hits_in_result"))
    add("判分不含 presolve 路径", no_presolve_ok,
        "verify_flag含presolve=%r 结果presolve命中=%r" % (code.get("presolve_in_verify_flag"),
        code.get("presolve_hits_in_result")))

    egress_ok = all(c["ok"] for c in checks[:4]) and egress_src_ok
    cmd_ok = all(c["ok"] for c in checks if c["check"].startswith("跑批命令"))
    fragment = {
        "eval_path": "pure_llm",
        "no_model_egress_proven": bool(egress_ok and (cmd_ok or not run_command)),
        "single_channel_proven": bool(single_ok),
        "channel_attribution_proven": bool(
            single_ok and isinstance(summary.get("provider"), str)
            and (not run_command or "--provider %s" % summary.get("provider") in " ".join(run_command))),
        "no_presolve_proven": bool(no_presolve_ok),
        "caveats": [
            "pure_llm 路径排除不了模型记忆与公开 writeup：无工具出口 ≠ 无先验知识",
            "channel_attribution 为代码级单通道证明，非网络层抓包；不覆盖 DNS/代理劫持",
            "airgap/seccomp 属 Go runner 路径，本路径 N/A；混用会让证据自相矛盾",
        ],
    }
    report = {"generated_by": "prove_pure_llm_path (result+AST，无人工布尔)",
              "checks": checks, "code_structure": code,
              "verdict": {k: v for k, v in fragment.items() if isinstance(v, bool)}}
    return fragment, report


def selftest():
    """变异验证：证明判据不是「永远报红」的摆设，且每道闸门真的会翻转结论。"""
    ok_evidence = {k: True for k, _ in EVIDENCE_KEYS}
    ok_evidence["pool_sha256"] = "f" * 64
    ok_evidence["result_pool_sha256"] = "f" * 64
    ok_evidence.update({"pool_fingerprint_ok": True, "pool_gate_ok": True,
                        "pool_in_version_control": True})
    plain_prob = {"id": "t1", "description": "ordinary task",
                  "flag_sha256": hashlib.sha256(b"flag{answer}").hexdigest()}
    def ctx(**kw):
        base = {"evidence": dict(ok_evidence), "leak_ids": set(),
                "leak_set_available": True, "trained_ids": set(),
                "trained_ids_available": True}
        base.update(kw)
        base["evidence_keys"] = evidence_keys(base["evidence"])
        return base
    hit = {"id": "t1", "solved": True, "hit_mode": "exact", "latency": 27.5, "error": ""}
    miss = {"id": "t1", "solved": False, "hit_mode": "", "latency": 13.0, "error": ""}

    cases = [
        ("全条件齐备+命中 => LLM_SOLVED",
         judge_one(hit, plain_prob, ctx())[0], LLM_SOLVED),
        ("缺 airgap 证据 => 命中也不可归因",
         judge_one(hit, plain_prob, ctx(evidence={**ok_evidence, "airgap_active": False}))[0],
         NOT_ATTRIBUTABLE),
        ("全条件齐备+未命中 => CLEAN_FAIL",
         judge_one(miss, plain_prob, ctx())[0], CLEAN_FAIL),
        ("题在官方 flag 泄漏集 => 不可归因",
         judge_one(hit, plain_prob, ctx(leak_ids={"t1"}))[0], NOT_ATTRIBUTABLE),
        ("题面含真答案明文 => 不可归因",
         judge_one(hit, {**plain_prob, "description": "the answer is flag{answer} here"}, ctx())[0],
         NOT_ATTRIBUTABLE),
        ("0 秒空跑 => 不可归因",
         judge_one({**hit, "latency": 0}, plain_prob, ctx())[0], NOT_ATTRIBUTABLE),
        ("泄漏集不可用 => fail-closed",
         judge_one(hit, plain_prob, ctx(leak_set_available=False))[0], NOT_ATTRIBUTABLE),
    ]
    # 跑批级：防空洞绿
    empty = judge_run({"details": []}, {"t1": plain_prob}, ok_evidence, {"x"}, True, set(), True)
    cases.append(("空批次不可引用（防空洞绿）", empty["claimable"], False))
    good = judge_run({"details": [hit, miss]}, {"t1": plain_prob}, ok_evidence,
                     {"x"}, True, set(), True)
    cases.append(("合规批次可引用且 rate=0.5", good["capability_rate"], 0.5))

    # §13 路径感知契约：pure_llm 用内生证据，且缺项仍必须翻转结论。
    pl_ok = {k: True for k, _ in PURE_LLM_EVIDENCE_KEYS}
    pl_ok["eval_path"] = "pure_llm"
    pl_ok["pool_sha256"] = "f" * 64
    pl_ok["result_pool_sha256"] = "f" * 64
    pl_ok.update({"pool_fingerprint_ok": True, "pool_gate_ok": True,
                  "pool_in_version_control": True})
    cases.append(("pure_llm 契约齐备+命中 => LLM_SOLVED",
                  judge_one(hit, plain_prob, ctx(evidence=pl_ok))[0], LLM_SOLVED))
    cases.append(("pure_llm 缺无出口证明 => 不可归因",
                  judge_one(hit, plain_prob, ctx(evidence={**pl_ok, "no_model_egress_proven": False}))[0],
                  NOT_ATTRIBUTABLE))
    cases.append(("未声明 eval_path => 按最严契约(pure_llm 证据缺 airgap)不可归因",
                  judge_one(hit, plain_prob, ctx(evidence={k: True for k, _ in PURE_LLM_EVIDENCE_KEYS}))[0],
                  NOT_ATTRIBUTABLE))
    pl_run = judge_run({"details": [hit, miss]}, {"t1": plain_prob}, pl_ok,
                       {"x"}, True, set(), True)
    cases.append(("pure_llm 合规批次可引用且 rate=0.5", pl_run["capability_rate"], 0.5))
    # 防洗白：旧脏池批次换用新干净池重新归因，指纹不一致必须不可引用；
    # 且该键由代码重算，人工在证据里填 True 也无效。
    dirty = {**pl_ok, "result_pool_sha256": "a" * 64}
    cases.append(("结果池指纹不一致 => 旧批次不可被新池洗白",
                  judge_run({"details": [hit, miss]}, {"t1": plain_prob}, dirty,
                            {"x"}, True, set(), True)["claimable"], False))
    cases.append(("人工把绑定键填 True 也无效（代码重算）",
                  judge_run({"details": [hit, miss]}, {"t1": plain_prob},
                            {**dirty, "result_pool_matches_proven": True},
                            {"x"}, True, set(), True)["claimable"], False))
    t2_hit = {"id": "t2", "solved": True, "hit_mode": "exact", "latency": 9.0, "error": ""}
    mixed = judge_run({"details": [hit, miss, t2_hit]},
                      {"t1": plain_prob, "t2": {**plain_prob, "id": "t2"}},
                      pl_ok, {"t2"}, True, set(), True)
    cases.append(("不可归因题剔除出分母（rate 仍 0.5）", mixed["capability_rate"], 0.5))
    cases.append(("被剔除题明确计数", mixed["excluded_not_attributable"], 1))
    cases.append(("题池未入库 => 不可引用（评委拿不到题）",
                  judge_run({"details": [hit, miss]}, {"t1": plain_prob},
                            {**pl_ok, "pool_in_version_control": False},
                            {"x"}, True, set(), True)["claimable"], False))
    cases.append(("人工把 pool_tracked_and_clean 填 True 也无效",
                  judge_run({"details": [hit, miss]}, {"t1": plain_prob},
                            {**pl_ok, "pool_in_version_control": False,
                             "pool_tracked_and_clean": True},
                            {"x"}, True, set(), True)["claimable"], False))

    # ── 调用层失败不得伪装成 0% 解出率（2026-11-08 实证：全批 HTTP 402）──
    def api_dead(pid, lat=3.99, msg="HTTP 402 Payment Required: 账户余额不足，请充值后重试。"):
        """真实字段形状：`error` 为空串，失败只在 llm_rounds / api_error_first 里。"""
        return {"id": pid, "solved": False, "latency": lat, "error": "",
                "llm_rounds": [{"finish_reason": "error", "error": msg,
                                "completion_tokens": 0, "prompt_tokens": 0,
                                "content_chars": 0, "tool_calls": 0}],
                "api_error_rounds": 1, "api_error_first": msg, "hit_mode": "",
                "tool_calls": []}

    dead = api_dead("t1")
    cases.append(("全轮 API 失败 => 该题不算有效开跑", _effective(dead), False))
    cases.append(("全轮 API 失败 => 不可归因（不是 CLEAN_FAIL）",
                  judge_one(dead, plain_prob, ctx(evidence=pl_ok))[0], NOT_ATTRIBUTABLE))
    dead_run = judge_run({"details": [dead, {**dead, "id": "t2"}]},
                         {"t1": plain_prob, "t2": {**plain_prob, "id": "t2"}},
                         pl_ok, {"x"}, True, set(), True)
    cases.append(("全批 API 失败 => rate 为 null 而非 0.0", dead_run["capability_rate"], None))
    cases.append(("全批 API 失败 => 不可引用", dead_run["claimable"], False))
    cases.append(("全批 API 失败 => 明确写进阻断理由",
                  any("API 层失败" in b for b in dead_run["blocking_reasons"]), True))
    # 反向（防洗白方向）：只有 1/3 题调用失败时，其余 2 题仍要出率，
    # 且失败那题不计入分母 —— 否则"剔除"会变成把分母做小的工具。
    partial = judge_run({"details": [dead, hit, miss]},
                        {"t1": plain_prob}, pl_ok, {"x"}, True, set(), True)
    cases.append(("1/3 题调用失败 => 仍出率且分母=2", partial["claimable_denominator"], 2))
    cases.append(("1/3 题调用失败 => rate 仍是 0.5", partial["capability_rate"], 0.5))
    cases.append(("失败题数可见", partial["api_call_failed_runs"], 1))
    cases.append(("分母被调用失败缩小 => 必须自己说明",
                  any("分母提示" in n for n in partial["notes"]), True))
    # 历史兼容：v1/v2 私池结果文件**整份没有** llm_rounds ⇒ 不得因此判废。
    legacy = {"id": "t1", "solved": True, "latency": 8.9, "error": ""}
    cases.append(("缺 llm_rounds 的历史文件仍是有效开跑（缺失≠否定）",
                  _effective(legacy), True))
    cases.append(("缺 llm_rounds 的历史命中仍是 LLM_SOLVED",
                  judge_one(legacy, plain_prob, ctx(evidence=pl_ok))[0], LLM_SOLVED))
    # 轮次中有一轮成功 ⇒ 有效（哪怕其余轮次 402）
    mixed_rounds = {"id": "t1", "solved": False, "latency": 30.0, "error": "",
                    "llm_rounds": [{"finish_reason": "error", "error": "HTTP 402"},
                                   {"finish_reason": "stop", "content_chars": 10}],
                    "api_error_rounds": 1, "api_error_first": "HTTP 402"}
    cases.append(("有一轮成功 ⇒ 有效开跑", _effective(mixed_rounds), True))
    # 402 文本变了也不该漏：结构判据不依赖措辞
    cases.append(("换代措辞('payment required' 之外的 402) 仍被结构判据抓到",
                  _effective(api_dead("t1", msg="HTTP 402 账单未结清")), False))

    failed = 0
    for name, got, want in cases:
        ok = got == want
        print("  %s %-42s got=%r want=%r" % ("PASS" if ok else "FAIL", name, got, want))
        failed += 0 if ok else 1
    print("变异验证：%d/%d 通过" % (len(cases) - failed, len(cases)))
    return 0 if failed == 0 else 1


def main():
    ap = argparse.ArgumentParser(description="纯 LLM 能力率归因判据（fail-closed）")
    ap.add_argument("result", nargs="?", help="跑批 result.json")
    ap.add_argument("--questions", help="题池 json（result 里题目来源）")
    ap.add_argument("--evidence", help="运行证据 json（显式声明各开关是否已被证明）")
    ap.add_argument("--leak-set", help="audit_public_flag_leak.py 文本输出，或 ID 列表 json")
    ap.add_argument("--out", help="写 verdict.json")
    ap.add_argument("--json", action="store_true", help="stdout 输出汇总 JSON")
    ap.add_argument("--selftest", action="store_true", help="跑变异验证并退出")
    args = ap.parse_args()

    if args.selftest:
        return selftest()
    if not args.result or not args.evidence:
        print("需要 <result.json> 与 --evidence；--selftest 可单独运行", file=sys.stderr)
        return 2

    repo_root = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
    try:
        result = _load_json(args.result)
    except Exception as exc:
        print("result.json 解析失败: %s" % exc, file=sys.stderr)
        return 2
    evidence = _load_json(args.evidence)
    leak_path = args.leak_set
    if leak_path and leak_path.endswith(".json"):
        try:
            ids = set(_load_json(leak_path))
            leak_available = len(ids) > 0
        except Exception:
            ids, leak_available = set(), False
    else:
        ids, leak_available = load_leak_ids(leak_path)
    trained, trained_available = load_trained_ids(repo_root)
    questions, _ = load_questions(args.questions)

    verdict = judge_run(result, questions, evidence, ids, leak_available,
                        trained, trained_available)
    if args.out:
        # newline="\n"：verdict 要跨机器可比；Windows 文本模式会写 \r\n。
        with open(args.out, "w", encoding="utf-8", newline="\n") as f:
            json.dump(verdict, f, ensure_ascii=False, indent=2)

    brief = {k: verdict[k] for k in ("run_id", "total", "effective_runs", "verdicts",
                                     "raw_solved_hits", "claimable", "claimable_denominator",
                                     "capability_rate", "blocking_reasons")}
    if args.json:
        print(json.dumps(brief, ensure_ascii=False, indent=2))
    else:
        print("=== 纯 LLM 能力率归因（fail-closed）===")
        print("批次 %s：%d 题 / 有效开跑 %d / 原始命中 %d"
              % (brief["run_id"], brief["total"], brief["effective_runs"], brief["raw_solved_hits"]))
        print("判定：LLM_SOLVED=%d  CLEAN_FAIL=%d  NOT_ATTRIBUTABLE=%d"
              % (brief["verdicts"][LLM_SOLVED], brief["verdicts"][CLEAN_FAIL],
                 brief["verdicts"][NOT_ATTRIBUTABLE]))
        print("可引用：%s    能力率：%s"
              % (brief["claimable"], "无可引用数字(null)" if brief["capability_rate"] is None
                 else brief["capability_rate"]))
        for b in brief["blocking_reasons"]:
            print("  阻断：%s" % b)
        if args.out:
            print("逐题明细：%s" % args.out)
    return 0 if verdict["claimable"] else 1


if __name__ == "__main__":
    sys.exit(main())
