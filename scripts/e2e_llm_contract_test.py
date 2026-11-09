#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""端到端契约测试：真实 orchestrator → 本地桩模型 → 结果文件 → judge_run。

## 为什么要这个文件，而不是再加一组 fixture

2026-11-08 那次「全批 402 被判成 0% 解出率」的根因，是**生产者与消费者对同一个键
的理解分叉**：orchestrator 只把失败写进 `llm_rounds[].error` / `api_error_first`，
判分器只读 `detail["error"]`。两边各自的单测当时都是绿的 —— 因为单测里的「结果
文件形状」是**我手写的、我以为生产者会写的**那个形状。生产者改键名、改语义，
单测不会红；只有真跑一遍才会红。

本文件让真实的 `scripts/ctf_stepfun_orchestrator.py` 去打一个**本地桩 HTTP 服务**，
因此断言的是**生产者实际落盘的字节**，不是任何人对它的假设。

## 零额度 / 零外网

桩服务只绑 127.0.0.1，`STEP_BASE_URL` 指向它；`STEP_API_KEY` 是本进程临时造的
哑值，从不打印、也从不进入任何真实端点。全程只走 loopback，因此在额度耗尽
（当前 stepfun / jiyuan 都是 402 的状态）下照常可跑，可进常规门禁。

## 覆盖的四类真实返回形态

| 桩模式 | 模拟的真实故障 | 修复前会被判成 |
|---|---|---|
| `solved` | 正常答对 | LLM_SOLVED（对照，必须仍然对） |
| `wrong` | 正常答错 | CLEAN_FAIL（对照，必须仍然对） |
| `envelope` | HTTP 200 + 无 `choices` 的错误信封（网关/代理常见） | **CLEAN_FAIL（假红）** |
| `http402` | HTTP 402 余额不足（本轮真跑批实际撞到的） | **CLEAN_FAIL（假红）** |
| `http401` | HTTP 401 鉴权失败，文本**不含**旧关键字表的任何词 | **CLEAN_FAIL（假红）** |

`http401` 是专门用来验「消费者那半边修复是否承重」的：修复前 `_effective()` 的
关键字表只有 `no available channel / cooldown / quota / 403 / 429`，而 402 的文本
恰好含 `quota` —— 只退消费者、留着修好的生产者，**402 与错误信封仍会被判对**。
必须给一个旧表不覆盖的失败形态，才能看出新增的 `api_call_failed()` 是否真的必要。

`timeout`（`_HardDeadline`）分支不在本文件里测：它要多花一个真实 timeout 的墙钟，
而它的落账形状与 `http402` 完全同路（外层 except → `all_rounds_api_failed=True`），
加进来只增加时长不增加信息量。该分支由 `check_pure_llm_caliber.py --selftest` 覆盖。

## 判据分五面（13 条）

1. **字段面**：每道题都有 `llm_rounds`；失败题的 `finish_reason == "error"`、
   `all_rounds_api_failed is True`、`error` 非空。任一条塌了，消费者就没有可靠信号。
2. **判分面**：同一份结果喂 `judge_run`，答错必须落 CLEAN_FAIL、没问到必须落
   NOT_ATTRIBUTABLE 且理由含 `api_call_failed_no_successful_round`。
3. **批次面**：混合批 3/5 失败 ⇒ claimable=True 但分母缩到 2、rate=0.5、
   notes 自报分母变化；全失败批 ⇒ claimable=False 且阻断理由写明「全批…失败」。
4. **0 秒边界面**（2026-11-09 补，见证据文档 §8）：`latency` 被
   `round(dt,2)` 抹成 0.0 时，有干净轮次仍算有效、无轮次仍 fail-closed；
   另把失败题 `latency` 强制成 3.99（402 事故的真实条件）再判一次，
   作为「退回修复前消费者」唯一不依赖本机快慢的证伪点。
5. **变异面**：5 组，各自问不同问题。M1/M3/M4/M5 该红，M2 是负对照
   （该红的字段面红、分类面必须仍绿）。该红不红、该绿却红都算判据无效。

运行：
    python scripts/e2e_llm_contract_test.py --selftest     # 含变异验证，打印表格
    pytest scripts/e2e_llm_contract_test.py -q             # 门禁入口
"""
from __future__ import annotations

import hashlib
import http.server
import json
import os
import shutil
import subprocess
import sys
import tempfile
import threading

HERE = os.path.dirname(os.path.abspath(__file__))
ROOT = os.path.dirname(HERE)
ORCH = os.path.join(HERE, "ctf_stepfun_orchestrator.py")
sys.path.insert(0, HERE)

import check_pure_llm_caliber as caliber  # noqa: E402

# 桩模型的答案。`solved` 用它命中；其余模式的期望指纹与之无关。
SOLVED_FLAG = "flag{e2e_stub_solved_7c1a}"
WRONG_FLAG = "flag{e2e_stub_wrong_answer_never_matches}"

# 混合批：四种形态各一道，用于同时验证「答对仍判对」「答错仍判错」「没问到不判错」。
MIXED_PLAN = (
    ("e2e_solved", "solved"),
    ("e2e_wrong", "wrong"),
    ("e2e_envelope", "envelope"),
    ("e2e_http402", "http402"),
    ("e2e_http401", "http401"),
)
# 全失败批：验证「全批一次调用都没成功」不得给读数。
ALLFAIL_PLAN = (
    ("e2e_envelope", "envelope"),
    ("e2e_http402", "http402"),
    ("e2e_http401", "http401"),
)
API_FAIL_IDS = ("e2e_envelope", "e2e_http402", "e2e_http401")


# ---------------------------------------------------------------- 桩 HTTP 服务
class _StubHandler(http.server.BaseHTTPRequestHandler):
    """最小 OpenAI 兼容端点：按 prompt 里的题号决定返回哪一种形态。"""

    protocol_version = "HTTP/1.1"
    probe_map = {}          # 题号 -> 模式，由 _serve() 注入

    def log_message(self, fmt, *args):   # 静音：桩服务不该污染测试输出
        return

    def _emit(self, code, payload):
        raw = json.dumps(payload, ensure_ascii=False).encode("utf-8")
        self.send_response(code)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(raw)))
        self.end_headers()
        self.wfile.write(raw)

    def do_POST(self):                     # noqa: N802 - BaseHTTPRequestHandler 约定
        n = int(self.headers.get("Content-Length") or 0)
        try:
            body = json.loads(self.rfile.read(n).decode("utf-8") or "{}")
        except Exception:
            body = {}
        # 🔴 故意**不睡**：让 loopback 往返真的 <5ms，逼生产者把 latency 写成
        # `round(dt, 2) = 0.0`。修复前 `_effective()` 只看墙钟，6 次里 5 次把
        # 真答过的题判成 NOT_ATTRIBUTABLE("ineffective_run")（rate 0.5→1.0）。
        # 2026-11-09 修好后这里反而成了**最锋利的回归探针**：不加睡眠才能保证
        # 每次都跑到那条边界；加睡眠等于把刚修好的 bug 绕开。
        # 题号出现在 build_prompt 的「题目名称：<id>」里；直接对整份请求体做子串匹配，
        # 不做结构解析 —— 桩服务不该依赖生产者的 payload 结构。
        text = json.dumps(body, ensure_ascii=False)
        mode = "http402"                   # 未登记的题：按最坏情况（余额不足）处理
        for pid, m in self.probe_map.items():
            if pid in text:
                mode = m
                break
        if mode == "solved":
            self._emit(200, _chat("推导过程：a+b=4。最终 flag 是 " + SOLVED_FLAG))
        elif mode == "wrong":
            self._emit(200, _chat("推导过程：a+b=5。最终 flag 是 " + WRONG_FLAG))
        elif mode == "envelope":
            # 200 + 无 choices：网关/反代把上游错误包成 200 的经典形态。
            # 旧代码把它当正文、finish 记 "stop"、api_error_rounds 硬编码 0。
            self._emit(200, {"object": "error", "error": {
                "code": "402", "type": "insufficient_quota",
                "message": "exceeded your current quota"}})
        elif mode == "http401":
            # 旧 `_effective()` 关键字表不含 "401" / "authentication"：
            # 只靠 error 文本判失败时，这一格会被当成「模型答错」。
            self._emit(401, {"error": {
                "code": "401", "type": "auth_error",
                "message": "authentication required"}})
        else:
            self._emit(402, {"error": {
                "code": "402", "type": "insufficient_quota",
                "message": "exceeded your current quota"}})


def _chat(content):
    return {"id": "stub", "object": "chat.completion", "model": "stub-model",
            "choices": [{"index": 0, "message": {"role": "assistant", "content": content},
                         "finish_reason": "stop"}],
            "usage": {"prompt_tokens": 11, "completion_tokens": 7, "total_tokens": 18}}


class _StubServer(http.server.ThreadingHTTPServer):
    daemon_threads = True


def _serve(plan):
    handler = type("_H", (_StubHandler,), {"probe_map": dict(plan)})
    srv = _StubServer(("127.0.0.1", 0), handler)
    threading.Thread(target=srv.serve_forever, daemon=True).start()
    return srv


# ---------------------------------------------------------------- 跑一批
def _benchmark(plan, path):
    """造题池。期望指纹：solved 题指向 SOLVED_FLAG，其余指向一个绝不可能被答到的串。"""
    probs = []
    for pid, mode in plan:
        want = SOLVED_FLAG if mode == "solved" else "flag{e2e_expected_%s_a41f}" % pid
        probs.append({
            "id": pid, "name": pid, "category": "misc",
            "description": "已知整数数组与目标值，推导出题目要求的字符串。",
            "flag_sha256": hashlib.sha256(want.encode("utf-8")).hexdigest(),
        })
    with open(path, "w", encoding="utf-8", newline="\n") as f:
        json.dump({"problems": probs}, f, ensure_ascii=False, indent=2)
    return {p["id"]: p for p in probs}


def _run_batch(orch, workdir, plan, tag):
    """跑真实 orchestrator，返回 (result_dict, CompletedProcess)。"""
    bm = os.path.join(workdir, "bench_%s.json" % tag)
    questions = _benchmark(plan, bm)
    out = os.path.join(workdir, "result_%s.json" % tag)
    srv = _serve(plan)
    try:
        env = dict(os.environ)
        # base_url 走 PROVIDERS["stepfun"]["base_url_env"] 覆盖 ⇒ 零外网。
        env["STEP_BASE_URL"] = "http://127.0.0.1:%d/v1" % srv.server_address[1]
        # 哑值，不是凭证：只为满足 load_key() 的存在性检查。绝不打印。
        env["STEP_API_KEY"] = "stub-dummy-not-a-credential"
        env["PYTHONIOENCODING"] = "utf-8"
        # 显式绕开代理：某些环境下 http_proxy 会把 127.0.0.1 也送出去。
        env["NO_PROXY"] = "127.0.0.1,localhost"
        env["no_proxy"] = env["NO_PROXY"]
        # 变异副本落在临时目录，找不到 scripts/ 下的同目录模块（agentic_binding）以及
        # scripts/experiments/ 下的共享 flag_util（orchestrator 按 __file__ 相对路径去找，
        # 而副本的 __file__ 在临时目录）。用 PYTHONPATH 兜住，而不是把副本写进仓库
        # —— 变异体绝不入库。
        old_pp = env.get("PYTHONPATH") or ""
        env["PYTHONPATH"] = os.pathsep.join(
            [HERE, os.path.join(HERE, "experiments")]
            + ([old_pp] if old_pp else []))
        cmd = [sys.executable, orch, "--provider", "stepfun",
               "--benchmark", bm, "--out", out, "--timeout", "20",
               "--concurrency", "1", "--slice", "e2e-stub"]
        proc = subprocess.run(cmd, cwd=ROOT, env=env, capture_output=True,
                              timeout=180, encoding="utf-8", errors="replace")
    finally:
        srv.shutdown()
        srv.server_close()
    if not os.path.isfile(out):
        raise AssertionError("orchestrator 没写出结果文件\nrc=%s\nstderr=%s"
                             % (proc.returncode, (proc.stderr or "")[-1500:]))
    with open(out, "r", encoding="utf-8") as f:
        return json.load(f), questions, proc


# ---------------------------------------------------------------- 判分
def _evidence():
    """判分所需的最小证据面。全部 True 才能让 claimable 只受「调用失败」影响。

    这里刻意不接真实题池/注册表：本文件测的是**分类契约**，不是证据门禁 ——
    证据面另有 audit_private_proof / verify_capability_evidence 专管。
    """
    sha = "a" * 64
    return {"eval_path": "pure_llm", "run_id": "e2e-stub",
            "no_model_egress_proven": True, "single_channel_proven": True,
            "channel_attribution_proven": True, "no_presolve_proven": True,
            "temperature_fixed": True, "pool_fingerprint_ok": True,
            "pool_gate_ok": True, "pool_in_version_control": True,
            "result_pool_sha256": sha, "pool_sha256": sha}


def _judge(result, questions):
    return caliber.judge_run(result, questions, _evidence(), set(), True, set(), True)


def _by_id(result):
    return {str(d.get("id")): d for d in result.get("details") or []}


def evaluate(orch=ORCH, workdir=None, judge_fn=None, judge_mod=None):
    """跑两批并返回 [(check_name, ok, detail), ...]。纯读，不改任何源文件。

    `judge_mod` 只给变异用：把消费者模块换成修复前的版本，验证「生产者真实
    落盘的字节」在旧判据下确实会被判错。**所有**断言（含 0 秒边界）都必须走
    同一个模块，否则变异改了判分器、边界断言却还在读真模块 ⇒ 假绿。
    """
    own = workdir is None
    workdir = workdir or tempfile.mkdtemp(prefix="e2e_llm_")
    mod = judge_mod or caliber
    judge = judge_fn or (lambda r, q: mod.judge_run(
        r, q, _evidence(), set(), True, set(), True))
    try:
        mixed, q_mixed, proc_m = _run_batch(orch, workdir, MIXED_PLAN, "mixed")
        allfail, q_af, _ = _run_batch(orch, workdir, ALLFAIL_PLAN, "allfail")
        vm = judge(mixed, q_mixed)
        va = judge(allfail, q_af)
    finally:
        if own:
            shutil.rmtree(workdir, ignore_errors=True)

    md = _by_id(mixed)
    checks = []

    # 1) 字段面：生产者必须落账。
    missing = [pid for pid in md if not isinstance(md[pid].get("llm_rounds"), list)
               or not md[pid]["llm_rounds"]]
    checks.append(("producer_ledger_present", not missing, "缺 llm_rounds: %s" % missing))

    bad_fail = {}
    for pid in API_FAIL_IDS:
        d = md.get(pid) or {}
        rounds = d.get("llm_rounds") or [{}]
        problems = []
        if d.get("all_rounds_api_failed") is not True:
            problems.append("all_rounds_api_failed=%r" % d.get("all_rounds_api_failed"))
        if not str(d.get("error") or ""):
            problems.append("error 为空")
        if any(str(r.get("finish_reason")) not in ("error", "timeout") for r in rounds):
            problems.append("有 finish_reason 干净的一轮: %s"
                            % [r.get("finish_reason") for r in rounds])
        if problems:
            bad_fail[pid] = "; ".join(problems)
    checks.append(("producer_marks_api_fail", not bad_fail, str(bad_fail)))

    bad_ok = {}
    for pid in ("e2e_solved", "e2e_wrong"):
        d = md.get(pid) or {}
        if d.get("all_rounds_api_failed") is not False or str(d.get("error") or ""):
            bad_ok[pid] = "all_rounds_api_failed=%r error=%r" % (
                d.get("all_rounds_api_failed"), d.get("error"))
    checks.append(("producer_marks_success", not bad_ok, str(bad_ok)))

    # 2) 判分面：三种归属各自落对桶。
    rows = {r["id"]: r for r in vm["rows"]}
    checks.append(("judge_llm_solved", rows["e2e_solved"]["verdict"] == caliber.LLM_SOLVED,
                   rows["e2e_solved"]["verdict"]))
    checks.append(("judge_clean_fail", rows["e2e_wrong"]["verdict"] == caliber.CLEAN_FAIL,
                   rows["e2e_wrong"]["verdict"]))
    bad_api = {}
    for pid in API_FAIL_IDS:
        r = rows[pid]
        if r["verdict"] != caliber.NOT_ATTRIBUTABLE:
            bad_api[pid] = r["verdict"]
        elif "api_call_failed_no_successful_round" not in r["reasons"]:
            bad_api[pid] = "理由缺 api_call_failed_no_successful_round: %s" % r["reasons"]
    checks.append(("judge_api_failed_not_clean_fail", not bad_api, str(bad_api)))

    # 3) 批次面：部分失败仍是合法读数（分母自报），全失败不得给读数。
    partial_problems = []
    if vm["claimable"] is not True:
        partial_problems.append("claimable=%r" % vm["claimable"])
    if vm["api_call_failed_runs"] != len(API_FAIL_IDS):
        partial_problems.append("api_call_failed_runs=%r（应为 %d）"
                                % (vm["api_call_failed_runs"], len(API_FAIL_IDS)))
    if vm["claimable_denominator"] != 2:
        partial_problems.append("分母=%r（应为 2）" % vm["claimable_denominator"])
    if vm["capability_rate"] != 0.5:
        partial_problems.append("rate=%r（应为 0.5）" % vm["capability_rate"])
    if not vm["notes"]:
        partial_problems.append("notes 未自报分母变化")
    checks.append(("batch_partial_keeps_reduced_denominator",
                   not partial_problems, "; ".join(partial_problems)))

    af_problems = []
    if va["claimable"] is not False:
        af_problems.append("claimable=%r（应为 False）" % va["claimable"])
    if va["capability_rate"] is not None:
        af_problems.append("rate=%r（应为 None）" % va["capability_rate"])
    if not any("全批" in b for b in va["blocking_reasons"]):
        af_problems.append("阻断理由未写「全批…失败」: %s" % va["blocking_reasons"])
    checks.append(("batch_allfail_has_no_reading", not af_problems, "; ".join(af_problems)))

    checks.append(("orchestrator_rc_zero", proc_m.returncode == 0,
                   "rc=%s stderr=%s" % (proc_m.returncode, (proc_m.stderr or "")[-300:])))
    # 4) 0 秒边界：用真实落盘字节，把 latency 强制成 0.0 后仍须判对。
    checks.extend(latency_boundary_checks(mixed, q_mixed, mod, judge)[0])
    return checks


# ---------------------------------------------------------------- 变异
# 三种变异各问一个不同的问题，别把它们混成一个「注入错误应该变红」。
#
#   M1 生产者：修复前的 200 错误信封处理 ⇒ 分类该红。
#   M2 生产者：抹掉三处信号里的两处 ⇒ **分类必须仍然绿**（负对照）。
#              实测这就是第一次写变异时「没变红」的原因：消费者有标记/轮次/文本
#              三条互不依赖的判据，冗余是真实生效的。把它从「失败」改记为证据。
#   M3 消费者：把 `_effective()` 退回修复前（只看 latency 与 error 文本）⇒
#              用**真实生产者字节**证明这次修复是承重墙，而不是自测里的自证。
CALIBER = os.path.join(HERE, "check_pure_llm_caliber.py")

MUTATIONS = {
    "m1_producer_envelope_as_answer": {
        "target": "producer",
        "edits": [('            no_choice = True\n            finish = "error"',
                   '            no_choice = False\n            finish = "stop"')],
        "expect_red": {"producer_marks_api_fail", "judge_api_failed_not_clean_fail",
                       "batch_partial_keeps_reduced_denominator",
                       "batch_allfail_has_no_reading"},
        "expect_green": set(),
    },
    "m2_producer_partial_erasure_redundancy": {
        "target": "producer",
        # 只抹两处**失败标记**，保留 llm_rounds。2026-11-09 修复后 llm_rounds
        # 同时是「0 秒格的正面证据」，把它也删掉就不再是纯净的负对照了
        # （实测那样的 M2 会连带把成功题判废，语义混成两件事）。
        "edits": [('"all_rounds_api_failed": all_failed,',
                   '"all_rounds_api_failed": False,'),
                  ('"error": (first_err[:300] if all_failed else ""),',
                   '"error": "",')],
        # 分类面必须仍绿 ⇒ 三条失败判据的冗余真实生效。
        "expect_red": {"producer_marks_api_fail"},
        "expect_green": {"producer_ledger_present",
                         "judge_api_failed_not_clean_fail",
                         "batch_partial_keeps_reduced_denominator",
                         "batch_allfail_has_no_reading",
                         "positive_latency_api_fail_not_clean_fail",
                         "zero_latency_with_clean_round_is_effective",
                         "zero_latency_row_still_clean_fail"},
    },
    # M5：新修复依赖 llm_rounds 当正面证据，那就必须能被「删掉它」证伪。
    # 用强制 latency=0.0 的边界断言判定，不依赖本机往返快慢 ⇒ 不 flaky。
    "m5_producer_no_rounds_kills_positive_evidence": {
        "target": "producer",
        "edits": [('            "llm_rounds": pstats,\n', ''),
                  ('            "llm_rounds": estats,\n', '')],
        "expect_red": {"producer_ledger_present",
                       "zero_latency_with_clean_round_is_effective",
                       "zero_latency_row_still_clean_fail"},
        "expect_green": {"judge_api_failed_not_clean_fail",
                         "batch_allfail_has_no_reading",
                         "positive_latency_api_fail_not_clean_fail"},
    },
    # M4：把 2026-11-09 的正面证据分支拿掉，退回「只看墙钟」。
    # 用真实生产者字节验这次修复是承重墙，不是自测里自己造的行。
    "m4_consumer_wallclock_only": {
        "target": "consumer",
        "edits": [('    if secs <= 0 and not _has_successful_round(detail):',
                   '    if secs <= 0:')],
        "expect_red": {"zero_latency_with_clean_round_is_effective",
                       "zero_latency_row_still_clean_fail"},
        "expect_green": {"positive_latency_api_fail_not_clean_fail"},
    },
    "m3_consumer_pre_fix_effective": {
        "target": "consumer",
        # 逐字还原 6215f80^ 的 `_effective()`：旧关键字表 + 无条件 return True。
        # 只改最后一行不够 —— 上面的 marks 表也是那次修复一起加的。
        "edits": [
            ('    if err and any(k in err.lower() for k in _API_FAIL_MARKS):\n'
             '        return False',
             '    if err and any(k in err.lower() for k in '
             '("no available channel", "cooldown", "quota", "403", "429")):\n'
             '        return False'),
            ('    return not api_call_failed(detail)', '    return True'),
        ],
        # 402 / envelope 的文本含 "quota"，旧表仍能挡住；401 挡不住。
        # 🔴 别用 `judge_api_failed_not_clean_fail` / `batch_partial` 当证伪点：
        # 桩不睡时失败题常落成 latency=0.0，旧消费者靠「0 秒空跑」闸门
        # 碰巧判对，实测 3 次里 1 次完全不变红（桶对、理由却是 ineffective_run）。
        # 改用强制 latency=3.99 的那条 ⇒ 100% 确定，且不依赖本机快慢。
        "expect_red": {"positive_latency_api_fail_not_clean_fail"},
        "expect_green": {"producer_ledger_present", "producer_marks_api_fail",
                         "judge_llm_solved", "judge_clean_fail",
                         "batch_allfail_has_no_reading"},
    },
}


def _mutated_copy(src, edits, dest):
    with open(src, "r", encoding="utf-8") as f:
        text = f.read()
    for old, new in edits:
        if old not in text:
            raise AssertionError("变异锚点未命中（源文件已变，变异无效）: %r" % old[:60])
        text = text.replace(old, new)
    with open(dest, "w", encoding="utf-8", newline="\n") as f:
        f.write(text)
    return dest


def _load_consumer(path, name):
    """把变异后的判分器当独立模块加载，避免污染 sys.modules 里的真判据。"""
    import importlib.util
    spec = importlib.util.spec_from_file_location(name, path)
    mod = importlib.util.module_from_spec(spec)
    sys.modules[name] = mod
    spec.loader.exec_module(mod)
    return mod


def run_mutations(workdir=None):
    """返回 [(name, ok, red_names, fail_detail), ...]；ok=预期红/预期绿都满足。"""
    own = workdir is None
    workdir = workdir or tempfile.mkdtemp(prefix="e2e_mut_")
    out = []
    try:
        for name, spec in MUTATIONS.items():
            sub = os.path.join(workdir, name)
            os.makedirs(sub, exist_ok=True)     # 每个变异独立目录，避免结果文件互相覆盖
            if spec["target"] == "producer":
                dest = os.path.join(sub, "orch_mutated.py")
                _mutated_copy(ORCH, spec["edits"], dest)
                res = evaluate(orch=dest, workdir=sub)
            else:
                dest = os.path.join(sub, "caliber_mutated.py")
                _mutated_copy(CALIBER, spec["edits"], dest)
                mod = _load_consumer(dest, "caliber_mut_%s" % name)
                res = evaluate(workdir=sub, judge_mod=mod)
            red = {n for n, ok, _ in res if not ok}
            problems = []
            miss_red = spec["expect_red"] - red
            if miss_red:
                problems.append("应红未红=%s" % sorted(miss_red))
            unexpected_red = spec["expect_green"] & red
            if unexpected_red:
                problems.append("应绿却红=%s" % sorted(unexpected_red))
            out.append((name, not problems, sorted(red), "; ".join(problems)))
    finally:
        if own:
            shutil.rmtree(workdir, ignore_errors=True)
    return out


# ---------------------------------------------------------------- 入口
_CACHE = {}


def _cached_evaluate():
    if "base" not in _CACHE:
        _CACHE["base"] = evaluate()
    return _CACHE["base"]


def test_e2e_producer_consumer_contract():
    res = _cached_evaluate()
    bad = [(n, d) for n, ok, d in res if not ok]
    assert not bad, "端到端契约不成立：\n" + "\n".join("  · %s: %s" % (n, d) for n, d in bad)


def test_mutations_turn_checks_red():
    if "mut" not in _CACHE:
        _CACHE["mut"] = run_mutations()
    bad = [(n, why) for n, ok, _red, why in _CACHE["mut"] if not ok]
    assert not bad, "变异结果与预期不符（判据无效或冗余失效）：\n" + "\n".join(
        "  · %s: %s" % (n, why) for n, why in bad)


def latency_boundary_checks(result, questions, mod, judge):
    """用**生产者真实落盘的字节**验 0 秒边界，返回 (checks, info)。

    `mod` / `judge` 由调用方注入（变异时是变异后的消费者），不允许在函数里
    偷偷回退到全局 `caliber` —— 那会让消费者变异对边界断言完全失效。

    刻意把 `latency` 强制改成 0.0（其余字段全来自真实结果文件），
    这样不依赖本机快慢、每次都跑到边界；修复前这三条里前两条必红。

    2026-11-09 前这里是「已知限制，只测量不改」；后来实测 19 份入库结果 /
    349 格中 `latency<=0` 为 0 格、旧新判据逐格 0 分歧，才确认改消费者
    对历史 verdict 零影响并真正修掉。别把「担心」当成「测量」。
    """
    rows = _by_id(result)
    d = rows.get("e2e_wrong")
    if not isinstance(d, dict):
        return [("zero_latency_probe_has_real_row", False, "缺 e2e_wrong 行")], {}
    zero = dict(d, latency=0.0)
    no_rounds = dict(zero, llm_rounds=[])
    one = judge({"summary": {}, "details": [zero]}, questions)
    zero_count = sum(1 for x in (result.get("details") or [])
                     if isinstance(x, dict) and x.get("latency") == 0)
    eff_zero = mod._effective(zero)
    eff_norounds = mod._effective(no_rounds)
    # 🔴 402 事故的真实条件是「latency=3.99 又过了『0 秒空跑』那道闸」。
    # 桩不睡时失败题可能落成 0.0，让修复前消费者**碰巧**判对（桶对但理由错）。
    # 故强制把失败题的 latency 设成正数再判一次：这条不依赖本机快慢，
    # 是 M3「退回修复前消费者」唯一稳定的证伪点。
    pos_rows = [dict(rows[pid], latency=3.99) for pid in API_FAIL_IDS
                if isinstance(rows.get(pid), dict)]
    pos = judge({"summary": {}, "details": pos_rows}, questions)
    pos_bad = [r["id"] for r in pos["rows"]
               if r["verdict"] != caliber.NOT_ATTRIBUTABLE
               or "api_call_failed_no_successful_round" not in r["reasons"]]
    return [
        ("positive_latency_api_fail_not_clean_fail",
         not pos_bad, "latency=3.99 下被误判/误归因的题=%s" % pos_bad),
        ("zero_latency_with_clean_round_is_effective",
         eff_zero is True, "_effective=%r" % eff_zero),
        ("zero_latency_row_still_clean_fail",
         one["verdicts"][caliber.CLEAN_FAIL] == 1 and one["attributable_runs"] == 1,
         "verdicts=%s denom=%s" % (one["verdicts"], one["claimable_denominator"])),
        ("zero_latency_without_rounds_fail_closed",
         eff_norounds is False,
         "_effective=%r；本批真实 latency=0.0 的格数=%d" % (eff_norounds, zero_count)),
    ], {"real_zero_latency_rows": zero_count}


def main(argv=None):
    import argparse
    ap = argparse.ArgumentParser(description="端到端契约测试（本地桩模型，零额度零外网）")
    ap.add_argument("--selftest", action="store_true", help="跑断言 + 变异验证并打印表格")
    ap.add_argument("--skip-mutations", action="store_true", help="只跑断言（快，但不算验证）")
    args = ap.parse_args(argv)

    print("=== 端到端契约：真实 orchestrator → 桩模型 → 结果文件 → judge_run ===")
    res = evaluate()
    bad = 0
    for name, ok, detail in res:
        print("  %-42s %s%s" % (name, "PASS" if ok else "FAIL",
                                "" if ok else "  ← %s" % detail))
        bad += 0 if ok else 1
    print("  %s（%d/%d）" % ("PASS" if not bad else "FAIL", len(res) - bad, len(res)))
    print("  （0 秒边界已作为正式断言上表；桩不睡，真实往返会把 latency 压到 0.0）")
    if args.skip_mutations:
        return 0 if not bad else 1

    print("=== 变异验证：M1/M3/M4/M5 应红，M2 负对照的分类面应仍绿 ===")
    mbad = 0
    for name, ok, red, why in run_mutations():
        print("  %-40s %s  变红=%s%s" % (name, "PASS" if ok else "FAIL", red,
                                        "" if ok else "  ← %s" % why))
        mbad += 0 if ok else 1
    print("  %s（%d/%d）" % ("PASS" if not mbad else "FAIL",
                            len(MUTATIONS) - mbad, len(MUTATIONS)))
    return 0 if not bad and not mbad else 1


if __name__ == "__main__":
    sys.exit(main())
