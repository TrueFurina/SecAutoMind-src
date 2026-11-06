#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""全基准集「题面即答案」横向审计门禁。

## 为什么要这个门禁（2026-10-16 实测动机）

PR #30 只给 **55 题真题集** 补了分子侧反注水门禁（``flag_in_*`` 四题的
description 直接写 flag 明文，``flag_scan`` 一扫即命中）。但那是**单点**——
同一个病根在别的基准集里没人查过。横向扫描后实锤：

| 基准集 | 题数 | 命中 | 题面即答案 | 引擎 | 宣传口径 → 真求解器口径 |
|---|---|---|---|---|---|
| ``benchmark.json``（自研 72） | 72 | 70 | **15** | 全部 ``flag_scan`` | 97.2% → **76.4%** |
| ``real_benchmark.json``（真题 55） | 55 | 20 | **4** | 全部 ``flag_scan`` | 36.4% → **29.1%** |

72 题集里 ``flag_scan`` 引擎恰好命中 15 题，**与题面即答案的 15 题完全重合**
（``web_sqli`` / ``forensic_1`` 等题面形如
``POST /login.php user=admin flag{REDACTED_web_sqli} UNION SELECT ...``）。
即：这个引擎在该集上 100% 靠读题面得出答案，与真题集 A 层是同一个病根。

## 判据：必须机验，不许靠"看着像"

初扫时 ``crc32`` / ``lcg`` / ``ecdsa`` / ``execution`` 四集也有 flag 明文，
**一度被我判为注水——实测是错的**：那些题的 flag 是**已知输入**
（CRC32 伪造、LCG 参数恢复本就给定原文求碰撞），sha256 与 ``flag_sha256`` 不相等。

因此唯一权威判据是 **sha256 比对**：
    题面文本提取出的 flag 串，其 sha256 == 该题 flag_sha256  ⇒ 答案就写在题面上
不相等 ⇒ flag 只是输入/样例，合法，不计入。

## 判别力设计（三态 + 覆盖度，均非恒真）

| 判据 | 条件 | 结论 |
|---|---|---|
| 覆盖度 | 扫到的基准集数 / 总题数低于下限 | FAIL（防「扫 0 文件 = 0 违规 = 全绿」） |
| 登记上限 | 每集题面即答案数 > 基线表登记值 | FAIL |
| 未登记集 | 基线表里没有的集出现 > 0 | FAIL |

基线表是**登记契约**：当前值（72 题集 15、55 题集 4）是 2026-10-16 实测值，
修好后应逐项下调为 0；新增基准集若带题面明文会立即变红，逼人显式登记。

## 用法
    python scripts/check_benchmark_plaintext_answer.py            # 报数
    python scripts/check_benchmark_plaintext_answer.py --check     # 门禁断言（exit 1 = 红）
    python scripts/check_benchmark_plaintext_answer.py --json      # 机读
"""
from __future__ import annotations

import argparse
import glob
import hashlib
import json
import os
import re
import sys

REPO_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
BENCH_DIR = os.path.join("data", "ctf_benchmark")
GLOB = os.path.join(BENCH_DIR, "*benchmark*.json")
SKIP_FILES = {"all_benchmarks_summary.json"}

# 常见 CTF flag 前缀。仅作"候选提取"用，是否真是答案由 sha256 比对裁定。
# ── 统一 flag 判定口径（2026-10-28 迁移）：大小写不敏感 + 前缀归一 ──
# 基准 72 个 flag 全小写 flag{}，LLM 常输出大写 FLAG{}；旧口径会「答对判未命中」。
import os as _fu_os, sys as _fu_sys
_fu_sys.path.insert(0, _fu_os.path.join(
    _fu_os.path.dirname(_fu_os.path.abspath(__file__)), 'experiments'))
from flag_util import candidate_variants  # noqa: E402
FLAG_RE = re.compile(r"(?:flag|FLAG|picoCTF|picoctf|d0g3|DASCTF|ctf)\{[^{}]{3,}\}", re.IGNORECASE)

# ── 第二判据：题面「自然语言自曝答案」（2026-11-06 第四个假绿）─────────────
# 动机：answer_is_in_statement() 只把 word{content} token 过 candidate_variants，
# 而 candidate_variants("flag{<X>}") 不产生裸内容变体 ⇒ 当真值登记为
# sha256(<X>)（裸内容）时，题面写着「writeup 明确给出 <X>。flag{端口}。」
# 这类句子永远扫不到，门禁对干净池实报 plaintext_answer=0 = 空洞绿。
# 本判据纯 sha256 反查题面 token 的裸/带壳形态，无明文输出（项目红线）。
SD_TOKEN_RE = re.compile(r"[A-Za-z0-9_][A-Za-z0-9_.\-]{0,63}")
SD_WORDING_RE = re.compile(
    r"writeup|题解|明确给出|答案(?:是|为|明确)|直接给出|flag\{[^}]*\}。|给出(?:密码|次数|端口|答案)",
    re.I)
SD_PREFIXES = ("flag", "FLAG", "DASCTF", "picoCTF", "ctf", "CTF", "sdctf",
               "BZHCTF", "NSSCTF", "GWHT", "moectf", "flag{")
SD_TEXT_FIELDS = ("description", "desc", "content", "name", "title", "statement")

# 题面字段：只从"给选手看的文本"里提取，不含 attachments 等工件路径。
TEXT_FIELDS = ("description", "prompt", "hint", "hints", "note", "summary")

# 登记契约：文件名 -> 允许的最大题面即答案数。
# 未登记文件按 0 处理（新增集带明文即红）。当前值为 2026-10-16 实测基线。
BASELINE = {
    "benchmark.json": 15,        # 自研 72 题集：15 题题面即答案，真求解器 55/72 = 76.4%
    "real_benchmark.json": 4,    # 真题 55 题集：4 题，真求解器 16/55 = 29.1%
}

# 第二判据（自然语言自曝答案）的登记契约：**未登记集一律按 0**。
# v1 干净池的 6 题是 2026-11-06 全量跑批后查实的历史遗留（见
# docs/evidence/capability_eval_20261105/全量160题_20261106.md），已有三份
# verdict 的 claim_scope.statement_tainted_ids 逐题标注。这里登记 6 只是让 CI
# 不为已知历史池常红；**评测入口另有前置守卫拒绝再用 v1 起新跑批**，且 v1 的
# 指纹已被三份 verdict 绑定，禁止改一字节来「洗白」。新池（v2 及以后）按 0。
SELF_DISCLOSURE_BASELINE = {
    "purellm_clean_benchmark.json": 6,
}

# 覆盖度下限：低于此值说明扫描范围被意外缩小，判 FAIL（fail-closed）。
MIN_SETS = 20
MIN_PROBLEMS = 200


def _load(path):
    with open(path, encoding="utf-8", errors="replace") as f:
        return json.load(f)


def _problem_text(prob):
    """拼接题面文本字段（只取 str，忽略 list/dict 以免误拼）。"""
    parts = []
    for field in TEXT_FIELDS:
        v = prob.get(field)
        if isinstance(v, str):
            parts.append(v)
        elif isinstance(v, list):
            parts.extend(x for x in v if isinstance(x, str))
    return "\n".join(parts)


def answer_is_in_statement(prob):
    """权威判据：题面里的 flag 串，sha256 是否等于该题答案指纹。

    返回 (是否答案在题面, 命中的明文串或 None)。
    没有 flag_sha256 的题无法裁定，返回 (False, None)——不计入分母也不误伤。
    """
    want = prob.get("flag_sha256")
    if not want:
        return False, None
    text = _problem_text(prob)
    for cand in FLAG_RE.findall(text):
        for v in candidate_variants(cand):
            if hashlib.sha256(v.encode("utf-8")).hexdigest() == want:
                return True, v
    return False, None


def _sd_forms(token, outer_prefixes):
    """题面 token 的全部可判分形态（裸内容 + 常见赛事外壳）。"""
    out = [token]
    for p in SD_PREFIXES:
        if p.endswith("{"):
            continue
        out.append("%s{%s}" % (p, token))
    for p in outer_prefixes:
        out.append("%s{%s}" % (p, token))
    out.extend(("flag{%s}" % token, "FLAG{%s}" % token))
    return list(dict.fromkeys(out))


def self_disclosure_in_statement(prob):
    """第二判据：题面 token 的任一形态 sha256 == flag_sha256 ⇒ 答案自曝。

    与 answer_is_in_statement() 互补：后者只认花括号 token 且不去壳，
    本函数覆盖「自然语言自曝裸内容」。返回证据 dict（**绝不含明文答案**，
    只给形态类别 / 长度 / sha8），未命中返回 None。无合法指纹不裁定。
    本函数是 scripts/audit_writeup_answer.py 与门禁共用的唯一真值源。
    """
    if not isinstance(prob, dict):
        return None
    want = str(prob.get("flag_sha256") or "").lower()
    if not re.fullmatch(r"[0-9a-f]{64}", want):
        return None
    text = " ".join(str(prob.get(k, "")) for k in SD_TEXT_FIELDS)
    if not text.strip():
        return None
    outer_prefixes = {m.group(1) for m in
                      re.finditer(r"([A-Za-z0-9_]+)\{", text)}
    for token in SD_TOKEN_RE.findall(text):
        for form in _sd_forms(token, outer_prefixes):
            if hashlib.sha256(form.encode("utf-8")).hexdigest() == want:
                return {
                    "pool": prob.get("pool", "?"),
                    "answer_form": "bare" if form == token else "wrapped",
                    "answer_form_sha8": hashlib.sha256(form.encode("utf-8")).hexdigest()[:8],
                    "answer_form_length": len(form),
                    "self_disclosing_wording": bool(SD_WORDING_RE.search(text)),
                    "reason": "题面 token 的 %s 形态 sha256 == 该题 flag_sha256" %
                              ("裸内容" if form == token else "带壳"),
                }
    return None


def analyze(repo_root=REPO_ROOT):
    """纯函数：扫描全部基准集，统计题面即答案。供主流程与变异用例共用同一判据。"""
    per_file = []
    for path in sorted(glob.glob(os.path.join(repo_root, GLOB))):
        name = os.path.basename(path)
        if name in SKIP_FILES:
            continue
        try:
            doc = _load(path)
        except (ValueError, OSError):
            continue
        probs = doc.get("problems", doc)
        if not isinstance(probs, dict):
            continue
        offenders = []
        sd_ids = []
        for pid, prob in probs.items():
            if not isinstance(prob, dict):
                continue
            leak, plain = answer_is_in_statement(prob)
            if leak:
                offenders.append({"id": pid, "plain": plain})
            # 第二判据单独计数字段，不并入 offenders —— 保持 plaintext_answer /
            # real_solver_caliber 的历史语义不变，避免口径漂移。
            if self_disclosure_in_statement(prob):
                sd_ids.append(pid)
        per_file.append({
            "file": name,
            "problems": len(probs),
            "plaintext_answer": len(offenders),
            "baseline": BASELINE.get(name, 0),
            "offenders": offenders,
            "self_disclosure_answer": len(sd_ids),
            "self_disclosure_baseline": SELF_DISCLOSURE_BASELINE.get(name, 0),
            "self_disclosure_ids": sd_ids,
        })
    return per_file


# 对外引用集 -> 其覆盖率报告（用于输出真求解器口径，供 check_quant_effect.py 机验）
CALIBER_SOURCES = {
    "benchmark.json": "coverage_report.json",
    "real_benchmark.json": "real_coverage_report.json",
}


def real_solver_caliber(repo_root=REPO_ROOT, per_file=None):
    """真求解器口径：(命中数 - 题面即答案命中数) / 总题数。

    只对 CALIBER_SOURCES 里登记了的对外引用集计算。返回
    ``[(文件名, 真求解器命中, 总题数, 百分比, 全量命中, 伪解数), ...]``。
    """
    if per_file is None:
        per_file = analyze(repo_root)
    out = []
    for p in per_file:
        cov_name = CALIBER_SOURCES.get(p["file"])
        if not cov_name:
            continue
        cov_path = os.path.join(repo_root, BENCH_DIR, cov_name)
        if not os.path.exists(cov_path):
            continue
        try:
            cov = _load(cov_path)
        except (ValueError, OSError):
            continue
        rows = cov.get("results", [])
        total = cov.get("total", len(rows))
        hit_ids = {r.get("id") for r in rows if r.get("sha256_match")}
        leak_ids = {o["id"] for o in p["offenders"]}
        fake = len(leak_ids & hit_ids)          # 伪解：题面即答案且被判命中
        real = len(hit_ids) - fake
        pct = (real * 100.0 / total) if total else 0.0
        out.append((p["file"], real, total, pct, len(hit_ids), fake))
    return out


def violations(per_file):
    """门禁判据。返回违规描述列表（空 = 通过）。"""
    bad = []
    total_sets = len(per_file)
    total_problems = sum(p["problems"] for p in per_file)
    if total_sets < MIN_SETS or total_problems < MIN_PROBLEMS:
        bad.append(
            "覆盖度不足：扫到 %d 个基准集 / %d 题，下限 %d 集 / %d 题。"
            "扫描范围被缩小会让判据恒真（扫 0 文件 = 0 违规 = 全绿）"
            % (total_sets, total_problems, MIN_SETS, MIN_PROBLEMS))
    for p in per_file:
        n = p["plaintext_answer"]
        base = p["baseline"]
        if n > base:
            tag = "未登记集" if p["file"] not in BASELINE else "已登记集"
            bad.append(
                "%s %s：题面即答案 %d 题 > 基线 %d（%s）。"
                "这些题的 flag 明文写在题面上且 sha256 == flag_sha256，"
                "靠 flag_scan 读出即算命中，不构成解题能力"
                % (tag, p["file"], n, base,
                   ", ".join(o["id"] for o in p["offenders"][:6])))
        sd = p.get("self_disclosure_answer", 0)
        sd_base = p.get("self_disclosure_baseline", 0)
        if sd > sd_base:
            bad.append(
                "%s：题面自然语言自曝答案 %d 题 > 基线 %d（%s）。"
                "真值登记为裸内容哈希时旧判据扫不到（candidate_variants 不去壳），"
                "这些题的答案已写在题面，禁止进入任何能力评测分母"
                % (p["file"], sd, sd_base, ", ".join(p["self_disclosure_ids"][:6])))
    return bad


def main():
    ap = argparse.ArgumentParser(description="全基准集题面即答案横向审计")
    ap.add_argument("--check", action="store_true", help="门禁断言模式（违规 exit 1）")
    ap.add_argument("--json", action="store_true", help="机读输出")
    args = ap.parse_args()

    per_file = analyze()
    if args.json:
        print(json.dumps(per_file, ensure_ascii=False, indent=1))
        return 0

    print("=== 全基准集「题面即答案」横向审计（判据：题面 flag 串 sha256 == flag_sha256）===")
    print()
    print("%-34s %5s %8s %7s" % ("基准集", "题数", "题面即答", "基线"))
    print("-" * 60)
    for p in per_file:
        flag = "  <-- 超标" if p["plaintext_answer"] > p["baseline"] else ""
        print("%-34s %5d %8d %7d%s"
              % (p["file"], p["problems"], p["plaintext_answer"], p["baseline"], flag))
    print("-" * 60)
    tot_p = sum(p["problems"] for p in per_file)
    tot_leak = sum(p["plaintext_answer"] for p in per_file)
    print("合计 %d 集 / %d 题，题面即答案 %d 题" % (len(per_file), tot_p, tot_leak))
    print()
    tot_sd = sum(p.get("self_disclosure_answer", 0) for p in per_file)
    print("=== 第二判据：题面自然语言自曝答案（sha256 反查裸/带壳形态）===")
    print("合计 %d 题；登记基线内 %d 题；未登记集一律零容忍" %
          (tot_sd, sum(p.get("self_disclosure_baseline", 0) for p in per_file)))
    for p in per_file:
        if p.get("self_disclosure_answer"):
            print("  %-46s %d 题（基线 %d）%s" %
                  (p["file"], p["self_disclosure_answer"],
                   p.get("self_disclosure_baseline", 0),
                   "  <-- 已知历史池，禁止用于新跑批" if p["file"] in SELF_DISCLOSURE_BASELINE
                   else "  <-- 超标"))
    print()
    if per_file:
        print("注：crc32 / lcg / ecdsa / execution 等集的 flag 明文经 sha256 比对"
              "与答案指纹不等（那些 flag 是已知输入，如 CRC32 伪造给定原文），故不计入。")

    print()
    print("=== 真求解器口径（命中 - 题面即答案伪解）===")
    for fname, real, total, pct, hit, fake in real_solver_caliber(REPO_ROOT, per_file):
        print("真求解器 %s: %d/%d = %.1f%%（全量命中 %d，伪解 %d）"
              % (fname, real, total, pct, hit, fake))

    bad = violations(per_file)
    if not args.check:
        print()
        print("报数模式：不判定（--check 才是门禁入口）。当前违规 %d 条" % len(bad))
        return 0

    print()
    if bad:
        print("🔴 FAIL —— %d 条违规：" % len(bad))
        for b in bad:
            print("  · %s" % b)
        return 1
    print("✅ PASS —— %d 集 / %d 题，两个判据均在登记基线内"
          "（花括号明文 %d / 自然语言自曝 %d）"
          % (len(per_file), tot_p, tot_leak, tot_sd))
    return 0


if __name__ == "__main__":
    sys.exit(main())
