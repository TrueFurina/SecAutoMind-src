#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""weekly_audit —— 立尺周审（2026-10-25 就职清单第 1 项机器化）。

定位：守门员全部例行检查压成一条命令。纯测量/纯编排——每项检查都复用
已有门禁，本脚本不新增任何执法逻辑；任一 FAIL 即 exit 1（fail-closed）。

七项检查：
  1 红测试核验    go build ./... + 定向执法测试（honesty/attribution/gate 家族）
  2 白名单腐化    secret_guard --audit-allowlist（0 失败）
  3 门禁健康      secret_guard 全树 verdict == PASS
  4 数据资产断链  A 库 verify 附件源存在性（2026-08-26 归档清理事故的防线）
  5 基准新鲜度    关键基准 JSON 的 mtime 距今 ≤ 阈值（默认 7 天；超期=该重跑，
                    报告不是审计的替代）
  6 归因分桶      最新结果记录的 solved_by 分布（presolve/python_skill/llm；
                    无记录=WARN 不 FAIL——LLM 层尚未跑批时正常）
  7 钩子激活位    .git/hooks/pre-commit 存在且含 secret_guard 调用（防被清空）
  8 记忆完整性    MEMORY.md 行数≥200 + 锚存在 + 双路径检测（2026-10-25 删除事故防线）
  9 报告位卫生    顶层 benchmark_report.json 不得被 mock 残留占据（mock 冒充战绩温床）

用法：
  python scripts/weekly_audit.py           # 人读报告
  python scripts/weekly_audit.py --json    # 机读（CI/观澜消费）
  python scripts/weekly_audit.py --max-age-days 14   # 放宽第 5 项阈值

退出码：0 = 全过/仅 WARN；1 = 任一 FAIL。
"""
from __future__ import annotations

import argparse
import datetime
import glob
import json
import os
import subprocess
import sys

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
PY = sys.executable


def _find_go():
    """PATH → 常见安装位（WorkBuddy/子进程环境常缺 PATH，A 库同款教训）。"""
    import shutil
    p = shutil.which("go")
    if p:
        return p
    for cand in ("E:/tools/go/bin/go.exe", "C:/Program Files/Go/bin/go.exe",
                 "C:/Go/bin/go.exe"):
        if os.path.isfile(cand):
            return cand
    return "go"


GO = _find_go()

# 第 4 项：verify 链依赖的附件源。active=必须在位（缺失=新事故 FAIL）；
# known_lost=已登记永久损失（2026-08-26 归档清理，台账在案）——监控的是
# 变化而非历史：天天红的历史项会让护栏沦为噪音被注释掉（A 库血教训）。
EXTERNAL_DEPS_ACTIVE = [
    os.path.join("CTF-Agent_融合", "ctf_agent", "data", "questions_ext_cybench",
                 "_attachments", "forensics",
                 "hackthebox_cyber_apocalypse_2024_forensics_medium_data_siege",
                 "capture.pcap"),  # pcap_ezrat_chat 端到端依赖
    os.path.join("CTF-Agent_融合", "ctf_agent", "data", "race_attachments",
                 "10735_logbool的附件", "tempdir", "MISC附件", "logbool.pcapng"),  # pcap_bool_blind
]
EXTERNAL_DEPS_KNOWN_LOST = [
    ("hg2022/RSA Attack 2/output.txt", "2026-08-26 归档清理损失，台账在案（verify_hgame2022_rsa 断链已登记）"),
    ("hg2022/RSA Attack 3/output.txt", "同上"),
]
# 第 5 项：基准新鲜度盯的对象
# 只盯"跑出来的报告"，不盯静态题库（benchmark.json=55 题题面输入，天生不变；
# 把输入当报告监控=天天假红——2026-10-25 立尺自纠）
FRESHNESS_TARGETS = [
    "data/ctf_benchmark/all_benchmarks_summary.json",
]
# 第 6 项：结果记录扫描位（runner/Poller 落盘；按 solved_by 键聚合）
RECORD_GLOBS = ["logs/**/poll_records*.json", "data/results/**/*records*.json",
                # A 库路径（CTF-Agent_融合 eval/benchmark.py 跑批；mm_* 多模型目录）
                "CTF-Agent_融合/ctf_agent/data/results/**/benchmark_report.json"]
# 归因值跨路径映射（Go 侧封闭枚举 vs A 库 eval 路径的历史命名）——统计前归一
SOLVED_BY_ALIASES = {"main_agent_llm": "llm", "presolve_llm": "llm"}


def run(cmd, cwd=ROOT, timeout=900):
    try:
        r = subprocess.run(cmd, cwd=cwd, capture_output=True, timeout=timeout,
                           text=True, encoding="utf-8", errors="replace")
        return r.returncode, (r.stdout or "") + (r.stderr or "")
    except subprocess.TimeoutExpired:
        return 124, "timeout"


def check_red_tests():
    rc, out = run([GO, "build", "./..."])
    if rc != 0:
        return "FAIL", "go build 失败: " + out.strip().splitlines()[-1][:120]
    rc, out = run([GO, "test", "-p=1", "-count=1", "./internal/ctfplatform/",
                   "-run", "TestSolvedBy|TestPollRecordSolvedBy|TestClassify|TestReflect"],
                  timeout=600)
    if rc != 0:
        return "FAIL", "执法测试红: " + out.strip().splitlines()[-1][:120]
    return "PASS", "build 绿 + 执法测试绿"


def check_allowlist():
    rc, out = run([PY, "scripts/secret_guard.py", "--audit-allowlist",
                   "--skip-flag-scan"])
    if rc != 0:
        return "FAIL", "白名单存在失效条目（腐化）: " + out.strip()[-120:]
    return "PASS", out.strip().splitlines()[-1] if out.strip() else "白名单空"


def check_gate_health():
    rc, out = run([PY, "scripts/secret_guard.py", "--skip-flag-scan"])
    if rc != 0:
        line = [l for l in out.splitlines() if "指纹命中" in l or "真实凭证命中" in l]
        return "FAIL", "门禁 BLOCK: " + (line[0] if line else "")[:120]
    return "PASS", "全树 verdict=PASS"


def check_external_deps():
    missing = [p for p in EXTERNAL_DEPS_ACTIVE if not os.path.isfile(os.path.join(ROOT, p))]
    if missing:
        return "FAIL", "外部附件源断链(新事故): " + "; ".join(missing)
    detail = "%d 个在位" % len(EXTERNAL_DEPS_ACTIVE)
    if EXTERNAL_DEPS_KNOWN_LOST:
        detail += "；%d 个已登记永久损失(2026-08-26, 仅监控新增)" % len(EXTERNAL_DEPS_KNOWN_LOST)
    return "PASS", detail


def check_freshness(max_age_days):
    problems, ages = [], []
    for rel in FRESHNESS_TARGETS:
        p = os.path.join(ROOT, rel)
        if not os.path.isfile(p):
            problems.append(rel + " 缺失")
            continue
        age = (datetime.datetime.now() - datetime.datetime.fromtimestamp(
            os.path.getmtime(p))).days
        ages.append((rel, age))
        if age > max_age_days:
            problems.append("%s 已 %d 天未刷新（> %d）" % (rel, age, max_age_days))
    if problems:
        return "WARN", "; ".join(problems) + " —— 报告不是审计的替代，该重跑"
    return "PASS", "; ".join("%s=%dd" % (os.path.basename(r), a) for r, a in ages)


def check_attribution():
    buckets = {"presolve": 0, "python_skill": 0, "llm": 0}
    unknown, files = [], 0
    for g in RECORD_GLOBS:
        for p in glob.glob(os.path.join(ROOT, g.replace("/**/", os.sep + "**" + os.sep)),
                           recursive=True):
            files += 1
            try:
                data = json.load(open(p, encoding="utf-8"))
            except Exception:
                continue
            recs = data if isinstance(data, list) else data.get("records", [])
            if not isinstance(recs, list):
                continue
            for rec in recs:
                if not isinstance(rec, dict):
                    continue
                sb = rec.get("solved_by")
                sb = SOLVED_BY_ALIASES.get(sb, sb)
                if rec.get("accepted") or rec.get("flag"):
                    if sb in buckets:
                        buckets[sb] += 1
                    elif sb is None:
                        unknown.append("缺 solved_by: " + str(rec.get("challenge_id", "?")))
                    else:
                        unknown.append("未登记归因 %r: %s" % (sb, rec.get("challenge_id", "?")))
    if files == 0:
        return "WARN", "无结果记录可审（LLM 层跑批后自动生效）"
    if unknown:
        return "FAIL", "归因缺失/未登记 %d 条: %s" % (
            len(unknown), "; ".join(unknown[:3]))
    total = sum(buckets.values())
    if total == 0:
        return "WARN", "记录存在但零解出（无法分桶校验）"
    return "PASS", "解出 %d 条：presolve=%d python_skill=%d llm=%d" % (
        total, buckets["presolve"], buckets["python_skill"], buckets["llm"])


def check_hook_live():
    p = os.path.join(ROOT, ".git", "hooks", "pre-commit")
    if not os.path.isfile(p):
        return "FAIL", ".git/hooks/pre-commit 激活位缺失（门禁被清空）"
    body = open(p, encoding="utf-8", errors="ignore").read()
    if "secret_guard" not in body:
        return "FAIL", "激活钩子不含 secret_guard 调用（门禁脱钩）"
    return "PASS", "激活位在且含门禁调用"


# 第 8 项背景：2026-10-25 MEMORY.md（352 行）被删，靠回收站救回（破晓处置）。
# 机检化：行数硬下限 + 标题锚存在 + 双路径并存检测（.workbuddy/ 旧版残留）。
MEMORY_FILE = os.path.join(".workbuddy-ai", "memory", "MEMORY.md")
MEMORY_MIN_LINES = 200  # 现值 352；跌破即疑遭删/截断（回收站先查，禁急重构）


def check_memory_integrity():
    p = os.path.join(ROOT, MEMORY_FILE)
    if not os.path.isfile(p):
        return "FAIL", "MEMORY.md 缺失——先查回收站恢复（2026-10-25 事故先例），禁急重构"
    n = sum(1 for _ in open(p, encoding="utf-8", errors="ignore"))
    if n < MEMORY_MIN_LINES:
        return "FAIL", "MEMORY.md 仅 %d 行（<%d）——疑删/截断，查回收站" % (n, MEMORY_MIN_LINES)
    head = open(p, encoding="utf-8", errors="ignore").read(400)
    if "KPI" not in head and "真值" not in head:
        return "WARN", "MEMORY.md 头部缺 KPI/真值锚——内容疑被替换（人工复核）"
    if os.path.isdir(os.path.join(ROOT, ".workbuddy", "memory")):
        return "WARN", "%d 行在位；但 .workbuddy/memory/ 旧路径并存（配置漂移，建议合并清理）" % n
    return "PASS", "%d 行在位" % n


# 第 9 项背景：2026-10-25 顶层 benchmark_report.json 被 mock 残留占据，真实报告在
# mm_* 子目录——真实落盘位与 mock 覆盖位混用是「mock 冒充战绩」病史的温床。
BENCH_REPORT = os.path.join("CTF-Agent_融合", "ctf_agent", "data", "results",
                            "benchmark_report.json")


def check_report_hygiene():
    p = os.path.join(ROOT, BENCH_REPORT)
    if not os.path.isfile(p):
        return "PASS", "顶层报告位空置（无混用）"
    try:
        mode = json.load(open(p, encoding="utf-8")).get("mode", "?")
    except Exception:
        return "WARN", "顶层报告 JSON 损坏"
    if mode == "mock":
        return "WARN", "顶层落盘位被 mock 残留占据（mode=mock）——真实跑批应另落 mm_* 类目录，mock 残留宜清"
    return "PASS", "顶层 mode=%s" % mode


CHECKS = [
    ("红测试核验", check_red_tests),
    ("白名单腐化", check_allowlist),
    ("门禁健康", check_gate_health),
    ("数据资产断链", check_external_deps),
    ("钩子激活位", check_hook_live),
    ("记忆完整性", check_memory_integrity),
    ("报告位卫生", check_report_hygiene),
]


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--json", action="store_true")
    ap.add_argument("--max-age-days", type=int, default=7)
    args = ap.parse_args()

    results = []
    for name, fn in CHECKS:
        results.append((name, *fn()))
    results.append(("基准新鲜度", *check_freshness(args.max_age_days)))
    results.append(("归因分桶", *check_attribution()))

    failed = [r for r in results if r[1] == "FAIL"]
    if args.json:
        print(json.dumps({
            "as_of": datetime.datetime.now().isoformat(timespec="seconds"),
            "checker": "立尺周审",
            "results": [{"name": n, "verdict": v, "detail": d} for n, v, d in results],
            "verdict": "FAIL" if failed else ("WARN" if any(r[1] == "WARN" for r in results) else "PASS"),
        }, ensure_ascii=False, indent=1))
    else:
        print("=" * 60)
        print("立尺周审 · %s" % datetime.datetime.now().strftime("%Y-%m-%d %H:%M"))
        print("=" * 60)
        for n, v, d in results:
            mark = {"PASS": "✅", "WARN": "⚠️ ", "FAIL": "🔴"}[v]
            print("  %s [%s] %s" % (mark, v, n))
            print("        %s" % d)
        print("-" * 60)
        print("总判定: %s" % ("FAIL" if failed else "PASS/WARN"))
    return 1 if failed else 0


if __name__ == "__main__":
    sys.exit(main())
