#!/usr/bin/env python3
"""overnight 三件套的离线自测（不花钱、不联网）。

覆盖的是**口径**，不是跑批：
  - 接口失败/超时不许算成「答错」，必须单列并剔出可计分分母
  - 污染题/硬不可用题不许进分母
  - pick_ids 的并集与去重
每条断言都对应一次真实踩坑（2026-11-07 凌晨：39/40 题 403 被旧口径写成 0/40）。
"""
import json
import os
import subprocess
import sys
import tempfile

HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, HERE)

import overnight_status as st  # noqa: E402

fails = []


def ck(name, cond, extra=""):
    if cond:
        print("ok   %s" % name)
    else:
        print("FAIL %s %s" % (name, extra))
        fails.append(name)


def write_json(path, obj):
    with open(path, "w", encoding="utf-8") as f:
        json.dump(obj, f, ensure_ascii=False)
    return path


def row(pid, **kw):
    base = {"id": pid, "solved": False, "tool_calls": 3, "latency": 10.0,
            "got": "", "api_error_rounds": 0, "timeout_rounds": 0,
            "truncated_rounds": 0, "llm_rounds": [{"finish_reason": "stop"}]}
    base.update(kw)
    return base


def main():
    tmp = tempfile.mkdtemp()
    bad = {"q_hard"}

    # ── classify 口径 ────────────────────────────────────────
    ck("硬不可用题判 NOT_ADMISSIBLE（不进分母）",
       st.classify(row("q_hard"), bad) == "NOT_ADMISSIBLE")
    ck("403 判 API_ERROR 而不是 EMPTY",
       st.classify(row("q1", api_error_rounds=1), bad) == "API_ERROR")
    ck("超时同样判 API_ERROR",
       st.classify(row("q2", timeout_rounds=1), bad) == "API_ERROR")
    ck("解出优先于一切（即使有截断）",
       st.classify(row("q3", solved=True, truncated_rounds=2), bad) == "SOLVED")
    ck("截断判 TRUNCATED",
       st.classify(row("q4", truncated_rounds=1), bad) == "TRUNCATED")
    ck("零工具调用判 NO_TOOL",
       st.classify(row("q5", tool_calls=0), bad) == "NO_TOOL")
    ck("交了答案但不匹配判 WRONG",
       st.classify(row("q6", got="CTF{flag}"), bad) == "WRONG")

    # ── status 汇总表：分母必须剔除接口失败与非计分题 ─────────
    details = [
        row("q_ok"),
        row("q_solved", solved=True, got="CTF{x}"),
        row("q_api", api_error_rounds=1),
        row("q_hard"),
    ]
    res = write_json(os.path.join(tmp, "a.result.json"),
                     {"summary": {"model": "m-A", "models_used": ["m-A"],
                                  "max_tokens": 16384, "solved": 1, "total": 4,
                                  "code_sha256": "deadbeef"},
                      "details": details})
    audit = write_json(os.path.join(tmp, "audit.json"),
                       {"tiers": {"C_contaminated": [], "D_hard_unavailable": ["q_hard"]}})
    out = os.path.join(tmp, "STATUS.md")
    rc = subprocess.run([sys.executable, os.path.join(HERE, "overnight_status.py"),
                         "--results", tmp, "--audit", audit, "--out", out],
                        capture_output=True, text=True, encoding="utf-8")
    ck("status 脚本 rc=0", rc.returncode == 0, rc.stderr[:200])
    md = open(out, encoding="utf-8").read()

    ck("分母 = 4 - 1 接口失败 - 1 硬不可用 = 2", "| 1/2 |" in md, md[:600])
    ck("rate 用可计分分母算（1/2 = 0.500）", "0.500" in md)
    ck("接口失败单列 1", "| 1 |" in md)
    ck("非计分单列 1", "| 1 | 0 |" in md or md.count("| 1 |") >= 2)
    ck("解出清单里出现 q_solved", "q_solved" in md)

    # ── 全部接口失败时，rate 必须显示 "-" 而不是 0.000 ────────
    res2 = write_json(os.path.join(tmp, "b.result.json"),
                      {"summary": {"model": "m-B", "models_used": ["m-B"],
                                   "max_tokens": 16384, "solved": 0, "total": 2},
                       "details": [row("q_api", api_error_rounds=2), row("q_api2", api_error_rounds=1)]})
    out2 = os.path.join(tmp, "S2.md")
    subprocess.run([sys.executable, os.path.join(HERE, "overnight_status.py"),
                    "--results", tmp, "--audit", audit, "--out", out2],
                   capture_output=True, text=True, encoding="utf-8")
    md2 = open(out2, encoding="utf-8").read()
    ck("全接口失败：可计分分母为 0，rate 记 '-' 而非 0.000",
       "| 0/0 | - |" in md2, md2[:600])

    # ── pick_ids ─────────────────────────────────────────────
    f1 = write_json(os.path.join(tmp, "p1.result.json"),
                    {"details": [row("a", solved=True), row("b", timeout_rounds=1)]})
    f2 = write_json(os.path.join(tmp, "p2.result.json"),
                    {"details": [row("a", solved=True), row("c", solved=True)]})
    r = subprocess.run([sys.executable, os.path.join(HERE, "overnight_pick_ids.py"),
                        "--what", "solved", f1, f2],
                       capture_output=True, text=True, encoding="utf-8")
    ck("pick_ids solved 并集去重 = a,c", r.stdout.strip() == "a,c", r.stdout)
    r = subprocess.run([sys.executable, os.path.join(HERE, "overnight_pick_ids.py"),
                        "--what", "timeout", f1, f2],
                       capture_output=True, text=True, encoding="utf-8")
    ck("pick_ids timeout = b", r.stdout.strip() == "b", r.stdout)

    # ── 损坏的结果文件不许让脚本崩 ───────────────────────────
    with open(os.path.join(tmp, "broken.result.json"), "w", encoding="utf-8") as f:
        f.write("{not json")
    out3 = os.path.join(tmp, "S3.md")
    rc = subprocess.run([sys.executable, os.path.join(HERE, "overnight_status.py"),
                         "--results", tmp, "--audit", audit, "--out", out3],
                        capture_output=True, text=True, encoding="utf-8")
    ck("损坏结果文件不会让 status 崩", rc.returncode == 0, rc.stderr[:200])
    ck("损坏文件被列进「结果文件损坏」",
       "结果文件损坏" in open(out3, encoding="utf-8").read())

    total = 18
    print("\nselftest %d/%d" % (total - len(fails), total))
    return 1 if fails else 0


if __name__ == "__main__":
    sys.exit(main())
