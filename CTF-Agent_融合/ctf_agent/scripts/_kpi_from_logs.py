#!/usr/bin/env python3
"""从原始跑批日志机算 KPI，禁止手写数字。

背景（2026-11-11 事故）：
    data/questions_real/_audit/verify_set_20261111.json 里的成功/轮数曾多次手写订正，
    每次都引入新错误（legendre 漏计 15 连成、exciting_inverse 少计 13 成）。
    根因不是"不小心"，而是"跑批 → 人眼读日志 → 手敲进 JSON"这条链上，
    第二、三步不可复算。本脚本把这两步换成机算：审计文件里的数字一律引用本脚本产出。

用法：
    # 扫一个目录下所有 .json（run_single.py / _verify_set.py 格式）
    python scripts/_kpi_from_logs.py --log-dir /tmp

    # 扫 .log（run_single.py 重定向输出格式）
    python scripts/_kpi_from_logs.py --log-dir /tmp/call2

    # 自定义分组（可多次）
    python scripts/_kpi_from_logs.py --log-dir /tmp \
        --group "ei_pre=ei_1.json,ei_2.json,ei2_*.json" \
        --group "ei_fixed=ei3_*.json,ei4_*.json,ei5_*.json,ei6_*.json"

    # 写文件
    python scripts/_kpi_from_logs.py --log-dir /tmp --json /tmp/kpi.json

输出结构：
    {
      "generated_at": "...",
      "log_dir": "...",
      "sources": {"json": N, "log": N},
      "groups": {
        "<name>": {
          "files": [...],
          "runs": int, "solved": int, "rate": float,
          "elapsed": {"min": f, "max": f, "avg": f, "values": [...]},
          "fails": [{"file":..,"elapsed_s":..,"error_category":..}],
          "attachment_missing": [{"file":..,"name":..}]
        }
      },
      "unmatched_files": [...]
    }

判据：
    - JSON 行判成功：str(row["match"]).lower() == "true"
    - LOG 判成功：行 "MATCH True"
    - 附件存在性：LOG 行 "ATT_EXISTS <name> True/False"
    - 攻击链计数：LOG 中 "确定性攻击链命中" / "crypto 攻击链未命中" 的出现次数
"""

from __future__ import annotations

import argparse
import fnmatch
import glob
import json
import os
import re
import sys
from datetime import datetime, timezone, timedelta


# 本项目已知批次的内置分组（无 --group 时生效）。
# 只声明"哪些文件属于哪批"，不声明任何统计结果——结果一律由文件内容算出。
DEFAULT_GROUPS = [
    ("exciting_inverse_pre_dispatch", ["ei_*.json", "ei2_*.json"]),
    ("exciting_inverse_dispatch_fixed", ["ei3_*.json", "ei4_*.json", "ei5_*.json", "ei6_*.json"]),
    ("exciting_inverse_path_fixed", ["ei7_*.json"]),
    ("simplelegendre_all", ["ld_*.json"]),
    ("ezrsa_regression", ["reg_real_crypto_ezrsa_*.json"]),
    ("filterrandom_regression", ["reg_real_crypto_filterrandom_*.json"]),
]


def _is_true(v) -> bool:
    if isinstance(v, bool):
        return v
    return str(v).strip().lower() in ("true", "1", "ok", "yes")


def parse_json_file(path: str) -> list[dict]:
    """解析 run_single.py / _verify_set.py 的 JSON。返回逐条记录。"""
    try:
        with open(path, encoding="utf-8") as f:
            d = json.load(f)
    except Exception as e:
        return [{"_parse_error": f"{type(e).__name__}: {e}"}]

    rows = d.get("rows")
    if not isinstance(rows, list):
        return [{"_parse_error": "no rows[]"}]

    out = []
    for r in rows:
        out.append(
            {
                "id": r.get("id"),
                "match": _is_true(r.get("match")),
                "elapsed_s": r.get("elapsed_s"),
                "error_category": r.get("error_category"),
                "flag": r.get("flag"),
                "source": os.path.basename(path),
            }
        )
    return out


_LOG_PATTERNS = {
    "elapsed": re.compile(r"^ELAPSED_S\s+([\d.]+)\s*$"),
    "flag": re.compile(r"^FLAG\s+(.*)$"),
    "match": re.compile(r"^MATCH\s+(\S+)\s*$"),
    "att_exists": re.compile(r"^ATT_EXISTS\s+(.+?)\s+(True|False)\s*$"),
    "error": re.compile(r'^ERROR\s+(\{.*\})\s*$'),
}


def parse_log_file(path: str) -> list[dict]:
    """解析 run_single.py 重定向的 .log。一文件一条记录。"""
    rec = {
        "id": None,
        "match": False,
        "elapsed_s": None,
        "error_category": None,
        "flag": None,
        "source": os.path.basename(path),
        "chain_hit": 0,
        "chain_miss": 0,
        "attachment_missing": [],
    }
    try:
        with open(path, encoding="utf-8", errors="replace") as f:
            lines = f.readlines()
    except Exception as e:
        return [{"_parse_error": f"{type(e).__name__}: {e}", "source": os.path.basename(path)}]

    for line in lines:
        s = line.rstrip("\n")
        m = _LOG_PATTERNS["elapsed"].match(s)
        if m:
            rec["elapsed_s"] = float(m.group(1))
            continue
        m = _LOG_PATTERNS["flag"].match(s)
        if m:
            val = m.group(1).strip()
            rec["flag"] = None if val in ("None", "") else val
            continue
        m = _LOG_PATTERNS["match"].match(s)
        if m:
            rec["match"] = _is_true(m.group(1))
            continue
        m = _LOG_PATTERNS["att_exists"].match(s)
        if m:
            name, exists = m.group(1), m.group(2)
            if exists == "False":
                rec["attachment_missing"].append(name)
            continue
        m = _LOG_PATTERNS["error"].match(s)
        if m:
            try:
                rec["error_category"] = json.loads(m.group(1)).get("category")
            except Exception:
                pass
            continue
        if "确定性攻击链命中" in s:
            rec["chain_hit"] += 1
        elif "crypto 攻击链未命中" in s:
            rec["chain_miss"] += 1

    if rec["id"] is None:
        rec["id"] = os.path.basename(path).rsplit(".", 1)[0]
    return [rec]


def aggregate(name: str, files: list[str]) -> dict:
    records = []
    parse_errors = []
    for f in files:
        ext = os.path.splitext(f)[1].lower()
        recs = parse_log_file(f) if ext == ".log" else parse_json_file(f)
        for r in recs:
            if "_parse_error" in r:
                parse_errors.append(r)
            else:
                records.append(r)

    runs = len(records)
    solved = sum(1 for r in records if r["match"])
    times = [r["elapsed_s"] for r in records if r["match"] and r["elapsed_s"] is not None]
    fails = [
        {
            "file": r["source"],
            "id": r["id"],
            "elapsed_s": r["elapsed_s"],
            "error_category": r["error_category"],
        }
        for r in records
        if not r["match"]
    ]
    att_missing = []
    for r in records:
        for nm in r.get("attachment_missing") or []:
            att_missing.append({"file": r["source"], "id": r["id"], "missing": nm})

    return {
        "files": [os.path.basename(f) for f in files],
        "runs": runs,
        "solved": solved,
        "rate": round(solved / runs, 4) if runs else 0.0,
        "elapsed": {
            "min": min(times) if times else None,
            "max": max(times) if times else None,
            "avg": round(sum(times) / len(times), 2) if times else None,
            "values": times,
        },
        "fails": fails,
        "attachment_missing": att_missing,
        "parse_errors": parse_errors,
    }


def main() -> int:
    ap = argparse.ArgumentParser(description="从原始跑批日志机算 KPI")
    ap.add_argument("--log-dir", required=True, help="日志目录")
    ap.add_argument(
        "--group",
        action="append",
        default=None,
        metavar="NAME=GLOB1,GLOB2",
        help="自定义分组，可多次；不给则用内置表",
    )
    ap.add_argument("--json", default=None, help="把结果写到该路径（默认只打印 stdout）")
    ap.add_argument("--quiet", action="store_true", help="只输出 JSON，不打印人类可读摘要")
    args = ap.parse_args()

    if not os.path.isdir(args.log_dir):
        print(f"[错误] 目录不存在: {args.log_dir}", file=sys.stderr)
        return 2

    if args.group:
        groups = []
        for spec in args.group:
            if "=" not in spec:
                print(f"[错误] --group 需要 NAME=GLOB 形式，收到: {spec}", file=sys.stderr)
                return 2
            name, pats = spec.split("=", 1)
            groups.append((name.strip(), [p.strip() for p in pats.split(",") if p.strip()]))
    else:
        groups = DEFAULT_GROUPS

    report = {
        "generated_at": datetime.now(timezone(timedelta(hours=8))).isoformat(timespec="seconds"),
        "log_dir": os.path.abspath(args.log_dir),
        "generator": "scripts/_kpi_from_logs.py",
        "groups": {},
        "unmatched_files": [],
    }

    claimed: set[str] = set()
    sources = {"json": 0, "log": 0}

    for name, pats in groups:
        files: list[str] = []
        for p in pats:
            full = p if os.path.isabs(p) else os.path.join(args.log_dir, p)
            files.extend(sorted(glob.glob(full)))
        files = [f for f in files if os.path.isfile(f)]
        for f in files:
            claimed.add(os.path.abspath(f))
            sources["log" if f.lower().endswith(".log") else "json"] += 1
        report["groups"][name] = aggregate(name, files)

    # 只把"看起来像跑批产物"的文件列为未归属，避免 /tmp 里的历史杂物刷屏。
    # 判据：.json 含 "rows" 键，或 .log 含 ELAPSED_S 行。
    def _looks_like_run_artifact(path: str) -> bool:
        try:
            if path.lower().endswith(".json"):
                with open(path, encoding="utf-8") as fh:
                    head = fh.read(4096)
                return '"rows"' in head
            if path.lower().endswith(".log"):
                with open(path, encoding="utf-8", errors="replace") as fh:
                    for _ in range(2000):
                        ln = fh.readline()
                        if not ln:
                            break
                        if ln.startswith("ELAPSED_S"):
                            return True
            return False
        except Exception:
            return False

    all_files = [
        os.path.abspath(f)
        for f in glob.glob(os.path.join(args.log_dir, "*"))
        if os.path.isfile(f) and not f.endswith(".txt")
    ]
    report["unmatched_files"] = sorted(
        os.path.basename(f)
        for f in all_files
        if f not in claimed and _looks_like_run_artifact(f)
    )

    text = json.dumps(report, ensure_ascii=False, indent=2)

    if not args.quiet:
        print("=" * 68)
        print(f"KPI 机算 · {report['log_dir']}")
        print(f"生成时间 {report['generated_at']} · 扫描 json={sources['json']} log={sources['log']}")
        print("=" * 68)
        for name, g in report["groups"].items():
            t = g["elapsed"]
            tdesc = (
                f"{t['min']}/{t['max']}/avg {t['avg']}s" if t["min"] is not None else "—"
            )
            print(f"\n[{name}]")
            print(f"  轮数={g['runs']} 成功={g['solved']} 成功率={g['rate']*100:.1f}% 成功耗时={tdesc}")
            if g["fails"]:
                print(f"  失败 {len(g['fails'])} 条：")
                for f in g["fails"][:10]:
                    print(f"    - {f['file']} {f['elapsed_s']}s {f['error_category']}")
            if g["attachment_missing"]:
                print(f"  附件缺失 {len(g['attachment_missing'])} 条")
            if g["parse_errors"]:
                print(f"  [解析失败] {len(g['parse_errors'])} 条：{g['parse_errors'][:3]}")
        if report["unmatched_files"]:
            print(f"\n未归属任何分组的文件 {len(report['unmatched_files'])} 个：")
            for f in report["unmatched_files"][:10]:
                print(f"  - {f}")
        print("\n" + "=" * 68)

    if args.json:
        with open(args.json, "w", encoding="utf-8", newline="\n") as f:
            f.write(text + "\n")
        print(f"[已写出] {args.json}")
    else:
        print(text)

    return 0


if __name__ == "__main__":
    sys.exit(main())
