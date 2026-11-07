#!/usr/bin/env python3
"""把 overnight 批次的所有结果文件喂给 summarize_external_runs.py，生成统一对照表。

为什么需要它：summarize 要求每个 --run 显式写 `标签:模型:路径`，而批次里有几十个
结果文件、模型名分散在各自的 summary.models_used 里。手工拼容易写错（写错模型名会被
summarize 判红，这是好事），但更重要的是**标签必须能从文件名推出来**，否则早上没法
把表里的一行对回磁盘上的一个文件。

用法：
  python scripts/overnight_collect.py --results <dir> --pool <pool.json> \
      --audit <pool_readiness.json> --out <SUMMARY.md>
"""
import argparse
import glob
import json
import os
import subprocess
import sys


def label_of(path):
    return os.path.basename(path).replace(".result.json", "")


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--results", required=True)
    ap.add_argument("--pool", required=True)
    ap.add_argument("--audit", required=True)
    ap.add_argument("--out", required=True)
    ap.add_argument("--summarizer", default="scripts/summarize_external_runs.py")
    a = ap.parse_args()

    files = sorted(glob.glob(os.path.join(a.results, "*.result.json")))
    files = [p for p in files if "isolation_proof" not in p]
    if not files:
        print("没有结果文件", file=sys.stderr)
        return 2

    args = [sys.executable, a.summarizer,
            "--pool", a.pool, "--audit", a.audit, "--out", a.out]
    skipped = []
    for p in files:
        try:
            d = json.load(open(p, encoding="utf-8"))
        except Exception:
            skipped.append((label_of(p), "json 损坏"))
            continue
        s = d.get("summary") or {}
        models = s.get("models_used") or ([s.get("model")] if s.get("model") else [])
        models = [m for m in models if m]
        if len(models) != 1:
            skipped.append((label_of(p), "模型不唯一: %s" % models))
            continue
        if not (d.get("details") or []):
            skipped.append((label_of(p), "无 details"))
            continue
        args += ["--run", "%s:%s:%s" % (label_of(p), models[0], os.path.abspath(p))]

    r = subprocess.run(args, capture_output=True, text=True, encoding="utf-8")
    sys.stdout.write(r.stdout)
    sys.stderr.write(r.stderr)
    if skipped:
        print("\n[collect] 跳过 %d 个文件：" % len(skipped), file=sys.stderr)
        for name, why in skipped:
            print("  - %s: %s" % (name, why), file=sys.stderr)
    return r.returncode


if __name__ == "__main__":
    sys.exit(main())
