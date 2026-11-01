#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""ctf_ci_regression.py —— CI 回归闸门封装（future-ready，待接入 .github/workflows/ci.yml）

把 ctf_arena_batch.py（自包含靶场批量回归器）包成 CI 友好的「两段式」工作流：

  - record：在主分支 / 发布点跑全量回归，把结果存为基线（artifact 或提交）。
  - check ：在 PR 跑全量回归，与基线对比；退化超闸门即红（exit 3）。

为何单独成脚本、不直接改 ci.yml：
  当前 .github/workflows/ci.yml 被并行会话占用（主树 docs/race-day-card 有 148 处未提交改动）。
  本脚本作为「待接线产物」先行落地；CI 释放后，把下方「ci.yml 接线片段」粘进流水线即可，
  无需改动 ctf_arena_batch.py 本身。

与既有 merge_gate.py 的关系（避免重复造轮子）：
  - merge_gate.py 已在 §五 落地「解题数只升不降 + sha256 校验」的聚合门禁（exit 0/1）。
  - 本脚本走 ctf_arena_batch.py 的「逐实例退化分类」粒度（stable/new_solved/regressed/new_broken/unknown），
    二者互补：merge_gate 管总量不回退，本脚本管单题能力倒退。接哪道闸由 CI 所有者决定。

manifest 约定：
  实例 list（详见 ctf_arena_batch.py 头部）。本封装支持两个令牌——
    - {{PY}} ：运行时替换为当前解释器绝对路径，跨平台可跑（不硬编码解释器）。
    - {{CWD}}：运行时替换为 manifest 所在目录绝对路径，solver 可用相对路径、
              清单与 solver 同目录即跨平台（不写死绝对路径）。

用法：
  python3 ctf_ci_regression.py record --manifest M.json --baseline baseline.json
  python3 ctf_ci_regression.py check  --manifest M.json --baseline baseline.json [--gate N]
  python3 ctf_ci_regression.py --self-test

ci.yml 接线片段（释放后启用）：
  # 主分支：记录基线（产物上传为 artifact，PR 阶段下载）
  - name: record regression baseline
    if: github.ref == 'refs/heads/main'
    run: python3 scripts/ctf_ci_regression.py record \
         --manifest scripts/arena_manifest.json \
         --baseline .ci/arena_baseline.json
  # PR：与基线比对，退化即红
  - name: regression check
    if: github.event_name == 'pull_request'
    run: python3 scripts/ctf_ci_regression.py check \
         --manifest scripts/arena_manifest.json \
         --baseline .ci/arena_baseline.json --gate 0
"""
from __future__ import annotations

import argparse
import json
import os
import subprocess
import sys
import tempfile

HERE = os.path.dirname(os.path.abspath(__file__))
ARENA = os.path.join(HERE, "ctf_arena_batch.py")
PY = sys.executable

# 退出码语义与 ctf_arena_batch.py 对齐：
# 0=全绿/退化在闸门内；1=运行错误；2=有题 UNSOLVED；3=退化超闸门（最高优先级）。

MANIFEST_TOKEN = "{{PY}}"
CWD_TOKEN = "{{CWD}}"


def _materialize_manifest(manifest_path: str) -> str:
    """读 manifest，把令牌替换为运行时真实值，写临时文件后返回路径。

    支持两种令牌：
      - {{PY}} ：替换为当前解释器绝对路径，使清单跨平台可跑（不硬编码解释器）。
      - {{CWD}}：替换为 manifest 所在目录绝对路径，使 solver 用相对路径、
                 清单与 solver 同目录即可跨平台，不必写死绝对路径。

    实现要点：先 json.load 原清单，再对字符串值做令牌替换，最后 json.dump 写回——
    这样 Windows 反斜杠路径（C:\\Users\\...）会被 json.dump 正确转义，
    不会污染 JSON 语法（曾踩坑：直接文本替换会把 \\U 变成非法 \\escape）。
    """
    with open(manifest_path, encoding="utf-8") as fh:
        data = json.load(fh)

    manifest_dir = os.path.dirname(os.path.abspath(manifest_path))

    def _subst(obj):
        if isinstance(obj, str):
            s = obj.replace(MANIFEST_TOKEN, PY).replace(CWD_TOKEN, manifest_dir)
            return s
        if isinstance(obj, list):
            return [_subst(x) for x in obj]
        if isinstance(obj, dict):
            return {k: _subst(v) for k, v in obj.items()}
        return obj

    data = _subst(data)
    tmp = os.path.join(tempfile.gettempdir(), "arena_manifest_%d.json" % os.getpid())
    with open(tmp, "w", encoding="utf-8") as fh:
        json.dump(data, fh, ensure_ascii=False, indent=2)
    return tmp


def _run_arena(extra: list) -> int:
    if not os.path.exists(ARENA):
        print("[ci] 找不到 ctf_arena_batch.py: %s" % ARENA, file=sys.stderr)
        return 1
    cmd = [PY, ARENA] + extra
    proc = subprocess.run(cmd)
    return proc.returncode


def cmd_record(manifest: str, baseline: str) -> int:
    tmp = _materialize_manifest(manifest)
    ledger = baseline + ".ledger.jsonl"
    return _run_arena(["--manifest", tmp,
                       "--save-baseline", baseline,
                       "--out", ledger])


def cmd_check(manifest: str, baseline: str, gate: int) -> int:
    tmp = _materialize_manifest(manifest)
    return _run_arena(["--manifest", tmp,
                       "--baseline", baseline,
                       "--gate-regression", str(gate)])


def main(argv=None) -> int:
    ap = argparse.ArgumentParser(
        description="CI 回归闸门封装（包裹 ctf_arena_batch.py）")
    sub = ap.add_subparsers(dest="cmd")

    pr = sub.add_parser("record", help="跑全量回归并存基线")
    pr.add_argument("--manifest", required=True, help="实例清单 JSON")
    pr.add_argument("--baseline", required=True, help="基线输出路径（JSON）")

    pc = sub.add_parser("check", help="与基线比对，退化超闸门即红")
    pc.add_argument("--manifest", required=True, help="实例清单 JSON")
    pc.add_argument("--baseline", required=True, help="历史基线 JSON")
    pc.add_argument("--gate", type=int, default=0, help="退化容忍上限，超出 → exit 3")

    ap.add_argument("--self-test", action="store_true",
                    help="委托 ctf_arena_batch.py 跑仪器自检")
    args = ap.parse_args(argv)

    if args.self_test:
        return _run_arena(["--self-test"])
    if args.cmd == "record":
        return cmd_record(args.manifest, args.baseline)
    if args.cmd == "check":
        return cmd_check(args.manifest, args.baseline, args.gate)

    ap.print_help()
    return 1


if __name__ == "__main__":
    sys.exit(main())
