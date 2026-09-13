#!/usr/bin/env python
# -*- coding: utf-8 -*-
"""生成「DasCTF 协议解析」双语言一致性 golden 文件。

真值来源（单一真值源 / single source of truth）：
    西湖论剑真源 ctf_agent/ctfplatform/dasctf.py 的
        - _parse_challenge(item: dict) -> ChallengeInfo
        - _strip_flag_wrapper(flag: str) -> str

Go 侧 internal/ctfplatform（parseChallenge / StripFlagWrapper）由
protocol_golden_test.go 断言与本 golden 逐字段一致。

用法：
    python scripts/gen_protocol_golden.py [--source <ctf_agent 目录>] [--check]

--check：只比对不写入（供 CI 使用），golden 过期则返回非 0。
"""
from __future__ import annotations

import argparse
import dataclasses
import json
import os
import sys
from pathlib import Path

REPO = Path(__file__).resolve().parent.parent
FIXTURES = REPO / "internal" / "ctfplatform" / "testdata" / "protocol_fixtures.json"
GOLDEN = REPO / "internal" / "ctfplatform" / "testdata" / "protocol_golden.json"

DEFAULT_SOURCE = Path(r"E:/Program/西湖论剑/ctf_agent")


def load_truth(source: Path):
    """导入真源模块，返回 (_parse_challenge, _strip_flag_wrapper)。"""
    source = Path(source)
    if not source.is_dir():
        raise SystemExit(f"真源目录不存在: {source}")
    # dasctf.py 内为 `from ctfplatform.base import ...`，故把 ctf_agent 挂到 sys.path
    sys.path.insert(0, str(source))
    try:
        from ctfplatform.dasctf import _parse_challenge, _strip_flag_wrapper  # type: ignore
    except Exception as exc:  # pragma: no cover - 环境问题要显式暴露
        raise SystemExit(f"导入真源失败（Python 环境/依赖问题）: {exc}") from exc
    return _parse_challenge, _strip_flag_wrapper


def build_golden(source: Path) -> dict:
    parse_challenge, strip_flag_wrapper = load_truth(source)
    fixtures = json.loads(FIXTURES.read_text(encoding="utf-8"))

    challenges = []
    for case in fixtures["challenges"]:
        info = parse_challenge(case["item"])
        d = dataclasses.asdict(info)
        # extra 是原始 item 回显（两侧实现细节不同，不参与一致性断言）
        d.pop("extra", None)
        challenges.append({"name": case["name"], **d})

    flags = []
    for raw in fixtures["flags"]:
        flags.append({"input": raw, "expected": strip_flag_wrapper(raw)})

    return {
        "_comment": "由 scripts/gen_protocol_golden.py 依据 Python 真源生成，请勿手改。",
        "source": str(source),
        "challenges": challenges,
        "flags": flags,
    }


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--source", default=str(DEFAULT_SOURCE), help="ctf_agent 目录（含 ctfplatform 包）")
    ap.add_argument("--check", action="store_true", help="只比对不写入")
    args = ap.parse_args()

    golden = build_golden(Path(args.source))

    if args.check:
        if not GOLDEN.exists():
            print(f"[FAIL] golden 不存在: {GOLDEN}")
            return 1
        existing = json.loads(GOLDEN.read_text(encoding="utf-8"))
        if existing.get("challenges") != golden["challenges"] or existing.get("flags") != golden["flags"]:
            print("[FAIL] golden 已过期（真源行为已变），请重跑生成器")
            return 1
        print("[OK] golden 与真源一致")
        return 0

    GOLDEN.parent.mkdir(parents=True, exist_ok=True)
    GOLDEN.write_text(
        json.dumps(golden, ensure_ascii=False, indent=2) + "\n", encoding="utf-8"
    )
    print(f"[OK] golden 已生成: {GOLDEN}")
    print(f"     题目用例 {len(golden['challenges'])} 条 / flag 用例 {len(golden['flags'])} 条")
    print("     ⚠️ 接着必须刷新冻结值，否则 CI 的 golden freeze check 会红：")
    print("        python scripts/check_golden_freeze.py --update")
    return 0


if __name__ == "__main__":
    sys.exit(main())
