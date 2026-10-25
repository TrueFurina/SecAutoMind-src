#!/usr/bin/env python
# -*- coding: utf-8 -*-
"""ctf-agent skills 双写同步：仓内真值源 → 实战引擎目录。

背景（2026-10-25 实测）：`CTF-Agent_融合/ctf_agent/skills/` 与
`/e/Program/ctf-agent/skills/` 经 `diff -rq` 验证 **内容完全一致**，但没有任何自动
同步机制——是手工拷贝。这意味着新增/修改 skill 只放一边，赛时引擎就看不到（或
仓内门禁看到的与实战不一致）。本脚本把"两边必须一致"变成可机验的门禁。

非破坏性设计（用户偏好：归位整合而非删除）：
  - 只从 SRC 覆盖到 DST，且只传 skill 资产（*.py / *.json / *.md）
  - **绝不删除 DST 独有文件**，只报告 `only_in_dst`
  - 自动跳过 `__pycache__` / `.pyc`

用法：
  python scripts/sync_ctf_agent_skills.py            # 执行同步
  python scripts/sync_ctf_agent_skills.py --check    # 只比对，不落盘（门禁用）
  python scripts/sync_ctf_agent_skills.py --json     # 机器可读

退出码：0 = 一致（或同步完成）；1 = --check 下发现不一致 / 同步失败。
"""
from __future__ import annotations

import argparse
import filecmp
import json
import shutil
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
SRC = ROOT / "CTF-Agent_融合" / "ctf_agent" / "skills"
DEFAULT_DST = Path(r"E:\Program\ctf-agent\skills")
ASSET_SUFFIX = {".py", ".json", ".md"}
SKIP_DIRS = {"__pycache__"}


def collect(d: Path) -> dict[str, Path]:
    """收集 skill 资产相对路径 → 绝对路径。"""
    out: dict[str, Path] = {}
    if not d.is_dir():
        return out
    for p in d.rglob("*"):
        if any(part in SKIP_DIRS for part in p.relative_to(d).parts):
            continue
        if p.is_file() and p.suffix in ASSET_SUFFIX:
            out[str(p.relative_to(d)).replace("\\", "/")] = p
    return out


def diff_state(src: dict[str, Path], dst: dict[str, Path]) -> dict:
    only_src, only_dst, changed = [], [], []
    for rel, sp in sorted(src.items()):
        dp = dst.get(rel)
        if dp is None:
            only_src.append(rel)
        elif not filecmp.cmp(sp, dp, shallow=False):
            changed.append(rel)
    for rel in sorted(dst):
        if rel not in src:
            only_dst.append(rel)
    return {"only_in_src": only_src, "only_in_dst": only_dst,
            "changed": changed, "in_sync": not (only_src or changed)}


def main() -> int:
    ap = argparse.ArgumentParser(description="ctf-agent skills 双写同步")
    ap.add_argument("--dst", default=str(DEFAULT_DST), help="实战引擎 skills 目录")
    ap.add_argument("--check", action="store_true", help="只比对不落盘（门禁用）")
    ap.add_argument("--require-dst", action="store_true",
                    help="目标目录不存在时视为 FAIL（赛前本机严格判定；CI 上不加此参数以免假红）")
    ap.add_argument("--json", action="store_true", help="JSON 输出")
    args = ap.parse_args()

    src, dst_dir = collect(SRC), Path(args.dst)
    if not SRC.is_dir():
        print(f"❌ 真值源不存在: {SRC}")
        return 1
    if not dst_dir.is_dir():
        # 环境不适用 ≠ 不一致：CI/换机上目标目录不存在是常态，默认 SKIP（rc=0），
        # 否则"双写门禁"在 CI 上恒红 = 假红事故。赛前本机要严格判定用 --require-dst。
        print(f"⏭️  实战引擎目录不存在: {dst_dir} —— SKIP"
              + ("（--require-dst：本机赛前必须确认，视为 FAIL）" if args.require_dst else ""))
        if args.json:
            print(json.dumps({"conclusion": "FAIL" if args.require_dst else "SKIP",
                              "reason": "dst_missing", "src_files": len(src),
                              "dst": str(dst_dir)}, ensure_ascii=False, indent=1))
        return 1 if args.require_dst else 0

    dst = collect(dst_dir)
    st = diff_state(src, dst)

    if args.check:
        if st["in_sync"] and not st["only_in_dst"]:
            print(f"✅ 双写一致：{len(src)} 个 skill 资产两边逐字节相同")
        else:
            print(f"❌ 双写不一致（本次失败点：skill 只放了一边）")
            for k in ("only_in_src", "changed", "only_in_dst"):
                for rel in st[k]:
                    print(f"   - {k}: {rel}")
        if args.json:
            print(json.dumps({"conclusion": "PASS" if st["in_sync"] and not st["only_in_dst"]
                              else "FAIL", **st}, ensure_ascii=False, indent=1))
        return 0 if (st["in_sync"] and not st["only_in_dst"]) else 1

    copied = 0
    for rel in st["only_in_src"] + st["changed"]:
        sp, dp = src[rel], dst_dir / rel
        dp.parent.mkdir(parents=True, exist_ok=True)
        shutil.copy2(sp, dp)
        copied += 1
    print(f"== 同步完成：复制/覆盖 {copied} 个文件（SRC {len(src)} → {dst_dir}）==")
    if st["only_in_dst"]:
        # 不用 f-string 内嵌 dict 下标（{'...'} 在 Python<3.12 是语法错误，CI 用的是 3.12 边界）
        extra = st["only_in_dst"]
        print("⚠️  DST 独有 " + str(len(extra)) + " 个文件未删除（非破坏性）："
              + "、".join(extra[:5]))
    if args.json:
        print(json.dumps({"conclusion": "OK", "copied": copied, **st},
                         ensure_ascii=False, indent=1))
    return 0


if __name__ == "__main__":
    sys.exit(main())
