#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""跨语言 golden 的「冻结校验」——CI 可跑，不需要真源仓库。

背景（2026-09-13 深度复检发现）：
    `gen_protocol_golden.py --check` 能校验「golden ↔ 真源」，但 CI 环境里**没有真源仓库**
    （西湖论剑 ctf_agent），因此该项一直没有接线。结果是：CI 只跑 `go test`
    （校验 Go ↔ golden），真源变更导致 golden 静默过期时，CI 依旧全绿。

本脚本用哈希冻结 golden 文件，补上这条：
    · 任何"未重跑生成器的手改"都会在 CI 暴露；
    · 真正重跑生成器后，须跑 `--update` 刷新冻结值（本地做，因为只有本地有真源）。

用法：
    python scripts/check_golden_freeze.py            # 校验（CI 步骤）
    python scripts/check_golden_freeze.py --update    # 用真源重跑生成器后刷新
退出码：0 = 一致；1 = golden 被改动且未刷新。
"""
from __future__ import annotations

import argparse
import hashlib
import json
import pathlib
import sys

try:
    sys.stdout.reconfigure(encoding="utf-8")
except Exception:
    pass

REPO = pathlib.Path(__file__).resolve().parent.parent
TESTDATA = REPO / "internal" / "ctfplatform" / "testdata"
FREEZE = TESTDATA / "golden_freeze.json"
FILES = ("protocol_fixtures.json", "protocol_golden.json", "request_golden.json")


def sha256(p: pathlib.Path) -> str:
    """按**规范化行尾（CRLF→LF）**计算哈希。

    原因：本仓 Windows 工作区是 CRLF、git 入库是 LF，CI（Linux）checkout 得到 LF。
    若直接用工作区字节算哈希，同一份文件在本地与 CI 的哈希必然不同 —— 冻结校验会在
    CI 上无条件失败（2026-09-13 实测踩到：本地 PASS、CI `failure`）。规范化后两侧一致。
    """
    data = p.read_bytes().replace(b"\r\n", b"\n")
    return hashlib.sha256(data).hexdigest()


def current() -> dict:
    out = {}
    for name in FILES:
        p = TESTDATA / name
        if p.is_file():
            out[name] = sha256(p)
    return out


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--update", action="store_true", help="刷新冻结值（重跑生成器后执行）")
    args = ap.parse_args()

    cur = current()
    if args.update:
        # newline="\n" 必须显式指定：否则 Windows 下会把 LF 写成 CRLF，
        # 与 Linux CI 生成的 golden 产生行尾差异（sha256 已做 LF 归一化，但文件本身不该被改写）。
        FREEZE.write_text(json.dumps(cur, ensure_ascii=False, indent=2) + "\n", encoding="utf-8", newline="\n")
        print("[OK] 已刷新 golden 冻结值：%s" % FREEZE.relative_to(REPO))
        for k, v in cur.items():
            print("     %s  %s" % (v[:16], k))
        return 0

    if not FREEZE.is_file():
        print("[FAIL] 缺少冻结文件 %s —— 请先跑 --update" % FREEZE.relative_to(REPO))
        return 1

    try:
        frozen = json.loads(FREEZE.read_text(encoding="utf-8"))
    except Exception as exc:
        print("[FAIL] 冻结文件解析失败: %s" % exc)
        return 1

    problems = []
    for name in FILES:
        if name not in frozen:
            continue  # 允许后续新增文件（宁漏勿误：旧冻结不含新文件不算篡改）
        if name not in cur:
            problems.append("%s 已丢失（冻结值存在但文件不在）" % name)
        elif cur[name] != frozen[name]:
            problems.append("%s 内容已变（frozen=%s… actual=%s…）"
                            % (name, frozen[name][:12], cur[name][:12]))

    print("=" * 62)
    print("跨语言 golden 冻结校验")
    print("=" * 62)
    for name in FILES:
        if name in cur:
            mark = "OK" if (name in frozen and cur[name] == frozen[name]) else "CHANGED"
            print("  [%-7s] %s" % (mark, name))
    print("-" * 62)
    if problems:
        print("[FAIL] golden 与冻结值不一致：")
        for p in problems:
            print("  - %s" % p)
        print("\n  这意味着有人改了 golden/fixtures 而没有重跑生成器（或改了却没更新冻结）。")
        print("  正解：本地用真源重跑 `python scripts/gen_protocol_golden.py --source <ctf_agent>`，")
        print("        再跑 `python scripts/check_golden_freeze.py --update` 刷新冻结值，一起提交。")
        print("=" * 62)
        return 1
    print("[PASS] golden 与冻结值一致（CI 侧可判定：未被手改）。")
    print("      注：golden↔真源的一致性需本地跑 gen_protocol_golden.py --check（CI 无真源仓库）。")
    print("=" * 62)
    return 0


if __name__ == "__main__":
    sys.exit(main())
