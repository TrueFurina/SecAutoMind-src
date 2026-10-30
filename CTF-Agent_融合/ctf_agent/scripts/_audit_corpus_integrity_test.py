#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""`_audit_corpus_integrity` 附件解析回归测试。

背景（2026-10-26 实锤）：
  `_resolve_attachment` 原用 `c.is_file()` 判定，于是**目录形态的附件**被误判为缺失。
  `ext_gctf2022_enigma` 声明 7 个附件，其中 `enigma/`（7 个源文件）与 `messages/`
  （7 个日期目录，含 may_12_2022/flag.ciphertext.txt + flag.fernet.txt）都是目录，
  被 `missing_attachments` 报成"缺 2 项"——实际附件完整。
  该误报会让 `require_payload=True` 把健康题剔出分母。

本测试锁住：
  ① 目录形态附件 → 不算缺失
  ② 文件形态附件 → 不算缺失
  ③ 真不存在的附件 → 必须算缺失（不能因本次修改而放过真缺失）
  ④ 混合场景：缺一个就报一个（逐文件语义不变）
  ⑤ 回归：真实数据 ext_gctf2022_enigma 不再被报缺失

用法：python scripts/_audit_corpus_integrity_test.py
退出码：0 = 全部通过；1 = 有用例失败。
"""
from __future__ import annotations

import json
import shutil
import sys
import tempfile
from pathlib import Path

CTF_ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(CTF_ROOT))

from scripts._audit_corpus_integrity import missing_attachments  # noqa: E402


def main() -> int:
    results: list[tuple[str, bool, str]] = []
    tmp = Path(tempfile.mkdtemp(prefix="aci_test_"))
    try:
        (tmp / "file.txt").write_text("hello", encoding="utf-8")
        (tmp / "subdir").mkdir()
        (tmp / "subdir" / "inner.txt").write_text("x", encoding="utf-8")
        qpath = tmp / "q.json"

        def run(name: str, atts: list[str], expect_missing: list[str]) -> None:
            q = {"id": name, "attachments": atts}
            got = missing_attachments(q, qpath, tmp, tmp)
            results.append((name, got == expect_missing, f"expect={expect_missing} got={got}"))

        run("case_dir", ["subdir"], [])
        run("case_file", ["file.txt"], [])
        run("case_missing", ["nope.bin"], ["nope.bin"])
        run("case_mixed", ["file.txt", "subdir", "nope.bin"], ["nope.bin"])

        # ⑥ 空目录不算有效附件（2026-10-26 二次修正）
        #    单用 exists() 会让空目录蒙混过关——与 attachment_available 的
        #    "空壳附件"是同一类漏洞。目录必须内含至少一个文件才算存在。
        (tmp / "empty_dir").mkdir(exist_ok=True)
        q3 = {"id": "emptydir", "attachments": ["empty_dir"]}
        got = missing_attachments(q3, qpath, tmp, tmp)
        results.append(("empty_dir_missing", got == ["empty_dir"],
                        f"expect=['empty_dir'] got={got}"))
        # ⑤ 目录形态附件的等价场景（不依赖真实数据）
        #    ⚠️ 原先此处读真实题 ext_gctf2022_enigma.json 做回归，但
        #    `ctf_agent/.gitignore:113` 把 `/data/*` 整体忽略 → CI 检出里该文件不存在，
        #    用例会被 `if is_file()` 静默跳过（= 假绿，正是 AGENTS 禁的形态）。
        #    改为用临时目录自造同构结构：题面声明 2 个目录附件，其中一个目录内有真实文件。
        (tmp / "att_a" / "messages").mkdir(parents=True, exist_ok=True)
        (tmp / "att_a" / "messages" / "flag.ciphertext.txt").write_text("X" * 64, encoding="utf-8")
        (tmp / "att_a" / "enigma").mkdir(exist_ok=True)
        (tmp / "att_a" / "enigma" / "machine.cc").write_text("// rotors", encoding="utf-8")
        q2 = {"id": "dirlike", "attachments": ["att_a/enigma", "att_a/messages"]}
        got = missing_attachments(q2, qpath, tmp, tmp)
        results.append(("dirlike_real_files", got == [],
                        f"expect=[] got={got}"))
    finally:
        # 清理失败不得影响判定结果：某些运行环境（本仓库 agent 沙箱）会注入审计钩子，
        # 在 shutil.rmtree 上抛 PermissionError，**即使传了 ignore_errors=True**
        # （钩子在异常分发前触发，ignore_errors 拦不住）。实测 20 次跑出 2 次假红。
        # 临时目录交给系统回收，判定以断言结果为准。
        try:
            shutil.rmtree(tmp, ignore_errors=True)
        except Exception:  # noqa: BLE001 - 清理失败与用例正确性无关
            pass

    failed = [r for r in results if not r[1]]
    for name, ok, msg in results:
        print(f"{'PASS' if ok else 'FAIL'}  {name:14} {msg}")
    print(f"\n{len(results) - len(failed)}/{len(results)} 通过")
    return 1 if failed else 0


if __name__ == "__main__":
    sys.exit(main())
