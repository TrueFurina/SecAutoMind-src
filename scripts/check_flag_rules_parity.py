#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""跨语言「占位符判据」一致性门禁（Go 引擎 ⇄ Python 门禁）。

## 为什么需要它（2026-10-25 复盘实锤）

同一个判据在两个语言里各写一份，靠人手抄，**抄的那一刻就开始漂**：

| | Go `presolve_registry.go` | Python `secret_guard.py`（首版，手抄） |
|---|---|---|
| 占位词 | 19 个 | 13 个（漏 7 个、自造 `demo`） |
| 低信息量检查 | `isLowInformationContent` | **没有** |

后果不是抽象的：Python 侧把 `DASCTF{placeholder}` / `DASCTF{todo}` 判成
「真赛事品牌」，而 Go 引擎在同一条串上判「不是 flag」——同一条数据，两套结论。

这一轮修掉的 53 条「假真泄露」是同一个病根的另一个切面（brand 维度没有共享判据）。
所以不再靠「记得同步」，改成**机验**：解析 Go 源码里的三样东西，与 Python 常量逐项比。

## 判据（四项，全部来自 Go 源码文本，不需要 go 工具链）

1. `flagPlaceholderRe` 的正则字面量 == `secret_guard.PLACEHOLDER_BODY_RE.pattern`
2. `flagPlaceholderWords` 的键集 == `secret_guard.PLACEHOLDER_WORDS`
3. `isLowInformationContent` 存在，且其分隔符集合 == Python `is_low_information_content` 用的集合
4. 上面任一项取不到（源码被改名/重构）→ **fail-closed 报红**，不许静默放过

## 用法
    python scripts/check_flag_rules_parity.py            # 人类可读
    python scripts/check_flag_rules_parity.py --check     # 门禁断言（exit 1 = 漂移）
    python scripts/check_flag_rules_parity.py --json      # 机读
"""
from __future__ import annotations

import argparse
import json
import os
import re
import sys

REPO_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
GO_REL = os.path.join("internal", "ctfplatform", "presolve_registry.go")

# Python 侧 is_low_information_content 认作「分隔符」的字符（改这里也要改 Go）。
PY_LOW_INFO_SEPARATORS = {"_", "-", " ", "."}


def parse_go_rules(src: str) -> dict:
    """从 Go 源码文本里抽出占位符判据。抽不到就抛错（调用方必须 fail-closed）。"""
    m = re.search(r"var\s+flagPlaceholderRe\s*=\s*regexp\.MustCompile\(`([^`]*)`\)", src)
    if not m:
        raise ValueError("找不到 `var flagPlaceholderRe = regexp.MustCompile(`...`)`")

    m_words = re.search(r"var\s+flagPlaceholderWords\s*=\s*map\[string\]bool\{(.*?)\n\}", src, re.S)
    if not m_words:
        raise ValueError("找不到 `var flagPlaceholderWords = map[string]bool{...}`")
    words = set(re.findall(r'"([a-z0-9]+)"\s*:\s*true', m_words.group(1)))
    if not words:
        raise ValueError("flagPlaceholderWords 解析出 0 个词（格式变了？）")

    m_fn = re.search(r"func\s+isLowInformationContent\s*\(([^)]*)\)\s*bool\s*\{(.*?)\n\}", src, re.S)
    if not m_fn:
        raise ValueError("找不到 `func isLowInformationContent`")
    body = m_fn.group(2)
    # Go 写法：if r == '_' || r == '-' || ... {
    seps = set(re.findall(r"r\s*==\s*'(.)'", body))
    if not seps:
        raise ValueError("isLowInformationContent 里解析不到分隔符字符集")

    return {"pattern": m.group(1), "words": words, "separators": seps}


def _load_py_side():
    sys.path.insert(0, os.path.join(REPO_ROOT, "scripts"))
    import secret_guard as sg  # noqa: E402
    return sg


def compare(go: dict, py_pattern: str, py_words, py_seps) -> list[str]:
    """纯函数：返回漂移清单（空 = 一致）。便于在不改源码的前提下做变异测试。"""
    out: list[str] = []
    if go["pattern"] != py_pattern:
        out.append(f"正则不一致：Go=`{go['pattern']}` / Py=`{py_pattern}`")
    go_words, py_words = set(go["words"]), set(py_words)
    if go_words != py_words:
        missing = sorted(go_words - py_words)
        extra = sorted(py_words - go_words)
        out.append(f"占位词表不一致：Py 漏 {missing}；Py 多 {extra}")
    go_seps, py_seps = set(go["separators"]), set(py_seps)
    if go_seps != py_seps:
        out.append(f"低信息量分隔符集不一致：Go={sorted(go_seps)} / Py={sorted(py_seps)}")
    return out


def check(repo_root: str = REPO_ROOT) -> tuple[list[str], dict]:
    """执行一致性检查。返回 (violations, detail)。"""
    path = os.path.join(repo_root, GO_REL)
    try:
        src = open(path, encoding="utf-8").read()
    except Exception as exc:  # noqa: BLE001
        return [f"读不到 Go 源码 {GO_REL}：{exc}"], {}
    try:
        go = parse_go_rules(src)
    except ValueError as exc:
        # fail-closed：判据取不到时必须报红，不许「解析失败 = 没问题」
        return [f"Go 判据解析失败（fail-closed，不许放过）：{exc}"], {}

    sg = _load_py_side()
    violations = compare(go, sg.PLACEHOLDER_BODY_RE.pattern,
                         sg.PLACEHOLDER_WORDS, PY_LOW_INFO_SEPARATORS)
    detail = {
        "go_pattern": go["pattern"],
        "py_pattern": sg.PLACEHOLDER_BODY_RE.pattern,
        "go_words": sorted(go["words"]),
        "py_words": sorted(sg.PLACEHOLDER_WORDS),
        "go_low_info_separators": sorted(go["separators"]),
        "py_low_info_separators": sorted(PY_LOW_INFO_SEPARATORS),
        "n_go_words": len(go["words"]),
        "n_py_words": len(sg.PLACEHOLDER_WORDS),
    }
    return violations, detail


def main(argv=None) -> int:
    ap = argparse.ArgumentParser(description="Go/Python 占位符判据一致性门禁")
    ap.add_argument("--check", action="store_true", help="门禁断言（exit 1 = 漂移）")
    ap.add_argument("--json", action="store_true", help="机读输出")
    ap.add_argument("--repo-root", default=REPO_ROOT)
    args = ap.parse_args(argv)

    violations, detail = check(args.repo_root)
    if args.json:
        print(json.dumps({"ok": not violations, "violations": violations, "detail": detail},
                         ensure_ascii=False, indent=1))
    else:
        if violations:
            print("❌ 占位符判据漂移（Go 引擎与 Python 门禁已不一致）")
            for v in violations:
                print(f"   - {v}")
            print("\n改法：先定 Go 侧为准，再同步 Python；两边必须逐词、逐正则字符相同。")
        else:
            print("✅ 占位符判据一致"
                  f"（正则 1 条、占位词 {detail['n_go_words']} 个、低信息量分隔符 "
                  f"{len(detail['go_low_info_separators'])} 个）")
    if args.check and violations:
        return 1
    return 0


if __name__ == "__main__":
    sys.exit(main())
