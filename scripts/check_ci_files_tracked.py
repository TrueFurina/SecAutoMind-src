#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""check_ci_files_tracked.py —— CI 引用的文件必须在库里。

## 为什么存在（2026-10-31 实锤）
全仓扫「被已跟踪文件引用、自己却未跟踪」时发现：**CI 的 test job 是挂的**。

- `internal/ctfplatform/live_targets.go` 未跟踪，但**已跟踪的** `live_target_test.go` /
  `live_target_cases_test.go` 直接用它 → 干净检出 `go vet` 报 `undefined: makeWeakJWT`；
- `ci.yml` 里 `run: python scripts/session_registry.py check` 等 **9 个** `run:` 指向的脚本
  根本不在库里 → CI 跑到那一步就是 "can't open file"。

这类漏洞的可怕之处：**本地永远绿**（因为文件就在磁盘上），只有 CI 会红，
而且报错是「文件不存在」，容易被人当成环境问题忽略。

## 判据
CI 在**干净检出**上跑 ⇒ 只有已跟踪文件存在。
所以：`ci.yml` / `release.yml` / `pages.yml` 里每个 `run:` 指向的 `.py/.sh/.js/.go`
都必须是**已跟踪**的。

## 用法
    python scripts/check_ci_files_tracked.py            # 0=全跟踪 / 1=有缺失
    python scripts/check_ci_files_tracked.py --verbose  # 连通过的一起列
    python scripts/check_ci_files_tracked.py --self-test

退出码：0 = 全部已跟踪；1 = 有引用悬空（fail-closed）；2 = 用法/环境错误。
"""
from __future__ import annotations

import argparse
import glob
import os
import re
import subprocess
import sys

# 只认这些"跑文件"的形态；`python -m` / `-c` 不是文件，跳过。
# 路径字符类刻意放宽到「非空白非引号」：本仓库真实路径含中文（如 `CTF-Agent_融合/...`），
# 早期用 [A-Za-z0-9_./\-] 会漏掉它们（自测 T2 抓到的）。
_P = r'(?P<p>"[^"]+\.[A-Za-z0-9]+"|\'[^\']+\.[A-Za-z0-9]+\'|[^\s"\'|&;]+\.(?:py|sh|js|cjs|mjs))'
_PATTERNS = (
    re.compile(r"\bpython3?\s+(?!-)" + _P),
    re.compile(r"\bbash\s+(?!-)" + _P),
    re.compile(r"\bnode\s+(?!-)" + _P),
    re.compile(r"\bgo\s+run\s+(?!-)(?P<p>\"[^\"]+\"|'[^']+'|[^\s\"'|&;]+)"),
)

_SKIP_TOKENS = ("$", "{", "}", "*", "?")


def extract_paths(text: str) -> list[tuple[str, int]]:
    """从工作流文本里抽出「会被执行的脚本路径」。返回 [(path, lineno)]，去重保序。

    刻意保守：含 `$`/`{}`/通配符的一律跳过（那是变量或 glob，静态判不了）。

    **按 step 块解析**，因为 `working-directory:` 会把块内相对路径改基：
    `ci.yml` 里 `working-directory: mcp-servers/security_triage_agent` + `run: python contract_test.py`
    指向的是 `mcp-servers/security_triage_agent/contract_test.py`，不是仓库根的 `contract_test.py`。
    """
    lines = text.splitlines()

    # 按「step 起始行」切块：`- name:` / `- uses:` / `- run:` 开头的行
    starts = [i for i, ln in enumerate(lines)
              if re.match(r"\s*-\s+(name|uses|run)\s*:", ln)]
    blocks: list[tuple[int, int]] = []
    for idx, s in enumerate(starts):
        e = starts[idx + 1] if idx + 1 < len(starts) else len(lines)
        blocks.append((s, e))
    if not blocks:
        blocks = [(0, len(lines))]

    out: list[tuple[str, int]] = []
    seen: set[str] = set()
    for s, e in blocks:
        chunk = lines[s:e]
        wd = ""
        for ln in chunk:
            m = re.match(r"\s*working-directory:\s*[\"']?([^\"'\s]+)", ln)
            if m:
                wd = m.group(1).replace("\\", "/").strip("/")
                break
        for off, ln in enumerate(chunk):
            if not re.search(r"\brun\s*:", ln) and not re.search(r"\b(?:python|bash|node|go\s+run)\b", ln):
                continue
            for pat in _PATTERNS:
                for m in pat.finditer(ln):
                    p = m.group("p").strip("\"'")
                    if not p or any(t in p for t in _SKIP_TOKENS):
                        continue
                    if p.startswith(("-", "/")):
                        continue
                    p = p.replace("\\", "/").lstrip("./")
                    if wd and not p.startswith(wd + "/"):
                        p = wd + "/" + p
                    if p and p not in seen:
                        seen.add(p)
                        out.append((p, s + off + 1))
    return out


def tracked_set(root: str) -> set[str]:
    """当前仓库已跟踪文件集合（`git ls-files`）。

    ⚠️ 必须用 `-z`：`git ls-files` 默认 `core.quotepath=true`，非 ASCII 路径会输出成
    八进制转义（`"CTF-Agent_\\350\\236\\215..."`），与本仓库大量中文路径对不上，
    会把「已跟踪」误判成「未跟踪」（自测之外的实跑抓到的）。
    """
    r = subprocess.run(["git", "ls-files", "-z"], cwd=root, capture_output=True)
    if r.returncode != 0:
        raise RuntimeError("git ls-files 失败：%s" % r.stderr.decode("utf-8", "replace").strip())
    out = r.stdout.decode("utf-8", "replace")
    return {x.replace("\\", "/") for x in out.split("\0") if x}


def find_missing(paths: list[tuple[str, int]], tracked: set[str]) -> list[tuple[str, int]]:
    return [(p, ln) for p, ln in paths if p not in tracked]


def main(argv: list[str] | None = None) -> int:
    ap = argparse.ArgumentParser(description="CI 引用的文件必须在库里")
    ap.add_argument("--root", default=".", help="仓库根（默认当前目录）")
    ap.add_argument("--verbose", action="store_true")
    ap.add_argument("--self-test", action="store_true", help="只跑内置样例，不读仓库")
    args = ap.parse_args(argv)

    if args.self_test:
        sample = "run: python scripts/a.py\nrun: python -m pip install x\n"
        got = [p for p, _ in extract_paths(sample)]
        if got == ["scripts/a.py"]:
            print("[PASS] self-test：提取 scripts/a.py 且跳过 python -m")
            return 0
        print("[FAIL] self-test：got %r" % (got,))
        return 1

    root = os.path.abspath(args.root)
    try:
        tracked = tracked_set(root)
    except (RuntimeError, OSError) as exc:
        print("[FAIL] 取不到 git 跟踪列表：%s" % exc, file=sys.stderr)
        return 2

    workflows = sorted(glob.glob(os.path.join(root, ".github", "workflows", "*.yml")))
    if not workflows:
        print("[FAIL] 找不到 .github/workflows/*.yml", file=sys.stderr)
        return 2

    total = 0
    missing: list[tuple[str, str, int]] = []
    for wf in workflows:
        try:
            text = open(wf, encoding="utf-8").read()
        except OSError as exc:
            print("[FAIL] 读不到 %s：%s" % (wf, exc), file=sys.stderr)
            return 2
        paths = extract_paths(text)
        total += len(paths)
        rel_wf = os.path.relpath(wf, root).replace("\\", "/")
        for p, ln in find_missing(paths, tracked):
            missing.append((rel_wf, p, ln))
        if args.verbose:
            print("  %-34s 引用 %d 个脚本" % (rel_wf, len(paths)))

    print("=" * 62)
    print("CI 引用文件跟踪检查（干净检出上，未跟踪 = 文件不存在）")
    print("=" * 62)
    print("  工作流 %d 个｜被引用的脚本 %d 个｜已跟踪 %d｜**未跟踪 %d**"
          % (len(workflows), total, total - len(missing), len(missing)))

    if missing:
        print("\n  [FAIL] 以下文件被 CI 执行，但不在库里（干净检出会失败）：")
        for wf, p, ln in missing:
            print("    %s:%d  →  %s" % (wf, ln, p))
        print("\n  处置：`git add <上述文件>` 后重跑；若该步骤已废弃，从工作流里删掉。")
        return 1

    print("\n  [PASS] 所有被 CI 执行的脚本都已入库。")
    return 0


if __name__ == "__main__":
    sys.exit(main())
