#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""前端运行时测试的**变异验证**门禁（2026-11-12 补齐 CI 盲区）。

为什么需要（AGENTS 第四条：失效的门禁比没有门禁更危险）
--------------------------------------------------------
CI 的 `web-js-tests` job 只证明"131 例现在能过"，**不证明这 131 例真能变红**——
把实现改坏而测试依旧全绿，就是哑门禁。GATES 地图里该 job 的"变异验证"长期标 **无**。

关键结构发现（写在这里省得下一个人重踩）
----------------------------------------
前端测试的取源方式是 **cwd 相对路径**：`fs.readFileSync('web/static/js/chat.js')`
读的是**仓库根 `web/` 副本**，而 `go:embed` 打进二进制的却是 `internal/app/web/`
副本（两份物理副本靠 `web-parity-gate` 维持相等）；另有测试直接读
`internal/handler/hitl.go` 这类 Go 源文本，还有 `require('./xxx.js')` 走测试文件同目录。
⇒ 变异验证必须**复刻整棵依赖树**才可信，所以本脚本搭 temp 树（web/ 全量 +
internal/app/web/static + internal/handler 被测 go 文件），并**先验基线**：
基线不是 rc=0 就立刻红并说明原因（宁可门禁不跑，不跑假绿）。

冗余层的教训（decisive 变异怎么选）
----------------------------------
第一轮我挑的两个变异都"改坏源码却仍全绿"，都不是测试失效：
① `key === 'Enter'` 改在函数区间外（测试只抽取函数体片段执行）；
② `event.isComposing` 改在**三层冗余守卫**上
   （`event.isComposing || 全局 isComposing || keyCode === 229`），任一层都足以拦住。
⇒ 变异必须打在**唯一决定行为的表达式**上（本文件的两条均如此，且各自有注释说明判据）。

用法
----
    python scripts/check_web_js_mutation.py          # 全跑
    python scripts/check_web_js_mutation.py --list   # 只看变异用例清单

退出码：0 = 基线绿且每条变异都变红；1 = 任何一条不成立（含锚点失效）。
"""
import argparse
import io
import os
import re
import shutil
import subprocess
import sys
import tempfile

try:
    sys.stdout.reconfigure(encoding="utf-8")
except Exception:
    pass

HERE = os.path.dirname(os.path.abspath(__file__))
ROOT = os.path.dirname(HERE)
TEST_GLOB_DIR = os.path.join("internal", "app", "web", "static", "js")

# 复刻依赖树所需（缺一即基线红，脚本会指名缺什么）
COPY_DIRS = [
    ("web", os.path.join("web")),
    (os.path.join("internal", "app", "web", "static"),
     os.path.join("internal", "app", "web", "static")),
]
COPY_FILES = [
    os.path.join("internal", "handler", "hitl.go"),
    os.path.join("internal", "handler", "hitl_logs.go"),
]

# ── 变异用例：每条都必须能单独把某条断言打红 ──────────────────────────────
# file  : 相对**temp 树**的源文件（即根 web 副本——测试真正读的那份）
# anchor: 必须存在的原文（找不到即"锚点失效"，门禁红而不是假绿）
# expect: 变异后 node --test 必须非 0
CASES = [
    {
        "name": "Enter 发送主分支被拆（唯一决定 sendCount 的条件）",
        "file": os.path.join("web", "static", "js", "chat.js"),
        "anchor": "if (event.key === 'Enter' && !event.shiftKey) {",
        "replace": "if (event.key === 'EnterMUTATED' && !event.shiftKey) {",
        # 判据：`聊天输入框按 Enter 发送并阻止原生换行` 依赖该表达式唯一决定发送；
        # 这里没有冗余层（Shift/IME 守卫在别的分支），所以是 decisive 变异。
    },
    {
        "name": "IME 三层守卫整体停用（逐层改不 decisive，须整体拆）",
        "file": os.path.join("web", "static", "js", "chat.js"),
        "anchor": "if (event.isComposing || isComposing || event.keyCode === 229) {",
        "replace": "if (false && (event.isComposing || isComposing || event.keyCode === 229)) {",
        # 判据：`输入法确认候选词时按 Enter 不会发送`。任一层单独改名都不改变行为
        # （三层任一为真即拦截），故变异必须整体短路才有效——这正是本用例存在的理由。
    },
]


def build_tree():
    """复刻测试依赖树；返回 temp 根目录（调用方负责删）。"""
    tree = tempfile.mkdtemp(prefix="sam_webjs_mut_")
    for src, dst in COPY_DIRS:
        s = os.path.join(ROOT, src)
        if not os.path.isdir(s):
            raise SystemExit("[BLOCK] 依赖树缺目录：%s（测试取源方式变了，须同步本脚本）" % src)
        shutil.copytree(s, os.path.join(tree, dst))
    for rel in COPY_FILES:
        s = os.path.join(ROOT, rel)
        if not os.path.isfile(s):
            raise SystemExit("[BLOCK] 依赖树缺文件：%s（测试取源方式变了，须同步本脚本）" % rel)
        d = os.path.join(tree, os.path.dirname(rel))
        os.makedirs(d, exist_ok=True)
        shutil.copy2(s, os.path.join(tree, rel))
    return tree


def test_files(tree):
    d = os.path.join(tree, TEST_GLOB_DIR)
    return [os.path.join(d, f) for f in sorted(os.listdir(d)) if f.endswith(".test.cjs")]


def run_tests(tree, node="node"):
    files = test_files(tree)
    if not files:
        return 2, "未找到任何 .test.cjs"
    p = subprocess.run([node, "--test"] + files, cwd=tree,
                       capture_output=True, text=True, encoding="utf-8", errors="ignore")
    out = (p.stdout or "") + (p.stderr or "")
    m = re.search(r"^# pass (\d+)", out, re.M)
    f = re.search(r"^# fail (\d+)", out, re.M)
    summary = "pass=%s fail=%s" % (m.group(1) if m else "?", f.group(1) if f else "?")
    return p.returncode, summary


def restore(tree, rel):
    shutil.copy2(os.path.join(ROOT, rel), os.path.join(tree, rel))


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--list", action="store_true", help="只列变异用例")
    args = ap.parse_args()
    if args.list:
        for i, c in enumerate(CASES, 1):
            print("  M%d %s" % (i, c["name"]))
        return 0

    if not shutil.which("node"):
        print("[BLOCK] 本机无 node —— 无法验证（fail-closed，不假装通过）")
        return 1

    print("=" * 70)
    print("前端运行时测试 · 变异验证（CI web-js-tests 的补齐）")
    print("=" * 70)
    tree = build_tree()
    try:
        rc, summary = run_tests(tree)
        if rc != 0:
            print("  [BLOCK] 基线不绿（%s）—— 变异验证不可信，先修依赖树复刻或测试本身" % summary)
            return 1
        print("  [OK] 基线 %s（未变异必须全过）" % summary)

        failures = []
        for i, c in enumerate(CASES, 1):
            path = os.path.join(tree, c["file"])
            s = io.open(path, encoding="utf-8", errors="ignore").read()
            if c["anchor"] not in s:
                print("  [FAIL] M%d 锚点失效（源码已重构，须同步本门禁）：%s" % (i, c["anchor"][:48]))
                failures.append(c["name"])
                continue
            io.open(path, "w", encoding="utf-8", newline="").write(
                s.replace(c["anchor"], c["replace"], 1))
            rc2, sum2 = run_tests(tree)
            restore(tree, c["file"])
            if rc2 == 0:
                print("  [FAIL] M%d 变异后仍全绿（%s）—— %s：断言对实现不敏感"
                      % (i, sum2, c["name"]))
                failures.append(c["name"])
            else:
                print("  [OK] M%d 如期变红（%s）—— %s" % (i, sum2, c["name"]))

        print("-" * 70)
        if failures:
            print("  结论：FAIL（%d/%d 条变异未变红）" % (len(failures), len(CASES)))
            return 1
        print("  结论：PASS —— web-js-tests 的行为敏感性已证明（%d 条 decisive 变异全变红）"
              % len(CASES))
        return 0
    finally:
        shutil.rmtree(tree, ignore_errors=True)


if __name__ == "__main__":
    sys.exit(main())
