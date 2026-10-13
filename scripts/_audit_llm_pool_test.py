#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""_audit_llm_pool.py 的回归 + 变异验证（不依赖 pytest，纯 stdlib）。

为什么必须存在
--------------
与 _audit_truth_sources_test.py 同因（2026-10-13）：该门禁决定"LLM 自主解题基线
（6/13）到底是外部真题口径还是自建题口径"——一个**对外数字的定性**门禁，却既无
回归测试、也无变异验证，一旦退化（比如 overlap 判据恒不报红）没人会发现。

并修复一处**空洞绿**：池文件缺失时旧版返回空池 → `all_green=True` → 静默报绿
（"口径从未被校验，门禁却一直给绿灯"），verdict 还输出与事实相反的"含自建题"。
现改为 fail-closed（缺失 / 解析 0 题 一律红）。

覆盖用例（每条都在独立 tempfile 夹具根上跑真实门禁子进程）：
    U1  合规：池 2 题、全自建、id/flag 唯一                       → exit 0
    U2  变异：池题真值命中仓库基准（口径污染/重叠）               → exit 1，重叠=1
    U3  变异：池内重复 id                                         → exit 1，重复 id=1
    U4  变异：池内重复 flag（同答案复用 → 虚高命中率）            → exit 1，重复 flag=1
    U5  fail-closed：池文件缺失                                    → exit 1 且点名"不存在"
    U6  fail-closed：池文件存在但解析 0 题（CASE_RE 脱钩）         → exit 1 且点名"解析到 0 题"
    U7  fail-closed：--target 指向不存在目录                       → exit 2
    U8  --json 契约：all_green/pool_size/self_authored/errors      → 字段齐且取值正确
    U9  真实仓库当前状态（回归基线，防夹具与真库脱节）             → exit 0

因果自变异（证明上面每个"红"确实由被改坏的那条判据产生）：
    M1  把 all_green 里的 `(not overlap)` 去掉 → U2 夹具必须**转绿**
    M2  把 all_green 里的 `(not errors)`  去掉 → U5 夹具必须**转绿**

用法：
    python scripts/_audit_llm_pool_test.py
    echo $?     # 0 = 全部通过
"""
import hashlib
import json
import os
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
GATE = os.path.join(HERE, "_audit_llm_pool.py")

POOL_REL = os.path.join("internal", "ctfplatform", "live_target_test.go")
BENCH_DIR = os.path.join("data", "ctf_benchmark")

_results = []


def _sha(s):
    return hashlib.sha256(s.encode("utf-8")).hexdigest()


def _write(root, relpath, content):
    path = os.path.join(root, relpath)
    os.makedirs(os.path.dirname(path), exist_ok=True)
    with open(path, "w", encoding="utf-8", newline="\n") as fh:
        fh.write(content)


def _write_pool(root, cases):
    """写一份形如 newLiveCases() 的 Go 源（只被 CASE_RE 正则解析，无需可编译）。"""
    body = ("package ctfplatform\n\n"
            "func newLiveCases() []liveCase {\n\treturn []liveCase{\n")
    for cid, title, flag in cases:
        body += '\t\t{id: "%s", title: "%s", flag: "%s"},\n' % (cid, title, flag)
    body += "\t}\n}\n"
    _write(root, POOL_REL, body)


def _write_bench(root, name, sha_list):
    probs = {("q%d" % i): {"id": "q%d" % i, "flag_sha256": s}
             for i, s in enumerate(sha_list)}
    _write(root, os.path.join(BENCH_DIR, name),
           json.dumps({"problems": probs}, ensure_ascii=False))


def _run(gate, target, extra=None):
    proc = subprocess.run(
        [sys.executable, gate, "--target", target] + (extra or []),
        capture_output=True, text=True, encoding="utf-8", errors="replace",
    )
    return proc.returncode, (proc.stdout or "") + (proc.stderr or "")


def _mkroot():
    return tempfile.mkdtemp(prefix="llmpool_")


def check(name, cond, detail=""):
    _results.append((name, bool(cond), detail))
    print("  %s %s%s" % ("PASS" if cond else "FAIL", name,
                         "" if cond else "  <- " + detail))


# ---------------------------------------------------------------- fixtures

def fx_compliant(root):
    _write_pool(root, [("1", "WEB-01", "flag{alpha}"), ("2", "WEB-02", "flag{beta}")])
    _write_bench(root, "bench.json", [_sha("flag{unrelated}")])


def fx_overlap(root):
    _write_pool(root, [("1", "WEB-01", "flag{alpha}")])
    _write_bench(root, "bench.json", [_sha("flag{alpha}")])   # 真值同源 → 重叠


def fx_dup_id(root):
    _write_pool(root, [("1", "WEB-01", "flag{alpha}"), ("1", "WEB-02", "flag{beta}")])


def fx_dup_flag(root):
    _write_pool(root, [("1", "WEB-01", "flag{same}"), ("2", "WEB-02", "flag{same}")])


def fx_zero_cases(root):
    _write(root, POOL_REL,
           "package ctfplatform\n\nfunc newLiveCases() []liveCase {\n"
           "\treturn []liveCase{}\n}\n")


# ---------------------------------------------------------------- cases

def case_compliant():
    root = _mkroot()
    try:
        fx_compliant(root)
        rc, out = _run(GATE, root)
        check("U1 合规（全自建、无重叠/重复）→ exit 0", rc == 0, "rc=%d\n%s" % (rc, out))
    finally:
        shutil.rmtree(root, ignore_errors=True)


def case_overlap():
    root = _mkroot()
    try:
        fx_overlap(root)
        rc, out = _run(GATE, root)
        check("U2 变异：口径重叠 → exit 1 且重叠=1",
              rc == 1 and "与仓库基准重叠: 1" in out, "rc=%d\n%s" % (rc, out))
    finally:
        shutil.rmtree(root, ignore_errors=True)


def case_dup_id():
    root = _mkroot()
    try:
        fx_dup_id(root)
        rc, out = _run(GATE, root)
        check("U3 变异：重复 id → exit 1 且重复 id=1",
              rc == 1 and "重复 id: 1" in out, "rc=%d\n%s" % (rc, out))
    finally:
        shutil.rmtree(root, ignore_errors=True)


def case_dup_flag():
    root = _mkroot()
    try:
        fx_dup_flag(root)
        rc, out = _run(GATE, root)
        check("U4 变异：重复 flag → exit 1 且重复 flag=1",
              rc == 1 and "重复 flag: 1" in out, "rc=%d\n%s" % (rc, out))
    finally:
        shutil.rmtree(root, ignore_errors=True)


def case_missing_pool():
    root = _mkroot()   # 不写池文件
    try:
        rc, out = _run(GATE, root)
        check("U5 fail-closed：池文件缺失 → exit 1 且点名",
              rc == 1 and "不存在" in out, "rc=%d\n%s" % (rc, out))
    finally:
        shutil.rmtree(root, ignore_errors=True)


def case_zero_cases():
    root = _mkroot()
    try:
        fx_zero_cases(root)
        rc, out = _run(GATE, root)
        check("U6 fail-closed：解析 0 题 → exit 1 且点名",
              rc == 1 and "解析到 0 题" in out, "rc=%d\n%s" % (rc, out))
    finally:
        shutil.rmtree(root, ignore_errors=True)


def case_missing_target():
    rc, out = _run(GATE, os.path.join(tempfile.gettempdir(), "llmpool_absent_xyz"))
    check("U7 --target 不存在 → exit 2（fail-closed）", rc == 2, "rc=%d\n%s" % (rc, out))


def case_json_contract():
    root = _mkroot()
    try:
        fx_compliant(root)
        rc, out = _run(GATE, root, ["--json"])
        try:
            rep = json.loads(out)
            ok = (rc == 0 and rep.get("all_green") is True
                  and rep.get("pool_size") == 2 and rep.get("self_authored") == 2
                  and rep.get("errors") == []
                  and rep.get("verdict", {}).get("denominator_is_external_truth") is False)
        except Exception as exc:  # noqa: BLE001
            ok = False
            rep = "json_error %s" % exc
        check("U8 --json 契约（all_green/pool_size/self_authored/errors）", ok,
              "rc=%d rep=%s" % (rc, rep))
    finally:
        shutil.rmtree(root, ignore_errors=True)


def case_repo_baseline():
    rc, out = _run(GATE, ROOT)
    check("U9 真实仓库基线 → exit 0", rc == 0, "rc=%d\n%s" % (rc, out))


# ------------------------------------------------- 因果自变异（证明红例是因果的）

def _mutate_gate(replace_from, replace_to):
    with open(GATE, "r", encoding="utf-8") as fh:
        src = fh.read()
    if replace_from not in src:
        return None, (lambda: None), "未找到可变异片段: %s" % replace_from
    mutated = src.replace(replace_from, replace_to, 1)
    fd, path = tempfile.mkstemp(prefix="llmpool_mut_", suffix=".py")
    with os.fdopen(fd, "w", encoding="utf-8", newline="\n") as fh:
        fh.write(mutated)
    return path, (lambda: os.remove(path)), ""


def case_causal_overlap():
    path, cleanup, err = _mutate_gate("(not overlap) and ", "")
    if path is None:
        check("M1 自变异：去掉 (not overlap) → U2 夹具转绿", False, err)
        return
    root = _mkroot()
    try:
        fx_overlap(root)
        rc, out = _run(path, root)
        check("M1 自变异：去掉 (not overlap) → U2 夹具转绿（证明红例因果）",
              rc == 0, "rc=%d（期望 0）\n%s" % (rc, out))
    finally:
        cleanup()
        shutil.rmtree(root, ignore_errors=True)


def case_causal_errors():
    path, cleanup, err = _mutate_gate("(not errors) and ", "")
    if path is None:
        check("M2 自变异：去掉 (not errors) → U5 夹具转绿", False, err)
        return
    root = _mkroot()
    try:
        rc, out = _run(path, root)   # 无池文件 → 旧版会报绿
        check("M2 自变异：去掉 (not errors) → U5 夹具转绿（证明 fail-closed 因果）",
              rc == 0, "rc=%d（期望 0）\n%s" % (rc, out))
    finally:
        cleanup()
        shutil.rmtree(root, ignore_errors=True)


def main():
    print("=" * 66)
    print("_audit_llm_pool 回归 + 变异验证")
    print("=" * 66)
    case_compliant()
    case_overlap()
    case_dup_id()
    case_dup_flag()
    case_missing_pool()
    case_zero_cases()
    case_missing_target()
    case_json_contract()
    case_repo_baseline()
    case_causal_overlap()
    case_causal_errors()

    failed = [n for n, ok, _ in _results if not ok]
    print("-" * 66)
    print("  合计 %d 用例，通过 %d，失败 %d" % (len(_results),
                                              len(_results) - len(failed), len(failed)))
    if failed:
        for n in failed:
            print("  [FAIL] %s" % n)
        return 1
    print("  [PASS] 门禁回归 + 变异验证全过")
    return 0


if __name__ == "__main__":
    sys.exit(main())
