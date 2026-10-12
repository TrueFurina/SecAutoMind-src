#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""check_web_asset_parity.py 的回归 + 变异验证（不依赖 pytest，纯 stdlib）。

门禁自身必须有回归测试，关键门禁必须有**变异验证**：
    —— 故意注入漂移，门禁必须变红；否则它只是个摆设。

覆盖用例：
    T1 两份完全一致                      → exit 0
    T2 目标缺文件（改了根 web/ 没同步）  → exit 1  ← 变异：删掉嵌入副本里的 js
    T3 目标文件内容旧（经典漂移）        → exit 1  ← 变异：改嵌入副本里的 js 内容
    T4 目标多出 vendor/ 文件（合法差异） → exit 0，且归入"预期额外"
    T5 目标多出非 vendor 文件            → exit 0，但归入"非预期额外"，不得静默吞掉
    T6 源目录不存在                      → exit 2（fail-closed，绝不当"通过"）
    T7 --sync 能把 T2/T3 的漂移修好并复验通过
    T8 CI 场景（根 web/ 无 vendor，因 gitignore）→ exit 0

用法：
    python scripts/check_web_asset_parity_test.py
    echo $?     # 0 = 全部通过
"""
import os
import sys
import json
import shutil
import subprocess
import tempfile

HERE = os.path.dirname(os.path.abspath(__file__))
ROOT = os.path.dirname(HERE)
CHECKER = os.path.join(HERE, "check_web_asset_parity.py")

_results = []


def run_checker(source, target):
    """跑门禁，返回 (exit_code, stdout)。"""
    proc = subprocess.run(
        [sys.executable, CHECKER, "--source", source, "--target", target, "--json"],
        capture_output=True,
        text=True,
        encoding="utf-8",
        errors="replace",
    )
    return proc.returncode, (proc.stdout or "") + (proc.stderr or "")


def make_pair(base, with_vendor_in_source=False):
    """构造一对源/目标副本目录。"""
    src = os.path.join(base, "web")
    tgt = os.path.join(base, "embed")
    os.makedirs(os.path.join(src, "static", "js"), exist_ok=True)
    os.makedirs(os.path.join(src, "templates"), exist_ok=True)
    os.makedirs(os.path.join(tgt, "static", "js"), exist_ok=True)
    os.makedirs(os.path.join(tgt, "templates"), exist_ok=True)

    for rel, body in [
        ("static/js/chat.js", "console.log('chat v1');\n"),
        ("static/css/style.css", "body{}\n"),
        ("templates/index.html", "<html>v1</html>\n"),
    ]:
        for root in (src, tgt):
            full = os.path.join(root, os.sep.join(rel.split("/")))
            os.makedirs(os.path.dirname(full), exist_ok=True)
            with open(full, "w", encoding="utf-8", newline="\n") as f:
                f.write(body)

    if with_vendor_in_source:
        os.makedirs(os.path.join(src, "static", "vendor"), exist_ok=True)
        with open(os.path.join(src, "static", "vendor", "xterm.js"), "w",
                  encoding="utf-8", newline="\n") as f:
            f.write("/*vendor*/\n")
        os.makedirs(os.path.join(tgt, "static", "vendor"), exist_ok=True)
        with open(os.path.join(tgt, "static", "vendor", "xterm.js"), "w",
                  encoding="utf-8", newline="\n") as f:
            f.write("/*vendor*/\n")
    return src, tgt


def case(name, cond, detail=""):
    _results.append((name, bool(cond), detail))
    print("  %s %s%s" % ("PASS" if cond else "FAIL", name,
                         ("  <- " + detail) if (detail and not cond) else ""))


def t1_identical(base):
    src, tgt = make_pair(base)
    code, _out = run_checker(src, tgt)
    case("T1 完全一致 → exit 0", code == 0, "got exit %d" % code)


def t2_missing_in_target(base):
    src, tgt = make_pair(base)
    os.remove(os.path.join(tgt, "static", "js", "chat.js"))  # 变异：嵌入副本缺文件
    code, out = run_checker(src, tgt)
    data = json.loads(out)
    case("T2 目标缺文件 → exit 1", code == 1, "got exit %d" % code)
    case("T2 正确点名缺失文件",
         data.get("missing_in_target") == ["static/js/chat.js"],
         json.dumps(data.get("missing_in_target"), ensure_ascii=False))


def t3_content_drift(base):
    src, tgt = make_pair(base)
    with open(os.path.join(tgt, "static", "js", "chat.js"), "w",
              encoding="utf-8", newline="\n") as f:
        f.write("console.log('chat v0 STALE');\n")  # 变异：嵌入副本内容是旧的
    code, out = run_checker(src, tgt)
    data = json.loads(out)
    case("T3 内容漂移 → exit 1", code == 1, "got exit %d" % code)
    case("T3 正确点名内容不一致",
         data.get("content_mismatch") == ["static/js/chat.js"],
         json.dumps(data.get("content_mismatch"), ensure_ascii=False))


def t4_expected_vendor_extra(base):
    src, tgt = make_pair(base)
    os.makedirs(os.path.join(tgt, "static", "vendor"), exist_ok=True)
    with open(os.path.join(tgt, "static", "vendor", "xterm.js"), "w",
              encoding="utf-8", newline="\n") as f:
        f.write("/*vendor*/\n")
    code, out = run_checker(src, tgt)
    data = json.loads(out)
    case("T4 目标多 vendor（合法差异）→ exit 0", code == 0, "got exit %d" % code)
    case("T4 归入 extra_in_target",
         data.get("extra_in_target") == ["static/vendor/xterm.js"],
         json.dumps(data.get("extra_in_target"), ensure_ascii=False))


def t5_unexpected_extra(base):
    src, tgt = make_pair(base)
    with open(os.path.join(tgt, "static", "js", "orphan.js"), "w",
              encoding="utf-8", newline="\n") as f:
        f.write("// only in embed\n")
    code, out = run_checker(src, tgt)
    data = json.loads(out)
    case("T5 目标多非 vendor 文件 → 不硬失败(exit 0)", code == 0, "got exit %d" % code)
    case("T5 但必须被记录，不得静默吞掉",
         "static/js/orphan.js" in (data.get("extra_in_target") or []),
         json.dumps(data.get("extra_in_target"), ensure_ascii=False))
    # 人类可读输出里必须标为"非预期"
    proc = subprocess.run([sys.executable, CHECKER, "--source", src, "--target", tgt],
                          capture_output=True, text=True, encoding="utf-8", errors="replace")
    case("T5 人类输出标记为非预期",
         "非预期" in (proc.stdout or "") and "orphan.js" in (proc.stdout or ""),
         (proc.stdout or "")[:200])


def t6_missing_source(base):
    src = os.path.join(base, "web")          # 故意不创建
    tgt = os.path.join(base, "embed")
    os.makedirs(tgt, exist_ok=True)
    code, _out = run_checker(src, tgt)
    case("T6 源目录不存在 → exit 2 (fail-closed)", code == 2, "got exit %d" % code)


def t7_sync_repairs(base):
    src, tgt = make_pair(base)
    os.remove(os.path.join(tgt, "static", "js", "chat.js"))          # 缺失
    with open(os.path.join(tgt, "templates", "index.html"), "w",
              encoding="utf-8", newline="\n") as f:
        f.write("<html>STALE</html>\n")                              # 内容旧
    proc = subprocess.run([sys.executable, CHECKER, "--source", src, "--target", tgt, "--sync"],
                          capture_output=True, text=True, encoding="utf-8", errors="replace")
    case("T7 --sync 执行成功", proc.returncode == 0, "got exit %d" % proc.returncode)
    code2, _ = run_checker(src, tgt)
    case("T7 同步后复验通过", code2 == 0, "got exit %d" % code2)
    with open(os.path.join(tgt, "static", "js", "chat.js"), encoding="utf-8") as f:
        body = f.read()
    case("T7 缺失文件已被补齐", "chat v1" in body, body)


def t8_ci_scenario(base):
    """CI 场景：根 web/ 无 vendor（gitignore），embed 有 vendor → 必须 PASS。"""
    src, tgt = make_pair(base)
    os.makedirs(os.path.join(tgt, "static", "vendor"), exist_ok=True)
    for name in ("xterm.js", "xterm.css", "cytoscape.min.js"):
        with open(os.path.join(tgt, "static", "vendor", name), "w",
                  encoding="utf-8", newline="\n") as f:
            f.write("/*v*/\n")
    code, _out = run_checker(src, tgt)
    case("T8 CI 场景(根无 vendor) → exit 0", code == 0, "got exit %d" % code)


def main():
    print("== check_web_asset_parity 回归 + 变异验证 ==")
    print("(每个 T2/T3 都是**故意注入的变异**，门禁不变红即为失效)\n")

    tmp = tempfile.mkdtemp(prefix="webparity_")
    try:
        for i, fn in enumerate([t1_identical, t2_missing_in_target, t3_content_drift,
                                t4_expected_vendor_extra, t5_unexpected_extra,
                                t6_missing_source, t7_sync_repairs, t8_ci_scenario], 1):
            sub = os.path.join(tmp, "case%d" % i)
            os.makedirs(sub, exist_ok=True)
            fn(sub)
    finally:
        shutil.rmtree(tmp, ignore_errors=True)

    failed = [n for n, ok, _ in _results if not ok]
    print("\n结果: %d/%d 通过" % (len(_results) - len(failed), len(_results)))
    if failed:
        print("失败用例:")
        for n in failed:
            print("  -", n)
        return 1
    print("[OK] 全部门禁变异用例通过。")
    return 0


if __name__ == "__main__":
    sys.exit(main())
