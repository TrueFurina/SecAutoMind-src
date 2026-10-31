#!/usr/bin/env python3
"""附件注入能力回归测试（含变异验证）。

背景：编排器原本**全面禁止** run_python 读文件（反作弊）。
为让模型能读「本题自己的工件」，新增 --artifact-dir 白名单模式：
只放宽「相对文件名的 open()」，其余一律拦。本测试锁住这个边界——
**越界读取必须被拦**，否则等于给模型开了一条读答案文件的通道。

用法：python scripts/test_artifact_inject.py
退出码 0 = 全通过；非 0 = 有失败（CI 会红）。
"""
from __future__ import annotations

import os
import shutil
import sys
import tempfile
import zipfile

HERE = os.path.dirname(os.path.abspath(__file__))
if HERE not in sys.path:
    sys.path.insert(0, HERE)

import ctf_stepfun_orchestrator as orch  # noqa: E402

FAILS: list[str] = []


def check(name: str, cond: bool, detail: str = "") -> None:
    if cond:
        print("  [PASS] %s" % name)
    else:
        print("  [FAIL] %s  %s" % (name, detail))
        FAILS.append(name)


def make_zip(path: str) -> None:
    """造一个测试工件：小文本 + 超阈值大文本 + 二进制。"""
    with zipfile.ZipFile(path, "w") as z:
        z.writestr("README.md", "# 调查要求\nMARKER_INLINE_OK\n")
        z.writestr("big.txt", "x" * (orch._ARTIFACT_INLINE_PER_FILE + 500))
        z.writestr("blob.bin", bytes(range(256)) * 4)


def main() -> int:
    print("=== [1] 守卫：工件模式放行「相对文件名 open」且不误伤普通字符串 ===")
    ok_cases = [
        ('print(open("VVMM.exe","rb").read()[:64])', "相对文件名读二进制"),
        ('print(open("README.md", encoding="utf-8").read())', "相对文件名读文本"),
        ('print("3/4")', "普通含斜杠字符串不得误伤"),
        ('print(math.gcd(12, 8))', "纯计算"),
    ]
    for code, label in ok_cases:
        allowed, reasons = orch._audit_code(code, artifact_mode=True)
        check("放行-" + label, allowed, "reasons=%s" % reasons)

    print("=== [2] 守卫：工件模式仍须拦截越界/危险操作（变异验证）===")
    bad_cases = [
        ('print(open("/home/user/SecAutoMind/data/answers/ycb2026_truth.json").read())', "读答案文件"),
        ('print(open("/etc/passwd").read())', "绝对路径 /etc"),
        ('print(os.listdir("."))', "列目录"),
        ('print(os.walk(".").__next__())', "遍历目录"),
        ('import urllib.request; urllib.request.urlopen("http://x")', "出网"),
        ('import subprocess; subprocess.run(["ls"])', "子进程"),
        ('print(eval("1+1"))', "动态执行"),
        ('from pathlib import Path; print(Path("x").read_text())', "pathlib 读文件"),
    ]
    for code, label in bad_cases:
        allowed, reasons = orch._audit_code(code, artifact_mode=True)
        check("拦截-" + label, not allowed, "竟被放行！reasons=%s" % reasons)

    print("=== [2b] \"..\" 穿越改为运行时拦截（正则层放行以不误伤字节串/注释，hook 精确拒）===")
    trav = 'print(open("../../artifacts/x.bin","rb").read())'
    allowed, reasons = orch._audit_code(trav, artifact_mode=True)
    check("正则层放行 .. (避免误伤)", allowed, "正则层竟拦: %s" % reasons)
    ok_with_dots = ('d=b"a..b"\nprint(open("README.md", encoding="utf-8").read() if d else "")')
    a2, _ = orch._audit_code(ok_with_dots, artifact_mode=True)
    check("字节串含 .. 不误伤", a2, "含 .. 字面量的代码被正则误拦")

    print("=== [3] 向后兼容：不传 --artifact-dir 时行为完全不变（仍禁一切文件读取）===")
    for code, label in [('print(open("VVMM.exe","rb").read())', "默认模式仍禁 open"),
                        ('print(open("README.md").read())', "默认模式仍禁读文本")]:
        allowed, reasons = orch._audit_code(code, artifact_mode=False)
        check("默认-" + label, not allowed, "默认模式竟放行！reasons=%s" % reasons)

    print("=== [4] prepare_artifacts：小文本内联 / 大文件只给清单 ===")
    tmp = tempfile.mkdtemp(prefix="inject_test_")
    try:
        zp = os.path.join(tmp, "att", "test.zip")
        os.makedirs(os.path.dirname(zp), exist_ok=True)
        make_zip(zp)
        cwd, info = orch.prepare_artifacts(os.path.dirname(zp), "test_pid", "test.zip")
        check("解压成功 cwd 非空", bool(cwd) and os.path.isdir(cwd or ""), "cwd=%s" % cwd)
        names = {f["name"] for f in (info or {}).get("files", [])}
        check("清单含 3 个文件", names == {"README.md", "big.txt", "blob.bin"}, "names=%s" % names)
        inline = (info or {}).get("inline", "")
        check("README.md 全文内联", "MARKER_INLINE_OK" in inline, "inline 缺标记")
        check("big.txt 未被内联(超阈值)", "big.txt（全文）" not in inline, "大文件被塞进 prompt")
        check("blob.bin 未被内联(二进制)", "blob.bin（全文）" not in inline, "二进制被塞进 prompt")

        print("=== [5] run_python_tool：cwd 隔离下真能读到本题工件 ===")
        if cwd:
            out = orch.run_python_tool('print(open("README.md", encoding="utf-8").read())',
                                       timeout=30, cwd=cwd, artifact_mode=True)
            check("读到 README 内容", "MARKER_INLINE_OK" in out, "out=%r" % out[:120])
            out2 = orch.run_python_tool('print(open("/etc/passwd").read())',
                                        timeout=30, cwd=cwd, artifact_mode=True)
            check("绝对路径仍被拦(BLOCKED)", "BLOCKED" in out2, "out=%r" % out2[:120])
            out3 = orch.run_python_tool('print(open("../../x.bin","rb").read())',
                                        timeout=30, cwd=cwd, artifact_mode=True)
            check(".. 穿越被运行时 hook 拦(BLOCKED)", "BLOCKED" in out3, "out=%r" % out3[:120])
            out4 = orch.run_python_tool('x=b"a..b"\nprint(open("README.md", encoding="utf-8").read())',
                                        timeout=30, cwd=cwd, artifact_mode=True)
            check("字节串含 .. 不影响正常读取", "MARKER_INLINE_OK" in out4, "out=%r" % out4[:120])

        print("=== [6] build_prompt：注入清单与限制说明 ===")
        p = orch.build_prompt({"id": "t", "description": "dd"}, info)
        check("prompt 含文件清单", "文件清单" in p and "README.md" in p, "缺清单")
        check("prompt 含相对文件名限制", "相对文件名" in p, "缺限制说明")
        check("prompt 含内联全文", "MARKER_INLINE_OK" in p, "缺内联")
        p0 = orch.build_prompt({"id": "t", "description": "dd"}, None)
        check("不传 info 时 prompt 无附件段", "本题附件" not in p0, "不该出现附件段")

        print("=== [7] 工具输出截断：头尾保留 + 中间省略 ===")
        big = orch.run_python_tool(
            'print("HEAD_MARK" + "x"*5000 + "TAIL_MARK")', timeout=30)
        check("头部保留", "HEAD_MARK" in big, "头被截掉")
        check("尾部保留(报错/结论在此)", "TAIL_MARK" in big, "尾被截掉")
        check("含省略标记", "中间省略" in big, "无省略标记")
        check("总长受控", len(big) < 2100, "len=%d" % len(big))

        print("=== [8] LLM 硬截止：降级不抛弃已积累推理（run4 事故）===")
        _orig = orch._post_json

        def _boom(*a, **kw):
            raise orch._HardDeadline("simulated slow-drip 180s")

        orch._post_json = _boom
        try:
            txt, used = orch.call_llm_agentic(
                {"api_base": "http://stub"}, "k", "m", "p", 180,
                max_iter=5, wall_budget=60)
            check("不抛异常(整题不崩)", True)
            check("降级文本留痕", "llm_hard_deadline" in txt, "txt=%r" % txt[:200])
            check("连续超时收口", "连续超时" in txt, "txt=%r" % txt[:200])
        finally:
            orch._post_json = _orig
    finally:
        shutil.rmtree(tmp, ignore_errors=True)
        if 'cwd' in dir() and cwd and os.path.isdir(cwd):
            shutil.rmtree(cwd, ignore_errors=True)

    print()
    if FAILS:
        print("SELFTEST: FAIL (%d) -> %s" % (len(FAILS), FAILS))
        return 1
    print("SELFTEST: PASS")
    return 0


if __name__ == "__main__":
    sys.exit(main())
