#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""check_doc_port_consistency.py 的回归 + 变异验证（纯 stdlib，不依赖 pytest）。

关键门禁必须有变异验证：故意把文档端口写回 8080，门禁必须变红。
用例：
    T1 临时目录端口=真值                -> exit 0
    T2 变异：URL 写 8080                -> exit 1 且点名
    T3 mcp.port（8081）在白名单          -> exit 0
    T4 变异：非豁免文件里出现靶场端口    -> exit 1（证明豁免不是全局放开）
    T5 目录不存在                        -> exit 2（fail-closed）
    T6 变异：docker -p 8080:8080         -> exit 1
    T7 真实 docs/ 当前状态               -> exit 0
"""
import os
import subprocess
import sys
import tempfile

try:
    sys.stdout.reconfigure(encoding="utf-8")
except Exception:
    pass

HERE = os.path.dirname(os.path.abspath(__file__))
ROOT = os.path.dirname(HERE)
CHECKER = os.path.join(HERE, "check_doc_port_consistency.py")
SHARE_CFG = os.path.join(ROOT, "config.share.yaml")

_results = []


def truth_port():
    import re
    with open(SHARE_CFG, "r", encoding="utf-8", errors="ignore") as fh:
        for line in fh:
            m = re.match(r"^  port:\s*(\d+)", line)
            if m:
                return m.group(1)
    raise SystemExit("无法解析 server.port")


def run(args):
    p = subprocess.run([sys.executable, CHECKER] + args,
                       capture_output=True, text=True, encoding="utf-8", errors="replace")
    return p.returncode, (p.stdout or "") + (p.stderr or "")


def write(path, text):
    os.makedirs(os.path.dirname(path), exist_ok=True)
    with open(path, "w", encoding="utf-8", newline="\n") as fh:
        fh.write(text)


def check(name, cond, detail=""):
    _results.append((name, bool(cond)))
    print("  %s %s%s" % ("PASS" if cond else "FAIL", name,
                         "" if cond else "  <- " + detail))


def main():
    print("=" * 64)
    print("check_doc_port_consistency 回归 + 变异验证")
    print("=" * 64)
    PORT = truth_port()

    with tempfile.TemporaryDirectory(prefix="docport_") as base:
        # T1 正确端口
        d1 = os.path.join(base, "ok")
        write(os.path.join(d1, "api.md"),
              "curl -k https://127.0.0.1:%s/api/auth/login\n" % PORT)
        rc, out = run(["--dir", d1])
        check("T1 端口=真值 -> exit 0", rc == 0, "rc=%d\n%s" % (rc, out))

        # T2 变异：写回 8080
        d2 = os.path.join(base, "bad")
        write(os.path.join(d2, "api.md"), "curl -k https://127.0.0.1:8080/api/auth/login\n")
        rc, out = run(["--dir", d2])
        check("T2 变异：URL 写 8080 -> exit 1 且点名",
              rc == 1 and "api.md" in out, "rc=%d\n%s" % (rc, out))

        # T3 mcp.port 白名单
        d3 = os.path.join(base, "mcp")
        write(os.path.join(d3, "mcp.md"), "见 http://127.0.0.1:8081/health\n")
        rc, out = run(["--dir", d3])
        check("T3 mcp.port(8081) 在白名单 -> exit 0", rc == 0, "rc=%d\n%s" % (rc, out))

        # T4 非豁免文件里的靶场端口必须报错
        d4 = os.path.join(base, "range")
        write(os.path.join(d4, "notes.md"), "靶场 http://127.0.0.1:8501 基线请求\n")
        rc, out = run(["--dir", d4])
        check("T4 变异：非豁免文件的 8501 -> exit 1", rc == 1 and "8501" in out,
              "rc=%d\n%s" % (rc, out))

        # T5 fail-closed
        rc, out = run(["--dir", os.path.join(base, "nope")])
        check("T5 目录不存在 -> exit 2", rc == 2, "rc=%d" % rc)

        # T6 docker 端口映射
        d6 = os.path.join(base, "docker")
        write(os.path.join(d6, "im.md"), "docker run -p 8080:8080 your/img\n")
        rc, out = run(["--dir", d6])
        check("T6 变异：docker -p 8080:8080 -> exit 1", rc == 1 and "8080" in out,
              "rc=%d\n%s" % (rc, out))

    # T7 真实 docs
    rc, out = run([])
    check("T7 真实 docs/ 当前状态 -> exit 0", rc == 0, "rc=%d\n%s" % (rc, out))

    failed = [n for n, ok in _results if not ok]
    print("-" * 64)
    print("  合计 %d 用例，通过 %d，失败 %d"
          % (len(_results), len(_results) - len(failed), len(failed)))
    if failed:
        for n in failed:
            print("  [FAIL] %s" % n)
        return 1
    print("  [PASS] 门禁回归 + 变异验证全过")
    return 0


if __name__ == "__main__":
    sys.exit(main())
