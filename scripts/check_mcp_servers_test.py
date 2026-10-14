#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""check_mcp_servers.py 的回归 + 变异验证（纯 stdlib，不依赖 pytest）。

关键门禁必须有变异验证：故意把目录/索引/依赖声明/协议行为改坏，门禁必须变红。
合成了一个「行为可切换」的 stdlib 假 MCP 服务（FIXTURE_MODE 控制），
从而能在不依赖 mcp / claude-agent-sdk 的前提下，逐条证明每个断言真能失败。

用例：
    T1  基线：目录=索引、服务齐备、协议合规        -> exit 0
    T2  变异：目录有服务但索引漏列（两份索引）      -> exit 1 且点名
    T3  变异：只漏中文索引                          -> exit 1
    T4  变异：索引指向不存在的目录（死链）          -> exit 1
    T5  变异：服务缺 README_CN.md                   -> exit 1
    T6  变异：实现多暴露一个工具而 README 未收录    -> exit 1（D7 正向）
    T7  变异：README 列了未暴露的工具且未标注可选项 -> exit 1（D7 反向）
    T8  基线：同样多列一个工具，但标注「默认关闭」  -> exit 0（证明 T7 的因果）
    T9  变异：try/except 引入未在文档点名的依赖     -> exit 1（C）
    T10 变异：对通知回了一条带 id 的响应           -> exit 1（D2）
    T11 变异：tools/list 的工具缺 inputSchema      -> exit 1（D4）
    T12 变异：未知工具被静默当成功返回              -> exit 1（D5）
    T13 --no-probe 时协议项跳过（同 T10 的坏服务）  -> exit 0（证明开关真生效）
    T14 fail-closed：--dir 不存在                  -> exit 2
    T15 fail-closed：索引文件缺失                  -> exit 2
    T16 真实 mcp-servers/ 当前状态                  -> exit 0
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
CHECKER = os.path.join(HERE, "check_mcp_servers.py")

_results = []


# 合成假 MCP 服务：只依赖标准库，行为由 FIXTURE_MODE 切换
FIXTURE_SERVER = r'''import json
import os
import sys

MODE = os.environ.get("FIXTURE_MODE", "ok")

TOOLS = [
    {"name": "asset_lookup", "description": "asset",
     "inputSchema": {"type": "object", "properties": {"event": {"type": "object"}},
                     "required": ["event"]}},
    {"name": "log_lookup", "description": "log",
     "inputSchema": {"type": "object", "properties": {"event": {"type": "object"}},
                     "required": ["event"]}},
]
if MODE == "extra_tool":
    TOOLS.append({"name": "bonus_tool", "description": "bonus",
                  "inputSchema": {"type": "object", "properties": {}}})


def send(obj):
    sys.stdout.write(json.dumps(obj) + "\n")
    sys.stdout.flush()


for line in sys.stdin:
    line = line.strip()
    if not line:
        continue
    try:
        msg = json.loads(line)
    except ValueError:
        continue
    method = msg.get("method")
    mid = msg.get("id")
    if method == "initialize":
        send({"jsonrpc": "2.0", "id": mid, "result": {
            "protocolVersion": "2024-11-05", "capabilities": {"tools": {}},
            "serverInfo": {"name": "fixture", "version": "1"}}})
    elif method == "notifications/initialized":
        if MODE == "notify":
            send({"jsonrpc": "2.0", "id": None,
                  "error": {"code": -32601, "message": "Method not found"}})
    elif method == "ping":
        send({"jsonrpc": "2.0", "id": mid, "result": {}})
    elif method == "tools/list":
        tools = []
        for t in TOOLS:
            tools.append({"name": t["name"], "description": t["description"]}
                         if MODE == "noschema" else dict(t))
        send({"jsonrpc": "2.0", "id": mid, "result": {"tools": tools}})
    elif method == "tools/call":
        name = (msg.get("params") or {}).get("name")
        if name not in [t["name"] for t in TOOLS]:
            if MODE == "unknown_silent":
                send({"jsonrpc": "2.0", "id": mid, "result": {
                    "content": [{"type": "text", "text": "ok"}], "isError": False}})
            else:
                send({"jsonrpc": "2.0", "id": mid,
                      "error": {"code": -32602, "message": "unknown tool"}})
        else:
            send({"jsonrpc": "2.0", "id": mid, "result": {
                "content": [{"type": "text", "text": "ok"}], "isError": False}})
    elif mid is not None:
        send({"jsonrpc": "2.0", "id": mid,
              "error": {"code": -32601, "message": "Method not found"}})
'''

GUARDED_DEP = "\nimport os\ntry:\n    import requests\nexcept ImportError:\n    pass\n"


def run(args, mode=None):
    env = dict(os.environ)
    env["PYTHONIOENCODING"] = "utf-8"
    if mode:
        env["FIXTURE_MODE"] = mode
    p = subprocess.run([sys.executable, CHECKER] + args, capture_output=True,
                       text=True, encoding="utf-8", errors="replace", env=env,
                       timeout=600)
    return p.returncode, (p.stdout or "") + (p.stderr or "")


def write(path, text):
    os.makedirs(os.path.dirname(path), exist_ok=True)
    with open(path, "w", encoding="utf-8", newline="\n") as fh:
        fh.write(text)


def tool_table(entries):
    rows = ["# 合成服务", "", "| 工具 | 说明 |", "|------|------|"]
    for item in entries:
        rows.append(item[1] if isinstance(item, tuple) else "| `%s` | 说明 |" % item)
    return "\n".join(rows) + "\n"


def make_root(base, sub, *, mode="ok", cn_tools=("asset_lookup", "log_lookup"),
              en_tools=None, guarded_dep=False, in_index=True, in_index_cn=None,
              dead_link=None, readme_cn=True, readme_md=True):
    """构造一个 mcp-servers 形态的合成根目录。"""
    root = os.path.join(base, sub)
    os.makedirs(root, exist_ok=True)
    if in_index_cn is None:
        in_index_cn = in_index
    rows_en, rows_cn = [], []
    if in_index:
        rows_en.append("| [svc](svc/) | synthetic service |")
    if in_index_cn:
        rows_cn.append("| [svc](svc/) | 合成服务 |")
    if dead_link:
        rows_en.append("| [%s](%s/) | dead |" % (dead_link, dead_link))
        rows_cn.append("| [%s](%s/) | 死链 |" % (dead_link, dead_link))
    write(os.path.join(root, "README.md"), "# index\n\n" + "\n".join(rows_en) + "\n")
    write(os.path.join(root, "README_CN.md"), "# 索引\n\n" + "\n".join(rows_cn) + "\n")

    svc = os.path.join(root, "svc")
    write(os.path.join(svc, "mcp_fixture.py"), FIXTURE_SERVER + (GUARDED_DEP if guarded_dep else ""))
    if readme_md:
        write(os.path.join(svc, "README.md"), tool_table(en_tools or cn_tools))
    if readme_cn:
        write(os.path.join(svc, "README_CN.md"), tool_table(cn_tools))
    return root


def check(name, cond, detail=""):
    _results.append((name, bool(cond)))
    print("  %s %s%s" % ("PASS" if cond else "FAIL", name,
                         "" if cond else "  <- " + detail.replace("\n", " | ")[:400]))


def main():
    print("=" * 64)
    print("check_mcp_servers 回归 + 变异验证")
    print("=" * 64)

    with tempfile.TemporaryDirectory(prefix="mcpgate_") as base:
        # T1 基线
        r1 = make_root(base, "t1")
        rc, out = run(["--dir", r1])
        check("T1 基线（目录=索引、协议合规）-> exit 0", rc == 0, "rc=%d\n%s" % (rc, out))

        # T2 变异：目录有服务、两份索引都漏列
        r2 = make_root(base, "t2", in_index=False)
        rc, out = run(["--dir", r2])
        check("T2 变异：两份索引都漏列 -> exit 1 且点名",
              rc == 1 and "未收录" in out and "svc" in out, "rc=%d\n%s" % (rc, out))

        # T3 变异：只漏中文索引
        r3 = make_root(base, "t3", in_index=True, in_index_cn=False)
        rc, out = run(["--dir", r3])
        check("T3 变异：只漏中文索引 -> exit 1 且点名 README_CN.md",
              rc == 1 and "README_CN.md" in out, "rc=%d\n%s" % (rc, out))

        # T4 变异：索引死链
        r4 = make_root(base, "t4", dead_link="ghost")
        rc, out = run(["--dir", r4])
        check("T4 变异：索引指向不存在的目录 -> exit 1",
              rc == 1 and "不存在的目录" in out, "rc=%d\n%s" % (rc, out))

        # T5 变异：缺中文 README
        r5 = make_root(base, "t5", readme_cn=False)
        rc, out = run(["--dir", r5])
        check("T5 变异：服务缺 README_CN.md -> exit 1",
              rc == 1 and "缺 README_CN.md" in out, "rc=%d\n%s" % (rc, out))

        # T6 变异：实现多暴露工具、README 未收录（D7 正向）
        r6 = make_root(base, "t6", mode="extra_tool")
        rc, out = run(["--dir", r6], mode="extra_tool")
        check("T6 变异：实现多暴露 bonus_tool 而 README 未收录 -> exit 1",
              rc == 1 and "未收录实现已暴露的工具" in out, "rc=%d\n%s" % (rc, out))

        # T7 变异：README 多列工具且未标注可选项（D7 反向）
        r7 = make_root(base, "t7", cn_tools=["asset_lookup", "log_lookup", "bonus_tool"])
        rc, out = run(["--dir", r7])
        check("T7 变异：README 多列未暴露工具且无标注 -> exit 1",
              rc == 1 and "未标注" in out, "rc=%d\n%s" % (rc, out))

        # T8 基线：同 T7 但标注「默认关闭」-> 应放行（证明 T7 判定的是标注而非工具数）
        marked = ("bonus_tool", "| `bonus_tool` | 备用工具（**默认关闭**） |")
        r8 = make_root(base, "t8", cn_tools=["asset_lookup", "log_lookup", marked],
                       en_tools=["asset_lookup", "log_lookup",
                                 ("bonus_tool", "| `bonus_tool` | spare (**off by default**) |")])
        rc, out = run(["--dir", r8])
        check("T8 基线：多列工具但标注「默认关闭」-> exit 0", rc == 0, "rc=%d\n%s" % (rc, out))

        # T9 变异：try/except 引入未在文档点名的依赖
        r9 = make_root(base, "t9", guarded_dep=True)
        rc, out = run(["--dir", r9])
        check("T9 变异：guarded import requests 未在文档点名 -> exit 1",
              rc == 1 and "requests" in out and "未在文档点名" in out,
              "rc=%d\n%s" % (rc, out))

        # T10 变异：对通知回带 id 的响应
        r10 = make_root(base, "t10", mode="notify")
        rc, out = run(["--dir", r10], mode="notify")
        check("T10 变异：通知被响应 -> exit 1", rc == 1 and "D2" in out,
              "rc=%d\n%s" % (rc, out))

        # T11 变异：tools/list 缺 inputSchema
        r11 = make_root(base, "t11", mode="noschema")
        rc, out = run(["--dir", r11], mode="noschema")
        check("T11 变异：工具缺 inputSchema -> exit 1", rc == 1 and "D4" in out,
              "rc=%d\n%s" % (rc, out))

        # T12 变异：未知工具被静默当成功
        r12 = make_root(base, "t12", mode="unknown_silent")
        rc, out = run(["--dir", r12], mode="unknown_silent")
        check("T12 变异：未知工具静默成功 -> exit 1", rc == 1 and "D5" in out,
              "rc=%d\n%s" % (rc, out))

        # T13 --no-probe 真生效（同一个坏服务，跳过协议面即放行）
        rc, out = run(["--dir", r12, "--no-probe"], mode="unknown_silent")
        check("T13 --no-probe 跳过协议面 -> exit 0", rc == 0 and "SKIP" in out,
              "rc=%d\n%s" % (rc, out))

        # T14 fail-closed：目录不存在
        rc, out = run(["--dir", os.path.join(base, "nope")])
        check("T14 --dir 不存在 -> exit 2", rc == 2, "rc=%d" % rc)

        # T15 fail-closed：索引文件缺失
        r15 = os.path.join(base, "t15")
        os.makedirs(r15, exist_ok=True)
        rc, out = run(["--dir", r15])
        check("T15 索引文件缺失 -> exit 2", rc == 2, "rc=%d" % rc)

    # T16 真实 mcp-servers/
    rc, out = run([])
    check("T16 真实 mcp-servers/ 当前状态 -> exit 0", rc == 0, "rc=%d\n%s" % (rc, out))

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
