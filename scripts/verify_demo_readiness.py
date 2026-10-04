#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""决赛演示就绪度一键闸门（只读，不改任何东西）。

为什么存在：演示日最怕「服务起不来 / 某通道没连上 / 关键命令渲染崩」。
这些以前靠人工 SSH 看日志，容易漏。本脚本把它们固化成一条命令：

  1) 服务存活：GET / -> 200
  2) 初始化完成：GET /api/setup/status -> needs_setup:false
  3) 四通道重连（可选 --log-ssh user@host）：从最近日志 grep 钉钉/微信/飞书/QQ
     的建链/收到消息实证行
  4) 关键单测/演练（引用，CI 真跑）：robot 帮助加粗、诊断口径、决赛整链路演练

退出码：0=绿（可演示），1=有红灯（先修再演示）。
"""
import argparse
import json
import os
import re
import subprocess
import sys
import urllib.request

try:
    sys.stdout.reconfigure(encoding="utf-8")
except Exception:
    pass

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
CHECKS = []


def check(name, ok, detail=""):
    CHECKS.append((name, ok, detail))
    mark = "✅" if ok else "❌"
    print("  %s %s%s" % (mark, name, (" — " + detail) if detail else ""))


def http_get(url, timeout=8):
    req = urllib.request.Request(url, headers={"User-Agent": "demo-readiness"})
    with urllib.request.urlopen(req, timeout=timeout) as r:
        return r.status, r.read().decode("utf-8", "ignore")


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--url", default="http://127.0.0.1:18086",
                    help="服务基址（默认本机 18086）")
    ap.add_argument("--log-ssh", default=None,
                    help="可选：user@host，SSH 拉最近日志核四通道重连")
    ap.add_argument("--log-path", default="/opt/secautomind/logs/secautomind.log",
                    help="远端日志路径（配合 --log-ssh）")
    args = ap.parse_args()

    base = args.url.rstrip("/")
    print("=" * 60)
    print("SecAutoMind 决赛演示就绪度闸门")
    print("  目标：%s" % base)
    print("=" * 60)

    # 1) 服务存活
    try:
        st, _ = http_get(base + "/")
        check("服务存活 GET / ", st == 200, "HTTP %d" % st)
    except Exception as e:
        check("服务存活 GET / ", False, "不可达：%s" % e)

    # 2) 初始化完成
    try:
        st, body = http_get(base + "/api/setup/status")
        if st == 200:
            try:
                needs = json.loads(body).get("needs_setup")
                check("初始化完成 /api/setup/status", needs is False,
                      "needs_setup=%s" % needs)
            except Exception:
                check("初始化完成 /api/setup/status", False, "响应非 JSON")
        else:
            check("初始化完成 /api/setup/status", False, "HTTP %d" % st)
    except Exception as e:
        check("初始化完成 /api/setup/status", False, "不可达：%s" % e)

    # 3) 四通道重连（可选）
    if args.log_ssh:
        try:
            cmd = ("ssh -o BatchMode=yes -o ConnectTimeout=20 -o StrictHostKeyChecking=no "
                   "%s 'tail -400 %s'" % (args.log_ssh, args.log_path))
            out = subprocess.run(cmd, shell=True, capture_output=True,
                                 text=True, encoding="utf-8", errors="ignore").stdout
            # 各通道建链/收到消息实证关键词（噪声词已排）
            ch_map = {
                "钉钉": r"钉钉.*(连接成功|已启动|收到|connected)",
                "微信": r"微信.*(已启动|收到|连接成功|connected)",
                "飞书": r"飞书.*(连接成功|已启动|收到|connected)|connected to wss://",
                "QQ": r"QQ.*(连接成功|已启动|收到|connected)",
            }
            for ch, pat in ch_map.items():
                ok = bool(re.search(pat, out, re.I))
                check("通道重连 %s" % ch, ok, "" if ok else "最近日志未见实证行")
        except Exception as e:
            check("通道重连（SSH）", False, "拉日志失败：%s" % e)
    else:
        print("  ℹ️  通道重连核对跳过（未传 --log-ssh）；演示前建议补跑：")
        print("     python scripts/verify_demo_readiness.py --url %s "
              "--log-ssh user@host" % base)

    # 4) 关键单测/演练（引用 CI 真跑，这里只提示）
    print("  ℹ️  以下由 CI 真跑（finals-rehearsal / handler 单测），本地一键：")
    print("     go test ./internal/ctfplatform/ -run TestRehearsal")
    print("     go test ./internal/handler/ -run 'TestCmdHelp|TestCmdDoctor'")

    passed = sum(1 for _, ok, _ in CHECKS if ok)
    total = len(CHECKS)
    print("-" * 60)
    print("  汇总：%d/%d 通过" % (passed, total))
    # 仅统计「硬指标」（存活 + 初始化 + 通道）是否全绿；引用项不计失败
    hard = [c for c in CHECKS if not c[1]]  # 失败项
    rc = 0 if not hard else 1
    print("  结论：%s" % ("🟢 可演示" if rc == 0 else "🔴 有红灯，先修"))
    print("=" * 60)
    sys.exit(rc)


if __name__ == "__main__":
    sys.exit(main())
