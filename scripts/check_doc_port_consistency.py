#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""文档端口一致性门禁 —— docs/ 里的服务端点必须等于 config.share.yaml 的 server.port。

背景（2026-09-30）：
    本项目对外文档里长期写 `http://localhost:8080`，而**交付包开箱的 config.yaml**
    端口是 18086（8080 只是 `config.example.yaml` 模板值 + `cmd/server/main.go:90`
    的「本项未设置」兜底）。docs 里的 curl / 浏览器地址 / nginx `proxy_pass` /
    Docker `-p` 都是**可执行指令**，读者会直接复制 —— 端口写错=照文档操作全失败。
    根因是一条错误注释「未启用 TLS 时为 http://localhost:8080」（端口与 TLS 无关）。

    修完必须上锁：真值只认 config.share.yaml，docs 偏离即红。

真值源：`config.share.yaml` 的 `server.port`（+ 允许的 `mcp.port`）。
用法：
    python scripts/check_doc_port_consistency.py              # 检查 docs/
    python scripts/check_doc_port_consistency.py --dir DIR    # 检查任意目录
    python scripts/check_doc_port_consistency.py --json
退出码：0 = 一致；1 = 有偏离；2 = 无法完成（fail-closed）
"""
import argparse
import fnmatch
import json
import os
import re
import sys

try:
    sys.stdout.reconfigure(encoding="utf-8")
except Exception:
    pass

HERE = os.path.dirname(os.path.abspath(__file__))
ROOT = os.path.dirname(HERE)
SHARE_CFG = os.path.join(ROOT, "config.share.yaml")

# 文档里"本服务端点"的三种实际形态
PATTERNS = [
    ("URL", re.compile(r"https?://(?:localhost|127\.0\.0\.1|0\.0\.0\.0):(\d+)")),
    ("lsof", re.compile(r"lsof\s+-i\s+:(\d+)")),
    ("docker", re.compile(r"-p\s+(\d+):(\d+)")),
]

# 材料线（他人负责，且含靶机等其他端口），默认跳过
# `archive`：归档目录按定义就是**过期快照**，且其中多份文档正在**复述"8080 与 18086 矛盾"这个 bug 本身**
# （勘误记录、事故复盘）。用现行端口标准去管历史记录，等于把"记录 bug 的文档"判成 bug。
# 2026-10-24 补：归档提交只把文档挪进 archive/ 而没同步本表 → 门禁立刻报 7 处假红。
SKIP_DIRS = {"competition-2026", ".git", "node_modules", "__pycache__", "archive"}

# 显式豁免：命中的**不是本服务端点**。范围必须极小、必须写理由，且总数有上限。
# （理由：豁免会腐化 —— 无上限的豁免清单等同于关掉门禁。）
EXEMPTIONS = [
    ("docs/evidence/E1E2-summary-deepseek-20260905.md", "127.0.0.1:8501",
     "本地授权靶场的地址（8501 是靶场端口，不是 SecAutoMind 服务端口）"),
    ("docs/真实靶场_LAMPSecurity_CTF4_可用性验证_20261021.md", "127.0.0.1:8080",
     "CTF4 授权靶场的目标地址（8080 是靶机 Web 端口，不是 SecAutoMind 服务端口；靶场由 scripts/ctf4_lab.sh 拉起）"),
    ("docs/非flag靶场证据探测_设计与训练记录_20261021.md", "127.0.0.1:8080",
     "CTF4 授权靶场的目标地址（8080 是靶机 Web 端口，不是 SecAutoMind 服务端口；BaseURL/ExploitURLsInText 均指向靶机）"),
    ("docs/QUICKSTART_NEXT_AGENT.md", "127.0.0.1:8772",
     "本机 HTTP_PROXY 代理地址（不是本服务端点；该行讲的是 urllib/requests 不豁免回环导致探活走代理）"),
]
MAX_EXEMPTIONS = 5

# 🔴 行内显式标注（2026-11-08 修 doc-port-gate 9 处假红）：
# 证据目录里大量端口**不是本服务端点**——靶机地址、模型自造的 SSRF payload、
# 复述"故意指向不可达端口"的失败日志原文。把这些改成 18086 等于**伪造证据**，
# 松掉全局规则又等于关掉门禁。故引入行内标注：端口与标注**必须同一行**，
# 且只在 `docs/evidence/` 下生效（证据目录按定义在记录别人/别处的端口）。
# 标注有上限（防止靠标注把门禁镀绿）；未标注的偏离照样红。
CITE_TAG = "[非本服务端口]"
CITE_PREFIX = "docs/evidence/"
MAX_CITES = 40


def is_cited(rel_to_root, line):
    return rel_to_root.startswith(CITE_PREFIX) and CITE_TAG in line


def exemption_for(finding):
    """finding['file'] 是相对被扫目录的路径，豁免清单写的是仓内相对路径 —— 用后缀对齐。"""
    rel = finding["file"].replace("\\", "/")
    for pat, needle, why in EXEMPTIONS:
        if (pat.endswith(rel) or fnmatch.fnmatch(rel, pat)) and needle in finding["text"]:
            return why
    return None


def read_ports():
    """从 config.share.yaml 取 (server.port, mcp.port)，按顶层段归属判断。"""
    server = mcp = None
    cur = None
    with open(SHARE_CFG, "r", encoding="utf-8", errors="ignore") as fh:
        for line in fh:
            m = re.match(r"^([A-Za-z_][\w-]*):", line)
            if m:
                cur = m.group(1)
                continue
            m = re.match(r"^  port:\s*(\d+)", line)
            if m:
                if cur == "server" and server is None:
                    server = m.group(1)
                elif cur == "mcp" and mcp is None:
                    mcp = m.group(1)
    if server is None:
        raise SystemExit("[FAIL-CLOSED] 未能从 config.share.yaml 解析 server.port")
    return server, mcp


def scan_dir(base, allowed):
    findings, scanned, skipped = [], 0, 0
    for dirpath, dirnames, filenames in os.walk(base):
        dirnames[:] = [d for d in dirnames if d not in SKIP_DIRS]
        for fn in filenames:
            if not fn.endswith((".md", ".html", ".txt", ".yaml", ".yml")):
                continue
            path = os.path.join(dirpath, fn)
            rel = os.path.relpath(path, base).replace("\\", "/")
            rel_root = os.path.relpath(path, ROOT).replace("\\", "/")
            if any(("/%s/" % s) in ("/" + rel) or rel.startswith(s + "/") for s in SKIP_DIRS):
                skipped += 1
                continue
            scanned += 1
            try:
                lines = open(path, "r", encoding="utf-8", errors="replace").read().splitlines()
            except OSError:
                continue
            for i, line in enumerate(lines, 1):
                for label, rx in PATTERNS:
                    for m in rx.finditer(line):
                        # URL/lsof 只有一个捕获组；docker `-p HOST:CONT` 取容器端口（最后一组）
                        g = m.groups()[-1]
                        if g not in allowed:
                            findings.append({
                                "file": rel, "line": i, "kind": label,
                                "port": g, "text": line.strip()[:130],
                                "cited": is_cited(rel_root, line),
                            })
    return findings, scanned, skipped


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--dir", default=None, help="检查目录（默认 docs/）")
    ap.add_argument("--json", action="store_true")
    args = ap.parse_args()

    server, mcp = read_ports()
    allowed = {server} | ({mcp} if mcp else set())

    base = os.path.abspath(args.dir) if args.dir else os.path.join(ROOT, "docs")
    if not os.path.isdir(base):
        print("[FAIL-CLOSED] 目录不存在：%s" % base, file=sys.stderr)
        return 2

    findings, scanned, skipped = scan_dir(base, allowed)

    # 豁免过滤（透明：被豁免的照样打印，只是不算失败）
    exempted, cited, real = [], [], []
    for f in findings:
        why = exemption_for(f)
        if why:
            f["exempt_reason"] = why
            exempted.append(f)
        elif f.get("cited"):
            cited.append(f)
        else:
            real.append(f)
    findings = real
    ok = not findings

    if len(cited) > MAX_CITES:
        print("  [FAIL] 行内标注 %d 处 > 上限 %d：标注已泛滥，收敛后再谈放行"
              % (len(cited), MAX_CITES))
        return 1

    if args.json:
        print(json.dumps({
            "truth_source": "config.share.yaml: server.port=%s, mcp.port=%s" % (server, mcp),
            "root": base, "scanned": scanned, "skipped_dirs": skipped,
            "ok": ok, "findings": findings, "exempted": exempted, "cited": cited,
        }, ensure_ascii=False, indent=2))
        return 0 if ok else 1

    if len(EXEMPTIONS) > MAX_EXEMPTIONS:
        print("  [FAIL] 豁免条目 %d 条 > 上限 %d：豁免清单已腐化，请收敛"
              % (len(EXEMPTIONS), MAX_EXEMPTIONS))
        return 1

    print("文档端口一致性 · 真值源 config.share.yaml server.port=%s（允许集合 %s）"
          % (server, sorted(allowed)))
    print("  扫描 %s（%d 个文件，跳过材料线 %d 个）" % (base, scanned, skipped))
    for f in exempted:
        print("  [SKIP] %s:%d 端口 %s —— 已豁免：%s"
              % (f["file"], f["line"], f["port"], f["exempt_reason"]))
    for f in cited:
        print("  [CITE] %s:%d 端口 %s —— 行内已标注「%s」（不是本服务端点，不改写）"
              % (f["file"], f["line"], f["port"], CITE_TAG))
        print("         %s" % f["text"])
    for f in findings:
        print("  [FAIL] %s:%d [%s] 端口 %s（应为 %s）"
              % (f["file"], f["line"], f["kind"], f["port"], server))
        print("         %s" % f["text"])
    if ok:
        print("  [PASS] docs 内服务端点端口与交付配置一致"
              "（另有 %d 处行内标注为非本服务端口，未计入失败）" % len(cited))
    else:
        print("  [BLOCK] %d 处端口偏离（照文档操作会连不上服务）" % len(findings))
    return 0 if ok else 1


if __name__ == "__main__":
    sys.exit(main())
