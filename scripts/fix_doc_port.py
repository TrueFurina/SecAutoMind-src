#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""把 docs/ 里的服务端点从 8080 统一到「交付配置真值」18086。

真值源：config.share.yaml 的 server.port（交付包顶替 config.yaml 用的那份）。
为什么必须改：文档里的 curl / 浏览器地址 / nginx proxy_pass / Docker 端口映射
都是**可执行指令**，读者会直接复制；而交付包开箱的 config.yaml 端口是 18086
（8080 仅是「本项未设置」时的代码兜底 + config.example.yaml 模板值）。

不动的地方（各有明确理由）：
  - cmd/server/main.go、internal/config/config.go 的 8080 —— 代码兜底，真实存在
  - internal/config/default_config.yaml —— go:embed 自举模板，改了要重建 exe
  - config.example.yaml 的**值** —— 与自举模板保持一致，只修其错误注释
  - docs/**/competition-2026/** —— 属材料线（他人负责）
  - knowledge_base/** —— 靶机 URL / 工具示例，非本服务端点

用法：
  python scripts/fix_doc_port.py            # dry-run，只打印将要改的行
  python scripts/fix_doc_port.py --apply    # 落盘
"""
import io
import os
import re
import sys

try:
    sys.stdout.reconfigure(encoding="utf-8")
except Exception:
    pass

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
SHARE_CFG = os.path.join(ROOT, "config.share.yaml")

SKIP_SUBSTR = ("competition-2026", "knowledge_base", os.sep + ".git" + os.sep)


def service_port():
    """从 config.share.yaml 读 server.port（第一个两空格缩进的 port:）。"""
    with open(SHARE_CFG, "r", encoding="utf-8", errors="ignore") as fh:
        for line in fh:
            m = re.match(r"^  port:\s*(\d+)", line)
            if m:
                return m.group(1)
    raise SystemExit("未能从 config.share.yaml 解析 server.port")


def build_rules(new_port):
    """返回 [(pattern, replacement, label)]，按顺序应用。"""
    old = "8080"
    return [
        ("https://127.0.0.1:8080", "https://127.0.0.1:%s" % new_port, "URL(https,127.0.0.1)"),
        ("http://127.0.0.1:8080", "http://127.0.0.1:%s" % new_port, "URL(http,127.0.0.1)"),
        ("https://localhost:8080", "https://localhost:%s" % new_port, "URL(https,localhost)"),
        ("http://localhost:8080", "http://localhost:%s" % new_port, "URL(http,localhost)"),
        ("lsof -i :8080", "lsof -i :%s" % new_port, "lsof"),
        ("-p 8080:8080", "-p %s:%s" % (new_port, new_port), "docker -p"),
    ]


CONFIG_EXAMPLE_RE = re.compile(r"^(\s*port:\s*)8080(\s*(?:#.*)?)$")


def main():
    apply = "--apply" in sys.argv
    new_port = service_port()
    print("真值源 config.share.yaml server.port = %s  （%s）"
          % (new_port, "落盘" if apply else "DRY-RUN"))
    print("=" * 74)

    files = []
    for base, dirs, names in os.walk(os.path.join(ROOT, "docs")):
        dirs[:] = [d for d in dirs if d not in ("competition-2026",)]
        for n in names:
            if n.endswith((".md", ".html")):
                files.append(os.path.join(base, n))
    files.sort()

    rules = build_rules(new_port)
    total = 0
    changed_files = 0
    for path in files:
        rel = os.path.relpath(path, ROOT).replace("\\", "/")
        if any(s in path for s in SKIP_SUBSTR):
            continue
        data = open(path, "rb").read()
        text = data.decode("utf-8")
        hits = []
        for old, new, label in rules:
            c = text.count(old)
            if c:
                hits.append((label, old, new, c))
                text = text.replace(old, new)
        # 配置示例行：仅当整行就是 port: 8080（可带注释）
        new_lines, cfg_hits = [], 0
        for ln in text.split("\n"):
            m = CONFIG_EXAMPLE_RE.match(ln)
            if m:
                new_lines.append("%s%s%s" % (m.group(1), new_port, m.group(2)))
                cfg_hits += 1
            else:
                new_lines.append(ln)
        if cfg_hits:
            hits.append(("config sample", "port: 8080", "port: %s" % new_port, cfg_hits))
        text = "\n".join(new_lines)

        if not hits:
            continue
        changed_files += 1
        print("\n%s" % rel)
        for label, old, new, c in hits:
            print("    %-22s x%-3d  %s -> %s" % (label, c, old, new))
            total += c
        if apply:
            with io.open(path, "wb") as fh:
                fh.write(text.encode("utf-8"))

    print("\n" + "=" * 74)
    print("涉及文件 %d 个，替换 %d 处%s" % (changed_files, total,
                                          "" if apply else "（未落盘）"))
    if not apply:
        print("加 --apply 落盘")
    return 0


if __name__ == "__main__":
    sys.exit(main())
