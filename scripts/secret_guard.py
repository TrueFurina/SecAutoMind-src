#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""SecAutoMind 密钥门禁（打包前/提交前必跑）

背景（2026-09-08 质检发现）：
    项目旧的打包前门禁命令是
        grep -rIl -E "sk-[A-Za-z0-9]{16,}|Bearer [A-Za-z0-9]{16,}" docs/ PPT/
    存在两个致命缺口：
      1. 正则 `sk-[A-Za-z0-9]{16,}` 匹配不到 `sk-ws-H.xxx` —— 第 4 位是连字符即断匹配，
         一把真实存活的千问 key 正是从这个洞漏过去的。门禁失效比没有门禁更危险。
      2. 只扫 docs/ PPT/，完全不扫 config.yaml —— 而 config.yaml 被 .gitignore 排除、
         不进 git 却会进交付 zip，恰恰是最该扫的位置。

本脚本修正这两点，并额外做到：
      - 自动区分「真实凭证」与「占位符/示例/测试假值」，后者不算违规
      - 输出一律打码（只显示前 6 后 4），绝不把完整密钥打到终端或日志
      - 扫磁盘真实文件（含 gitignore 的文件），而不是只扫 git 跟踪文件

用法：
    python scripts/secret_guard.py                  # 人类可读报告
    python scripts/secret_guard.py --json           # 机器可读
    python scripts/secret_guard.py --dir .          # 指定扫描根目录

退出码：
    0 = 无真实凭证命中（可交付）
    1 = 发现真实凭证（禁止打包，必须先轮换/移除）
"""
import os
import re
import sys
import json

try:
    sys.stdout.reconfigure(encoding="utf-8")
except Exception:
    pass

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))

# 扫描的文本后缀（跳过二进制/产物）
TEXT_EXT = {
    ".go", ".py", ".md", ".yaml", ".yml", ".json", ".sh", ".ps1", ".bat",
    ".html", ".htm", ".txt", ".env", ".toml", ".ini", ".cfg", ".conf",
    ".js", ".ts", ".vue", ".tmpl", ".nsi", ".b64", ".csv",
}

# 不扫描的目录（二进制产物 / 第三方 / 工具链 / 版本库）
SKIP_DIRS = {
    ".git", ".workbuddy", "node_modules", "dist", "build", "vendor",
    "__pycache__", ".venv", "venv", "logs", "chat_uploads", "data_backup_boot",
    "data_backup_boot2", "execution", ".idea", ".vscode",
}
SKIP_FILE_SUFFIX = {".exe", ".dll", ".ico", ".png", ".jpg", ".jpeg", ".gif",
                    ".zip", ".7z", ".pdf", ".docx", ".pptx", ".db", ".woff",
                    ".woff2", ".ttf", ".mp4", ".bin", ".so", ".dylib"}
MAX_FILE_BYTES = 5 * 1024 * 1024

# 凭证模式（修正版：前缀后允许连字符/点/下划线，不再被第 4 位连字符截断）
PATTERNS = [
    ("OpenAI式 sk- 前缀", re.compile(r"\bsk[-_][A-Za-z0-9][A-Za-z0-9._\-]{10,}")),
    ("千问 ws 通道 key", re.compile(r"\bsk-ws-[A-Za-z0-9][A-Za-z0-9._\-]{8,}")),
    ("Anthropic key", re.compile(r"\bsk-ant-[A-Za-z0-9._\-]{12,}")),
    ("AWS Access Key", re.compile(r"\b(?:AKIA|ASIA)[0-9A-Z]{12,}\b")),
    ("GitHub Token", re.compile(r"\bgh[pousr]_[A-Za-z0-9]{16,}\b")),
    ("Slack Token", re.compile(r"\bxox[baprs]-[A-Za-z0-9\-]{10,}")),
    ("PEM 私钥", re.compile(r"-----BEGIN [A-Z ]*PRIVATE KEY-----")),
    ("飞书 app_secret", re.compile(r"app_secret\s*[:=]\s*['\"]?([A-Za-z0-9]{24,})['\"]?")),
    ("Bearer 长令牌", re.compile(r"\bBearer\s+([A-Za-z0-9._\-]{24,})")),
]

# 这些路径下的命中属于测试夹具 / CTF 真题语料，本就该含假凭证，
# 不阻塞交付，但单独列为「可疑」交人工确认，避免真凭证藏在其中被忽略。
SUSPECT_PATH = re.compile(
    r"_test\.go$|data/ctf_benchmark/|/tests?/|/testdata/|_example|\.example",
    re.I,
)

# CTF 真题语料里的 flag 常常长得像凭证（如 picoCTF{@sk_th3_...}），统一判为占位
FLAG_LIKE = re.compile(r"picoCTF\{|flag\{|CTF\{|DASCTF\{", re.I)

# 门禁自身的测试夹具：secret_guard_test.py 必须内嵌「形似真凭证」的样本才能验证检出能力，
# 否则门禁会把自己写成的数据报成 BLOCK（自指死锁）。
# ⚠️ 安全约束：这里只豁免**精确文件名**，绝不用模糊前缀，避免有人把真密钥塞进同名文件绕过门禁；
#    且这些样本是公开的测试向量（sk-ws-H.PMPEYIE... 等），不是本项目使用的真实凭证。
SELF_EXEMPT = {"scripts/secret_guard_test.py"}

# 占位符 / 示例 / 测试假值特征（命中即判为安全）
PLACEHOLDER = re.compile(
    r"xxxx|XXXX|\bxxx\b|\.\.\.|\$\{|YOUR_|your_|REPLACE|replace_me|CHANGE_ME|"
    r"placeholder|PLACEHOLDER|example|EXAMPLE|EXAMPLE\.COM|dummy|DUMMY|"
    r"fake|FAKE|invalid|INVALID|test-key|testkey|<[^>]*>|\[.*填写.*\]|"
    r"待填|占位|示例|请填写|你的",
    re.I,
)


def mask(s):
    """打码：只保留前 6 与后 4 位，其余用 * 替代。铁律：输出绝不出现完整密钥。"""
    s = s.strip()
    if len(s) <= 12:
        return s[:3] + "*" * max(0, len(s) - 3)
    return s[:6] + "*" * (len(s) - 10) + s[-4:]


def is_placeholder(value):
    return bool(PLACEHOLDER.search(value)) or bool(FLAG_LIKE.search(value))


def scan_dir(root):
    findings = []
    scanned = 0
    for dirpath, dirnames, filenames in os.walk(root):
        dirnames[:] = [d for d in dirnames
                       if d not in SKIP_DIRS and not d.startswith(".") or d == "."]
        dirnames[:] = [d for d in dirnames if d not in SKIP_DIRS]
        for fn in filenames:
            ext = os.path.splitext(fn)[1].lower()
            if ext in SKIP_FILE_SUFFIX:
                continue
            if ext and ext not in TEXT_EXT and fn not in (".env", "Dockerfile"):
                continue
            path = os.path.join(dirpath, fn)
            try:
                if os.path.getsize(path) > MAX_FILE_BYTES:
                    continue
                with open(path, "r", encoding="utf-8", errors="ignore") as fh:
                    lines = fh.read().splitlines()
            except Exception:
                continue
            scanned += 1
            for lineno, line in enumerate(lines, 1):
                rel = os.path.relpath(path, root).replace("\\", "/")
                # flag 特征必须看整行：PATTERNS 只截取 `sk_th3...` 片段，
                # 其外的 `picoCTF{` 前缀不在片段内，只看片段会漏判（2026-09-09 实测修复）。
                line_is_flag = bool(FLAG_LIKE.search(line))
                for label, pat in PATTERNS:
                    for m in pat.finditer(line):
                        # 优先取捕获组（例如 app_secret: xxx 只取值，不把字段名算进密钥）
                        raw = m.group(1) if pat.groups and m.group(1) else m.group(0)
                        ph = (is_placeholder(raw) or line_is_flag
                              or rel in SELF_EXEMPT)
                        suspect = (not ph) and bool(SUSPECT_PATH.search(rel))
                        findings.append({
                            "file": rel,
                            "line": lineno,
                            "kind": label,
                            "masked": mask(raw),
                            "placeholder": ph,
                            "suspect": suspect,
                        })
    return scanned, findings


def main():
    root = ROOT
    if "--dir" in sys.argv:
        root = os.path.abspath(sys.argv[sys.argv.index("--dir") + 1])
    scanned, findings = scan_dir(root)

    real = [f for f in findings if not f["placeholder"] and not f["suspect"]]
    suspect = [f for f in findings if f["suspect"]]
    placeholder = [f for f in findings if f["placeholder"]]

    if "--json" in sys.argv:
        print(json.dumps({
            "scanned_files": scanned,
            "real_findings": real,
            "suspect_findings": suspect,
            "placeholder_findings": len(placeholder),
            "verdict": "BLOCK" if real else "PASS",
        }, ensure_ascii=False, indent=2))
        return 1 if real else 0

    print("=" * 66)
    print("SecAutoMind 密钥门禁 · 扫描根目录 %s" % root)
    print("=" * 66)
    print("  已扫描文本文件   %d" % scanned)
    print("  占位符/示例命中  %d（判定安全，不计违规）" % len(placeholder))
    print("  可疑命中         %d（测试夹具/CTF 语料，不阻塞但请人工确认）" % len(suspect))
    print("  真实凭证命中     %d" % len(real))
    print("-" * 66)
    if real:
        print("  [BLOCK] 发现真实凭证，禁止打包交付：\n")
        for f in real:
            print("    %s:%d" % (f["file"], f["line"]))
            print("      类型: %s" % f["kind"])
            print("      值(已打码): %s" % f["masked"])
        print("\n  处理顺序：")
        print("    1) 到对应平台【轮换/revoke】该凭证（泄露过的 key 不可继续使用）")
        print("    2) 改为环境变量注入（本项目 env 优先级高于 yaml）")
        print("    3) 重跑本脚本直到 PASS，再打包")
    else:
        print("  [PASS] 未发现真实凭证，可进入打包流程。")
    if suspect:
        print("\n  可疑命中清单（测试/语料，通常无需处理）：")
        for f in suspect[:15]:
            print("    %s:%d  %s  %s" % (f["file"], f["line"], f["kind"], f["masked"]))
        if len(suspect) > 15:
            print("    ... 另有 %d 条" % (len(suspect) - 15))
    print("=" * 66)
    return 1 if real else 0


if __name__ == "__main__":
    sys.exit(main())
