#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""文档静态检查门禁 —— 四类「文档里说了、现实里没有」的问题。

背景（2026-10-13 实测，四类真实缺陷，此前均无任何门禁能发现）
--------------------------------------------------------------
1. **代码块不闭合**：`docs/zh-CN/competition-2026/决赛当天runbook_20260917.md`
   有一段排查命令**缺少开头围栏**（只有孤立的结尾 ```），CommonMark 下会把后续
   `## 1. 开赛步骤` 标题吞进代码块、把命令段渲染成普通正文 —— 一份**现场照着做的
   操作手册**被渲染错乱。数字门禁只看数字、doc-port 只看端口，都发现不了。
2. **本地链接断裂**：Markdown 里的 `[文本](相对路径)` 指向不存在的文件/目录。
3. **引用不存在的脚本**：文档/`go.mod` 注释里写 `scripts/xxx.sh` / `scripts/xxx.py`，
   而该文件从未存在（实测 `scripts/check-docs.py`、`scripts/bootstrap-go.sh` 两例）——
   读者照做必然失败。
   > 2026-10-25 修正假阳性：旧实现只从 `scripts/` 起截，把
   > `CTF-Agent_融合/ctf_agent/scripts/_kpi_canonical.py`（真实存在）误判为
   > `scripts/_kpi_canonical.py` 不存在。现改为向左扩展到完整路径起点。
4. **英文文档缺中文对应**：`docs/en-US/` 下每篇 `.md` 都应有一份同名 `docs/zh-CN/` 文档
   （中文为源、英文是子集；实测英文全部有中文对应，反向不成立故只单向校验）。

它是什么 / 不是什么
------------------
本门禁只做**存在性与结构**检查（可机验、零歧义），不做风格审查、不校验外部 URL 可达性
（外部站点抖动会造成假红）。

扫描面：`<root>/docs/**/*.md` + `<root>/*.md`（与 `check_material_numbers.py` 的现行
材料面正交互补：那边管数字，这边管引用与结构）。

历史档处理（与 `check_material_numbers.py` 同源）
------------------------------------------------
- **围栏 / 本地链接：查全部文档**——渲染错乱与断链在任何文档里都是缺陷（读者会看），
  与文件新旧无关（实测缺陷正落在一份带日期的 runbook 上）。
- **`scripts/` 引用：只查现行文档**——历史档里的脚本引用是对**当时真实状态**的记录
  （脚本当时存在/被使用，后被移除或误判），改了即属重写历史。故复用
  `check_material_numbers.is_historical()`，保持历史判定单一规则源。

用法：
    python scripts/check_docs_lint.py                 # 检查当前仓库
    python scripts/check_docs_lint.py --root DIR      # 检查任意根（供回归测试）
    python scripts/check_docs_lint.py --json          # 机器可读
退出码：0 = 通过；1 = 有问题；2 = 无法完成（fail-closed）。
"""
import argparse
import importlib.util
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

# 本地链接里视为"外部/非文件"的前缀（不检查其可达性）
EXTERNAL_PREFIX = ("http://", "https://", "mailto:", "tel:", "ftp://", "data:")
# scripts/ 下引用必须带这些扩展名才算"文件引用"（避免把 `scripts/ 目录` 之类散文误判）
SCRIPT_EXT = (".py", ".sh", ".go", ".js", ".json", ".yaml", ".yml", ".nsi", ".ps1", ".bat", ".cmd")

FENCE_RE = re.compile(r"^([ \t]{0,3})(`{3,}|~{3,})(.*)$")
LINK_RE = re.compile(r"\[[^\]]*\]\(\s*<?([^)>\s]+)>?[^)]*\)")
SCRIPT_REF_RE = re.compile(r"scripts/[A-Za-z0-9_./\-]+(?:\.[A-Za-z0-9]+)")

# 路径向左扩展的停止字符：空白、反引号、引号、括号、表格竖线、中文标点
_PATH_STOP = set(" \t\r\n`\"'()[]{}<>|，、。；：*")


def _expand_path_token(text: str, start: int, end: int) -> str:
    """把 `scripts/...` 匹配向左扩展到完整路径的起点。

    2026-10-25 实锤假阳性：文档写
    `CTF-Agent_融合/ctf_agent/scripts/_kpi_canonical.py`（文件真实存在），
    旧实现只从 `scripts/` 起截，得到 `scripts/_kpi_canonical.py`，再拼到仓库根
    → 必然不存在 → 假红 4 处，把 CI 卡住。向左扩到路径起点即可正确解析。
    """
    i = start
    while i > 0 and text[i - 1] not in _PATH_STOP:
        i -= 1
    return text[i:end]


def _load_material_gate():
    """复用材料门禁的『历史档』判定，避免两套规则渐行渐远。"""
    path = os.path.join(HERE, "check_material_numbers.py")
    spec = importlib.util.spec_from_file_location("_cmn_for_lint", path)
    mod = importlib.util.module_from_spec(spec)
    try:
        spec.loader.exec_module(mod)
    except SystemExit:  # 该模块自身以 SystemExit 结束也无妨，模块属性已就绪
        pass
    return mod


_CMN = _load_material_gate()
SNAPSHOT_MARK = getattr(_CMN, "SNAPSHOT_MARK", "CALIBER-SNAPSHOT")


def is_historical(rpath, first_lines):
    """历史档：内容前 40 行带 SNAPSHOT 标记，或路径内嵌早于今天的日期。"""
    if SNAPSHOT_MARK in "".join(first_lines[:40]):
        return True
    try:
        return bool(_CMN.is_historical(rpath))
    except Exception:
        return False


def iter_docs(root):
    """产出待检 Markdown 文件（docs/ 递归 + 根目录 *.md）。"""
    seen = set()
    docs = os.path.join(root, "docs")
    if os.path.isdir(docs):
        for dp, dns, fns in os.walk(docs):
            dns[:] = [d for d in dns if d not in (".git", "node_modules")]
            for fn in fns:
                if fn.lower().endswith(".md"):
                    p = os.path.join(dp, fn)
                    if p not in seen:
                        seen.add(p)
                        yield p
    if os.path.isdir(root):
        for fn in sorted(os.listdir(root)):
            if fn.lower().endswith(".md"):
                p = os.path.join(root, fn)
                if os.path.isfile(p) and p not in seen:
                    seen.add(p)
                    yield p


def rel(path, root):
    return os.path.relpath(path, root).replace("\\", "/")


def check_fences(lines):
    """代码块围栏检查。返回 [(line_no, 描述), ...]。

    判据 = 状态机（真未闭合）+ **围栏数奇偶**。为什么两条都要：
    实测缺陷「一段命令缺开头围栏、却多出一个孤立结尾 ```」在 CommonMark 下**表面平衡**
    （那个 ``` 被解析成新块的开头），状态机发现不了；但它的围栏总数是**奇数**，
    而合法文档的围栏必然成对 → 奇偶判据能抓住它。两者互补，缺一会漏。
    """
    problems = []
    fence_idx = []
    in_fence = False
    fence_char = ""
    fence_len = 0
    open_line = 0
    for i, raw in enumerate(lines, 1):
        m = FENCE_RE.match(raw.rstrip("\n").rstrip("\r"))
        if not m:
            continue
        fence_idx.append(i)
        marker, rest = m.group(2), m.group(3)
        if not in_fence:
            in_fence, fence_char, fence_len, open_line = True, marker[0], len(marker), i
            continue
        if marker[0] == fence_char and len(marker) >= fence_len and rest.strip() == "":
            in_fence = False
            fence_char, fence_len, open_line = "", 0, 0
    if in_fence:
        problems.append((open_line, f"代码块在第 {open_line} 行开启，直到文件结束都没有闭合"))
    elif len(fence_idx) % 2 == 1:
        problems.append((fence_idx[0],
                         f"代码块围栏数为奇数（共 {len(fence_idx)} 个），存在多余或错位的围栏"))
    return problems


def check_links(text, filedir):
    """本地链接可达性检查（跳过外部链接、纯锚点）。"""
    problems = []
    for m in LINK_RE.finditer(text):
        url = m.group(1).strip()
        if not url or url.startswith("#"):
            continue
        if url.lower().startswith(EXTERNAL_PREFIX) or url.startswith("/"):
            continue
        target = url.split("#", 1)[0].split("?", 1)[0]
        if not target:
            continue
        if not os.path.exists(os.path.normpath(os.path.join(filedir, target))):
            line_no = text[:m.start()].count("\n") + 1
            problems.append((line_no, f"本地链接指向不存在的路径：`{url}`"))
    return problems


def _is_absolute_ref(token):
    """token 是否为**仓库外**的绝对路径（家目录 / 根路径 / 盘符）。

    2026-10-31 实锤：交接文档里写服务器上的路径 `~/SecAutoMind/scripts/session_registry.py`
    与 `~/sam_s1/scripts/stepfun_s2_server_batch.py`，本门禁把它们当"仓库相对路径"去
    `os.path.exists(root/token)` → 必然不存在 → 7 处误报。
    这类路径属于**部署目标机**，仓库既无权也不该校验；只校验仓库内相对路径。
    """
    t = token.replace("\\", "/")
    return t.startswith("~") or t.startswith("/") or (len(t) > 1 and t[1] == ":")


def check_script_refs(text, root):
    """scripts/ 引用必须真实存在（只校验仓库内相对路径）。"""
    problems = []
    for m in SCRIPT_REF_RE.finditer(text):
        token = _expand_path_token(text, m.start(), m.end())
        if not token.lower().endswith(SCRIPT_EXT):
            continue
        token = token.rstrip(".,);:、。")
        if _is_absolute_ref(token):
            continue
        if not os.path.exists(os.path.join(root, token)):
            line_no = text[:m.start()].count("\n") + 1
            problems.append((line_no, f"引用了不存在的脚本：`{token}`"))
    return problems


def check_bilingual_parity(root):
    """英文文档必须有一份同名中文文档（中文为源，英文是子集）。

    实测（2026-10-13）：docs/zh-CN 66 篇、docs/en-US 32 篇，英文全部有中文对应；
    反向不成立（大量中文文档尚无英文版），故只沿 en→zh 单向校验 —— 加双向会假红。
    """
    findings = []
    zh_dir = os.path.join(root, "docs", "zh-CN")
    en_dir = os.path.join(root, "docs", "en-US")
    # 只在"有英文文档目录"时校验；中文目录缺失则所有英文文档都会被判为缺对应（正确行为）
    if not os.path.isdir(en_dir):
        return findings
    for dp, dns, fns in os.walk(en_dir):
        dns[:] = [d for d in dns if d not in (".git", "node_modules")]
        for fn in fns:
            if not fn.lower().endswith(".md"):
                continue
            under = os.path.relpath(os.path.join(dp, fn), en_dir)
            if not os.path.isfile(os.path.join(zh_dir, under)):
                findings.append({
                    "file": rel(os.path.join(dp, fn), root), "line": 1,
                    "message": "英文文档缺少对应中文文档：`docs/zh-CN/%s`"
                               % under.replace(os.sep, "/"),
                })
    return findings


def run(root):
    findings = []
    for path in iter_docs(root):
        rpath = rel(path, root)
        try:
            with open(path, encoding="utf-8", errors="ignore") as fh:
                text = fh.read()
        except OSError as e:
            raise SystemExit(f"FATAL: 无法读取 {rpath}: {e}")
        lines = text.splitlines()
        filedir = os.path.dirname(path)
        historical = is_historical(rpath, lines)
        problems = check_fences(lines) + check_links(text, filedir)
        # scripts/ 引用只查现行文档（历史档里的脚本引用是当时的真实记录）
        if not historical:
            problems += check_script_refs(text, root)
        for lineno, desc in problems:
            findings.append({"file": rpath, "line": lineno, "message": desc})
    findings += check_bilingual_parity(root)
    findings.sort(key=lambda x: (x["file"], x["line"]))
    return findings


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--root", default=ROOT, help="扫描根（默认仓库根）")
    ap.add_argument("--json", action="store_true", help="以 JSON 输出")
    args = ap.parse_args()

    root = os.path.abspath(args.root)
    if not os.path.isdir(root):
        print(f"FATAL: root 不存在：{root}", file=sys.stderr)
        return 2

    findings = run(root)

    if args.json:
        print(json.dumps({"ok": not findings, "count": len(findings),
                          "findings": findings}, ensure_ascii=False, indent=2))
    else:
        print("=" * 70)
        print("文档静态检查（代码块闭合 / 本地链接 / scripts 引用 / 双语对应）")
        print("=" * 70)
        if not findings:
            print("  [PASS] 未发现不闭合代码块、断裂本地链接、不存在的脚本引用或缺失的中文对应")
        else:
            for f in findings:
                print(f"  [{f['file']}:{f['line']}] {f['message']}")
            print(f"\n共 {len(findings)} 处问题。")
        print("=" * 70)
        print("结论：" + ("PASS —— 文档引用与结构自洽。" if not findings
                          else "FAIL —— 见上。"))

    return 1 if findings else 0


if __name__ == "__main__":
    sys.exit(main())
