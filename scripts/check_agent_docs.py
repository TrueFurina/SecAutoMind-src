#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""文档结构门禁（十一防线 P-01/P-02/P-03/P-09/P-10 的机验部分）。

为什么需要
----------
"常驻文件 ≤300 行、一个事实一个真源、文档索引不能烂" 这三条，只写在文档里就一定会烂：
- AGENTS.md 每次加教训都会变长，没人会主动删；
- 路由表里的路径会随重构失效，写错的路径看起来最像证据；
- docs/ 顶层文档会持续增长，索引一定漏登。

本门禁把四条判据变成退出码：
  C1 AGENTS.md ≤ 300 行（常驻区预算）
  C2 docs/AGENT_ROUTES.md 中反引号路径必须真实存在（防编造路径）
  C3 docs/ 顶层每个 .md 必须在 docs/INDEX.md 登记（防文档失控增长）
  C4 docs/收尾清单.md 必须含 8 项打钩 + 取证边界段（防清单退化成空壳）

用法
----
  python scripts/check_agent_docs.py            # 正常检查，rc=0 通过
  python scripts/check_agent_docs.py --json     # 机器可读
  python scripts/check_agent_docs.py --self-test  # 变异验证：注入错误必须变红

退出码：0 = 通过；1 = 违反判据。
"""

import argparse
import json
import os
import re
import shutil
import sys
import tempfile

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))

MAX_AGENTS_LINES = 300
ROUTES_DOC = "docs/AGENT_ROUTES.md"
INDEX_DOC = "docs/INDEX.md"
CLOSING_DOC = "docs/收尾清单.md"

# 反引号里"像路径"的 token：不含通配符/占位符/空格
PATH_TOKEN = re.compile(r"^[A-Za-z0-9_./\-\u4e00-\u9fff]+$")
PATH_EXT = (".go", ".py", ".js", ".css", ".yaml", ".yml", ".md", ".sh",
            ".json", ".txt", ".toml", ".nsi", ".bat", ".ps1")


def _read(path):
    with open(path, encoding="utf-8", errors="ignore") as fh:
        return fh.read()


def check_agents_budget(root):
    p = os.path.join(root, "AGENTS.md")
    if not os.path.isfile(p):
        return ["C1 AGENTS.md 不存在"]
    n = len(_read(p).splitlines())
    if n > MAX_AGENTS_LINES:
        return ["C1 AGENTS.md %d 行 > 上限 %d 行（常驻区预算超支）"
                % (n, MAX_AGENTS_LINES)]
    return []


def _extract_paths(text):
    out = []
    for m in re.finditer(r"`([^`\n]+)`", text):
        tok = m.group(1).strip()
        # 命令串取第一个 token（如 "python scripts/x.py --json"）
        if " " in tok:
            tok = tok.split()[0]
        if not tok or not PATH_TOKEN.match(tok):
            continue
        if not (tok.endswith("/") or tok.endswith(PATH_EXT)):
            continue
        out.append(tok)
    return out


# 工具态目录：被 .gitignore 覆盖、干净检出里永远不存在。
# 路由表提到它们是**教训句**（如「交付包排除面必须覆盖 .workbuddy-ai/」），
# 不是「仓库里应该有这个目录」。详见 check_routes_paths 内注释。
TOOL_STATE_DIRS = {".workbuddy", ".workbuddy-ai", ".box-agent", ".atomcode", ".git", "node_modules"}


def check_routes_paths(root):
    p = os.path.join(root, ROUTES_DOC)
    if not os.path.isfile(p):
        return ["C2 %s 不存在" % ROUTES_DOC]
    bad = []
    seen = set()
    for tok in _extract_paths(_read(p)):
        if tok in seen:
            continue
        seen.add(tok)
        # 工具态目录（2026-10-26 修，2026-10-31 被并行会话覆盖后重打）：
        # 路由表里 `.workbuddy-ai/` 是**教训句**（"交付包排除面必须覆盖它"），
        # 而该目录被 .gitignore 覆盖、干净检出永远不存在 → 判"引用了不存在的路径"是误报。
        # 只跳过这几类，普通路径仍照常校验（下方有变异自测钉住）。
        if tok.rstrip("/") in TOOL_STATE_DIRS:
            continue
        if not os.path.exists(os.path.join(root, tok.rstrip("/"))):
            bad.append(tok)
    return ["C2 路由表引用了不存在的路径: %s" % b for b in bad]


def check_index_coverage(root):
    docs_dir = os.path.join(root, "docs")
    if not os.path.isdir(docs_dir):
        return ["C3 docs/ 不存在"]
    actual = sorted(f for f in os.listdir(docs_dir)
                    if f.endswith(".md") and os.path.isfile(os.path.join(docs_dir, f)))
    idx = os.path.join(root, INDEX_DOC)
    if not os.path.isfile(idx):
        return ["C3 %s 不存在（文档索引缺失）" % INDEX_DOC]
    text = _read(idx)
    missing = [f for f in actual if ("docs/" + f) not in text and f not in text]
    errs = ["C3 未在 INDEX 登记: docs/%s" % f for f in missing]
    # 反向：INDEX 里点名但不存在的文档 = 索引指向空气
    for m in re.finditer(r"`docs/([^`\s]+\.md)`", text):
        name = m.group(1)
        if any(ch in name for ch in "*?<>{}"):  # 通配/占位符不是具体文档
            continue
        if not os.path.isfile(os.path.join(root, "docs", name)):
            errs.append("C3 INDEX 指向不存在的文档: docs/%s" % name)
    return errs


def check_closing_list(root):
    p = os.path.join(root, CLOSING_DOC)
    if not os.path.isfile(p):
        return ["C4 %s 不存在" % CLOSING_DOC]
    text = _read(p)
    errs = []
    items = re.findall(r"^###\s*([1-8])\.", text, re.M)
    if len(set(items)) != 8:
        errs.append("C4 收尾清单应含 8 项打钩，实际识别到 %d 项" % len(set(items)))
    if "取证边界" not in text:
        errs.append("C4 收尾清单缺少「取证边界声明」段")
    if "- [ ]" not in text:
        errs.append("C4 收尾清单没有可打钩的复选框")
    return errs


# 顶层文档数上限：**只许减，不许增**（2026-10-24 建卡时的存量 44 份）。
# 机制意义：这个仓库的复杂度是单调增长的——每次事故产出一份文档 + 一个门禁，
# 从不退役。加这个上限，是让"新增一份顶层文档"变成一次显式决策（要么退役旧的，
# 要么把新文档放进子目录），而不是顺手写一个。
TOP_LEVEL_CAP = 44
# ── C5 顶层白名单（2026-10-31 收紧）────────────────────────────────────
# 旧判据是「顶层 ≤ 44 份」——只在**撞线时**才红。实测后果：并行会话往顶层丢文件，
# 一次性把顶层推到 45 份触发红，然后要有人中途停下来清理（2026-10-31 实况）。
# 现改为**白名单**：顶层只允许这 32 份，多出任何一份立刻红。
# 收益：把「顶层膨胀」从「事后撞线」变成「当场拦住」，且**不需要搬迁任何存量文档**
# （32 份存量共被引用 332 次，搬迁成本极高且易断链）。
# 维护：确需新增顶层文档时，同时把名字加进本名单 —— 等于强制一次显式评审。
TOP_LEVEL_ALLOWLIST = {
    "2027决赛作战规划.md",
    "AGENT_ROUTES.md",
    "GATES.md",
    "Go静态检查基线-2026-10-21.md",
    "HITL_human档招募方案.md",
    "IM机器人演示与部署验收清单.md",
    "INDEX.md",
    "LessonsLearned.md",
    "MCP工具分级注册方案-2026-10-19.md",
    "Octop_取精去糟与反哺清单_20261018.md",
    "QUICKSTART_NEXT_AGENT.md",
    "README.md",
    "URGENT_提交格式_裸内容.md",
    "cross_bench_report.md",
    "dual_repo_coherence.md",
    "external_bench_report.md",
    "hitl_failure_boundary.md",
    "merge_xhlj_roadmap_20261023.md",
    "quant_effect.md",
    "static_benchmark_gap_analysis_20261023.md",
    "产品优化规划.md",
    "决赛对标分析_SecAutoMind_vs_西湖论剑.md",
    "口径修复清单.md",
    "工具契约与输出边界-2026-10-20.md",
    "收尾清单.md",
    "服务器实机验证_Runbook_20261020.md",
    "真实靶场_LAMPSecurity_CTF4_可用性验证_20261021.md",
    "真题数据补齐方案_20261021.md",
    "腾讯轻量云部署指南.md",
    "规划-移植与优化总纲.md",
    "还能做什么_能力菜单与提示词_20261024.md",
    "非flag靶场证据探测_设计与训练记录_20261021.md",
}


def check_top_level_cap(root):
    docs_dir = os.path.join(root, "docs")
    if not os.path.isdir(docs_dir):
        return ["C5 docs/ 不存在"]
    n = len([f for f in os.listdir(docs_dir)
             if f.endswith(".md") and os.path.isfile(os.path.join(docs_dir, f))])
    if n > TOP_LEVEL_CAP:
        return ["C5 docs/ 顶层 %d 份 > 上限 %d：新文档请放子目录"
                "（docs/specs|docs/archive|docs/templates），或先退役一份旧文档" % (n, TOP_LEVEL_CAP)]
    extra = sorted(f for f in os.listdir(docs_dir)
                   if f.endswith(".md") and os.path.isfile(os.path.join(docs_dir, f))
                   and f not in TOP_LEVEL_ALLOWLIST)
    if extra:
        return ["C5 docs/ 顶层出现白名单外的新文档 %d 份：%s —— 请放到 docs/specs|docs/archive|"
                "docs/templates；确属顶层文档则同时加进 TOP_LEVEL_ALLOWLIST（强制一次评审）"
                % (len(extra), ", ".join(extra))]
    return []


def check_gates_map(root):
    """门禁地图必须与 ci.yml 同步（防止"改了门禁没人知道"）。"""
    ci = os.path.join(root, ".github", "workflows", "ci.yml")
    if not os.path.isfile(ci):
        return []  # 无 CI 的检出（自测夹具）不适用
    try:
        import gen_gates_map as gen
    except ImportError:
        return ["C6 无法导入 scripts/gen_gates_map.py"]
    expected = gen.render(gen.parse(ci))
    gm = os.path.join(root, "docs", "GATES.md")
    if not os.path.isfile(gm):
        return ["C6 docs/GATES.md 不存在：跑 python scripts/gen_gates_map.py --write"]
    if _read(gm).rstrip("\n") != expected.rstrip("\n"):
        return ["C6 docs/GATES.md 与 ci.yml 不一致（门禁地图过期）："
                "跑 python scripts/gen_gates_map.py --write"]
    return []


CHECKS = (check_agents_budget, check_routes_paths, check_index_coverage,
          check_closing_list, check_top_level_cap, check_gates_map)


def run_all(root):
    errs = []
    for fn in CHECKS:
        errs.extend(fn(root))
    return errs


# ── 变异验证：每个用例都必须让对应判据变红 ─────────────────────────────
def _mk_tree(base):
    os.makedirs(os.path.join(base, "docs"), exist_ok=True)
    # 最小 ci.yml + 与之同步的 GATES.md（C6 需要两者一致）
    ci_dir = os.path.join(base, ".github", "workflows")
    os.makedirs(ci_dir, exist_ok=True)
    ci = os.path.join(ci_dir, "ci.yml")
    with open(ci, "w", encoding="utf-8") as fh:
        fh.write("jobs:\n"
                 "  # 演示门禁：守演示用。\n"
                 "  demo-gate:\n"
                 "    runs-on: ubuntu-latest\n"
                 "    steps:\n"
                 "      - name: demo\n"
                 "        run: python scripts/demo_test.py\n")
    import gen_gates_map as gen
    with open(os.path.join(base, "docs", "GATES.md"), "w", encoding="utf-8") as fh:
        fh.write(gen.render(gen.parse(ci)))
    with open(os.path.join(base, "AGENTS.md"), "w", encoding="utf-8") as fh:
        fh.write("# AGENTS\n")
    with open(os.path.join(base, ROUTES_DOC), "w", encoding="utf-8") as fh:
        fh.write("# ROUTES\n\n| a | `AGENTS.md` |\n")
    with open(os.path.join(base, INDEX_DOC), "w", encoding="utf-8") as fh:
        fh.write("# INDEX\n\n- docs/INDEX.md\n- docs/AGENT_ROUTES.md\n- docs/收尾清单.md\n- docs/GATES.md\n")
    with open(os.path.join(base, CLOSING_DOC), "w", encoding="utf-8") as fh:
        fh.write("# 收尾\n\n## 一、八项打钩\n\n")
        for i in range(1, 9):
            fh.write("### %d. 项%d\n- [ ] 判据\n\n" % (i, i))
        fh.write("## 二、取证边界声明\n")


def self_test():
    cases = []

    def case(name, mutate, expect_fail):
        base = tempfile.mkdtemp(prefix="docsgate_")
        try:
            _mk_tree(base)
            mutate(base)
            errs = run_all(base)
            got_fail = bool(errs)
            cases.append((name, expect_fail, got_fail, errs))
        finally:
            shutil.rmtree(base, ignore_errors=True)

    def m_baseline(b):
        pass

    def m_agents_long(b):
        with open(os.path.join(b, "AGENTS.md"), "w", encoding="utf-8") as fh:
            fh.write("# AGENTS\n" + "x\n" * 400)

    def m_fake_path(b):
        with open(os.path.join(b, ROUTES_DOC), "a", encoding="utf-8") as fh:
            fh.write("\n`internal/does_not_exist_xyz.go`\n")

    def m_index_missing(b):
        with open(os.path.join(b, "docs", "orphan_doc.md"), "w", encoding="utf-8") as fh:
            fh.write("# orphan\n")

    def m_index_ghost(b):
        with open(os.path.join(b, INDEX_DOC), "a", encoding="utf-8") as fh:
            fh.write("\n- `docs/ghost_doc.md`\n")

    def m_closing_short(b):
        with open(os.path.join(b, CLOSING_DOC), "w", encoding="utf-8") as fh:
            fh.write("# 收尾\n\n### 1. 只有一项\n- [ ] x\n")

    def m_gates_stale(b):
        with open(os.path.join(b, ".github", "workflows", "ci.yml"), "a",
                  encoding="utf-8") as fh:
            fh.write("  # 新增门禁：忘了更新地图。\n  new-gate:\n"
                     "    runs-on: ubuntu-latest\n    steps:\n"
                     "      - name: n\n        run: python scripts/n.py\n")

    def m_tool_state_dir(b):
        # 2026-10-31 回归：路由表提到 gitignored 的工具态目录**不得**判红。
        # 真事故：CI 在干净检出上恒红，报 "C2 路由表引用了不存在的路径: .workbuddy-ai/"，
        # 而那句话是教训（"交付包排除面必须覆盖 .workbuddy-ai/"），目录本身永远不入仓。
        with open(os.path.join(b, ROUTES_DOC), "a", encoding="utf-8") as fh:
            fh.write("\n交付包排除面必须覆盖 `.workbuddy-ai/`（曾把账号口令发给评委）\n")

    def m_new_top_doc(b):
        # 2026-10-31：C5 从「计数 ≤44」收紧为「白名单」。
        # 白名单外的新顶层文档必须**当场**变红，而不是等撞到 44 份。
        with open(os.path.join(b, "docs", "随手新文档.md"), "w", encoding="utf-8") as fh:
            fh.write("# 新文档\n")

    case("基线应通过", m_baseline, False)
    case("AGENTS 超 300 行应红", m_agents_long, True)
    case("路由表假路径应红", m_fake_path, True)
    case("路由表工具态目录应绿（不误报）", m_tool_state_dir, False)
    case("INDEX 漏登文档应红", m_index_missing, True)
    case("INDEX 指向幽灵文档应红", m_index_ghost, True)
    case("收尾清单缺项应红", m_closing_short, True)
    case("改门禁未更新地图应红", m_gates_stale, True)
    case("顶层白名单外新文档应红", m_new_top_doc, True)

    ok = True
    for name, expect_fail, got_fail, errs in cases:
        good = expect_fail == got_fail
        ok = ok and good
        print("  [%s] %-24s 期望%s 实际%s" % (
            "OK" if good else "FAIL", name,
            "红" if expect_fail else "绿", "红" if got_fail else "绿"))
        if not good:
            for e in errs[:3]:
                print("        %s" % e)
    print("文档结构门禁自测：%s（%d 项）" % ("PASS" if ok else "FAIL", len(cases)))
    return 0 if ok else 1


def main():
    ap = argparse.ArgumentParser(description="文档结构门禁")
    ap.add_argument("--json", action="store_true")
    ap.add_argument("--self-test", action="store_true")
    ap.add_argument("--root", default=ROOT)
    args = ap.parse_args()

    if args.self_test:
        return self_test()

    errs = run_all(args.root)
    if args.json:
        print(json.dumps({"ok": not errs, "errors": errs}, ensure_ascii=False, indent=2))
    else:
        print("=" * 62)
        print("文档结构门禁（P-01/P-02/P-03/P-09/P-10）")
        print("=" * 62)
        if errs:
            for e in errs:
                print("  [FAIL] %s" % e)
            print("-" * 62)
            print("结论：FAIL（%d 项）" % len(errs))
        else:
            print("  [PASS] C1 AGENTS.md ≤ %d 行" % MAX_AGENTS_LINES)
            print("  [PASS] C2 路由表路径全部存在")
            print("  [PASS] C3 docs 顶层文档全部登记")
            print("  [PASS] C4 收尾清单八项齐备")
            print("  [PASS] C5 docs 顶层文档数 ≤ %d（只许减不许增）" % TOP_LEVEL_CAP)
            print("  [PASS] C6 门禁地图与 ci.yml 一致")
            print("-" * 62)
            print("结论：PASS")
    return 0 if not errs else 1


if __name__ == "__main__":
    sys.exit(main())
