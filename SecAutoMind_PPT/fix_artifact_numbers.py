# -*- coding: utf-8 -*-
"""把交付物 .pptx 里的过期数字按 `scripts/count_stats.py` 真值定点改写。

背景（2026-10-18 实测，非推测）
--------------------------------
`scripts/make_delivery_package.py` 的第 5 道自验 `check_artifact_numbers.py` 报红 **76 处**，
导致交付包**被自动删除**（rc=1，宁可不出包）：
    90 工具（真值 91）· 121,786 行（真值 129,233）· 237 测试文件（真值 312）
    · 26/26 与 28/28 测试包（真值 37/37）· 32 个 internal 包（真值 37 个包）
分布在 6 个 pptx 里。根因同 #41：**产物被改过而生成器/数字没跟上**，
且 `SecAutoMind_PPT/*.pptx` 全部 untracked（不入 git）→ CI 看不见，只有打包时才暴露。

为什么不重新生成
----------------
- `冲击冠军版`：生成器 `make_champion_ppt.py` 已是新数字，可重跑；
- `模板版`：生成器 `make_template_ppt.py` 的输入是视觉母版 `演示模板版.pptx`
  （2026-10-18 取证：它与 `闽江御盾•智防矩阵.pptx` **字节完全相同**，sha256 8525b308…）；
- `集大成版`/`草稿内容版`/`闽江睿御`/`闽江御盾`：无生成器或生成器已停更。
故统一采用**定点文本替换**（同 `A11_ppt_text_swap.py` 手法）：只改 run.text 里的数字字面量，
字号/颜色/位置/段落结构一律不动，且新旧字符串**等长**，不存在溢出风险。

两个实测坑（本脚本已内置，勿退化）
--------------------------------
1. **必须递归组合(GroupShape)与表格单元格**：只遍历 slide.shapes 顶层会"改 59 处还剩 15 处"；
2. **必须按段落定位、再落回单个 run**：PowerPoint 常把 `90个` 与 `YAML` 拆成两个 run，
   run 级正则（`90(?=\\s*个?\\s*YAML)`）在 run 里**永远不命中**——这叫假绿。

用法
----
    python SecAutoMind_PPT/fix_artifact_numbers.py --dry-run
    python SecAutoMind_PPT/fix_artifact_numbers.py --apply

退出码：0 = 完成（apply 后回读零残留）；1 = 有跨 run 无法安全改写 / 落盘后仍残留 / 真值取不到
"""
import argparse
import json
import re
import subprocess
import sys
from pathlib import Path

PPT_DIR = Path(__file__).resolve().parent
REPO = PPT_DIR.parent
COUNT_STATS = REPO / "scripts" / "count_stats.py"

# 视觉母版 = 构建输入，不是交付物（check_artifact_numbers.py 同样「恒久排除」它）：
# 改它没有交付意义，反而会破坏 make_template_ppt.py 依赖的母版字节。
EXCLUDE = {"演示模板版.pptx"}


# ── 真值 ─────────────────────────────────────────────────────────────
def load_truth():
    out = subprocess.run([sys.executable, str(COUNT_STATS), "--json"],
                         capture_output=True, text=True, encoding="utf-8", cwd=str(REPO))
    if out.returncode != 0:
        raise SystemExit("count_stats.py 失败，取不到真值：\n" + (out.stderr or out.stdout))
    truth = json.loads(out.stdout[out.stdout.find("{"):])
    # internal 包数口径 = go list ./internal/... 的包数
    # （count_stats.internal_dirs=34 是**子目录数**，两者不可混用）
    try:
        gl = subprocess.run(["go", "list", "./internal/..."], capture_output=True, text=True,
                            encoding="utf-8", cwd=str(REPO))
        paths = [ln for ln in (gl.stdout or "").splitlines() if ln.strip()]
        truth["internal_go_packages"] = len(paths) if gl.returncode == 0 and paths else None
    except Exception:
        truth["internal_go_packages"] = None
    return truth


def build_rules(truth):
    """(正则, 替换, 说明)。新旧字符串等长——保版式。"""
    rules = []
    tools = truth.get("tools_yaml")
    if tools:
        rules.append((r"(?<![\d.])90(?=\s*个?\s*YAML)", str(tools), "工具 YAML 数 90→%s" % tools))
        rules.append((r"(?<![\d.])90(?=\s*工具)", str(tools), "工具数 90→%s" % tools))

    lines = truth.get("non_test_lines")
    if lines:
        new = "{:,}".format(lines)
        for old in ("121,786", "111,058"):
            rules.append((re.escape(old), new, "非测试代码行 %s→%s" % (old, new)))

    tfiles = truth.get("test_files")
    if tfiles:
        rules.append((r"(?<![\d.])237(?=\s*个?\s*测试)", str(tfiles), "测试文件数 237→%s" % tfiles))

    pkgs = truth.get("test_packages")
    if pkgs and truth.get("go_packages"):
        for old in ("26/26", "28/28"):
            rules.append((re.escape(old), "%d/%d" % (pkgs, pkgs), "测试包 %s→%d/%d" % (old, pkgs, pkgs)))

    ipkgs = truth.get("internal_go_packages")
    if ipkgs:
        for old in ("32", "33"):
            rules.append((r"(?<![\d.])" + old + r"(?=\s*个\s*internal)",
                          str(ipkgs), "internal 包数 %s→%s" % (old, ipkgs)))
    return rules


# ── 遍历（递归组合 + 表格）────────────────────────────────────────────
def iter_text_frames(shapes):
    for shape in shapes:
        if getattr(shape, "has_table", False) and shape.has_table:
            for row in shape.table.rows:
                for cell in row.cells:
                    if cell.text_frame is not None:
                        yield cell.text_frame
            continue
        if getattr(shape, "has_text_frame", False) and shape.has_text_frame:
            yield shape.text_frame
        sub = getattr(shape, "shapes", None)      # GroupShape
        if sub is not None:
            for tf in iter_text_frames(sub):
                yield tf


def iter_paragraphs(prs):
    for sidx, slide in enumerate(prs.slides, 1):
        for tf in iter_text_frames(slide.shapes):
            for para in tf.paragraphs:
                yield sidx, para


# ── 段落级定位 → 单 run 落点 ──────────────────────────────────────────
def plan_paragraph(para, rules):
    """返回 (edits, unresolved)。edits=[(run, old, new, desc, sidx)]；unresolved=[(desc, full)]"""
    full = para.text
    runs = list(para.runs)
    if not runs or not full:
        return [], []
    bounds, off = [], 0
    for r in runs:
        bounds.append((off, off + len(r.text), r))
        off += len(r.text)
    if off != len(full):
        # 段落文本 ≠ runs 拼接（含字段/换行符等）→ 结构不确定，保守放弃而不是瞎改
        for pat, _repl, desc in rules:
            if re.search(pat, full):
                return [], [(desc, full)]
        return [], []

    hits = []
    for pat, repl, desc in rules:
        for m in re.finditer(pat, full):
            hits.append((m.start(), m.end(), repl, desc))
    if not hits:
        return [], []

    edits, unresolved = [], []
    # 从右往左改，保证左侧偏移不受影响
    for start, end, repl, desc in sorted(hits, key=lambda x: -x[0]):
        host = [b for b in bounds if b[0] <= start and end <= b[1]]
        if len(host) != 1:
            unresolved.append((desc, full))
            continue
        s0, _e0, run = host[0]
        cur = run.text
        run.text = cur[:start - s0] + repl + cur[end - s0:]
    return edits, unresolved


def scan(prs, rules):
    """只读扫描：返回 (待改处数, [(sid, old, new, desc)], unresolved)"""
    changes, unresolved = [], []
    for sidx, para in iter_paragraphs(prs):
        before = para.text
        # 干跑不落盘：在副本上试算
        plan, unres = _simulate(para, rules)
        unresolved.extend(unres)
        if plan:
            changes.append((sidx, before, plan))
    return changes, unresolved


def _simulate(para, rules):
    """不改真对象：用文本推算将被替换的相邻片段（仅用于 dry-run 报告）。"""
    full = para.text
    plan = []
    for pat, repl, desc in rules:
        for m in re.finditer(pat, full):
            plan.append((m.group(0), repl, desc))
    return plan, []


def bare_stat_edits(prs, truth, apply):
    """处理「裸数字统计卡」：`90` / `237` 这类数字单独一个文本框，语义全靠同页的标签形状
    （如旁边的 `YAML 工具配方`、`测试文件`）。**必须有同页标签佐证才改**，否则宁可报 WARN——
    孤立数字没有上下文，盲改就是猜。"""
    KEYWORD = {
        "90": ("YAML", "工具"),
        "237": ("测试文件",),
        "121,786": ("行",),
        "111,058": ("行",),
    }
    NEW = {
        "90": str(truth.get("tools_yaml") or ""),
        "237": str(truth.get("test_files") or ""),
        "121,786": "{:,}".format(truth["non_test_lines"]) if truth.get("non_test_lines") else "",
        "111,058": "{:,}".format(truth["non_test_lines"]) if truth.get("non_test_lines") else "",
    }
    changed, warn = 0, []
    for sidx, slide in enumerate(prs.slides, 1):
        paras = [p for tf in iter_text_frames(slide.shapes) for p in tf.paragraphs]
        texts = [p.text.strip() for p in paras]
        for para in paras:
            bare = para.text.strip()
            if bare not in KEYWORD or not NEW.get(bare):
                continue
            labels = [t for t in texts if t and t != bare]
            if not any(k in t for k in KEYWORD[bare] for t in labels):
                warn.append((sidx, bare, "同页无 %s 标签佐证" % "/".join(KEYWORD[bare])))
                continue
            for run in para.runs:
                if run.text.strip() == bare:
                    if apply:
                        run.text = run.text.replace(bare, NEW[bare])
                    changed += 1
                    print("  s%02d 裸数字卡 %r ⇒ %r（同页标签佐证）" % (sidx, bare, NEW[bare]))
                    break
    return changed, warn


def main():
    ap = argparse.ArgumentParser()
    g = ap.add_mutually_exclusive_group(required=True)
    g.add_argument("--apply", action="store_true")
    g.add_argument("--dry-run", action="store_true")
    args = ap.parse_args()

    from pptx import Presentation

    truth = load_truth()
    rules = build_rules(truth)
    if not rules:
        raise SystemExit("真值为空，无法构造规则（fail-closed）")
    print("真值：tools_yaml=%s non_test_lines=%s test_files=%s test_packages=%s "
          "go_packages=%s internal_go_packages=%s"
          % (truth.get("tools_yaml"), truth.get("non_test_lines"), truth.get("test_files"),
             truth.get("test_packages"), truth.get("go_packages"),
             truth.get("internal_go_packages")))
    if not truth.get("go_packages"):
        print("  [SKIP] 测试包/internal 包口径：本机无 go → 不改这些数字（禁止写入未验证值）")

    total = 0
    hard_fail = 0
    for f in sorted(PPT_DIR.glob("*.pptx")):
        if f.name in EXCLUDE:
            print("\n[SKIP] %s —— 视觉母版（构建输入），按门禁口径恒久排除" % f.name)
            continue
        prs = Presentation(str(f))

        if args.dry_run:
            changes, _unres = scan(prs, rules)
            if changes:
                print("\n%s  →  %d 段命中" % (f.name, len(changes)))
                for sidx, before, plan in changes:
                    for old, new, desc in plan:
                        print("  s%02d [%s] %r ⇒ %r   （段落：%r）"
                              % (sidx, desc, old, new, before.strip()[:48]))
                total += sum(len(p) for _s, _b, p in changes)
            bare_n, bare_warn = bare_stat_edits(prs, truth, apply=False)
            total += bare_n
            for sidx, bare, why in bare_warn:
                print("  s%02d 裸数字卡 %r 未改：%s" % (sidx, bare, why))
            continue

        # apply
        # 先判定该文件是否真有命中——无命中就不写盘（否则 python-pptx 重存会白白改动字节/哈希）
        has_hit = any(re.search(pat, para.text)
                      for _s, para in iter_paragraphs(prs)
                      for pat, _r, _d in rules)
        file_unres = []
        if has_hit:
            for _sidx, para in iter_paragraphs(prs):
                _e, unres = plan_paragraph(para, rules)   # 内部直接改 run.text
                if unres:
                    file_unres.extend(unres)
        bare_n, bare_warn = bare_stat_edits(prs, truth, apply=True)
        for sidx, bare, why in bare_warn:
            print("  s%02d 裸数字卡 %r 未改：%s" % (sidx, bare, why))
        total += bare_n
        if not has_hit and bare_n == 0:
            continue
        prs.save(str(f))
        if has_hit:
            total += 1
        # 回读自证（写入类工具必须证落盘）
        chk = Presentation(str(f))
        left = 0
        for _sidx, para in iter_paragraphs(chk):
            for pat, _repl, _desc in rules:
                if re.search(pat, para.text):
                    left += 1
                    break
        if file_unres:
            print("\n%s  [WARN] 跨 run 无法安全改写 %d 处（需人工）：" % (f.name, len(file_unres)))
            for desc, full in file_unres[:6]:
                print("   %s : %r" % (desc, full.strip()[:64]))
            hard_fail += len(file_unres)
        print("%s  落盘校验：段落级残留旧口径 = %d" % (f.name, left))
        if left:
            hard_fail += left

    print("\n模式=%s；dry-run 命中 %d 处；无法安全改写/残留 %d 处"
          % ("APPLY" if args.apply else "DRY-RUN", total, hard_fail))
    return 1 if hard_fail else 0


if __name__ == "__main__":
    sys.exit(main())
