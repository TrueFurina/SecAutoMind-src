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
  （2026-10-18 取证：它曾被复制成 `闽江御盾•智防矩阵.pptx`；当时 sha256 相同
  `8525b308…`，但当晚两文件各自定点修正后**已分叉**，别再拿"字节相同"当依据）；
- `集大成版`/`草稿内容版`/`闽江睿御`/`闽江御盾`：无生成器或生成器已停更。
故统一采用**定点文本替换**（同 `A11_ppt_text_swap.py` 手法）：只改 run.text 里的数字字面量，
字号/颜色/位置/段落结构一律不动，且新旧字符串**等长**，不存在溢出风险。

两个实测坑（本脚本已内置，勿退化）
--------------------------------
1. **必须递归组合(GroupShape)与表格单元格**：只遍历 slide.shapes 顶层会"改 59 处还剩 15 处"；
2. **必须按段落定位、再落回单个 run**：PowerPoint 常把 `90个` 与 `YAML` 拆成两个 run，
   run 级正则（`90(?=\\s*个?\\s*YAML)`）在 run 里**永远不命中**——这叫假绿。

第三个坑（2026-10-18 第二次踩，已重构）
--------------------------------------
首版把"旧值→新值"硬编码成元组（`121,786/111,058 → 新版`）。真值再走一步（129,233 → 129,286）后
**一条都匹配不上**，脚本打印"命中 0 处 / 模式=APPLY"看着成功，门禁照旧报红。
根因：我在门禁（`check_material_numbers.ANCHORS`，它才是判红依据）之外另立了一套规则表。
现规则**直接复用 ANCHORS**，替换值取自 count_stats —— 与门禁同源，不可能再"改完还红"。
门禁未锚定的产物专有写法（`N/N 测试包`、`N 个 internal 包`）才单列，且只用真值、不写死旧值。

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
    """规则 = 门禁自己的 ANCHORS 表（单一规则源）+ 少量门禁看不见的产物专有形态。

    为什么必须复用 `check_material_numbers.ANCHORS` 而不是各写一份：
    交付门禁 `check_artifact_numbers.py` 判红时用的就是这张表，逐字相同；如果我这里
    另立一套"旧值→新值"硬编码表，就会出现 2026-10-18 那次实测的退化——
    上次只硬编码了 `121,786/111,058 → 新版`，这次真值从 129,233 走到 129,286 时
    **一条都匹配不上**（dry-run 命中 0 处），门禁照旧报红，而脚本却打印"完成"。
    规则只有一份，才不会与门禁渐行渐远。

    返回 [(pat, kind, payload, label)]：
      · kind="cast" → payload 是 count_stats 真值，替换**捕获组 n**那一段（保留千分位风格）；
      · kind="span" → payload 是替换整段匹配的字符串（门禁看不见的产物专有写法）。
    """
    sys.path.insert(0, str(REPO / "scripts"))
    import check_material_numbers as cmn

    rules, missing = [], []
    for pat, key, label in cmn.ANCHORS:
        want = truth.get(key)
        if want is None:
            missing.append("%s(%s)" % (label, key))
            continue
        rules.append((pat, "cast", want, label))

    # ── 门禁看不见的产物专有形态（门禁未锚定 ⇒ 只能靠本脚本自证，改错没有第二道闸）──
    # ① 「N/N 测试包全绿」：数字对，且两数必须相等（真值 = 有测试的包数）。
    pkgs = truth.get("test_packages")
    if pkgs:
        rules.append((r"(?<![\d.])(?P<n>\d+)(?<![\d])/\d+(?=\s*(?:个)?(?:测试)?包)",
                      "cast_pair", pkgs, "测试包（N/N）"))
    # ② 「N 个 internal 包」：门禁只锚定后置写法（internal 目录 34），前置写法看不见。
    #    注意口径：internal 子目录数(34) ≠ go list ./internal/... 的包数(37)，PPT 说"包"取后者。
    ipkgs = truth.get("internal_go_packages")
    if ipkgs:
        rules.append((r"(?<![\d.])(?P<n>\d+)(?=\s*(?:个\s*)?internal)",
                      "cast", ipkgs, "internal 包数"))

    if missing:
        print("  [WARN] 真值缺字段，跳过这些锚点（禁止写入未验证值）：%s" % ", ".join(missing))
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
def rule_hits(full, rules):
    """把规则跑在段落文本上，返回 [(start, end, new, desc)]（同一 span 只保留一条）。

    「cast」类只替换捕获组 n 那一段 —— 这样既保住周围单位的字形，
    又保证写进去的值**必定**来自 count_stats（不存在"硬编码旧值匹配不上"的退化）。
    """
    hits, seen = [], set()
    for pat, kind, payload, label in rules:
        for m in re.finditer(pat, full):
            if kind == "cast":
                s, e = m.span("n")
                got = m.group("n")
                new = "{:,}".format(payload) if "," in got else str(payload)
                desc = "%s %s→%s" % (label, got, new)
            elif kind == "cast_pair":
                # "N/M 测试包" 只有 N==M 才是「全绿」写法；不等就不猜（宁可不改）
                seg = m.group(0)
                a, b = seg.split("/")
                if a != b:
                    continue
                s, e = m.start(), m.end()
                new = "%d/%d" % (payload, payload)
                desc = "%s %s→%s" % (label, seg, new)
            else:
                s, e = m.start(), m.end()
                new, desc = str(payload), label
            if new == full[s:e] or (s, e) in seen:
                continue
            seen.add((s, e))
            hits.append((s, e, new, desc))
    return hits


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
        return [], [("段落文本与 run 拼不一致", full)] if rule_hits(full, rules) else []

    hits = rule_hits(full, rules)
    if not hits:
        return [], []

    edits, unresolved = [], []
    last_start = len(full) + 1
    # 从右往左改，保证左侧偏移不受影响
    for start, end, new, desc in sorted(hits, key=lambda x: -x[0]):
        if end > last_start:
            unresolved.append((desc + "（与前一处重叠）", full))
            continue
        host = [b for b in bounds if b[0] <= start and end <= b[1]]
        if len(host) != 1:
            unresolved.append((desc, full))
            continue
        s0, _e0, run = host[0]
        cur = run.text
        run.text = cur[:start - s0] + new + cur[end - s0:]
        last_start = start
        edits.append((run, cur, run.text, desc, 0))
    return edits, unresolved


def scan(prs, rules):
    """只读扫描：返回 ([(sid, 段落原文, [(old, new, desc)])], unresolved)"""
    changes, unresolved = [], []
    for sidx, para in iter_paragraphs(prs):
        hits = rule_hits(para.text, rules)
        if hits:
            changes.append((sidx, para.text,
                            [(para.text[s:e], new, desc) for s, e, new, desc in hits]))
    return changes, unresolved


def _simulate(para, rules):
    """不改真对象：用文本推算将被替换的相邻片段（仅用于 dry-run 报告）。"""
    return [(para.text[s:e], new, desc) for s, e, new, desc in rule_hits(para.text, rules)], []



def neighbor_stat_edits(prs, rules, apply):
    """按**空间邻接**修正「大数字 + 下方标签」卡片（数据卡布局）。

    为什么必须做这一步（2026-10-18 实测）：数据卡把「数值」与「单位」拆成两个独立
    TextBox（同一 left、标签在数字正下方 0.56"），门禁读回时按 SEP=" " 拼成
    「312 测试文件」，于是报「测试文件数=312，真值=313」；而**段落级**视图里
    "312" 与 "测试文件" 谁也不认识谁 → 段内正则永远不命中，改完仍是红。

    判据不新发明语义：把「数字 + 空格 + 标签」按门禁同一 SEP 拼起来，喂给**同一套
    rules**；只有当匹配到的数字段正是开头那段（即这确实是"数字+单位"结构）才改。
    多个标签给出互相矛盾的字段时一律不动并 WARN——那是猜。
    """
    def text_shapes(slide):
        out = []
        for sh in slide.shapes:            # 只取顶层：组内坐标系是子空间，混算会错位
            if not (getattr(sh, "has_text_frame", False) and sh.has_text_frame):
                continue
            txt = sh.text_frame.text.strip()
            if not txt or sh.left is None or sh.top is None:
                continue
            out.append((sh, txt, sh.left, sh.top, sh.width or 0, sh.height or 0))
        return out

    def num_of(txt):
        if re.fullmatch(r"\d{1,3}(?:,\d{3})*|\d+", txt):
            return txt
        return None

    changed, warn = 0, []
    for sidx, slide in enumerate(prs.slides, 1):
        shapes = text_shapes(slide)
        for sh, txt, left, top, width, height in shapes:
            num = num_of(txt)
            if not num:
                continue
            cands = []
            for sh2, txt2, l2, t2, w2, _h2 in shapes:
                if sh2 is sh or num_of(txt2):
                    continue
                dy = (t2 - top)
                if not (0 <= dy <= 1000000):   # ≤1 英寸，标签在数字下方
                    continue
                overlap = min(left + width, l2 + w2) - max(left, l2)
                if overlap <= 0.6 * min(width, w2):
                    continue
                combined = num + " " + txt2
                for s, e, new, desc in rule_hits(combined, rules):
                    if s == 0 and e == len(num) and new != num:
                        cands.append((new, desc, txt2))
            fields = {c[0] for c in cands}
            if len(fields) > 1:
                warn.append((sidx, num, "邻接标签给出矛盾字段：%s" % "; ".join(c[1] for c in cands)))
                continue
            if not cands:
                continue
            new, desc, label = cands[0]
            for para in sh.text_frame.paragraphs:
                for run in para.runs:
                    if run.text.strip() == num:
                        if apply:
                            run.text = run.text.replace(num, new)
                        changed += 1
                        print("  s%02d 邻接数据卡 %r ⇒ %r（标签 %r｜%s）"
                              % (sidx, num, new, label[:16], desc))
                        break
    return changed, warn


def bare_stat_edits(prs, truth, apply):
    """处理「裸数字统计卡」：`90` / `237` 这类数字单独一个文本框，语义全靠同页的标签形状
    （如旁边的 `YAML 工具配方`、`测试文件`）。**必须有同页标签佐证才改**，否则宁可报 WARN——
    孤立数字没有上下文，盲改就是猜。

    LEGACY_BARE 是**历史值台账**：键 = 曾经写错过的字面量，值 = 它对应的 count_stats 字段。
    台账而非"任意裸数字"是刻意的：裸数字没有语义，只有"这个旧值当年确实代表这个口径"
    才允许改。新增漂移值须先确认它代表哪个字段再登记（登记错 = 把别的指标改坏）。
    """
    LEGACY_BARE = {
        "90": ("tools_yaml", ("YAML", "工具")),
        "237": ("test_files", ("测试文件",)),
        "121,786": ("non_test_lines", ("行",)),
        "111,058": ("non_test_lines", ("行",)),
    }
    NEW = {}
    for lit, (key, _kw) in LEGACY_BARE.items():
        want = truth.get(key)
        if want is None:
            continue
        NEW[lit] = "{:,}".format(want) if "," in lit else str(want)
    changed, warn = 0, []
    for sidx, slide in enumerate(prs.slides, 1):
        paras = [p for tf in iter_text_frames(slide.shapes) for p in tf.paragraphs]
        texts = [p.text.strip() for p in paras]
        for para in paras:
            bare = para.text.strip()
            if bare not in LEGACY_BARE or not NEW.get(bare):
                continue
            keywords = LEGACY_BARE[bare][1]
            labels = [t for t in texts if t and t != bare]
            if not any(k in t for k in keywords for t in labels):
                warn.append((sidx, bare, "同页无 %s 标签佐证" % "/".join(keywords)))
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
            nb_n, nb_warn = neighbor_stat_edits(prs, rules, apply=False)
            total += nb_n
            for sidx, bare, why in nb_warn:
                print("  s%02d 邻接数据卡 %r 未改：%s" % (sidx, bare, why))
            continue

        # apply
        # 先判定该文件是否真有命中——无命中就不写盘（否则 python-pptx 重存会白白改动字节/哈希）
        has_hit = any(rule_hits(para.text, rules)
                      for _s, para in iter_paragraphs(prs))
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
        nb_n, nb_warn = neighbor_stat_edits(prs, rules, apply=True)
        total += nb_n
        for sidx, bare, why in nb_warn:
            print("  s%02d 邻接数据卡 %r 未改：%s" % (sidx, bare, why))
        if not has_hit and bare_n == 0 and nb_n == 0:
            continue
        prs.save(str(f))
        if has_hit:
            total += 1
        # 回读自证（写入类工具必须证落盘）
        chk = Presentation(str(f))
        left = sum(1 for _s, para in iter_paragraphs(chk) if rule_hits(para.text, rules))
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
