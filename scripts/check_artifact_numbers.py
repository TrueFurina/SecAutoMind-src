#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""产物数字门禁 —— 把口径检查推进到**渲染后的二进制交付物**（.pptx / .docx / .pdf）。

为什么需要它（2026-10-04 实锤）
------------------------------
`check_material_numbers.py` 只扫文本（.md/.html/.py/.txt）。但评委真正拿到手的是
.pptx / .docx / .pdf —— 这些二进制容器里的数字**从未被任何门禁打开过**，
于是「同一页自相矛盾」可以长期存活：

  · 答辩 PPT（冲击冠军版 / 模板版）统计框写「90 YAML 工具配方」，
    同页标题却写「91 工具」；
  · 答辩 PPT（模板版）统计框写「270 测试文件」，
    同页正文却写「286 测试文件」。

两者在源脚本里都是 `('90', 'YAML 工具配方')` 这种**数字与单位拆成两个字符串字面量**
的写法：文本锚点要求"数字紧跟单位"，看不见它；而**产物读回**时同一形状内的 runs
拼接成「90 YAML 工具配方」「270 测试文件」，立刻原形毕露。

它做什么
--------
遍历 .pptx / .docx / .pdf，按**形状 / 段落 / 页**抽出可见文本，套用
`check_material_numbers.py` 的**同一套 BANNED / ANCHORS 表**
（单一规则源 —— 另写一份规则必然与门禁渐行渐远），逐单元比对 count_stats 真值。

拼接口径（关键，决定真假阳性）
------------------------------
- 同一形状/段落内的文本 run **不加分隔**拼接：这正是"人眼在幻灯片上读到的连续文字"，
  也是 `1` + `YAML` 这类被拆开的字面量重新连起来的地方。
- **形状之间用空格分隔**：生成脚本普遍把"数值"与"单位标签"写成两个独立形状，
  渲染出来人眼读到的正是相邻的「90 YAML 工具配方」—— 空格既保住这一相邻语义，
  又挡住「0」+「286 测试文件」被粘成 "0286" 而漏检（见回归测试 T6）。
  ⚠️ 曾用 " | " 分隔，结果把「90」与「YAML 工具配方」拆开、**把真实漂移放过了**，
  3 个答辩 PPT 全 0 命中 —— 分隔符选错会让门禁变成摆设，这一点已由回归测试锁死。

为什么不在 CI 里跑
------------------
交付产物都是 .gitignore 的本地件（几 MB～60 MB 二进制），**CI 检出里根本不存在**。
所以本门禁的用武之地是**打包那一刻**（make_delivery_package.py 的第五条红线）与
提交前本地自检；CI 侧只跑它的回归测试（check_artifact_numbers_test.py），
用合成夹具证明"门禁真能变红"（对齐 secret-gate / web-parity-gate 的做法）。

用法：
    python scripts/check_artifact_numbers.py                   # 扫仓库内全部产物
    python scripts/check_artifact_numbers.py --dir <staging>   # 扫指定目录（打包用）
    python scripts/check_artifact_numbers.py --list            # 只列出将被检查的产物
    python scripts/check_artifact_numbers.py --exclude '*模板*'  # 追加排除 glob（可重复）

退出码：0 = 通过；1 = 数字漂移；2 = fail-closed（无真值 / 产物无法解析 / 缺 PDF 解析库）
"""
import argparse
import fnmatch
import os
import re
import sys
import zipfile
import xml.etree.ElementTree as ET

try:
    sys.stdout.reconfigure(encoding="utf-8")
except Exception:
    pass

HERE = os.path.dirname(os.path.abspath(__file__))
if HERE not in sys.path:
    sys.path.insert(0, HERE)

# 复用门禁：BANNED / ANCHORS / 真值 / 扫描豁免，全部以 check_material_numbers 为准。
import check_material_numbers as cmn  # noqa: E402

ARTIFACT_EXT = (".pptx", ".docx", ".pdf")

# 技术性排除：不是"判它无关紧要"，而是这些目录里的产物属缓存/归档/依赖，
# 既不属于台面交付件，也不该被本门禁的道德责任覆盖。
SKIP_DIR_PARTS = {
    ".git", ".workbuddy", "node_modules", "__pycache__", ".cache", ".slidep",
    ".render", "_render", "_archive", "_qc_orig", "_qc_fix", "installer",
    "dist", "build", "vendor",
}

# ── 恒久排除：构建输入件。判定标准极窄，**必须能证明其文字永不到达读者**──────
#   · 演示模板版.pptx —— make_template_ppt.py 的视觉母版**输入**。该脚本只克隆其
#     首页全屏背景图（make_template_ppt.py:32-36 选 ≥90% 页面的图片形状，
#     :63-67 仅 add_picture 该图 blob），文字与形状文本一个都不进产物；已实测
#     生成物 SecAutoMind_参赛答辩_模板版.pptx 读回为 0 命中。
#     它本身会被交付包原样携带（供接收方重生成 PPT），但其可见文字不构成交付语义。
# 放在这里而不是各调用点：清单只此一份，避免「打包脚本 vs 裸跑门禁」两处漂移。
ALWAYS_EXCLUDE = ["演示模板版.pptx"]

# OOXML 命名空间
A_NS = "http://schemas.openxmlformats.org/drawingml/2006/main"
P_NS = "http://schemas.openxmlformats.org/presentationml/2006/main"
W_NS = "http://schemas.openxmlformats.org/wordprocessingml/2006/main"

SHAPE_TAGS = tuple("{%s}%s" % (P_NS, t) for t in ("sp", "graphicFrame", "pic", "grpSp", "cxnSp"))
PARA_TAG = "{%s}p" % W_NS

# 形状 / 段落之间的分隔符。
# 必须是**空白**，不能是 "|" 这类符号：生成脚本普遍把"数值"与"单位标签"写成两个独立
# 形状（stat() 里的 v 与 lb），渲染出来人眼读到的就是相邻的「90 YAML 工具配方」。
# 用 "|" 会把这对拆开、把本该抓到的漂移放过（实测：3 个答辩 PPT 用它扫时 0 命中，
# 而它们确实写着 90）；用空格既保住这一相邻语义（锚点用 \s* 就能吃下），
# 又能挡住「0」+「286 测试文件」粘成 "0286" 这种跨形状串号（见回归测试 T6）。
SEP = " "

PPTX_TEXT_PARTS = re.compile(
    r"^ppt/(slides/slide|notesSlides/notesSlide|charts/chart|diagrams/data|"
    r"diagrams/drawing|slideLayouts/slideLayout|slideMasters/slideMaster)\d*\.xml$")
DOCX_TEXT_PARTS = re.compile(
    r"^word/(document|header\d*|footer\d*|footnotes|endnotes|comments)\.xml$")


# ---------------------------------------------------------------------------
# 抽取
# ---------------------------------------------------------------------------
def _xml_text(blob, tag):
    try:
        root = ET.fromstring(blob)
    except ET.ParseError:
        return ""
    return "".join(t.text or "" for t in root.iter(tag))


def extract_pptx(path):
    """→ [(单元名, 文本, 形状边界偏移)]。单元 = 一张幻灯片（形状间用 SEP 分隔）。"""
    units = []
    with zipfile.ZipFile(path) as z:
        names = [n for n in z.namelist() if PPTX_TEXT_PARTS.match(n)]
        names.sort()
        for n in names:
            try:
                root = ET.fromstring(z.read(n))
            except ET.ParseError:
                continue
            chunks = []
            for el in root.iter():
                if el.tag not in SHAPE_TAGS:
                    continue
                txt = "".join(t.text or "" for t in el.iter("{%s}t" % A_NS))
                if txt.strip():
                    chunks.append(txt)
            if chunks:
                units.append((os.path.basename(n),) + _join(chunks))
    return units


def extract_docx(path):
    """→ [(单元名, 文本, 段落边界偏移)]。单元 = 一个 document part（段落间用 SEP 分隔）。"""
    units = []
    with zipfile.ZipFile(path) as z:
        names = [n for n in z.namelist() if DOCX_TEXT_PARTS.match(n)]
        names.sort()
        for n in names:
            try:
                root = ET.fromstring(z.read(n))
            except ET.ParseError:
                continue
            chunks = []
            for p in root.iter(PARA_TAG):
                txt = "".join(t.text or "" for t in p.iter("{%s}t" % W_NS))
                if txt.strip():
                    chunks.append(txt)
            if chunks:
                units.append((os.path.basename(n),) + _join(chunks))
    return units


def _join(chunks):
    """把若干"形状/段落"文本拼成一个单元，并返回各拼接处的偏移 → (文本, 边界列表)。"""
    text, bounds = "", []
    for i, c in enumerate(chunks):
        if i:
            bounds.append(len(text))
            text += SEP
        text += c
    return text, bounds


def extract_pdf(path):
    """→ [(单元名, 文本, [])]。单元 = 一页。需要 pypdf。"""
    from pypdf import PdfReader  # 延迟导入：只有真要读 pdf 时才要求
    units = []
    with open(path, "rb") as fh:
        reader = PdfReader(fh)
        for i, page in enumerate(reader.pages, 1):
            try:
                txt = page.extract_text() or ""
            except Exception as exc:            # 单页失败不掩盖整体：记下来
                raise RuntimeError("第 %d 页抽取失败：%s" % (i, exc))
            if txt.strip():
                units.append(("page%d" % i, txt, []))
    return units


def _number_span(m):
    """取该匹配里「那个数字」的 (start, end)。

    ANCHORS 都带命名组 n（门禁强制约定）；**BANNED 没有** —— 它们有的是旧数字字面量，
    直接用正则找匹配内的第一段连续数字退化处理即可（实测 BANNED 里数字都在开头，
    形如 `90\\s*(个)?(工具|YAML)`；反序的 `工具\\s*YAML\\s*90` 也能正确取到末段）。
    """
    try:
        return m.start("n"), m.end("n")
    except IndexError:                   # 无命名组 n（BANNED 系）→ 退化为"匹配里第一段数字"
        pass
    mm = re.search(r"\d[\d,]*", m.group(0))
    if not mm:
        return m.start(), m.start()
    return m.start() + mm.start(), m.start() + mm.end()


def number_precedes_boundary(m, bounds):
    """跨形状匹配的合法性判据：**数字必须整体落在它跨越的那条边界之前**。

    为什么必须有这条（2026-10-04，回归测试 T1 当场揪出）：
    形状间用空格拼接后，「286 测试文件」（形状 A）与「91」（形状 B）会被拼成
    「286 测试文件 91」，命中「测试文件数（后置）」锚点 —— 纯属拼接产物，
    人眼在幻灯片上看到的是两张互不相干的统计卡。
    而「90」（形状 A）+「YAML 工具配方」（形状 B）拼成「90 YAML 工具配方」是**真实语义**
    （数值卡与紧邻的标签卡）。判据就是数字相对边界的位置：数字在前 → 真，标签在前 → 假。
    """
    _ns, ne = _number_span(m)
    for b in bounds:
        if m.start() <= b < m.end():
            return ne <= b
    return True


EXTRACTORS = {".pptx": extract_pptx, ".docx": extract_docx, ".pdf": extract_pdf}


# ---------------------------------------------------------------------------
# 生成器 → 产物 的路径链路（2026-10-18 新增）
# ---------------------------------------------------------------------------
# 为什么必须查这个（这是「数字漂移反复复发」的结构性根因，不是洁癖）：
#   三个 PPT 生成器的 `OUT` 原本都指向
#       E:/Program/2026挑战杯：SecAutoMind-v1.7.17-share/SecAutoMind_PPT/…
#   实测该目录**早已不存在** —— 于是：
#     ① 生成器一跑就 FileNotFoundError，等于「看着有生成器、其实跑不了」（假齐备）；
#     ② 即便目录还在，产物也落在仓库/冻结清单/交付包**之外**：仓库内那份 pptx 永不更新，
#        而所有门禁检查的正是仓库内那份 → 数字改了、产物没动，静默漂移；
#     ③ 手工改产物的人以为「重跑生成器就好」，实际跑出来的是另一个文件 →
#        只好继续手改产物，生成器越来越落后（#41 同款：产物↔生成器契约断裂）。
#   故把「OUT 必须在仓库内、且必须是冻结清单里的交付件、且实物存在」写成判据。
GENERATOR_DIR = "SecAutoMind_PPT"
FREEZE_MANIFEST = os.path.join("docs", "final-artifacts.freeze.json")


def _assign_out_value(tree):
    """取模块级最后一次 `OUT = …` 的 AST 值节点（多次赋值取最后一次，与运行时一致）。"""
    import ast
    last = None
    for node in tree.body:
        if isinstance(node, ast.Assign):
            for t in node.targets:
                if isinstance(t, ast.Name) and t.id == "OUT":
                    last = node.value
    return last


def _parse_generator_out(path):
    """解析某个生成脚本的 `OUT` → (文件名, 是否锚定 __file__, 绝对路径字面量列表, 错误)。

    与 check_generator_out_paths 共用同一解析，避免"门禁说的 OUT"和"冻结清单记的 OUT"
    各解各的（同族教训：修复器曾另立规则表，真值一动就整条失效）。
    """
    import ast
    with open(path, "r", encoding="utf-8", errors="ignore") as fh:
        src = fh.read()
    try:
        tree = ast.parse(src)
    except SyntaxError as exc:
        return "", False, [], "语法错误，无法核验 OUT：%s" % exc
    node = _assign_out_value(tree)
    if node is None:
        return "", False, [], "没有模块级 `OUT = …` —— 无法机验产物落点"
    lits = [n.value for n in ast.walk(node)
            if isinstance(n, ast.Constant) and isinstance(n.value, str)]
    abs_lit = [s for s in lits
               if re.match(r"^[A-Za-z]:[\\/]", s) or s.startswith("/") or s.startswith("\\\\")]
    anchored = "__file__" in ast.unparse(node)
    return (lits[-1] if lits else ""), anchored, abs_lit, ""


def generator_map(repo_root):
    """→ {产物文件名: 生成脚本相对路径}。只认能解析出 OUT 文件名的脚本。"""
    import glob
    out = {}
    gen_dir = os.path.join(repo_root, GENERATOR_DIR)
    if not os.path.isdir(gen_dir):
        return out
    for path in sorted(glob.glob(os.path.join(gen_dir, "make_*.py"))):
        name, _anch, _abs, err = _parse_generator_out(path)
        if not err and name.lower().endswith(tuple(ARTIFACT_EXT)):
            out[name] = os.path.relpath(path, repo_root).replace("\\", "/")
    return out


def check_generator_out_paths(repo_root, require_artifacts=True):
    """→ [(脚本相对路径, 原因)]，空列表 = 通过。

    判据（全部 fail-closed，缺一条就报）：
      1. 脚本里必须存在模块级 `OUT = …`；
      2. OUT 的表达式必须锚定 `__file__`（即"落在脚本自己所在目录"），
         不允许出现盘符绝对路径字面量（如 `r'E:/…'`）；
      3. OUT 的文件名必须能在**冻结清单** artifacts 里找到同名项（产物↔交付面必须挂上）；
      4. 该文件必须真实存在于仓库 `SecAutoMind_PPT/` 下。

    为什么 4 要可关（require_artifacts）：产物是 `.gitignore` 的本地二进制，
    **CI 检出里不存在**（几 MB～60 MB）。若 CI 也查"实物存在"，本判据会恒红 →
    反向变成"一致地误杀"。故 CI 只钉 1~3（纯静态、对 git 跟踪文件成立），
    本地/打包时钉满 4 条（`--generators-only --require-artifacts` 或裸跑门禁）。
    """
    import glob
    import json

    bad, scripts = [], []
    gen_dir = os.path.join(repo_root, GENERATOR_DIR)
    if not os.path.isdir(gen_dir):
        return [("%s/" % GENERATOR_DIR, "生成器目录不存在")]
    for path in sorted(glob.glob(os.path.join(gen_dir, "make_*.py"))):
        rel = os.path.relpath(path, repo_root).replace("\\", "/")
        scripts.append(rel)
        name, anchored, abs_lit, err = _parse_generator_out(path)
        if err:
            bad.append((rel, err))
            continue

        # ② 绝对路径字面量一律禁止（盘符 / 正斜杠绝对 / UNC）
        if abs_lit:
            bad.append((rel, "OUT 使用绝对路径字面量 %r —— 换机器/目录删了就断，"
                             "必须写成 `Path(__file__).resolve().parent / '…'`" % abs_lit[0]))
            continue
        if not anchored:
            bad.append((rel, "OUT 未锚定 `__file__` —— 产物落点不确定"))
            continue

        # ③④ 文件名必须是交付物扩展名（`… / 'x.pptx'` 形态）
        if not name.lower().endswith(tuple(ARTIFACT_EXT)):
            bad.append((rel, "OUT 末尾不是 %s 文件名（取到 %r）"
                        % ("/".join(ARTIFACT_EXT), name)))
            continue
        manifest = os.path.join(repo_root, FREEZE_MANIFEST)
        if not os.path.isfile(manifest):
            bad.append((rel, "缺冻结清单 %s —— 无法核验产物↔交付面" % FREEZE_MANIFEST))
            continue
        try:
            with open(manifest, "r", encoding="utf-8") as fh:
                arts = (json.load(fh) or {}).get("artifacts") or {}
        except Exception as exc:
            bad.append((rel, "冻结清单无法解析：%s" % exc))
            continue
        if not any(os.path.basename(k) == name for k in arts):
            bad.append((rel, "OUT 产物 %r 不在冻结清单 artifacts 里 —— "
                             "生成出来的东西没人保护（先入清单再谈交付）" % name))
            continue
        if require_artifacts and not os.path.isfile(os.path.join(gen_dir, name)):
            bad.append((rel, "OUT 声明的产物 %r 在 %s/ 下不存在（生成器跑不出来？）"
                        % (name, GENERATOR_DIR)))
    if not scripts:
        bad.append(("%s/make_*.py" % GENERATOR_DIR, "一个生成器都没找到 —— 判据空转"))
    return bad


# ---------------------------------------------------------------------------
# 扫描
# ---------------------------------------------------------------------------
def is_skipped_dir(rel):
    return any(p in SKIP_DIR_PARTS for p in rel.replace("\\", "/").split("/"))


def iter_artifacts(root, exclude_globs=()):
    for dirpath, dirnames, filenames in os.walk(root):
        rel_dir = os.path.relpath(dirpath, root).replace("\\", "/")
        rel_dir = "" if rel_dir == "." else rel_dir
        dirnames[:] = [d for d in dirnames
                       if not is_skipped_dir("%s/%s" % (rel_dir, d) if rel_dir else d)]
        for fn in sorted(filenames):
            if os.path.splitext(fn)[1].lower() not in ARTIFACT_EXT:
                continue
            if fn.startswith((".", "_")):
                continue
            rel = "%s/%s" % (rel_dir, fn) if rel_dir else fn
            if any(fnmatch.fnmatch(rel, g) or fnmatch.fnmatch(fn, g) for g in exclude_globs):
                continue
            yield os.path.join(dirpath, fn), rel


def scan(root, truth, exclude_globs=()):
    """→ (hits, files, problems)

    hits     = [(rel, unit, kind, label, got, want, snippet)]  kind ∈ {banned, anchor}
    files    = [(rel, 单元数)]
    problems = [(rel, 原因)]  —— 无法解析 / 缺库；fail-closed
    """
    hits, files, problems = [], [], []
    for path, rel in iter_artifacts(root, exclude_globs):
        ext = os.path.splitext(path)[1].lower()
        try:
            units = EXTRACTORS[ext](path)
        except ImportError as exc:
            problems.append((rel, "缺少解析库：%s（PDF 需 pypdf: pip install pypdf）" % exc))
            continue
        except Exception as exc:
            problems.append((rel, "解析失败：%s: %s" % (type(exc).__name__, exc)))
            continue

        files.append((rel, len(units)))
        # 产物自带历史快照标记（文本框里写 CALIBER-SNAPSHOT）→ 整件豁免，与文本门禁同款约定
        if any(cmn.SNAPSHOT_MARK in txt for _u, txt, _b in units):
            continue
        if cmn.is_historical(rel):
            continue

        for unit, text, bounds in units:
            for pat, why in cmn.BANNED:
                for m in re.finditer(pat, text):
                    if not number_precedes_boundary(m, bounds):
                        continue
                    s, e = max(0, m.start() - 30), min(len(text), m.end() + 30)
                    hits.append((rel, unit, "banned", why, m.group(0),
                                 None, text[s:e].replace("\n", " ")))
            for pat, key, label in cmn.ANCHORS:
                for m in re.finditer(pat, text):
                    if not number_precedes_boundary(m, bounds):
                        continue
                    want = truth.get(key)
                    if want is None:
                        problems.append((rel, "count_stats 未返回锚点字段 %s" % key))
                        continue
                    got = int(m.group("n").replace(",", ""))
                    if got != int(want):
                        s, e = max(0, m.start() - 30), min(len(text), m.end() + 30)
                        hits.append((rel, unit, "anchor", label, got, int(want),
                                     text[s:e].replace("\n", " ")))
    return hits, files, problems


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--dir", default=None, help="要扫描的目录（默认仓库根）")
    ap.add_argument("--exclude", action="append", default=[],
                    help="追加排除 glob（按相对路径或文件名匹配，可重复）")
    ap.add_argument("--list", action="store_true", help="只列出将被检查的产物，不做比对")
    ap.add_argument("--generators-only", action="store_true",
                    help="只查「生成器 OUT → 产物」路径链路（可在 CI 跑，不需要产物文件）")
    ap.add_argument("--require-artifacts", action="store_true",
                    help="配合 --generators-only：额外要求 OUT 指向的产物实物存在（本地/打包用）")
    args = ap.parse_args()

    # 只查生成器链路：不读产物、不需要 pypdf，纯 AST 静态判据 → 可直接进 CI。
    if args.generators_only:
        require_art = bool(args.require_artifacts)
        gen_bad = check_generator_out_paths(cmn.ROOT, require_artifacts=require_art)
        print("=" * 74)
        print("生成器 → 产物 路径链路检查（%s/make_*.py）" % GENERATOR_DIR)
        if gen_bad:
            for rel, why in gen_bad:
                print("  [FAIL] %s —— %s" % (rel, why))
            print("  结论：FAIL —— %d 处断裂" % len(gen_bad))
            return 1
        print("  结论：PASS —— 生成器的 OUT 均锚定 __file__、落在仓库内、在冻结清单里%s"
              % ("、实物存在" if require_art else "（未查实物存在：CI 检出里没有产物）"))
        return 0

    # 恒久排除（构建输入件）与调用方追加排除合并，统一生效。
    excludes = list(ALWAYS_EXCLUDE) + list(args.exclude)

    root = os.path.abspath(args.dir) if args.dir else cmn.ROOT
    if not os.path.isdir(root):
        print("[FAIL-CLOSED] 目录不存在：%s" % root, file=sys.stderr)
        return 2

    print("=" * 74)
    print("产物数字门禁 · 读回 .pptx/.docx/.pdf 后套用「材料口径门禁」同一套规则")
    print("  扫描根：%s" % root)
    if ALWAYS_EXCLUDE:
        print("  恒久排除（构建输入，文字不构成交付语义）：%s" % ", ".join(ALWAYS_EXCLUDE))

    if args.list:
        found = list(iter_artifacts(root, excludes))
        for _p, rel in found:
            print("    %s" % rel)
        print("  共 %d 个产物（--list 不比对）" % len(found))
        return 0

    try:
        truth = cmn.load_truth()
    except SystemExit as exc:
        print("[FAIL-CLOSED] %s" % exc, file=sys.stderr)
        return 2

    missing = sorted({k for _p, k, _l in cmn.ANCHORS if truth.get(k) is None})
    if missing:
        print("[FAIL-CLOSED] count_stats 未返回锚点字段 %s —— 门禁绝不静默跳过检查" % missing,
              file=sys.stderr)
        return 2

    print("  锚定 HEAD: %s" % truth.get("head"))
    hits, files, problems = scan(root, truth, excludes)

    # 生成器 → 产物的路径链路（只在扫仓库根时做：打包暂存目录里没有生成器脚本）
    gen_bad = []
    if os.path.abspath(root) == os.path.abspath(cmn.ROOT):
        gen_bad = check_generator_out_paths(root)
    print("-" * 74)
    for rel, n in files:
        print("  · %-72s %d 个文本单元" % (rel, n))
    if not files:
        print("  [WARN] 未发现任何产物 —— 若预期有产物，说明扫描根/排除规则写错了。")

    if hits:
        print("-" * 74)
        print("  [FAIL] 产物数字与真值不符 %d 处：" % len(hits))
        for rel, unit, kind, label, got, want, snip in hits:
            if kind == "banned":
                print("    %s (%s)  已作废旧口径「%s」" % (rel, unit, label))
            else:
                print("    %s (%s)  %s=%s，真值=%s" % (rel, unit, label, got, want))
            print("        上下文…%s…" % snip)

    if gen_bad:
        print("-" * 74)
        print("  [FAIL] 生成器 → 产物 路径链路断裂 %d 处（改产物也改了数字，重跑却落到别处）："
              % len(gen_bad))
        for rel, why in gen_bad:
            print("    %s —— %s" % (rel, why))

    if problems:
        print("-" * 74)
        print("  [FAIL-CLOSED] %d 个产物无法核验（宁可拦下，不可放过）：" % len(problems))
        for rel, why in problems:
            print("    %s —— %s" % (rel, why))

    print("=" * 74)
    if hits or problems or gen_bad:
        if gen_bad:
            print("  结论：FAIL —— 生成器 OUT 不在可交付链路内（仓库内 + 冻结清单 + 实物存在）。")
        else:
            print("  结论：FAIL —— 产物口径漂移或无法核验，禁止打包/提交。")
        if hits and not problems and not gen_bad:
            print("  修复：改生成脚本里的数字 → 重新生成产物 → 复跑本门禁。")
        return 1
    print("  结论：PASS —— %d 个产物的可见文本与单一真值源一致。" % len(files))
    return 0


if __name__ == "__main__":
    sys.exit(main())
