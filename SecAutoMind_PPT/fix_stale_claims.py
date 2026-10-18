#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""定点修正交付 PPT 里的**过期技术断言 / 过期分发体积**。

为什么写这个脚本而不是打开 PowerPoint 手工改
--------------------------------------------
1. 手工改的产物没有任何留痕：下次换人接手，不知道哪一处是"有意为之"还是"漏改"；
2. 这些 PPT **没有生成器**（`集大成版`/`草稿内容版`/`闽江睿御`/`闽江御盾` 属历史遗留，
   `演示模板版` 是视觉母版），所以只能定点改——但"定点改"必须可复现、可复核；
3. 同一处文字在 PowerPoint 里常被拆成多个 run（`cgo` / `构建与` / `exe` 三个 run），
   run 级字符串匹配找不到、段落级整段重写又会丢格式。故：**先按 run 改，改不到才退到
   段落级并把整段文案写进第一个 run**，每处改动都打印出来。

判据（真值来源）
----------------
- cgo：`.github/workflows/release.yml` 三平台一律 `CGO_ENABLED=0`，
  `go.mod` 用 `github.com/glebarez/go-sqlite`（纯 Go 驱动），全仓 `import "C"` 数为 0
  → **早已不依赖 cgo**。`集大成版` 已写「纯 Go 免 CGO」，其余几份仍写 cgo，属同一事实
  三种口径，必须统一。
- 分发体积：`count_stats.py` 的 `setup_mb` / `exe_mb`（MB = 10^6），实测 20.3 / 89.5。
  旧值 33.6 / 158 MB 是 09-05 那代 159,051,447 B 的 `+dirty` 构建。

用法
----
    python SecAutoMind_PPT/fix_stale_claims.py            # 预演（不写盘）
    python SecAutoMind_PPT/fix_stale_claims.py --apply    # 实际写入
退出码：0 = 全部命中并已改（或预演无遗漏）；1 = 有目标未命中（说明文案已变，判据需复核）
"""
import argparse
import sys
from pathlib import Path

from pptx import Presentation
from pptx.enum.shapes import MSO_SHAPE_TYPE

HERE = Path(__file__).resolve().parent

# (文件, 旧串, 新串, 说明)
RULES = [
    ("演示模板版.pptx", "cgo", "纯 Go", "cgo 构建 → 纯 Go 构建"),
    # 母版自己的团队介绍行还写着 90（它在 check_artifact_numbers 的 ALWAYS_EXCLUDE 里，
    # 扫描永远看不到它）—— 但它是**随包发给接收方**的文件，留着旧数没道理。
    ("演示模板版.pptx", "90个YAML", "91个YAML", "工具 YAML 数 90 → 91"),
    ("演示模板版.pptx", "×90工具", "×91工具", "封面条工具数 90 → 91"),
    ("闽江御盾•智防矩阵.pptx", "cgo", "纯 Go", "cgo 构建 → 纯 Go 构建"),
    ("SecAutoMind（闽江睿御•智体矩阵）——基于Go+大模型、可离线运行的多智能体自主决策通用网络安全平台，"
     "人机协同、全程可审计.pptx", "cgo", "纯 Go", "cgo 构建 / cgo sqlite → 纯 Go"),
    ("草稿内容版.pptx", "33.6 MB", "20.3 MB", "Setup 体积 33.6 → 20.3 MB"),
    ("草稿内容版.pptx", "158 MB", "89.5 MB", "绿色版体积 158 → 89.5 MB"),
    ("草稿内容版.pptx", "原生 cgo 编译", "原生编译（纯 Go 免 CGO）", "原生 cgo 编译 → 纯 Go"),
    ("草稿内容版.pptx", "cgo sqlite", "纯 Go sqlite 驱动", "cgo sqlite → 纯 Go sqlite 驱动"),
]


def iter_paragraphs(shapes):
    """递归遍历（组合形状 / 表格单元格都要走到，只看顶层会漏）。"""
    for sh in shapes:
        if sh.shape_type == MSO_SHAPE_TYPE.GROUP:
            yield from iter_paragraphs(sh.shapes)
            continue
        if getattr(sh, "has_text_frame", False):
            for para in sh.text_frame.paragraphs:
                yield para
        if getattr(sh, "has_table", False):
            for row in sh.table.rows:
                for cell in row.cells:
                    for para in cell.text_frame.paragraphs:
                        yield para


def replace_in_paragraph(para, old, new):
    """→ (改法, 说明)。改法 ∈ {"run", "para", None}。

    优先 run 级：保住 PowerPoint 自己的格式切分（同一段里往往混着加粗、字号、颜色）。
    跨 run 的写法（`cgo` | `构建与`）在 run 级天然能找到——只要整串落在同一个 run 内；
    真正跨 run 切开的（`原` | `生 cgo 编` | `译`）才退到段落级。
    """
    for run in para.runs:
        if old in run.text:
            run.text = run.text.replace(old, new)
            return "run", "run 级替换"
    if old in para.text:
        if not para.runs:
            return None, "无 run（空段落），跳过"
        para.runs[0].text = para.text.replace(old, new)
        for run in para.runs[1:]:
            run.text = ""
        return "para", "段落级替换（原文跨 run 切分，已合并进首个 run）"
    return None, "未命中"


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--apply", action="store_true", help="实际写盘（默认只预演）")
    args = ap.parse_args()

    by_file = {}
    for fn, old, new, why in RULES:
        by_file.setdefault(fn, []).append((old, new, why))

    missed = []
    for fn, rules in by_file.items():
        path = HERE / fn
        if not path.exists():
            missed.append("%s：文件不存在" % fn)
            continue
        prs = Presentation(str(path))
        hits = {r[0]: 0 for r in rules}
        texts = []
        for slide_no, slide in enumerate(prs.slides, 1):
            for para in iter_paragraphs(slide.shapes):
                texts.append(para.text)
                for old, new, why in rules:
                    if old not in para.text:
                        continue
                    how, detail = replace_in_paragraph(para, old, new)
                    if how:
                        hits[old] += 1
                        print("  [%s p%d] %s → %s（%s）" % (fn[:18], slide_no, old, new, detail))
        for old, new, why in rules:
            if hits[old]:
                continue
            # 幂等：旧串已不在、新串已在 —— 说明上一轮已经改过，不是判据失效。
            # （脚本会被反复跑：母版改了要重跑生成器、重跑后又要复核，一次失败就永远红
            #  的脚本等于没有脚本。故这里区分「已修正」与「文案已变」。）
            if any(new in t for t in texts):
                print("  [skip] %s：「%s」已不存在且「%s」已在 → 视为已修正" % (fn[:18], old, new))
                continue
            missed.append("%s：未命中「%s」（%s）—— 文案已变，判据需复核" % (fn, old, why))
        total = sum(hits.values())
        if total and args.apply:
            prs.save(str(path))
            print("  [SAVE] %s（%d 处）" % (fn[:40], total))
        elif total:
            print("  [DRY ] %s（%d 处，未写盘）" % (fn[:40], total))

    # 落盘后回读自证：旧串必须 0 残留（预演模式不验，因为没写）
    if args.apply:
        print("\n=== 回读自证 ===")
        for fn, rules in by_file.items():
            path = HERE / fn
            if not path.exists():
                continue
            prs = Presentation(str(path))
            left = []
            for slide_no, slide in enumerate(prs.slides, 1):
                for para in iter_paragraphs(slide.shapes):
                    for old, _new, _why in rules:
                        if old in para.text:
                            left.append((slide_no, old))
            print("  %-42s 残留 %d 处" % (fn[:42], len(left)))
            for s, o in left:
                print("     p%d 仍含「%s」" % (s, o))
            if left:
                missed.append("%s：回读仍有 %d 处旧串" % (fn, len(left)))

    if missed:
        print("\n[FAIL] %d 项需要人工复核：" % len(missed))
        for m in missed:
            print("  · " + m)
        return 1
    print("\n[PASS] %d 条规则全部就位（%s）"
          % (len(RULES), "本次有写盘" if args.apply else "预演：未写盘"))
    return 0


if __name__ == "__main__":
    sys.exit(main())
