#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""把 competition-2026 下四份材料 markdown 转为 A4 打印版合订本 HTML。
用法: python build_print_html.py
产物: SecAutoMind_参赛材料合订本_打印版.html
仅依赖 markdown 库（venv: python -m pip install markdown）。
"""
import re
import markdown
from pathlib import Path

HERE = Path(__file__).resolve().parent

DOCS = [
    ("技术报告_SecAutoMind_202609.md", "技术报告"),
    ("方案设计文档_SecAutoMind_202609.md", "方案设计文档"),
    ("原创性与保密性声明_模板_SecAutoMind.md", "原创性及保密性声明（模板）"),
    ("演示视频脚本_SecAutoMind_202609.md", "演示视频脚本"),
]

MD_EXT = ["tables", "fenced_code", "toc", "sane_lists", "nl2br"]


def convert(md_text: str, idx: int) -> str:
    html = markdown.markdown(md_text, extensions=MD_EXT)
    # 命名空间化锚点，避免多文档 id 冲突
    html = re.sub(r'id="([^"]+)"', lambda m: f'id="d{idx}_{m.group(1)}"', html)
    html = re.sub(r'href="#([^"]+)"', lambda m: f'href="#d{idx}_{m.group(1)}"', html)
    return html


def main():
    sections = []
    for i, (fn, title) in enumerate(DOCS):
        md = (HERE / fn).read_text(encoding="utf-8")
        body = convert(md, i)
        sections.append(
            f'<section class="doc page-break">\n'
            f'<h1 class="doctitle">{title}</h1>\n{body}\n</section>'
        )
    combined = "\n".join(sections)

    css = """
    @page { size: A4; margin: 16mm 15mm; }
    * { box-sizing: border-box; }
    body {
      font-family: "Microsoft YaHei", "PingFang SC", "Noto Sans CJK SC", "Source Han Sans SC", sans-serif;
      color: #1a1a1a; font-size: 10.5pt; line-height: 1.5; margin: 0; padding: 0;
    }
    h1, h2, h3, h4 { color: #0b3d91; line-height: 1.3; }
    h1.doctitle { text-align: center; font-size: 20pt; border-bottom: 3px solid #0b3d91;
      padding-bottom: 8px; margin-bottom: 18px; }
    h2 { font-size: 14pt; margin-top: 18px; border-left: 4px solid #0b3d91; padding-left: 8px; }
    h3 { font-size: 12pt; }
    h4 { font-size: 11pt; }
    a { color: #0b3d91; text-decoration: none; }
    p { margin: 6px 0; text-align: justify; }
    table { border-collapse: collapse; width: 100%; margin: 10px 0;
      font-size: 9.5pt; page-break-inside: avoid; }
    th, td { border: 1px solid #b0b8c4; padding: 5px 7px; vertical-align: top; }
    th { background: #e7eefb; font-weight: 600; }
    tr:nth-child(even) td { background: #f6f8fc; }
    code { background: #f1f3f6; border: 1px solid #d6dbe3; border-radius: 3px;
      padding: 0 3px; font-family: "Cascadia Code", Consolas, monospace; font-size: 9pt; }
    pre { background: #f5f7fa; border: 1px solid #d6dbe3; border-radius: 5px;
      padding: 8px 10px; overflow-x: auto; page-break-inside: avoid; font-size: 9pt;
      font-family: "Cascadia Code", Consolas, monospace; }
    pre code { background: none; border: none; padding: 0; }
    blockquote { border-left: 4px solid #c9a227; margin: 8px 0; padding: 4px 12px;
      background: #fffdf3; color: #5a4b00; }
    ul, ol { padding-left: 22px; }
    .toc { background: #f6f8fc; border: 1px solid #d6dbe3; border-radius: 5px;
      padding: 8px 14px; margin: 12px 0; font-size: 9.5pt; }
    .toc ul { list-style: none; padding-left: 14px; }
    .page-break { page-break-before: always; }
    .cover { page-break-after: always; height: 247mm; display: flex; flex-direction: column;
      justify-content: center; align-items: center; text-align: center; }
    .cover .logo { font-size: 13pt; letter-spacing: 4px; color: #0b3d91; margin-bottom: 30px; }
    .cover h1 { font-size: 30pt; margin: 0 0 16px; color: #0b3d91; }
    .cover .sub { font-size: 13pt; color: #333; margin: 4px 0; }
    .cover .meta { margin-top: 40px; font-size: 11pt; color: #555; line-height: 1.9; }
    .footnote { font-size: 8.5pt; color: #888; text-align: center; margin-top: 30px;
      border-top: 1px solid #ddd; padding-top: 8px; }
    @media print { .page-break { page-break-before: always; } a { color: inherit; } }
    """

    cover = f"""
    <div class="cover">
      <div class="logo">SEC-AUTO-MIND</div>
      <h1>参赛材料合订本</h1>
      <div class="sub">2026 挑战杯"揭榜挂帅" XH-202609</div>
      <div class="sub">《具备自主决策能力的通用网络安全智能体技术研究》</div>
      <div class="meta">
        作品名称：SecAutoMind（v1.7.17）<br/>
        发榜单位：杭州安恒信息技术股份有限公司<br/>
        合订内容：技术报告 · 方案设计文档 · 原创性及保密性声明（模板） · 演示视频脚本<br/>
        版本：2026-09-03 草稿 v1（提交前请删除内部备注与占位项）
      </div>
    </div>
    """

    html = f"""<!DOCTYPE html>
<html lang="zh-CN">
<head>
<meta charset="utf-8"/>
<title>SecAutoMind 参赛材料合订本</title>
<style>{css}</style>
</head>
<body>
{cover}
{combined}
<div class="footnote">本合订本由仓库 docs/zh-CN/competition-2026/ 下四份 markdown 自动生成，供团队评审与打印提交。</div>
</body>
</html>
"""
    out = HERE / "SecAutoMind_参赛材料合订本_打印版.html"
    out.write_text(html, encoding="utf-8")
    print("written:", out, "size:", out.stat().st_size)


if __name__ == "__main__":
    main()
