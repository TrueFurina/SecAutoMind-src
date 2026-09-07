# -*- coding: utf-8 -*-
"""生成 SecAutoMind 集大成版参赛答辩 PPT（24 页，深色科技风）。

融合：
- 冲击冠军版（深色科技视觉 / 完整叙事结构 / OFFLINE AI / INNOVATION×3）
- 原始中文版（一句话方案 / 评分对照 / 部署实操 / 细节表述）
- 新增 v1.7.18→v1.7.25 产品化与实测内容（首启向导 / 跨平台 CI / 多 LLM / RBAC 演示 / 视频引导）

16:9（13.333 x 7.5 inch）。
"""
from pptx import Presentation
from pptx.util import Inches, Pt, Emu
from pptx.dml.color import RGBColor
from pptx.enum.text import PP_ALIGN, MSO_ANCHOR
from pptx.enum.shapes import MSO_SHAPE

# ── 主题色（与冲击冠军版一致） ──
BG = RGBColor(0x0A, 0x11, 0x28)
PANEL = RGBColor(0x11, 0x1C, 0x33)
PANEL2 = RGBColor(0x0E, 0x18, 0x30)
INK = RGBColor(0xE8, 0xEC, 0xF3)
MUTED = RGBColor(0x7A, 0x8B, 0xB0)
ACCENT = RGBColor(0x00, 0xFF, 0x9D)
ACCENT2 = RGBColor(0x00, 0xB3, 0xFF)
WARN = RGBColor(0xFF, 0xB4, 0x54)
LINE = RGBColor(0x23, 0x34, 0x54)
GOLD = RGBColor(0xFF, 0xD7, 0x6E)

SW, SH = Inches(13.333), Inches(7.5)

prs = Presentation()
prs.slide_width = SW
prs.slide_height = SH
BLANK = prs.slide_layouts[6]


def add_slide():
    return prs.slides.add_slide(BLANK)


def rect(slide, x, y, w, h, fill=PANEL, line=None, radius=None):
    shape = slide.shapes.add_shape(MSO_SHAPE.ROUNDED_RECTANGLE if radius else MSO_SHAPE.RECTANGLE, x, y, w, h)
    shape.fill.solid()
    shape.fill.fore_color.rgb = fill
    if line:
        shape.line.color.rgb = line
        shape.line.width = Pt(1)
    else:
        shape.line.fill.background()
    return shape


def bg(slide):
    rect(slide, 0, 0, SW, SH, fill=BG)
    # 右上光晕
    glow = slide.shapes.add_shape(MSO_SHAPE.OVAL, Inches(10.2), Inches(-1.6), Inches(5), Inches(5))
    glow.fill.solid()
    glow.fill.fore_color.rgb = RGBColor(0x0E, 0x2A, 0x4A)
    glow.line.fill.background()


def text(slide, x, y, w, h, runs, size=18, color=INK, bold=False, align=PP_ALIGN.LEFT, anchor=MSO_ANCHOR.TOP, line_spacing=1.0, wrap=True):
    tb = slide.shapes.add_textbox(x, y, w, h)
    tf = tb.text_frame
    tf.word_wrap = wrap
    tf.vertical_anchor = anchor
    if isinstance(runs, str):
        runs = [(runs, size, color, bold)]
    # 兼容两种形态：[(txt,sz,col,bd), ...] 单段多 run；
    # [[...段落1...], [...段落2...]] 多段落（每段落内是 4 元组）
    if runs and isinstance(runs[0], (list, tuple)) and runs[0] and isinstance(runs[0][0], (list, tuple)):
        paras = runs
    else:
        paras = [runs]
    first = True
    for para in paras:
        p = tf.paragraphs[0] if first else tf.add_paragraph()
        first = False
        p.alignment = align
        p.line_spacing = line_spacing
        for item in para:
            txt, sz, col, bd = item
            r = p.add_run()
            r.text = txt
            r.font.size = Pt(sz)
            r.font.bold = bd
            r.font.color.rgb = col
    return tb


def tag(slide, x, y, label, color=ACCENT):
    t = text(slide, x, y, Inches(4), Inches(0.3), label, size=12, color=color, bold=True)
    return t


def card(slide, x, y, w, h, title, body_lines, accent=ACCENT, title_size=17, body_size=13):
    rect(slide, x, y, w, h, fill=PANEL, line=LINE, radius=True)
    bar = rect(slide, x, y + Inches(0.14), Inches(0.06), Inches(0.34), fill=accent)
    text(slide, x + Inches(0.22), y + Inches(0.12), w - Inches(0.4), Inches(0.4),
         title, size=title_size, color=INK, bold=True)
    body = []
    for ln in body_lines:
        if isinstance(ln, tuple):
            body.append(ln)
        else:
            body.append((ln, body_size, MUTED, False))
    text(slide, x + Inches(0.22), y + Inches(0.52), w - Inches(0.4), h - Inches(0.65),
         body, size=body_size, line_spacing=1.12)


def stat(slide, x, y, w, value, label, color=ACCENT, vsize=44):
    text(slide, x, y, w, Inches(0.7), value, size=vsize, color=color, bold=True, align=PP_ALIGN.CENTER)
    text(slide, x, y + Inches(0.72), w, Inches(0.4), label, size=13, color=MUTED, align=PP_ALIGN.CENTER)


def footer(slide, n, total=24):
    text(slide, Inches(0.5), Inches(7.08), Inches(4), Inches(0.3),
         "SecAutoMind · 2026 Challenge Cup · XH-202609", size=9, color=MUTED)
    text(slide, Inches(11.6), Inches(7.08), Inches(1.3), Inches(0.3),
         f"{n:02d} / {total}", size=9, color=MUTED, align=PP_ALIGN.RIGHT)


def chip(slide, x, y, w, label, fill=PANEL2, color=ACCENT2, size=12):
    c = rect(slide, x, y, w, Inches(0.34), fill=fill, line=LINE, radius=True)
    text(slide, x, y + Inches(0.02), w, Inches(0.3), label, size=size, color=color, align=PP_ALIGN.CENTER)


def sec_banner(slide, idx, title):
    """章节标题条"""
    text(slide, Inches(0.5), Inches(0.32), Inches(12), Inches(0.5), title, size=27, color=INK, bold=True)
    rect(slide, Inches(0.52), Inches(0.95), Inches(1.1), Inches(0.05), fill=ACCENT)


# ═══════════════════════════════════════════════
# 01 封面
# ═══════════════════════════════════════════════
s = add_slide()
bg(s)
text(s, Inches(0.8), Inches(0.55), Inches(8), Inches(0.4),
     [("2026 CHALLENGE CUP · 揭榜挂帅 · 安恒信息发榜", 15, MUTED, False)])
text(s, Inches(0.8), Inches(2.15), Inches(12), Inches(1.5),
     [("Sec", 64, ACCENT, True), ("Auto", 64, INK, True), ("Mind", 64, INK, True)])
text(s, Inches(0.82), Inches(3.3), Inches(11), Inches(0.6),
     [("自主决策 · 多智能体协同 · 全链路攻防推演平台", 24, ACCENT2, True)])
text(s, Inches(0.82), Inches(4.15), Inches(11.6), Inches(1.2),
     [[("面向赛题 XH-202609「具备自主决策能力的通用网络安全智能体技术研究」\n", 17, INK, False),
       ("以 3 层编排 × 90 工具 × 18 Agent，打造可离线运行的 AI 安全作战指挥舱——", 17, MUTED, False),
       ("双击即用 · 跨平台 · 可验证", 17, ACCENT, True)]], size=17, line_spacing=1.4)
chip(s, Inches(0.85), Inches(5.6), Inches(2.6), "Windows / Linux / macOS")
chip(s, Inches(3.65), Inches(5.6), Inches(2.6), "首启向导 · 零配置密钥")
chip(s, Inches(6.45), Inches(5.6), Inches(3.0), "多 LLM 自动轮询 · 全链路审计")
footer(s, 1)

# ═══════════════════════════════════════════════
# 02 目录
# ═══════════════════════════════════════════════
s = add_slide()
bg(s)
sec_banner(s, 0, "目录  CONTENTS")
items = [
    ("01", "赛题理解与总体方案", "XH-202609 要一个怎样的智能体 · 我们做什么"),
    ("02", "核心能力与技术架构", "五层架构 · 三层编排 · 90 工具 · HITL 审计 · 离线"),
    ("03", "技术创新", "自动选型 / YAML 工具化 / 人类可控 / 产品化闭环"),
    ("04", "产品化与跨平台交付", "双击即用 · 首启向导 · 三端 CI · 多 LLM 零配置"),
    ("05", "实测验证与评分对照", "编译零错误 · 测试全绿 · 向导/权限/CI 实测"),
    ("06", "部署 · 场景 · 演示", "云上跑 · 教学与竞赛 · 演示视频"),
]
y = Inches(1.4)
for num, t, d in items:
    rect(s, Inches(1.2), y, Inches(10.8), Inches(0.82), fill=PANEL, line=LINE, radius=True)
    text(s, Inches(1.6), y + Inches(0.1), Inches(0.9), Inches(0.6), num, size=26, color=ACCENT, bold=True)
    text(s, Inches(2.6), y + Inches(0.1), Inches(9), Inches(0.45), t, size=17, color=INK, bold=True)
    text(s, Inches(2.6), y + Inches(0.48), Inches(9), Inches(0.3), d, size=11.5, color=MUTED)
    y += Inches(0.92)
footer(s, 2)

# ═══════════════════════════════════════════════
# 03 章节扉页 · 01 赛题理解
# ═══════════════════════════════════════════════
s = add_slide()
bg(s)
text(s, Inches(1), Inches(2.4), Inches(11), Inches(1.4), "01", size=110, color=RGBColor(0x14, 0x24, 0x42), bold=True)
text(s, Inches(1), Inches(4.2), Inches(11), Inches(0.8),
     [("赛题理解与总体方案", 40, INK, True)])
text(s, Inches(1.02), Inches(5.1), Inches(9), Inches(0.5),
     "赛题 XH-202609 要一个怎样的智能体 · 我们用一句话与一张图回答", size=16, color=MUTED)
footer(s, 3)

# ═══════════════════════════════════════════════
# 04 赛题：要一个怎样的智能体
# ═══════════════════════════════════════════════
s = add_slide()
bg(s)
sec_banner(s, 1, "赛题 XH-202609：要一个怎样的智能体？")
text(s, Inches(0.52), Inches(1.05), Inches(12), Inches(0.4),
     [("命题单位：安恒信息（揭榜挂帅）——面向真实网络攻防场景，要求智能体「", 14, MUTED, False),
      ("能自主决策、能通用对抗、能人机协同、能证明有效", 14, ACCENT, True), ("」", 14, MUTED, False)])
# 左侧：痛点
card(s, Inches(0.6), Inches(1.7), Inches(5.9), Inches(4.9), "现实痛点：安全智能体为何难落地", [
    ("▸ 告警洪峰与攻击路径复杂：", 13.5, INK, True),
    ("单一 AI 无法完成“分析-决策-执行”闭环", 13, MUTED, False),
    ("▸ 工具割裂：", 13.5, INK, True),
    ("Nmap 在命令行、Burp 在 GUI、脚本各写各的，Agent 无法统一编排", 13, MUTED, False),
    ("▸ 风险难控：", 13.5, INK, True),
    ("自主执行危险操作缺少审批与审计，不敢真正交给 AI", 13, MUTED, False),
], accent=WARN)
# 右侧：赛题评分 5 维
card(s, Inches(6.8), Inches(1.7), Inches(5.9), Inches(4.9), "赛题评分结构（5 维度 · 每维 20 分）", [
    ("① 自主任务理解能力", 13.5, ACCENT2, True),
    ("    自然语言 / 结构化 / 压缩包 / 接口文档 → 可执行计划", 12.5, MUTED, False),
    ("② 多场景自主决策与执行", 13.5, ACCENT2, True),
    ("    渗透 / 应急 / 漏洞挖掘 / 逆向，全闭环动态调整", 12.5, MUTED, False),
    ("③ 运行鲁棒性与决策可靠性", 13.5, ACCENT2, True),
    ("    可解释 · 可审计 · 可复现，对抗干扰稳定", 12.5, MUTED, False),
    ("④⑤ 人机协同 · 应用成效", 13.5, ACCENT2, True),
    ("    HITL 审批 + 现场实战协同 + 部署落地证据", 12.5, MUTED, False),
], accent=ACCENT2)
footer(s, 4)

# ═══════════════════════════════════════════════
# 05 总体方案：一句话
# ═══════════════════════════════════════════════
s = add_slide()
bg(s)
sec_banner(s, 2, "SecAutoMind 总体方案：一句话讲清我们在做什么")
text(s, Inches(0.6), Inches(1.3), Inches(12.1), Inches(1.2),
     [[("以「", 20, MUTED, False),
       ("规划 / 执行 / 审计 / 复盘", 20, ACCENT, True),
       ("」四类 Agent 协同，通过共享事实黑板传递上下文；用 ", 20, MUTED, False),
       ("90 个 YAML 安全工具 + 3 种编排模式", 20, ACCENT, True),
       ("，构建可离线运行的自主决策攻防推演平台。", 20, MUTED, False)]],
     line_spacing=1.35)
# 四类 Agent
agents = [
    ("规划 Agent", "拆解目标 → 生成行动计划", ACCENT),
    ("执行 Agent", "调用工具 → 完成子任务", ACCENT2),
    ("审计 Agent", "复核结果 → 发现偏差", WARN),
    ("复盘 Agent", "沉淀经验 → 知识入库", GOLD),
]
x = Inches(0.6)
for name, desc, col in agents:
    rect(s, x, Inches(3.1), Inches(3.0), Inches(1.6), fill=PANEL, line=LINE, radius=True)
    rect(s, x, Inches(3.1), Inches(3.0), Inches(0.09), fill=col)
    text(s, x + Inches(0.25), Inches(3.35), Inches(2.6), Inches(0.5), name, size=18, color=INK, bold=True)
    text(s, x + Inches(0.25), Inches(3.95), Inches(2.6), Inches(0.7), desc, size=12.5, color=MUTED)
    x += Inches(3.14)
# 底部一句话能力
text(s, Inches(0.6), Inches(5.2), Inches(12.1), Inches(1.2),
     [[("一句话交付：", 15, MUTED, False),
       ("双击 exe → 首启向导设密码 → 浏览器打开 → 给它一个任务，它自主完成并在每一步留下审计证据。", 15, INK, True)]],
     line_spacing=1.3)
footer(s, 5)

# ═══════════════════════════════════════════════
# 06 章节扉页 · 02 核心能力
# ═══════════════════════════════════════════════
s = add_slide()
bg(s)
text(s, Inches(1), Inches(2.4), Inches(11), Inches(1.4), "02", size=110, color=RGBColor(0x14, 0x24, 0x42), bold=True)
text(s, Inches(1), Inches(4.2), Inches(11), Inches(0.8), [("核心能力与技术架构", 40, INK, True)])
text(s, Inches(1.02), Inches(5.1), Inches(9), Inches(0.5),
     "五层架构 · 三层编排 · 90 工具 × 18 Agent · HITL 审计 · 离线可跑", size=16, color=MUTED)
footer(s, 6)

# ═══════════════════════════════════════════════
# 07 系统架构：五层
# ═══════════════════════════════════════════════
s = add_slide()
bg(s)
sec_banner(s, 3, "系统架构：五层解耦 · 纵深防御")
layers = [
    ("① Web 控制台", "仪表盘 / 对话 / 资产 / 漏洞 / 工作流 / C2 / 审计回放 / 多用户 RBAC", ACCENT),
    ("② Agent 编排层", "规划 / 执行 / 审计 / 复盘 Agent · Deep / Plan-Execute / Supervisor 三种编排", ACCENT2),
    ("③ 安全工具层", "90 个 YAML 工具配方 + MCP 协议 · 注入型与独立型统一接入", WARN),
    ("④ 知识层", "攻防知识库 / 复盘沉淀 / 模型多通道（qwen · deepseek · openai…自动探测）", GOLD),
    ("⑤ 数据与安全底座", "审计日志全链路 · HITL 审批 · RBAC 权限隔离 · SQLite 本地持久化", ACCENT2),
]
y = Inches(1.35)
for name, desc, col in layers:
    rect(s, Inches(1.6), y, Inches(10.2), Inches(0.92), fill=PANEL, line=LINE, radius=True)
    rect(s, Inches(1.6), y, Inches(0.09), Inches(0.92), fill=col)
    text(s, Inches(1.95), y + Inches(0.08), Inches(3.3), Inches(0.7), name, size=17, color=INK, bold=True)
    text(s, Inches(5.35), y + Inches(0.13), Inches(6.2), Inches(0.7), desc, size=13, color=MUTED, wrap=True)
    y += Inches(1.04)
text(s, Inches(0.6), Inches(6.62), Inches(12), Inches(0.4),
     "五层间通过事实黑板与审计总线通信：上层可解释、下层可替换、全链可审计", size=13, color=ACCENT, align=PP_ALIGN.CENTER)
footer(s, 7)

# ═══════════════════════════════════════════════
# 08 三层多智能体编排
# ═══════════════════════════════════════════════
s = add_slide()
bg(s)
sec_banner(s, 4, "自主决策：三种编排模式支撑不同复杂度")
modes = [
    ("Deep Agent · 单 Agent 深度推理", ["循环调用工具直至达成目标", "适合：单点渗透、单一漏洞利用", "决策链清晰、可完整回放"], ACCENT),
    ("Plan-Execute · 先规划后执行", ["先产出多步计划 → 逐步执行校验", "适合：渗透测试、应急响应多步流程", "计划即证据，偏差即审计事件"], ACCENT2),
    ("Supervisor · 监督者分发", ["编排器分解子任务 → 多 Agent 并行", "适合：攻击链推演、多目标复杂任务", "黑板共享上下文、结果汇聚"], WARN),
]
x = Inches(0.6)
for title, body, col in modes:
    rect(s, x, Inches(1.5), Inches(3.95), Inches(3.9), fill=PANEL, line=LINE, radius=True)
    rect(s, x, Inches(1.5), Inches(3.95), Inches(0.09), fill=col)
    text(s, x + Inches(0.25), Inches(1.75), Inches(3.5), Inches(0.75), title, size=16, color=INK, bold=True, wrap=True)
    yb = Inches(2.6)
    for ln in body:
        text(s, x + Inches(0.25), yb, Inches(3.5), Inches(0.7), [("▸ ", 12.5, col, True), (ln, 12.5, MUTED, False)], wrap=True)
        yb += Inches(0.78)
    x += Inches(4.1)
text(s, Inches(0.6), Inches(5.7), Inches(12.1), Inches(0.9),
     [[("关键：编排器按任务复杂度自动选型（创新点一）——", 14.5, MUTED, False),
       ("简单任务不浪费 token，复杂任务不轻易失败", 14.5, INK, True)]], line_spacing=1.3)
footer(s, 8)

# ═══════════════════════════════════════════════
# 09 通用性巨型数字
# ═══════════════════════════════════════════════
s = add_slide()
bg(s)
sec_banner(s, 5, "通用性：90 工具 × 18 Agent × 全链路覆盖")
stats = [
    ("90", "YAML 安全工具配方", ACCENT),
    ("18", "角色化 Agent", ACCENT2),
    ("13", "安全场景覆盖", WARN),
    ("27", "外部协议 / 注入型工具", GOLD),
]
x = Inches(0.75)
for val, lbl, col in stats:
    stat(s, x, Inches(1.6), Inches(2.9), val, lbl, color=col)
    x += Inches(3.05)
card(s, Inches(0.6), Inches(3.4), Inches(6.1), Inches(3.1), "场景 → 工具 → Agent 自动匹配", [
    ("▸ 信息收集：Nmap / Fscan / 子域枚举…", 12.5, MUTED, False),
    ("▸ 渗透利用：Sqlmap / Metasploit / 漏洞库…", 12.5, MUTED, False),
    ("▸ Web 安全：XSS / SQLi / 目录爆破 / 指纹…", 12.5, MUTED, False),
    ("▸ 应急响应：进程排查 / 日志分析 / 样本提取…", 12.5, MUTED, False),
    ("▸ 攻防推演：攻击链编排 / C2 会话 / 报告生成…", 12.5, MUTED, False),
], accent=ACCENT)
card(s, Inches(7.0), Inches(3.4), Inches(5.8), Inches(3.1), 'Agent 看到的工具是「配方」而非「命令」', [
    ("YAML 配方 = 元数据 + 参数 Schema + 权限声明", 13, ACCENT, True),
    ("→ Agent 按 Schema 生成参数，无需知道底层命令", 13, MUTED, False),
    ("→ 工具白名单 + 危险标记，未授权工具不可调用", 13, MUTED, False),
    ("→ 新工具 = 新增一个 YAML，天然可扩展", 13, ACCENT2, True),
], accent=ACCENT2)
footer(s, 9)

# ═══════════════════════════════════════════════
# 10 HITL 与审计（含 RBAC 实测）
# ═══════════════════════════════════════════════
s = add_slide()
bg(s)
sec_banner(s, 6, "人机协同：敏感操作审批 + 全链路可审计")
card(s, Inches(0.6), Inches(1.4), Inches(6.1), Inches(4.6), "HITL 人工审批（AI 自主、人类可控）", [
    ("▸ 危险操作进审批队列：", 13, INK, True),
    ("命令执行 / 提权 / 数据删除 / 外联", 12.5, MUTED, False),
    ("▸ 前端实时呈现 + 拒绝机制", 13, INK, True),
    ("    带倒计时，超时自动挂起（防失控）", 12.5, MUTED, False),
    ("▸ 工具白名单双层校验", 13, INK, True),
    ("    调用前校验 + 权限点二次拦截", 12.5, MUTED, False),
    ("▸ 审批动作本身也进审计", 13, INK, True),
], accent=WARN)
card(s, Inches(6.9), Inches(1.4), Inches(5.9), Inches(4.6), "全链路审计 · RBAC 权限隔离（已实测）", [
    ("▸ 审计日志：谁在何时做了什么、结果如何", 12.5, MUTED, False),
    ("▸ 审计 Agent 复核结果偏差 → 自动上报", 12.5, MUTED, False),
    ("▸ RBAC 多角色（实测 2026-09）：", 12.5, ACCENT2, True),
    ("    审计员 auditor = 23 项权限全只读", 12.5, ACCENT, True),
    ("    auditor 尝试建号/写操作 → HTTP 403", 12.5, ACCENT, True),
    ("▸ 按操作者 / 时间 / 类别筛选回放", 12.5, MUTED, False),
], accent=ACCENT2)
footer(s, 10)

# ═══════════════════════════════════════════════
# 11 离线自主决策
# ═══════════════════════════════════════════════
s = add_slide()
bg(s)
sec_banner(s, 7, "离线自主决策：笔记本也能跑的 AI 安全平台")
text(s, Inches(0.6), Inches(1.35), Inches(12), Inches(0.5),
     "不依赖云端算力 · 适配学生笔记本本地部署 · 演示现场不翻车", size=15, color=MUTED)
card(s, Inches(0.6), Inches(2.0), Inches(5.9), Inches(4.0), "本地一键部署", [
    ("▸ Windows 双击 exe 即用（GUI 无黑窗）", 13, MUTED, False),
    ("▸ Linux/macOS 单文件 chmod +x 运行", 13, MUTED, False),
    ("▸ 数据全本地：SQLite + 文件知识库", 13, MUTED, False),
    ("▸ 前端资源内嵌二进制，无外部依赖", 13, MUTED, False),
], accent=ACCENT)
card(s, Inches(6.8), Inches(2.0), Inches(5.9), Inches(4.0), "环境自适应", [
    ("▸ 自动识别靶场类型", 13, ACCENT2, True),
    ("    Linux / Windows / Web / 云环境 → 切换工具集", 12.5, MUTED, False),
    ("▸ 多 LLM 通道自动探测（qwen 默认）", 13, ACCENT2, True),
    ("    无云端 key 也能用本地模型通道", 12.5, MUTED, False),
    ("▸ 网络波动自动重试与切换", 13, ACCENT2, True),
], accent=ACCENT2)
footer(s, 11)

# ═══════════════════════════════════════════════
# 12 章节扉页 · 03 技术创新
# ═══════════════════════════════════════════════
s = add_slide()
bg(s)
text(s, Inches(1), Inches(2.4), Inches(11), Inches(1.4), "03", size=110, color=RGBColor(0x14, 0x24, 0x42), bold=True)
text(s, Inches(1), Inches(4.2), Inches(11), Inches(0.8), [("技术创新", 40, INK, True)])
text(s, Inches(1.02), Inches(5.1), Inches(9), Inches(0.5),
     "自动选型编排 · YAML 工具化 · 人类可控 · 工程级产品化闭环", size=16, color=MUTED)
footer(s, 12)

# ═══════════════════════════════════════════════
# 13 创新一：按复杂度自动选编排
# ═══════════════════════════════════════════════
s = add_slide()
bg(s)
sec_banner(s, 8, "创新点一：三层多智能体编排——按复杂度自动选型")
card(s, Inches(0.6), Inches(1.5), Inches(6.0), Inches(3.3), "现有方案的局限", [
    ("▸ 单 Agent「一条道走到黑」：", 13, MUTED, False),
    ("    复杂任务成功率低、token 浪费大", 12.5, MUTED, False),
    ("▸ 固定编排：", 13, MUTED, False),
    ("    简单任务也走重流程，响应慢", 12.5, MUTED, False),
    ("▸ 无统一事实上下文：", 13, MUTED, False),
    ("    多步决策互相割裂、无法回放", 12.5, MUTED, False),
], accent=WARN)
card(s, Inches(6.9), Inches(1.5), Inches(5.9), Inches(3.3), "我们的做法", [
    ("▸ 编排器先做任务复杂度评估", 13, ACCENT, True),
    ("▸ 自动选择：", 13, ACCENT2, True),
    ("    Deep（简单） / Plan-Execute（多步） / Supervisor（并行复杂）", 12.5, MUTED, False),
    ("▸ 共享事实黑板：决策上下文全程可追溯", 13, ACCENT, True),
    ("▸ 失败自动降级 / 换通道重试", 13, ACCENT, True),
], accent=ACCENT)
text(s, Inches(0.6), Inches(5.2), Inches(12.1), Inches(0.8),
     [[("为什么新？", 16, WARN, True),
       ("  不是「编排模式多」，而是「按复杂度自动选型 + 黑板统一记忆」——效率与成功率兼得。", 15, INK, True)]], line_spacing=1.3)
footer(s, 13)

# ═══════════════════════════════════════════════
# 14 创新二：90 工具 YAML 统一对抗
# ═══════════════════════════════════════════════
s = add_slide()
bg(s)
sec_banner(s, 9, "创新点二：90 工具 × 18 Agent 的「全链路通用对抗」")
card(s, Inches(0.6), Inches(1.5), Inches(6.0), Inches(3.3), "行业痛点：安全工具碎片化", [
    ("▸ Nmap 在命令行、Burp 在 GUI", 13, MUTED, False),
    ("▸ 脚本各写各的，Agent 无法统一编排", 13, MUTED, False),
    ("▸ 工具间无上下文共享", 13, MUTED, False),
    ("▸ 能力难扩展：加工具=改代码", 13, MUTED, False),
], accent=WARN)
card(s, Inches(6.9), Inches(1.5), Inches(5.9), Inches(3.3), "我们的统一抽象", [
    ("▸ 90 个 YAML 工具配方（元数据+Schema）", 13, ACCENT, True),
    ("▸ MCP 协议统一接入注入型 / 独立型工具", 13, ACCENT, True),
    ("▸ Agent 按 Schema 自动生成调用参数", 13, MUTED, False),
    ("▸ 新增工具 = 新增 YAML（可扩展）", 13, ACCENT2, True),
    ("▸ 覆盖 13 场景：渗透/应急/Web/逆向…", 13, MUTED, False),
], accent=ACCENT)
footer(s, 14)

# ═══════════════════════════════════════════════
# 15 创新三：HITL 人类可控
# ═══════════════════════════════════════════════
s = add_slide()
bg(s)
sec_banner(s, 10, "创新点三：HITL 审批 × 全链路审计——「AI 自主、人类可控」")
card(s, Inches(0.6), Inches(1.5), Inches(6.0), Inches(4.5), "工程级兜底设计", [
    ("▸ 敏感操作 HITL 审批（带倒计时）", 13, ACCENT, True),
    ("    命令执行 / 提权 / 删除 / 外联", 12.5, MUTED, False),
    ("▸ 审计 Agent 复核执行结果", 13, ACCENT, True),
    ("▸ 工具白名单 + 权限点双层拦截", 13, ACCENT2, True),
    ("▸ 全链路证据留存（谁/何时/何操作/结果）", 13, ACCENT2, True),
], accent=ACCENT)
card(s, Inches(6.9), Inches(1.5), Inches(5.9), Inches(4.5), "为什么这是创新", [
    ("▸ 自主决策 ≠ 放任自流", 13, INK, True),
    ("    现有 Agent 框架大多「执行完才报告」", 12.5, MUTED, False),
    ("▸ 我们让「审批先于执行」且可编程", 13, INK, True),
    ("    危险阈值 / 审批人 / 超时策略均可配", 12.5, MUTED, False),
    ("▸ 审计是产品能力而非日志后补", 13, ACCENT, True),
    ("    审计回放页：按操作者/时间/类别筛选", 12.5, MUTED, False),
], accent=ACCENT2)
footer(s, 15)

# ═══════════════════════════════════════════════
# 16 创新四：工程级产品化闭环（新）
# ═══════════════════════════════════════════════
s = add_slide()
bg(s)
sec_banner(s, 11, "创新点四：工程级产品化闭环——从「能跑」到「能用」")
text(s, Inches(0.6), Inches(1.3), Inches(12), Inches(0.5),
     "很多参赛系统止步于演示 demo；我们按「正式软件」标准交付了完整产品闭环", size=14.5, color=MUTED)
steps = [
    ("双击即用", "GUI 无黑窗\n自动开浏览器\n1 秒启动", ACCENT),
    ("首启向导", "设专属密码\n初始密码一次有效\n安全不裸奔", ACCENT2),
    ("桌面入口", "首次运行自动\n创建快捷方式\n带品牌图标", WARN),
    ("绿色版/安装版", "Setup 向导安装\n或单文件直跑\n数据全本地", GOLD),
]
x = Inches(0.6)
for title, body, col in steps:
    rect(s, x, Inches(2.1), Inches(3.0), Inches(2.3), fill=PANEL, line=LINE, radius=True)
    rect(s, x, Inches(2.1), Inches(3.0), Inches(0.09), fill=col)
    text(s, x + Inches(0.2), Inches(2.3), Inches(2.6), Inches(0.5), title, size=16, color=INK, bold=True)
    text(s, x + Inches(0.2), Inches(2.85), Inches(2.6), Inches(1.4), body, size=11.5, color=MUTED, line_spacing=1.25)
    x += Inches(3.14)
text(s, Inches(0.6), Inches(4.8), Inches(12.1), Inches(1.3),
     [[("产品级 = 每一条用户路径都被实测过：", 15, ACCENT, True),
       ("双击→向导→登录→对话→审计，全流程 7 步实测通过；无人值守也能跑（防重复双击幂等）。", 14, MUTED, False)]],
     line_spacing=1.35)
footer(s, 16)

# ═══════════════════════════════════════════════
# 17 章节扉页 · 04 产品化与跨平台
# ═══════════════════════════════════════════════
s = add_slide()
bg(s)
text(s, Inches(1), Inches(2.4), Inches(11), Inches(1.4), "04", size=110, color=RGBColor(0x14, 0x24, 0x42), bold=True)
text(s, Inches(1), Inches(4.2), Inches(11), Inches(0.8), [("产品化与跨平台交付", 40, INK, True)])
text(s, Inches(1.02), Inches(5.1), Inches(9), Inches(0.5),
     "三端发布 · 官网分发 · 多 LLM 零配置 · 密钥环境变量化", size=16, color=MUTED)
footer(s, 17)

# ═══════════════════════════════════════════════
# 18 跨平台三端发布（新）
# ═══════════════════════════════════════════════
s = add_slide()
bg(s)
sec_banner(s, 12, "跨平台三端发布：CI 自动构建 · 官网分发")
plats = [
    ("Windows", "Setup 安装版 33.6 MB\n（选目录+快捷方式+卸载）\n绿色版 158 MB", ACCENT),
    ("Linux", "amd64 单文件\nchmod +x 即跑\n原生 cgo 编译", ACCENT2),
    ("macOS", "Apple Silicon arm64\n+ Intel amd64\n原生编译", WARN),
]
x = Inches(0.6)
for name, body, col in plats:
    rect(s, x, Inches(1.5), Inches(4.0), Inches(3.3), fill=PANEL, line=LINE, radius=True)
    text(s, x + Inches(0.3), Inches(1.7), Inches(3.4), Inches(0.5), name, size=21, color=col, bold=True)
    text(s, x + Inches(0.3), Inches(2.4), Inches(3.4), Inches(2.0), body, size=13, color=MUTED, line_spacing=1.35)
    x += Inches(4.18)
text(s, Inches(0.6), Inches(5.2), Inches(12.1), Inches(1.4),
     [[("CI 流水线：", 14.5, ACCENT, True),
       ("push tag → GitHub Actions 三平台原生编译（含 cgo sqlite）→ 产物自动上传 Release → 官网（GitHub Pages）三端下载，全程可复现、无需本机环境。", 14, MUTED, False)]],
     line_spacing=1.35)
footer(s, 18)

# ═══════════════════════════════════════════════
# 19 多 LLM × 零配置密钥（新）
# ═══════════════════════════════════════════════
s = add_slide()
bg(s)
sec_banner(s, 13, "多 LLM 通道 × 零配置密钥：开箱即用")
card(s, Inches(0.6), Inches(1.4), Inches(6.0), Inches(4.7), "密钥环境变量化（不再手填 config）", [
    ("▸ config 支持 ${ENV} 引用", 13, ACCENT, True),
    ("    DASHSCOPE_API_KEY / DEEPSEEK_API_KEY…", 12.5, MUTED, False),
    ("▸ 留空/占位自动回退环境变量", 13, ACCENT, True),
    ("    按 base_url 精确匹配 provider，不串 key", 12.5, MUTED, False),
    ("▸ 全凭据覆盖", 13, ACCENT2, True),
    ("    AI / 知识库 / 测绘工具 / 机器人通道 secret", 12.5, MUTED, False),
    ("▸ 无明文密钥落盘 → 安全交接演示", 13, ACCENT2, True),
], accent=ACCENT)
card(s, Inches(6.9), Inches(1.4), Inches(5.9), Inches(4.7), "多通道自动探测 + 失败轮询", [
    ("▸ 检测到哪个模型 key 自动激活哪个通道", 13, ACCENT, True),
    ("    qwen-max（默认）/ deepseek / openai /", 12.5, MUTED, False),
    ("    siliconflow / moonshot / zhipu / ark / claude…", 12.5, MUTED, False),
    ("▸ 默认 qwen-max，失败自动轮询下一通道", 13, ACCENT, True),
    ("    实测：8 通道全带真实 key 自动激活", 12.5, ACCENT, True),
    ("▸ 演示现场：一个 key 挂了自动切，不翻车", 13, ACCENT2, True),
], accent=ACCENT2)
footer(s, 19)

# ═══════════════════════════════════════════════
# 20 章节扉页 · 05 实测验证
# ═══════════════════════════════════════════════
s = add_slide()
bg(s)
text(s, Inches(1), Inches(2.4), Inches(11), Inches(1.4), "05", size=110, color=RGBColor(0x14, 0x24, 0x42), bold=True)
text(s, Inches(1), Inches(4.2), Inches(11), Inches(0.8), [("实测验证 · 全部磁盘实证", 40, INK, True)])
text(s, Inches(1.02), Inches(5.1), Inches(9), Inches(0.5),
     "编译零错误 · 测试全绿 · 系统实启动 · 向导/权限/CI 全流程实测", size=16, color=MUTED)
footer(s, 20)

# ═══════════════════════════════════════════════
# 21 实测验证（升级版）
# ═══════════════════════════════════════════════
s = add_slide()
bg(s)
sec_banner(s, 14, "实测验证：编译零错误 · 测试全绿 · 全流程实证")
text(s, Inches(0.6), Inches(1.2), Inches(12), Inches(0.4),
     "（2026-09 实测，全部为磁盘/接口真实数据，无模拟）", size=13, color=MUTED)
stats2 = [
    ("0", "编译错误\n（123,149 行 Go）", ACCENT),
    ("28/28", "测试包全绿\n（0 FAIL，见证据文件）", ACCENT2),
    ("1s", "双击启动\nHTTP 200 服务就绪", WARN),
    ("7/7", "首启向导实测\n（设密码→登录→文件删除）", GOLD),
]
x = Inches(0.75)
for val, lbl, col in stats2:
    stat(s, x, Inches(1.7), Inches(2.9), val, lbl, color=col, vsize=40)
    x += Inches(3.05)
card(s, Inches(0.6), Inches(4.0), Inches(6.1), Inches(2.6), "工程实证", [
    ("▸ go build ./... 退出码 0（全量编译零错误）", 12.5, MUTED, False),
    ("▸ 核心包 go test 全绿（database/agent/…）", 12.5, MUTED, False),
    ("▸ 系统实启动：GET / → 200，端口监听正常", 12.5, MUTED, False),
    ("▸ 三平台 CI（Win/Linux/macOS）构建全绿", 12.5, ACCENT, True),
], accent=ACCENT)
card(s, Inches(6.9), Inches(4.0), Inches(5.9), Inches(2.6), "产品实测", [
    ("▸ 首启向导 7 步：错误密码拒/设密码/文件删除…", 12.5, MUTED, False),
    ("▸ RBAC 隔离：auditor 写操作 → HTTP 403", 12.5, ACCENT, True),
    ("▸ 飞书机器人 wss 长连接实测连接成功", 12.5, ACCENT, True),
    ("▸ 多 LLM：8 通道自动激活带真实 key", 12.5, MUTED, False),
], accent=ACCENT2)
footer(s, 21)

# ═══════════════════════════════════════════════
# 22 与评分标准逐项对照
# ═══════════════════════════════════════════════
s = add_slide()
bg(s)
sec_banner(s, 15, "与评分标准逐项对照：我们怎么拿高分？")
rows = [
    ("自主任务理解", "自然语言/结构化作任务 → 场景 Agent 自动解析生成计划", "★★★★★", ACCENT),
    ("多场景自主决策执行", "渗透/应急/漏洞/逆向全链路 + 三层编排按复杂度自动选型", "★★★★★", ACCENT),
    ("运行鲁棒与决策可靠", "可解释（黑板）· 可审计（全链路）· 可复现（幂等/回放）", "★★★★★", ACCENT),
    ("人机协同", "HITL 审批 + RBAC 多角色 + auditor 只读实测 403 隔离", "★★★★★", ACCENT2),
    ("应用成效与可部署性", "双击即用 + 三端 CI + 官网分发 + 演示视频（详见演示页）", "★★★★★", ACCENT2),
]
y = Inches(1.4)
for name, resp, stars, col in rows:
    rect(s, Inches(0.6), y, Inches(12.2), Inches(0.98), fill=PANEL, line=LINE, radius=True)
    text(s, Inches(0.9), y + Inches(0.12), Inches(2.6), Inches(0.75), name, size=16, color=INK, bold=True)
    text(s, Inches(3.6), y + Inches(0.14), Inches(6.6), Inches(0.75), resp, size=12.5, color=MUTED, wrap=True)
    text(s, Inches(10.4), y + Inches(0.24), Inches(2.2), Inches(0.5), stars, size=15, color=ACCENT, bold=True)
    y += Inches(1.08)
footer(s, 22)

# ═══════════════════════════════════════════════
# 23 部署 · 场景 · 演示引导
# ═══════════════════════════════════════════════
s = add_slide()
bg(s)
sec_banner(s, 16, "部署 · 适用场景 · 演示视频")
card(s, Inches(0.6), Inches(1.4), Inches(4.0), Inches(4.9), "部署（三选一）", [
    ("▸ Windows 安装版 / 绿色版", 13, ACCENT, True),
    ("    双击 → 向导 → 浏览器打开", 12, MUTED, False),
    ("▸ Linux / macOS 单文件", 13, ACCENT, True),
    ("    chmod +x && ./secautomind-ai", 12, MUTED, False),
    ("▸ 云主机部署", 13, ACCENT, True),
    ("    HTTPS + 反向代理即可公网使用", 12, MUTED, False),
], accent=ACCENT)
card(s, Inches(4.9), Inches(1.4), Inches(4.0), Inches(4.9), "适用场景", [
    ("▸ 高校网络攻防教学", 13, ACCENT2, True),
    ("    自动化推演 + 标准化复盘报告", 12, MUTED, False),
    ("▸ 安全竞赛训练", 13, ACCENT2, True),
    ("    CTF 解题 / 渗透实操陪练", 12, MUTED, False),
    ("▸ 应急与演练", 13, ACCENT2, True),
    ("    攻击链推演 + 审计留证", 12, MUTED, False),
], accent=ACCENT2)
card(s, Inches(9.2), Inches(1.4), Inches(3.6), Inches(4.9), "演示视频", [
    ("完整产品演示已录制：", 14, GOLD, True),
    ("① 首启向导设密码", 12.5, MUTED, False),
    ("② 对话任务 → 自主决策", 12.5, MUTED, False),
    ("③ 敏感操作 HITL 审批", 12.5, MUTED, False),
    ("④ 审计回放全链路留证", 12.5, MUTED, False),
    ("⑤ RBAC 权限隔离展示", 12.5, MUTED, False),
    ("⑥ 跨平台三端启动", 12.5, MUTED, False),
], accent=GOLD)
footer(s, 23)

# ═══════════════════════════════════════════════
# 24 总结 + 致谢
# ═══════════════════════════════════════════════
s = add_slide()
bg(s)
text(s, Inches(0.8), Inches(0.9), Inches(11.8), Inches(0.6),
     [("总结  SUMMARY", 15, MUTED, False)])
text(s, Inches(0.8), Inches(1.6), Inches(11.8), Inches(2.2),
     [[("做了什么：", 17, ACCENT, True),
       ("3 层编排 × 90 工具 × 18 Agent 的自主决策攻防推演平台——", 17, INK, True),
       ("编译零错误、核心测试全绿、系统实启动、三端可下载、首启向导与审计全流程实测。", 17, MUTED, False)]],
     line_spacing=1.4)
text(s, Inches(0.8), Inches(3.5), Inches(11.8), Inches(1.0),
     [[("技术创新：", 17, ACCENT2, True),
       ("按复杂度自动选编排 · YAML 工具统一对抗 · HITL 人类可控 · 工程级产品化闭环", 17, INK, True)]],
     line_spacing=1.4)
text(s, Inches(0.8), Inches(5.0), Inches(11.8), Inches(1.0),
     [[("展望：", 17, GOLD, True),
       ("持续扩充工具与场景知识 · 人机协同实战深度打磨 · 让 AI 安全智能体真正「自主、通用、可控」", 17, MUTED, False)]],
     line_spacing=1.4)
rect(s, Inches(0.8), Inches(6.0), Inches(11.7), Inches(0.02), fill=LINE)
text(s, Inches(0.8), Inches(6.3), Inches(11.8), Inches(0.5),
     "SecAutoMind · 2026 中国青年科技创新「揭榜挂帅」擂台赛 · 安恒信息发榜 · XH-202609", size=14, color=ACCENT, align=PP_ALIGN.CENTER)
footer(s, 24)

# ═══════════════════════════════════════════════
# 保存
# ═══════════════════════════════════════════════
OUT = r'E:/Program/2026挑战杯：SecAutoMind-v1.7.17-share/SecAutoMind_PPT/SecAutoMind_参赛答辩_集大成版.pptx'
prs.save(OUT)
print(f'✅ 全部 24 页生成完成 → {OUT}')
