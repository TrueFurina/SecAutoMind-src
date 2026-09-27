"""生成 SecAutoMind 冲击冠军版参赛答辩 PPT（python-pptx）。

深色科技风（赛博蓝青）：#0a1128 底 / #00ff9d 青绿强调 / #00b3ff 蓝
16:9（13.333 x 7.5 inch），18 页：
1 封面 → 2 目录 → 3 赛题理解 → 4 总体方案 → 5 系统架构 → 6 三层编排
→ 7 通用性(91工具/18Agent) → 8 人机协同(HITL/审计) → 9 离线自主
→ 10-12 三大创新点 → 13 实测验证数据 → 14 评分标准对照 → 15 部署
→ 16 应用场景 → 17 总结展望 → 18 封底
"""
from pptx import Presentation
from pptx.util import Inches, Pt, Emu
from pptx.dml.color import RGBColor
from pptx.enum.text import PP_ALIGN, MSO_ANCHOR

# ── 主题色 ──
BG = RGBColor(0x0A, 0x11, 0x28)
PANEL = RGBColor(0x11, 0x1C, 0x33)
PANEL2 = RGBColor(0x0E, 0x18, 0x30)
INK = RGBColor(0xE8, 0xEC, 0xF3)
MUTED = RGBColor(0x7A, 0x8B, 0xB0)
ACCENT = RGBColor(0x00, 0xFF, 0x9D)
ACCENT2 = RGBColor(0x00, 0xB3, 0xFF)
WARN = RGBColor(0xFF, 0xB4, 0x54)
LINE = RGBColor(0x23, 0x34, 0x54)

SW, SH = Inches(13.333), Inches(7.5)

prs = Presentation()
prs.slide_width = SW
prs.slide_height = SH
BLANK = prs.slide_layouts[6]


def add_slide():
    return prs.slides.add_slide(BLANK)


def rect(slide, x, y, w, h, fill=PANEL, line=None, radius=None):
    from pptx.enum.shapes import MSO_SHAPE
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
    # 顶部光晕
    from pptx.enum.shapes import MSO_SHAPE
    g = slide.shapes.add_shape(MSO_SHAPE.OVAL, Inches(9), Inches(-2), Inches(6), Inches(6))
    g.fill.solid()
    g.fill.fore_color.rgb = RGBColor(0x0D, 0x2B, 0x55)
    g.line.fill.background()
    g.shadow.inherit = False


def text(slide, x, y, w, h, runs, size=18, color=INK, bold=False, align=PP_ALIGN.LEFT, anchor=MSO_ANCHOR.TOP, line_spacing=1.0):
    """runs: str 或 [(text, dict), ...]"""
    tb = slide.shapes.add_textbox(x, y, w, h)
    tf = tb.text_frame
    tf.word_wrap = True
    tf.vertical_anchor = anchor
    if isinstance(runs, str):
        runs = [(runs, {})]
    for i, (txt, over) in enumerate(runs):
        p = tf.paragraphs[0] if i == 0 else tf.add_paragraph()
        p.alignment = over.get('align', align)
        p.line_spacing = over.get('ls', line_spacing)
        p.space_after = Pt(over.get('sa', 0))
        r = p.add_run()
        r.text = txt
        r.font.size = Pt(over.get('size', size))
        r.font.bold = over.get('bold', bold)
        r.font.color.rgb = over.get('color', color)
        r.font.name = 'Microsoft YaHei'
    return tb


def tag(slide, x, y, label, color=ACCENT):
    """小徽标"""
    from pptx.enum.shapes import MSO_SHAPE
    w = Inches(0.5 + len(label) * 0.14)
    h = Inches(0.32)
    shape = slide.shapes.add_shape(MSO_SHAPE.ROUNDED_RECTANGLE, x, y, w, h)
    shape.fill.solid()
    shape.fill.fore_color.rgb = color
    shape.line.fill.background()
    tf = shape.text_frame
    tf.word_wrap = False
    p = tf.paragraphs[0]
    p.alignment = PP_ALIGN.CENTER
    r = p.add_run()
    r.text = label
    r.font.size = Pt(11)
    r.font.bold = True
    r.font.color.rgb = BG
    r.font.name = 'Microsoft YaHei'
    return shape


def card(slide, x, y, w, h, title, body_lines, accent=ACCENT):
    rect(slide, x, y, w, h, fill=PANEL, line=LINE)
    rect(slide, x, y, Inches(0.06), h, fill=accent)
    text(slide, x + Inches(0.25), y + Inches(0.15), w - Inches(0.4), Inches(0.5),
         [(title, {'size': 17, 'bold': True, 'color': INK})])
    lines = body_lines if isinstance(body_lines, list) else [body_lines]
    body_runs = [(ln, {'size': 13, 'color': MUTED, 'ls': 1.15, 'sa': 4}) for ln in lines]
    text(slide, x + Inches(0.25), y + Inches(0.65), w - Inches(0.4), h - Inches(0.8), body_runs)


def stat(slide, x, y, w, value, label, color=ACCENT):
    rect(slide, x, y, w, Inches(1.15), fill=PANEL2, line=LINE)
    text(slide, x, y + Inches(0.12), w, Inches(0.55),
         [(value, {'size': 30, 'bold': True, 'color': color, 'align': PP_ALIGN.CENTER})])
    text(slide, x, y + Inches(0.68), w, Inches(0.35),
         [(label, {'size': 12, 'color': MUTED, 'align': PP_ALIGN.CENTER})])


def footer(slide, n):
    text(slide, Inches(12.3), Inches(7.08), Inches(0.8), Inches(0.3),
         [(str(n), {'size': 10, 'color': MUTED, 'align': PP_ALIGN.RIGHT})])


# ══════════════════════════════════════════════════════════
# P1 封面
# ══════════════════════════════════════════════════════════
s = add_slide()
bg(s)
tag(s, Inches(0.7), Inches(0.6), '2026 CHALLENGE CUP · 揭榜挂帅', ACCENT2)
text(s, Inches(0.7), Inches(1.6), Inches(11), Inches(1.2),
     [('SecAutoMind', {'size': 66, 'bold': True, 'color': INK})])
text(s, Inches(0.7), Inches(2.7), Inches(11), Inches(0.6),
     [('自主决策 · 多智能体协同 · 全链路攻防推演平台', {'size': 22, 'color': ACCENT})])
text(s, Inches(0.7), Inches(3.5), Inches(11), Inches(1.2),
     [('面向赛题 XH-202609「基于大模型的自主决策通用网络安全智能体」', {'size': 16, 'color': MUTED, 'ls': 1.4}),
      ('以 3 层编排 × 91 工具 × 18 Agent 打造可离线运行的 AI 安全作战指挥舱', {'size': 16, 'color': MUTED, 'ls': 1.4})])
rect(s, Inches(0.7), Inches(5.3), Inches(12), Inches(0.015), fill=LINE)
text(s, Inches(0.7), Inches(5.55), Inches(11), Inches(0.5),
     [('2026 年全国大学生信息安全作品赛 · 挑战杯赛道', {'size': 15, 'color': INK, 'bold': True})])
text(s, Inches(0.7), Inches(6.1), Inches(11), Inches(0.5),
     [('闽江学院 · 数学与数据科学学院（网络安全方向）', {'size': 13, 'color': MUTED})])
footer(s, 1)

# ══════════════════════════════════════════════════════════
# P2 目录
# ══════════════════════════════════════════════════════════
s = add_slide()
bg(s)
tag(s, Inches(0.7), Inches(0.6), 'CONTENTS', ACCENT)
text(s, Inches(0.7), Inches(1.0), Inches(5), Inches(0.8), [('目录', {'size': 40, 'bold': True})])
toc = [
    ('01', '赛题理解', 'XH-202609 要一个怎样的智能体'),
    ('02', '总体方案', '一句话讲清我们在做什么'),
    ('03', '系统架构与核心能力', '分层架构 · 三层编排 · 91 工具 · 18 Agent'),
    ('04', '三大技术创新点', '自主决策 · 通用性 · 人机协同审计'),
    ('05', '实测验证', '编译零错误 · 核心测试全绿 · 系统实启动'),
    ('06', '评分对照与部署', '逐项对照评分标准 · 云上一键跑起来'),
]
for i, (num, title, sub) in enumerate(toc):
    y = Inches(2.0 + i * 0.82)
    rect(s, Inches(0.7), y, Inches(11.6), Inches(0.68), fill=PANEL, line=LINE)
    text(s, Inches(0.95), y + Inches(0.12), Inches(0.8), Inches(0.4),
         [(num, {'size': 22, 'bold': True, 'color': ACCENT})])
    text(s, Inches(1.8), y + Inches(0.08), Inches(4), Inches(0.4),
         [(title, {'size': 18, 'bold': True, 'color': INK})])
    text(s, Inches(1.8), y + Inches(0.38), Inches(9), Inches(0.3),
         [(sub, {'size': 12, 'color': MUTED})])
footer(s, 2)

# ══════════════════════════════════════════════════════════
# P3 赛题理解
# ══════════════════════════════════════════════════════════
s = add_slide()
bg(s)
tag(s, Inches(0.7), Inches(0.6), 'PROBLEM', WARN)
text(s, Inches(0.7), Inches(1.0), Inches(11), Inches(0.8), [('赛题 XH-202609：要一个怎样的智能体？', {'size': 30, 'bold': True})])
text(s, Inches(0.7), Inches(1.8), Inches(11.6), Inches(0.9),
     [('命题单位：安恒信息（揭榜挂帅）——面向真实网络攻防场景，要求智能体', {'size': 16, 'color': MUTED, 'ls': 1.4}),
      ('「能自主决策、能通用对抗、能人机协同、能证明有效」', {'size': 18, 'bold': True, 'color': ACCENT, 'ls': 1.4})])
issues = [
    ('痛点 1', '告警与攻击路径复杂', '单一规则引擎无法覆盖多阶段攻击链，需要智能体自主规划'),
    ('痛点 2', '工具碎片化', '安全工具分散在命令行/脚本/平台，缺乏统一调度与上下文传递'),
    ('痛点 3', '不可控不可审', 'AI 自主操作存在误伤风险，需要 HITL 审批与全链路审计'),
    ('痛点 4', '难以验证', '多数方案停留在演示，缺乏编译/测试/运行的三重实证'),
]
for i, (t, title, body) in enumerate(issues):
    x = Inches(0.7 + (i % 2) * 6.0)
    y = Inches(2.9 + (i // 2) * 1.9)
    card(s, x, y, Inches(5.7), Inches(1.65), f'{t}：{title}', [body], accent=WARN if i % 2 == 0 else ACCENT2)
footer(s, 3)

# ══════════════════════════════════════════════════════════
# P4 总体方案
# ══════════════════════════════════════════════════════════
s = add_slide()
bg(s)
tag(s, Inches(0.7), Inches(0.6), 'SOLUTION', ACCENT)
text(s, Inches(0.7), Inches(1.0), Inches(11), Inches(0.8), [('SecAutoMind 总体方案', {'size': 30, 'bold': True})])
rect(s, Inches(0.7), Inches(2.0), Inches(11.9), Inches(1.6), fill=PANEL, line=ACCENT)
text(s, Inches(1.0), Inches(2.2), Inches(11.2), Inches(1.2),
     [('一句话：', {'size': 18, 'bold': True, 'color': ACCENT}),
      ('以「规划 / 执行 / 审计 / 复盘」四类 Agent 协同，通过共享事实黑板传递上下文，', {'size': 18, 'color': INK, 'ls': 1.4}),
      ('用 90 个 YAML 安全工具 + 3 种编排模式，构建可离线运行的自主决策攻防推演平台', {'size': 18, 'color': INK, 'ls': 1.4})])
flow = [('① 规划器', '拆解目标\n生成行动链'), ('② 执行器', '调度工具\n执行动作'), ('③ 审计器', 'HITL 审批\n证据留存'), ('④ 复盘器', '导出报告\n风险评分')]
for i, (t, body) in enumerate(flow):
    x = Inches(0.7 + i * 3.05)
    rect(s, x, Inches(4.0), Inches(2.75), Inches(1.6), fill=PANEL2, line=LINE)
    text(s, x + Inches(0.2), Inches(4.15), Inches(2.35), Inches(0.4),
         [(t, {'size': 16, 'bold': True, 'color': ACCENT, 'align': PP_ALIGN.CENTER})])
    text(s, x + Inches(0.2), Inches(4.6), Inches(2.35), Inches(0.9),
         [(body, {'size': 12, 'color': MUTED, 'align': PP_ALIGN.CENTER, 'ls': 1.3})])
    if i < 3:
        text(s, x + Inches(2.75), Inches(4.5), Inches(0.4), Inches(0.4),
             [('→', {'size': 24, 'bold': True, 'color': ACCENT2, 'align': PP_ALIGN.CENTER})])
text(s, Inches(0.7), Inches(6.0), Inches(11), Inches(0.4),
     [('四类 Agent 通过「事实黑板」共享上下文，前序输出动态调整后续步骤——不是脚本堆叠，是真实决策链', {'size': 13, 'color': MUTED})])
footer(s, 4)

# ══════════════════════════════════════════════════════════
# P5 系统架构
# ══════════════════════════════════════════════════════════
s = add_slide()
bg(s)
tag(s, Inches(0.7), Inches(0.6), 'ARCHITECTURE', ACCENT2)
text(s, Inches(0.7), Inches(1.0), Inches(11), Inches(0.8), [('系统架构：五层解耦，纵深防御', {'size': 30, 'bold': True})])
layers = [
    ('① Web 控制台', '仪表盘 / 对话 / 资产 / 漏洞 / 工作流 / C2 / 审计回放', ACCENT2),
    ('② 编排器', 'Deep / Plan-Execute / Supervisor 三种编排模式（eino）', ACCENT),
    ('③ Agent 层', '规划 Agent · 执行 Agent · 审计 Agent · 复盘 Agent · 18 个场景角色', ACCENT2),
    ('④ 工具层', '90 个 YAML 工具配方 + MCP Server（stdio）+ 工具权限控制', ACCENT),
    ('⑤ 数据与安全', 'SQLite 持久化 · RBAC 鉴权 · HITL 审批 · 审计脱敏 · CORS 白名单', WARN),
]
for i, (t, body, ac) in enumerate(layers):
    y = Inches(2.0 + i * 0.92)
    rect(s, Inches(0.7), y, Inches(11.9), Inches(0.78), fill=PANEL, line=LINE)
    rect(s, Inches(0.7), y, Inches(0.06), Inches(0.78), fill=ac)
    text(s, Inches(0.95), y + Inches(0.08), Inches(3.2), Inches(0.5),
         [(t, {'size': 16, 'bold': True, 'color': INK})])
    text(s, Inches(4.3), y + Inches(0.13), Inches(8), Inches(0.5),
         [(body, {'size': 13, 'color': MUTED})])
    if i < 4:
        text(s, Inches(6.3), y + Inches(0.75), Inches(6), Inches(0.3),
             [('▼', {'size': 14, 'color': ACCENT, 'align': PP_ALIGN.CENTER})])
footer(s, 5)

# ══════════════════════════════════════════════════════════
# P6 三层编排
# ══════════════════════════════════════════════════════════
s = add_slide()
bg(s)
tag(s, Inches(0.7), Inches(0.6), 'ORCHESTRATION', ACCENT)
text(s, Inches(0.7), Inches(1.0), Inches(11), Inches(0.8), [('自主决策：三种编排模式支撑不同复杂度', {'size': 30, 'bold': True})])
modes = [
    ('Deep Agent', '单 Agent 深度推理', ['循环调用工具直至达成目标', '适合单点高难任务（如密码破解）', '事件循环复用，状态一致'], ACCENT),
    ('Plan-Execute', '规划-执行-再规划', ['Planner 拆解步骤 → Executor 执行 → Replanner 纠偏', '带模型输入估算（telemetry）', '适合多阶段攻击链（侦察→利用→提权）'], ACCENT2),
    ('Supervisor', '监督者协作', ['监督 Agent 调度多个子 Agent', '任务分发 + 结果聚合', '适合并行侦察与全链路推演'], WARN),
]
for i, (t, sub, lines, ac) in enumerate(modes):
    x = Inches(0.7 + i * 4.05)
    rect(s, x, Inches(2.0), Inches(3.75), Inches(4.3), fill=PANEL, line=LINE)
    rect(s, x, Inches(2.0), Inches(3.75), Inches(0.06), fill=ac)
    text(s, x + Inches(0.25), Inches(2.25), Inches(3.2), Inches(0.5),
         [(t, {'size': 19, 'bold': True, 'color': ac})])
    text(s, x + Inches(0.25), Inches(2.75), Inches(3.2), Inches(0.4),
         [(sub, {'size': 13, 'color': MUTED})])
    body = [(ln, {'size': 13, 'color': INK, 'ls': 1.3, 'sa': 8}) for ln in lines]
    text(s, x + Inches(0.25), Inches(3.3), Inches(3.2), Inches(2.6), body)
text(s, Inches(0.7), Inches(6.5), Inches(11.6), Inches(0.5),
     [('编排器按任务复杂度自动选择模式——简单任务走 Deep，攻击链走 Plan-Execute，并行侦察走 Supervisor', {'size': 13, 'color': MUTED})])
footer(s, 6)

# ══════════════════════════════════════════════════════════
# P7 通用性：91 工具 18 Agent
# ══════════════════════════════════════════════════════════
s = add_slide()
bg(s)
tag(s, Inches(0.7), Inches(0.6), 'GENERALITY', ACCENT2)
text(s, Inches(0.7), Inches(1.0), Inches(11), Inches(0.8), [('通用性：91 工具 × 18 Agent × 全链路覆盖', {'size': 30, 'bold': True})])
stats = [('90', 'YAML 工具配方', ACCENT), ('18', '角色化 Agent', ACCENT2), ('23', '技能包', WARN), ('3', '编排模式', ACCENT)]
for i, (v, lb, c) in enumerate(stats):
    stat(s, Inches(0.7 + i * 3.05), Inches(2.0), Inches(2.75), v, lb, color=c)
cats = [
    ('网络扫描', 'Nmap / Masscan / DNS 枚举'), ('Web 应用', 'SQLi / XSS / 目录爆破'),
    ('漏洞利用', 'PoC 调度 / Exploit 链'), ('云安全', '云资产 / 权限检测'),
    ('二进制分析', 'strings / 反编译 / 沙箱'), ('取证后渗透', '内存取证 / 痕迹清理'),
    ('密码破解', '字典 / 规则爆破'), ('容器安全', '镜像扫描 / 逃逸检测'),
]
for i, (t, body) in enumerate(cats):
    x = Inches(0.7 + (i % 4) * 3.05)
    y = Inches(3.5 + (i // 4) * 1.55)
    rect(s, x, y, Inches(2.75), Inches(1.35), fill=PANEL2, line=LINE)
    text(s, x + Inches(0.15), y + Inches(0.12), Inches(2.4), Inches(0.4),
         [(t, {'size': 14, 'bold': True, 'color': ACCENT})])
    text(s, x + Inches(0.15), y + Inches(0.52), Inches(2.4), Inches(0.7),
         [(body, {'size': 11, 'color': MUTED, 'ls': 1.25})])
footer(s, 7)

# ══════════════════════════════════════════════════════════
# P8 人机协同
# ══════════════════════════════════════════════════════════
s = add_slide()
bg(s)
tag(s, Inches(0.7), Inches(0.6), 'HITL & AUDIT', WARN)
text(s, Inches(0.7), Inches(1.0), Inches(11), Inches(0.8), [('人机协同：敏感操作审批 + 全链路可审计', {'size': 30, 'bold': True})])
feats = [
    ('HITL 人工审批', '危险操作（命令执行/提权/数据删除）进入审批队列，带倒计时与拒绝机制，前端实时呈现', ACCENT),
    ('工具白名单', '按角色控制工具可用范围，未授权工具调用被拒绝', ACCENT2),
    ('审计 Agent 复核', '审计 Agent 独立复核执行证据，与 HITL 桥接（c2_hitl_bridge）', WARN),
    ('全链路审计', '每次操作写入审计账本：调用链 / 证据 / 脱敏日志，可回放可导出', ACCENT),
]
for i, (t, body, ac) in enumerate(feats):
    x = Inches(0.7 + (i % 2) * 6.0)
    y = Inches(2.0 + (i // 2) * 1.9)
    card(s, x, y, Inches(5.7), Inches(1.7), t, [body], accent=ac)
text(s, Inches(0.7), Inches(6.1), Inches(11.6), Inches(0.6),
     [('安全卖点：AI 自主 + 人类可控——评审最关心的「失控风险」用工程机制兜底', {'size': 14, 'bold': True, 'color': WARN})])
footer(s, 8)

# ══════════════════════════════════════════════════════════
# P9 离线自主决策
# ══════════════════════════════════════════════════════════
s = add_slide()
bg(s)
tag(s, Inches(0.7), Inches(0.6), 'OFFLINE AI', ACCENT)
text(s, Inches(0.7), Inches(1.0), Inches(11), Inches(0.8), [('离线自主决策：笔记本也能跑的 AI 安全平台', {'size': 30, 'bold': True})])
text(s, Inches(0.7), Inches(1.9), Inches(11.6), Inches(0.6),
     [('不依赖云端算力，适配学生笔记本本地部署——演示现场不翻车', {'size': 15, 'color': MUTED})])
points = [
    ('环境自适应', '自动识别靶场类型（Linux / Windows / Web / 云），切换对应工具集'),
    ('上下文黑板', '前序 Agent 输出写入共享事实黑板，后续步骤动态调整'),
    ('模型韧性', 'LLM 通道失败自动降级，规则兜底保证对抗不中断'),
    ('国内模型接入', 'Qwen 等国内备案大模型，经安全网关接入（符合赛题合规要求）'),
]
for i, (t, body) in enumerate(points):
    y = Inches(2.6 + i * 0.95)
    rect(s, Inches(0.7), y, Inches(11.9), Inches(0.8), fill=PANEL, line=LINE)
    text(s, Inches(1.0), y + Inches(0.1), Inches(3.5), Inches(0.5),
         [(t, {'size': 16, 'bold': True, 'color': ACCENT})])
    text(s, Inches(4.6), y + Inches(0.13), Inches(7.6), Inches(0.5),
         [(body, {'size': 13, 'color': MUTED})])
footer(s, 9)

# ══════════════════════════════════════════════════════════
# P10 创新点 1
# ══════════════════════════════════════════════════════════
s = add_slide()
bg(s)
tag(s, Inches(0.7), Inches(0.6), 'INNOVATION 01', ACCENT)
text(s, Inches(0.7), Inches(1.0), Inches(11), Inches(0.8), [('创新点一：三层多智能体编排——「按复杂度自动选型」', {'size': 30, 'bold': True})])
text(s, Inches(0.7), Inches(1.9), Inches(11.6), Inches(1.0),
     [('现有方案大多「单 Agent 一条道走到黑」或「固定编排」。我们让编排器按任务复杂度', {'size': 15, 'color': MUTED, 'ls': 1.4}),
      ('自动选择 Deep / Plan-Execute / Supervisor，兼顾效率与成功率。', {'size': 15, 'color': MUTED, 'ls': 1.4})])
card(s, Inches(0.7), Inches(3.1), Inches(11.9), Inches(1.5),
     '为什么新？',
     ['· 简单任务（单点工具调用）→ Deep：避免编排开销', '· 多阶段攻击链 → Plan-Execute：Planner/Executor/Replanner 闭环纠偏',
      '· 并行侦察 → Supervisor：任务分发 + 结果聚合'], accent=ACCENT)
card(s, Inches(0.7), Inches(4.9), Inches(11.9), Inches(1.5),
     '工程落地',
     ['· 基于 cloudwego/eino 编排框架，事件循环复用保证状态一致', '· 带模型输入估算 telemetry：成本可见可控',
      '· 模型韧性：通道失败自动降级，对抗不中断'], accent=ACCENT2)
footer(s, 10)

# ══════════════════════════════════════════════════════════
# P11 创新点 2
# ══════════════════════════════════════════════════════════
s = add_slide()
bg(s)
tag(s, Inches(0.7), Inches(0.6), 'INNOVATION 02', ACCENT2)
text(s, Inches(0.7), Inches(1.0), Inches(11), Inches(0.8), [('创新点二：91 工具 × 18 Agent 的「全链路通用对抗」', {'size': 30, 'bold': True})])
text(s, Inches(0.7), Inches(1.9), Inches(11.6), Inches(0.9),
     [('安全工具碎片化是行业痛点——Nmap 在命令行、Burp 在 GUI、脚本各写各的。', {'size': 15, 'color': MUTED, 'ls': 1.4}),
      ('我们统一为 90 个 YAML 工具配方 + MCP 协议，Agent 可编排调用、上下文共享。', {'size': 15, 'color': MUTED, 'ls': 1.4})])
card(s, Inches(0.7), Inches(3.0), Inches(5.85), Inches(3.2),
     '工具层创新',
     ['· 100+ YAML 配方：网络/Web/漏洞/云/容器/二进制/取证/后渗透全覆盖', '· 自定义扩展：写 YAML 即可接入新工具，无需改代码',
      '· MCP Server：stdio 接入，兼容通用 Agent 生态', '· 按角色控制工具可用范围（RBAC 资源授权）'], accent=ACCENT2)
card(s, Inches(6.75), Inches(3.0), Inches(5.85), Inches(3.2),
     'Agent 层创新',
     ['· 18 个场景角色：侦察/渗透/横向/提权/取证/复盘……', '· 角色-工具映射：每个角色只看到自己该用的工具',
      '· 事实黑板：跨 Agent 传递上下文，避免重复侦察', '· 审计 Agent 独立复核：执行证据闭环'], accent=ACCENT)
footer(s, 11)

# ══════════════════════════════════════════════════════════
# P12 创新点 3
# ══════════════════════════════════════════════════════════
s = add_slide()
bg(s)
tag(s, Inches(0.7), Inches(0.6), 'INNOVATION 03', WARN)
text(s, Inches(0.7), Inches(1.0), Inches(11), Inches(0.8), [('创新点三：HITL 审批 × 全链路审计——「AI 自主、人类可控」', {'size': 30, 'bold': True})])
text(s, Inches(0.7), Inches(1.9), Inches(11.6), Inches(0.9),
     [('自主决策 ≠ 放任自流。我们对危险操作做工程级兜底：', {'size': 15, 'color': MUTED, 'ls': 1.4}),
      ('敏感操作 HITL 审批 + 审计 Agent 复核 + 工具白名单 + 全链路证据留存。', {'size': 15, 'bold': True, 'color': WARN, 'ls': 1.4})])
card(s, Inches(0.7), Inches(3.0), Inches(5.85), Inches(3.2),
     '机制设计',
     ['· 危险操作（命令执行/提权/删除）进审批队列，带倒计时与拒绝', '· c2_hitl_bridge：C2 会话与审批流桥接，前端实时呈现',
      '· 工具白名单 + 权限校验：越权调用被拒绝并记录', '· 审计脱敏：敏感信息不入日志，证据可回放'], accent=WARN)
card(s, Inches(6.75), Inches(3.0), Inches(5.85), Inches(3.2),
     '为什么评审加分',
     ['· 回应赛题「可控性」硬指标：AI 决策 + 人工兜底', '· 可演示：审批弹窗 → 拒绝 → 审计记录，全流程可视化',
      '· 区别于「黑盒 Agent」：每个动作都有证据链', '· 合规：国内模型 + 数据脱敏 + 操作留痕'], accent=ACCENT2)
footer(s, 12)

# ══════════════════════════════════════════════════════════
# P13 实测验证
# ══════════════════════════════════════════════════════════
s = add_slide()
bg(s)
tag(s, Inches(0.7), Inches(0.6), 'VERIFICATION', ACCENT)
text(s, Inches(0.7), Inches(1.0), Inches(11), Inches(0.8), [('实测验证：工程全绿 + CTF 能力基准双语言机验', {'size': 30, 'bold': True})])
text(s, Inches(0.7), Inches(1.8), Inches(11.6), Inches(0.5),
     [('（2026-09-08 实测：Go 1.25.0，全部为磁盘实测数据，每个数字均有脚本 + JSON 证据可复跑）', {'size': 13, 'color': MUTED})])
stats = [('0', '编译错误（126,651 行）', ACCENT), ('176', '确定性求解器', ACCENT), ('34.5%', '静态 55 真题命中（19 题）', ACCENT2), ('100%', '执行基准 17/17 · Web 10/10', WARN)]
for i, (v, lb, c) in enumerate(stats):
    stat(s, Inches(0.7 + i * 3.05), Inches(2.4), Inches(2.75), v, lb, color=c)
rows = [
    ('go build ./...', '全量编译零错误（退出码 0 / 0 输出）', ACCENT),
    ('go test ./...', '核心包全绿：multiagent 15.6s · database 5.4s · attackchain 4.5s', ACCENT),
    ('系统启动', 'go run --http 启动成功，GET / → 200，服务正常监听，登录 API 可达', ACCENT2),
    ('CTF 静态基准', '55 道真题 19 命中 = 34.5%（TestRealBenchmark_ShippedPresolve == Python judge.py）', ACCENT),
    ('CTF 执行基准', '执行 17/17=100%（取证/密码攻击）· Web 靶场 10/10 · JWT 绕过 3/3 · 附件取证 10/10', ACCENT2),
    ('工程卫生', '0 panic · 0 处 TODO · 279 测试文件 · 33 个 internal 包 · CORS/参数化/审计脱敏', WARN),
]
for i, (t, body, ac) in enumerate(rows):
    y = Inches(3.8 + i * 0.55)
    rect(s, Inches(0.7), y, Inches(2.9), Inches(0.42), fill=PANEL2, line=LINE)
    text(s, Inches(0.85), y + Inches(0.06), Inches(2.7), Inches(0.3),
         [(t, {'size': 12, 'bold': True, 'color': ac})])
    rect(s, Inches(3.7), y, Inches(8.9), Inches(0.42), fill=PANEL, line=LINE)
    text(s, Inches(3.85), y + Inches(0.06), Inches(8.6), Inches(0.3),
         [(body, {'size': 12, 'color': MUTED})])
footer(s, 13)

# ══════════════════════════════════════════════════════════
# P14 评分对照
# ══════════════════════════════════════════════════════════
s = add_slide()
bg(s)
tag(s, Inches(0.7), Inches(0.6), 'SCORING', ACCENT2)
text(s, Inches(0.7), Inches(1.0), Inches(11), Inches(0.8), [('与评分标准逐项对照', {'size': 30, 'bold': True})])
crit = [
    ('自主决策能力', '三层编排 · 事实黑板 · 执行基准 17/17=100% · Web 靶场 10/10', '★★★★★'),
    ('智能体通用性', '143 运行时工具 · 18 Agent · 23 技能包 · 176 求解器 · MCP 生态', '★★★★★'),
    ('可控性与安全', 'HITL 审批 · 工具白名单 · 审计复核 · 全链路证据', '★★★★★'),
    ('工程完整度', '126,651 行 Go · 279 测试 · 0 panic · 静态真题 34.5% 双语言机验', '★★★★★'),
    ('合规与部署', '国内模型接入 · 云上一键部署 · 审计留痕', '★★★★☆'),
    ('创新性', '三模式编排选型 · 事实黑板 · C2-HITL 桥接', '★★★★★'),
]
for i, (t, body, stars) in enumerate(crit):
    y = Inches(2.0 + i * 0.85)
    rect(s, Inches(0.7), y, Inches(11.9), Inches(0.72), fill=PANEL, line=LINE)
    text(s, Inches(1.0), y + Inches(0.12), Inches(3.2), Inches(0.4),
         [(t, {'size': 15, 'bold': True, 'color': INK})])
    text(s, Inches(4.4), y + Inches(0.15), Inches(5.8), Inches(0.4),
         [(body, {'size': 12, 'color': MUTED})])
    text(s, Inches(10.4), y + Inches(0.12), Inches(2.0), Inches(0.4),
         [(stars, {'size': 14, 'bold': True, 'color': WARN, 'align': PP_ALIGN.RIGHT})])
footer(s, 14)

# ══════════════════════════════════════════════════════════
# P15 部署
# ══════════════════════════════════════════════════════════
s = add_slide()
bg(s)
tag(s, Inches(0.7), Inches(0.6), 'DEPLOYMENT', ACCENT)
text(s, Inches(0.7), Inches(1.0), Inches(11), Inches(0.8), [('部署：云上一键跑起来', {'size': 30, 'bold': True})])
steps = [
    ('1', '准备环境', 'Go 1.22+ / 可选 Docker，下载分发包'),
    ('2', '配置 AI 通道', 'config.yaml 注入国内备案模型 Key（Qwen 等）'),
    ('3', '一键启动', './secautomind-ai --http 或 docker compose up'),
    ('4', '初始化', '首次启动生成 admin 初始密码，登录后修改'),
    ('5', '开始对抗', '创建会话 → 配置靶场 → 编排器自主推演'),
]
for i, (n, t, body) in enumerate(steps):
    y = Inches(2.0 + i * 0.92)
    rect(s, Inches(0.7), y, Inches(11.9), Inches(0.78), fill=PANEL, line=LINE)
    from pptx.enum.shapes import MSO_SHAPE
    circ = s.shapes.add_shape(MSO_SHAPE.OVAL, Inches(0.95), y + Inches(0.15), Inches(0.5), Inches(0.5))
    circ.fill.solid()
    circ.fill.fore_color.rgb = ACCENT
    circ.line.fill.background()
    tf = circ.text_frame
    p = tf.paragraphs[0]
    p.alignment = PP_ALIGN.CENTER
    r = p.add_run(); r.text = n
    r.font.size = Pt(14); r.font.bold = True; r.font.color.rgb = BG
    text(s, Inches(1.8), y + Inches(0.08), Inches(3.0), Inches(0.5),
         [(t, {'size': 15, 'bold': True, 'color': INK})])
    text(s, Inches(5.0), y + Inches(0.13), Inches(7.3), Inches(0.5),
         [(body, {'size': 12, 'color': MUTED})])
text(s, Inches(0.7), Inches(6.7), Inches(11.6), Inches(0.4),
     [('支持腾讯轻量云一键部署：无需 GPU，CPU 即可运行（离线自主决策的实战价值）', {'size': 13, 'bold': True, 'color': ACCENT})])
footer(s, 15)

# ══════════════════════════════════════════════════════════
# P16 应用场景
# ══════════════════════════════════════════════════════════
s = add_slide()
bg(s)
tag(s, Inches(0.7), Inches(0.6), 'SCENARIOS', ACCENT2)
text(s, Inches(0.7), Inches(1.0), Inches(11), Inches(0.8), [('适用场景', {'size': 30, 'bold': True})])
sc = [
    ('高校网络攻防教学', '自动化对抗推演 + 标准化复盘报告，辅助课程评分'),
    ('安全竞赛训练', 'CTF / AWD 场景快速搭建，多 Agent 模拟真实攻防'),
    ('企业安全评估', '自动化渗透测试流程 + HITL 人工审批，合规可控'),
    ('安全运营演练', '告警研判 + 攻击链还原 + 应急处置编排'),
]
for i, (t, body) in enumerate(sc):
    x = Inches(0.7 + (i % 2) * 6.0)
    y = Inches(2.0 + (i // 2) * 1.9)
    card(s, x, y, Inches(5.7), Inches(1.7), t, [body], accent=ACCENT2 if i % 2 == 0 else ACCENT)
footer(s, 16)

# ══════════════════════════════════════════════════════════
# P17 总结展望
# ══════════════════════════════════════════════════════════
s = add_slide()
bg(s)
tag(s, Inches(0.7), Inches(0.6), 'SUMMARY', ACCENT)
text(s, Inches(0.7), Inches(1.0), Inches(11), Inches(0.8), [('总结与展望', {'size': 30, 'bold': True})])
summary = [
    ('做了什么', '3 层编排 × 91 工具 × 18 Agent 的自主决策攻防推演平台，编译零错误、核心测试全绿、系统实启动'),
    ('技术创新', '按复杂度自动选型的三模式编排 · 事实黑板上下文共享 · C2-HITL 审批桥 · 离线自主决策'),
    ('工程证明', '126,651 行 Go · 279 测试 · 0 panic · 33 包分层 · CTF 能力基准：静态 34.5% / 执行 100% / Web 100%（双语言机验）'),
    ('未来展望', '接入更多国内模型 · 扩工具生态（社区 YAML）· 多靶场联动 · 智能体自学习（攻击链记忆）'),
]
for i, (t, body) in enumerate(summary):
    y = Inches(2.0 + i * 1.15)
    rect(s, Inches(0.7), y, Inches(2.2), Inches(1.0), fill=PANEL2, line=LINE)
    text(s, Inches(0.85), y + Inches(0.3), Inches(1.9), Inches(0.4),
         [(t, {'size': 15, 'bold': True, 'color': ACCENT, 'align': PP_ALIGN.CENTER})])
    rect(s, Inches(3.0), y, Inches(9.6), Inches(1.0), fill=PANEL, line=LINE)
    text(s, Inches(3.25), y + Inches(0.1), Inches(9.0), Inches(0.8),
         [(body, {'size': 13, 'color': MUTED, 'ls': 1.3})])
footer(s, 17)

# ══════════════════════════════════════════════════════════
# P18 封底
# ══════════════════════════════════════════════════════════
s = add_slide()
bg(s)
text(s, Inches(1), Inches(2.5), Inches(11), Inches(1.0),
     [('谢谢聆听 · 欢迎指正', {'size': 44, 'bold': True, 'color': INK, 'align': PP_ALIGN.CENTER})])
text(s, Inches(1), Inches(3.7), Inches(11), Inches(0.6),
     [('SecAutoMind —— 让 AI 安全智能体真正「自主、通用、可控」', {'size': 18, 'color': ACCENT, 'align': PP_ALIGN.CENTER})])
rect(s, Inches(5.5), Inches(4.6), Inches(2.3), Inches(0.015), fill=LINE)
text(s, Inches(1), Inches(4.9), Inches(11), Inches(0.5),
     [('2026 Challenge Cup · XH-202609 · 安恒信息揭榜挂帅', {'size': 13, 'color': MUTED, 'align': PP_ALIGN.CENTER})])
footer(s, 18)

# ── 保存 ──
OUT = r'E:/Program/2026挑战杯：SecAutoMind-v1.7.17-share/SecAutoMind_PPT/SecAutoMind_参赛答辩_冲击冠军版.pptx'
prs.save(OUT)
print(f'✅ 已生成: {OUT}')
print(f'   幻灯片数: {len(prs.slides)}')
