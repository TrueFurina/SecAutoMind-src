# -*- coding: utf-8 -*-
"""SecAutoMind 集大成版 PPT · 第 10 页（HITL 页）纯文本替换。

约束（用户指令）：保留前两页、仅替换文字不动视觉样式、新字数贴近原文避免溢出。
实现：直接编辑 .pptx 既有 run 的 .text，字体/配色/版式/位置全部保留；slide 1-2 不动。

替换依据（均事实可溯源）：
1. risk_policy.yaml 已接入 Go HITL 闸门（本会话完成）：LoadRiskPolicy 启动加载，
   shouldInterrupt 以 90 工具每工具 hitl 字段为权威敏感度源 → 见 right/left 卡对应改写。
2. 整改补充_20260905：实测决策链含 2 次自动审批拒绝，拒绝后 Agent 自动降级安全工具
   完成任务（证据 hitl_rejected ×2）→ 见 left 卡拒绝机制改写。
"""
from pptx import Presentation
import copy

SRC = "SecAutoMind_参赛答辩_集大成版.pptx"

# (slide_index_0based, shape_index, para_index, run_index, old_text, new_text)
# 全部取自 dump 实测，old 必须精确匹配
EDITS = [
    # slide 10 (idx 9), left HITL card (shape 7), 拒绝机制子行
    (9, 7, 0, 3,
     "    带倒计时，超时自动挂起（防失控）",
     "    实测 2 次自动拒绝后降级安全工具"),
    # slide 10 (idx 9), left HITL card (shape 7), 白名单校验子行 → 加 risk_policy 驱动
    (9, 7, 0, 5,
     "    调用前校验 + 权限点二次拦截",
     "    风险策略文件驱动 90 工具判定"),
]

p = Presentation(SRC)
made = 0
for sidx, shidx, pidx, ridx, old, new in EDITS:
    s = p.slides[sidx]
    sh = s.shapes[shidx]
    tf = sh.text_frame
    para = tf.paragraphs[pidx]
    run = para.runs[ridx]
    cur = run.text
    assert cur == old, f"MISMATCH slide{sidx+1} sh{shidx} p{pidx} r{ridx}: got {cur!r} expected {old!r}"
    run.text = new
    made += 1
    print(f"[ok] slide{sidx+1} sh{shidx} p{pidx} r{ridx}: {old!r} -> {new!r} (len {len(old)}->{len(new)})")

p.save(SRC)
print(f"\n保存完成，共替换 {made} 处。文件: {SRC}")
