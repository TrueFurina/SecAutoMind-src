"""监督反思 Agent：轻量模型，战略判断，不直接解题。

v2.0 架构核心之二：只做一件事——每步执行后判断方向对不对。
- 输入：结构化步骤摘要（不是原始日志）
- 输出：裁决 verdict：continue / redirect / switch_strategy / upgrade_model / give_up
- 轻量模型实现（默认用 config.light_model 动态——不硬编码旧模型名），降低 token 消耗

触发策略（由 MainAgent 控制）：
- 每 2-3 步咨询一次
- 连续失败 2 次强制咨询
"""

from __future__ import annotations

import logging
from typing import Optional

logger = logging.getLogger(__name__)

# ── 环境归因硬闸（2026-11-11 ext47 实证事故的代码级防线）──────────────
# 只加提示词不够：观察文本里本来就可能带着主 Agent 自写的「工具不可用」，
# 监督 LLM 顺着它把失败推给环境。这里做输出侧过滤——命中即视为无效裁决，
# 该次咨询退回确定性规则/默认继续，绝不让"环境坏了"的结论进入主循环。
#
# 判定口径：监督者只有步骤摘要，没有注册表与容器依赖清单，任何关于
# 工具/依赖可用性的断言都属越权推断，一律作废。
_ENV_BLAME_PATTERNS = (
    "工具不可用", "工具不存在", "工具缺失", "找不到工具", "工具未注册",
    "环境问题", "环境缺", "环境故障", "环境异常", "依赖缺失", "缺依赖",
    "镜像里没有", "容器里没有", "tool unavailable", "tool not found",
    "environment issue", "missing dependency",
)


def _has_env_blame(text: str) -> bool:
    """文本是否包含越权的环境归因断言。"""
    if not text:
        return False
    low = str(text).lower()
    return any(p.lower() in low for p in _ENV_BLAME_PATTERNS)

from core.main_agent import (
    ERR_TOOL_FAILURE,
    VERDICT_CONTINUE,
    VERDICT_GIVE_UP,
    VERDICT_REDIRECT,
    VERDICT_SWITCH,
    VERDICT_UPGRADE,
    AgentContext,
    SupervisionVerdict,
)


class SupervisorAgent:
    """监督反思 Agent：轻量模型裁决 + 确定性规则兜底。"""

    def __init__(self, llm_client=None):
        """
        Args:
            llm_client: 可选 callable(system, user, attempt) -> str|dict，
                        未提供时使用 llm.client（轻量模型）并配合确定性规则兜底。
        """
        self.llm_client = llm_client

    async def review(self, ctx: AgentContext) -> SupervisionVerdict:
        """对当前上下文做出监督裁决。"""
        # ── 第一优先：确定性规则（0 token，稳定可靠）──
        rule_verdict = self._rule_based_review(ctx)
        if rule_verdict is not None:
            return rule_verdict

        # ── 第二优先：轻量模型裁决 ──
        llm_verdict = await self._llm_review(ctx)
        if llm_verdict is not None:
            return llm_verdict

        # ── 兜底：继续 ──
        return SupervisionVerdict(action=VERDICT_CONTINUE, reason="监督无法判定，默认继续")

    # ── 确定性规则（0 token，先行）──────────────────────

    def _rule_based_review(self, ctx: AgentContext) -> Optional[SupervisionVerdict]:
        steps = ctx.steps
        if not steps:
            return None

        # 规则 1：工具连续失败 ≥2 次 → 换策略
        tool_failures = sum(
            1 for s in steps[-3:] if s.error_category == ERR_TOOL_FAILURE
        )
        if tool_failures >= 2:
            return SupervisionVerdict(
                action=VERDICT_SWITCH,
                reason=f"工具连续失败 {tool_failures} 次",
                suggestion="更换工具或改用脚本方式绕过",
            )

        # 规则 2：同一动作重复 ≥3 次 → 死循环
        if len(steps) >= 3:
            recent_actions = [s.action for s in steps[-3:]]
            if len(set(recent_actions)) == 1:
                return SupervisionVerdict(
                    action=VERDICT_REDIRECT,
                    reason=f"检测到死循环: 重复执行 {recent_actions[0]} 3 次",
                    suggestion="换一个完全不同的思路（换工具/换方向/换目标文件）",
                )

        # 规则 3：连续失败 ≥2 次 → 升级模型
        if ctx.stuck_count >= 2:
            try:
                from config import AppConfig
                _heavy = AppConfig.from_env().heavy_model
            except Exception:  # noqa: BLE001
                _heavy = "heavy_model"
            return SupervisionVerdict(
                action=VERDICT_UPGRADE,
                reason=f"连续失败 {ctx.stuck_count} 次",
                suggestion=f"升级到重型模型（{_heavy}）重试",
            )

        # 规则 4：步骤数超限但无进展 → 放弃（防烧钱，根据难度调整阈值）
        # 2026-08-21 修复：12步阈值太低，crypto/pwn/reverse难题经常需要20+步
        _cat = str(getattr(ctx.question, "category", "")).lower()
        _max_steps = 25 if _cat in ("crypto", "pwn", "reverse") else 18
        # 已经升级过模型/切换过策略的话，额外给步骤
        _max_steps += 4 * (ctx.model_upgrades + ctx.strategy_switches)
        if len(steps) >= _max_steps and not ctx.candidate_flag:
            return SupervisionVerdict(
                action=VERDICT_GIVE_UP,
                reason=f"已执行 {len(steps)} 步无进展（上限{_max_steps}）",
                suggestion="记录失败原因，切换到下一题",
            )

        # 规则 5：连续推理但观察为空/无进展（≥3 次）→ 疑似跑偏，
        # 交给轻量模型裁决（专家意见：复杂场景用 AI 反思，规则识别不了）
        if len(steps) >= 3:
            recent_reason_empty = sum(
                1 for s in steps[-3:]
                if s.action == "reason" and not s.observation
            )
            if recent_reason_empty >= 2 and not ctx.candidate_flag:
                return None  # 落到 LLM 裁决路径（不直接给结论）

        return None

    # ── 轻量模型裁决 ────────────────────────────────────

    async def _llm_review(self, ctx: AgentContext) -> Optional[SupervisionVerdict]:
        system = (
            "你是 CTF 解题的监督者。只做战略判断，不直接解题。"
            "根据最近的执行步骤判断方向："
            "continue=方向正确继续；redirect=方向偏了需要换思路；"
            "switch_strategy=当前方法失败需换策略；upgrade_model=需更强模型；give_up=放弃此题。"
            "重点关注：模型是否在重复无效推理（观察为空）、是否偏离题目目标、"
            "是否有更高效的攻击路径（如换工具/换思路/先做信息收集）。"
            # ── 工具可用性断言禁令（2026-11-11 实证事故）──
            # ext47 跑批 7 道题里，监督 LLM 反复写「rea_probe 工具不可用属环境问题」，
            # 把「模型没调用该工具」误诊成「环境缺工具」。实测该工具在注册表里
            # （inventory('rev') 第 5 位）、容器内 node 与 rea.mjs 均在、日志工具层
            # 就绪列表也含它，全程无一次真实调用失败。这个误判让失败归因整条链条
            # 都指向错误方向（归因到环境而非模型行为），必须从提示词上堵死。
            "**你无权判断工具可用性**：你看不到工具注册表、看不到容器依赖清单，"
            "因此禁止输出「工具不可用」「工具不存在」「环境问题」「环境缺依赖」"
            "这类结论。步骤里出现[工具:xxx]说明它被用过；出现[无工具]或观察里"
            "声称某工具不可用，一律理解为「模型没有真正调用/没有拿到有效输入」，"
            "归到模型行为（该换工具、该下沉深挖），不得归因到环境。"
            '输出 JSON: {"action": "continue|redirect|switch_strategy|upgrade_model|give_up", '
            '"reason": "一句话原因", "suggestion": "明确修正方向"}。'
            "若不确定，选 continue，不要随意放弃。"
        )
        user = self._build_review_prompt(ctx)
        result = await self._llm_json(system, user)
        if not result:
            return None
        action = str(result.get("action", VERDICT_CONTINUE))
        if action not in (VERDICT_CONTINUE, VERDICT_REDIRECT, VERDICT_SWITCH,
                          VERDICT_UPGRADE, VERDICT_GIVE_UP):
            action = VERDICT_CONTINUE
        reason = str(result.get("reason", ""))
        suggestion = str(result.get("suggestion", ""))
        # ── 硬闸：越权环境归因整条作废 ──
        # 监督者看不到注册表/容器依赖，任何「工具不可用/环境问题」的断言都是
        # 越权推断。作废后退回确定性规则路径（review() 的兜底为「默认继续」），
        # 不允许这种结论进入主循环——它会把失败归因整体引向环境而非模型行为。
        if _has_env_blame(reason) or _has_env_blame(suggestion):
            logger.warning(
                "监督 LLM 裁决含越权环境归因，已丢弃: action=%s reason=%s suggestion=%s",
                action, reason[:80], suggestion[:80],
            )
            return None
        logger.info("监督 LLM 裁决: action=%s reason=%s", action, reason)
        return SupervisionVerdict(
            action=action,
            reason=reason,
            suggestion=suggestion,
        )

    async def _llm_json(self, system: str, user: str) -> Optional[dict]:
        if self.llm_client is not None:
            out = await self.llm_client(system, user, 0)
            return out if isinstance(out, dict) else None
        from llm.client import ai_chat_json
        from config import AppConfig

        # P1 修复：模型名由 config 统一（不硬编码 v4-flash——旧模型名在
        # deepseek 端点会失败）
        _cfg = AppConfig.from_env()
        return ai_chat_json([{"role": "user", "content": user}], system=system,
                            model=_cfg.light_model, max_tokens=300)

    def _build_review_prompt(self, ctx: AgentContext) -> str:
        parts = [f"题目: {getattr(ctx.question, 'title', '')}",
                 f"题型: {getattr(ctx.question, 'category', '')}",
                 str(getattr(ctx.question, 'description', '') or '')[:200]]
        if ctx.hint_text:
            parts.append(f"提示: {ctx.hint_text}")
        if ctx.correction:
            corr = ctx.correction
            cparts = ["上一轮错误归因:"]
            if corr.get("error_category"):
                cparts.append(f"  error_category: {corr['error_category']}")
            if corr.get("key_info"):
                cparts.append(f"  key_info: {corr['key_info'][:100]}")
            parts.append("\n".join(cparts))
        if ctx.steps:
            recent = []
            for s in ctx.steps[-5:]:
                err = f" [错误:{s.error_category}]" if s.error_category else ""
                # 2026-08-26 攻 wrong_direction：补工具证据——监督 LLM 需区分
                # "方向对但无工具证据(空转)" vs "方向错"，缺 tool_used 会误判 wrong_direction
                tool = f" [工具:{s.tool_used}]" if s.tool_used else " [无工具]"
                obs = s.observation[:80]
                # 2026-11-11 ext47 事故：观察文本里可能带主 Agent 自写的
                # 「工具不可用」字样，监督 LLM 会顺着它把失败推给环境。
                # 这里把该片段就地标注成因，切断传染路径。
                if _has_env_blame(obs):
                    obs = obs + "（注：此为客户端的自我陈述，非已证实的环境事实；" \
                                "有[工具:xxx]标记即说明该工具被调用过）"
                recent.append(f"- {s.stage} | {s.action}{err}{tool} | {obs}")
            parts.append("最近步骤:\n" + "\n".join(recent))
        parts.append(f"候选 flag: {ctx.candidate_flag or '无'}")
        parts.append(f"策略切换次数: {ctx.strategy_switches}  模型升级次数: {ctx.model_upgrades}")
        return "\n".join(parts)
