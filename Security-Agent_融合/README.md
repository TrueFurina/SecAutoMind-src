# Security-Agent 融合留存说明

**融合日期**：2026-10-14
**操作人**：AI 协助（仅复制，未删除任何源文件）

## 为什么有这个目录
挑战杯（揭榜挂帅专项赛 XH-202609）**只能提交一个作品**。已确定以 **SecAutoMind** 作为唯一提交作品，
**Security-Agent 不再作为独立作品**。为在源文件夹被手动删除前不丢失其成果，将 Security-Agent 的
提交材料、源码与文档**整体复制留存**于本目录（位于 SecAutoMind 仓库内）。

> 原文件夹 `E:\Program\2026挑战杯：Security-Agent-安全事件研判智能体\` 由用户**手动删除**，
> 本目录即其留存的唯一副本。

## 目录内容
| 子目录 | 来源 | 说明 |
|---|---|---|
| `submission/` | Security-Agent/submission/ | 提交材料包：程序材料(Dockerfile/部署手册)、技术报告.md、方案介绍PPT.pptx、演示视频分镜脚本.md、原创性及保密性声明.md（空白模板） |
| `security_agent/` | Security-Agent/security_agent/ | 源码（106 文件 / 43 .py），Python + LLM 架构 |
| `docs/` | Security-Agent/docs/ | 架构/使用/测试等文档（21 篇） |
| `reports/` | Security-Agent/reports/ | 评测报告等 |
| `root_files/` | Security-Agent 根级关键文件 | GOAL_PROMPT.md / HANDOVER.md / todo.md / README* / SECURITY.md / pyproject.toml / test_ai.py / XH-202614 研究 PDF |

## 融合消费清单（2026-11-01 立项）

> **定性已变更**：上节「仅为留存、非整合」写于 2026-10-14，**已过期**。
> 2026-11-01 用户明确要求「这个也要融合本项目，因为决赛要比拼 CTF」。
> 判据沿用本仓既有标准（见 `CTF-Agent_融合/_MIGRATION_NOTES.md`）：
> **迁过去必须有人消费** —— 每一项都要给出消费点，不是搬仓库。

### 已消费（代码级落地，有测试）

| 来源 | 落点 | 消费点 | 提交 |
|---|---|---|---|
| `ai/client.py::DEFAULT_MAX_OUTPUT_TOKENS` 的实测下限 8000 | `internal/runnerl3/llm_solver.go` `maxOutTokens` | L3 每轮 `WithMaxTokens`。原值 4096 被 reasoning 吃掉大半，正文可能空/半截 | `ee19bf0` |
| `ai/client.py::_log_empty_response` 的两类分流 | `internal/runnerl3/llm_solver.go` 空响应诊断 + `SolveOutcome.Truncated` | 把「被预算截断」与「模型不会」在报告里分开；此前 `finish_reason` 全仓零读取 | `1709887` |

两条都有变异验证（共 5 个变异，全部能打红）。

### 待消费（有明确收益，尚未动）

| 来源 | 可消费的东西 | 为什么值得 |
|---|---|---|
| `docs/GENERALIZATION_AUDIT.md` 的 v1/v2/v3 三集分离 | **冻结 holdout 方法**：v1/v2 暴露根因后即转为开发集，v3 只跑一次、无论好坏直接计入 | 本项目目前只有 1 道 heldout 真题，`real_benchmark.json` 55 题已被调参、外部池 16/40 可下载真值 ⇒ 手上没有任何可信泛化数字。这套三集分离是现成模板 |
| 同上 §5.2「评测不幂等」 | **写隔离 + 读隔离同处一个实现**（它第二次才想明白：只关写不够，存量记忆仍会被读回注入） | 对照检查用：本项目 `runnerl3` 已确认无记忆/历史注入（grep `memory\|history` 零命中），但**这是"没查过"而不是"查过没问题"** —— 该结论应落到可复现的检查脚本上 |
| 同上 §5.4「跨事件共享键该怎么分类」 | 判据：哪些共享键必须隔离、哪些可以复用 | 外部池 40 题共用附件目录、共用 `/tmp` 收件箱，正需要这条判据 |

### 不消费（明确列出，防止下次会话重复调研）

| 模块 | 规模 | 不消费理由 |
|---|---|---|
| `tools/implementations.py` | 462 行 | 11 个工具里 9 个是 SOC 专用（资产画像/日志检索/情报/工单/剧本/主机隔离），CTF 解题用不上 |
| `prefilter/engine.py` | 715 行 | 三态预筛（AUTO_CLOSE / AUTO_ESCALATE / NEED_LLM）本项目已有等价物：L2 确定性 skill 路由命中即止、miss 才进 L3 |
| `agent/orchestrator.py` + `agents/impl.py` | 937 行 | 四段流水线（Planner→Classifier→Triage→Reviewer）绑定 SOC 事件模型；其中 Reviewer「预筛确定性结论直接采纳」的原则本项目已按同样方式实现 |
| `web/server.py`、`reporting/render.py` | 1530 行 | Web 面板与报告渲染，对解题零贡献 |
| `ai/triage.py` | 947 行 | 研判提示词与评分 rubric 是 SOC 域（误报/风险等级），CTF 的判据是 sha256，不需要 rubric |
| 模式 5「JSON fence-stripping」 | — | 本项目 flag 提取走正则（`extractFlagCandidates`），不解析 JSON，fence 不影响 |
| 模式 12「Critic Agent 对抗验证」 | — | CTF 有客观真值，`sha256` 比对比任何 critic 评分都硬；加 critic 只会多烧 token |

### 本轮顺带查出的本项目缺陷（不属融合，但同期发现）

**`temperature` 从未设置**：`internal/runnerl3/llm_solver.go` 两处 `ChatModelConfig`
只给了 APIKey/BaseURL/Model，走 provider 默认（DeepSeek 默认 1.0）。
后果：同题同模型两次跑必然不同 —— 这解释了此前未解释的方差
（Primes 300.0s / `candidates_suppressed` vs 复跑 54.3s / `answer_wrong`），
也意味着**此前所有单次跑批数字都不可复现**。

⚠️ 不贸然改的原因：`deepseek-reasoner` 一类推理模型对 `temperature` 支持不一致，
设错可能导致请求直接失败。要做成默认关闭的可选开关，且必须真机先验证 provider 接受。

## 边界
- **未删除任何源文件**：删除原 Security-Agent 文件夹由用户手动执行。
- **未做整体移植**：只按「有消费点」逐项取用（见上表），Python 源码不并入 Go 主树。
- 本目录的源码仍只作为**判据与经验的来源**，不是运行依赖。

## 随 Security-Agent 带过来的两个已知缺口（供后续决策）
1. **演示视频 .mp4 缺失**：原 Security-Agent 仅有「演示视频分镜脚本.md」，从未录制实际视频。
2. **声明函为空白模板**：`submission/03_声明函/原创性及保密性声明.md` 的【学校全称】/【手机号】/签字/盖章均未填。

若后续要把 Security-Agent 的叙事并入 SecAutoMind 单一提交，这两项需另行补齐。
