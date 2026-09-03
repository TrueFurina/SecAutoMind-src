# SecAutoMind 技术报告

**赛题**：挑战杯"揭榜挂帅" XH-202609《具备自主决策能力的通用网络安全智能体技术研究》
**发榜单位**：杭州安恒信息技术股份有限公司
**作品名称**：SecAutoMind —— 具备自主决策能力的通用网络安全智能体平台
**版本**：v1.7.17（分发包）｜本文档 2026-09-03 版

> 撰写原则：本报告所有工程性陈述均可在仓库中溯源（给出 `internal/`、`tools/`、`agents/`、`docs/` 路径）；未经实测的量化对比一律在 §7 明确标注"待验证"，不虚构数据。

---

## 1. 摘要

SecAutoMind 是一个面向攻防实战与应急响应场景的**通用网络安全智能体平台**。它把"任务理解 → 多智能体编排 → 工具调用 → 决策审计"做成一条可运营链路：Web 管理面 / 8 类 IM 机器人 / OpenAPI 三种入口接收自然语言任务，由 Eino ADK（CloudWeGo）驱动的单代理与三种多代理编排（Deep / Plan-Execute / Supervisor）负责拆解与执行，通过 **90 个 YAML 内置工具 + 外部 MCP 联邦 + 23 个技能包 + 可视化工作流引擎**四层插件化能力池完成动作，全过程支持 HITL 人工审批、推理轨迹流式展示、工具执行监控与平台审计，默认使用国内备案大模型（通义 qwen / DeepSeek），可一键部署于受控环境。

作品以"**通用**"为设计目标：不止覆盖传统渗透测试，还内置应急响应、防护加固、攻击面枚举、漏洞研判、报告整改等 18 个角色化子代理；以"**可信可解释**"为安全基线：决策链（thinking/reasoningChain/planning）全量入审计、高危工具默认经 HITL、凭据仅走环境变量注入；以"**低门槛落地**"为工程基线：单体 Go + SQLite + 静态前端，预编译 150MB 单文件一键启动，零公网回调（机器人走 Stream 长连接）即可演示。

工程验证：`go vet ./...` 退出码 0，`go test ./...` 26 个含测试包全部通过（证据见 `docs/evidence-build-test-20260903.txt`）；三平台（linux/darwin/windows）原生 CGo 构建工作流已入库（`.github/workflows/release.yml`）。

---

## 2. 赛题理解与总体目标

赛题要求"具备**自主决策能力**的**通用**网络安全智能体"，结合 5 维评分（任务理解与执行设计 / 系统架构与工程实现 / 决策逻辑与可解释性 / 工具协同与扩展能力 / 创新与附加价值），我们将其拆解为四条可验证的产品目标：

| # | 目标 | 对应评分维度 | 落地形态 |
|---|---|---|---|
| G1 | 能"听懂"自然语言、附件与结构化任务并自主拆解出可执行计划 | 任务理解与执行设计 | 多角色子代理 + Deep/Plan-Execute 编排 + WebShell/附件上下文 |
| G2 | 能力池足够宽、扩展零门槛 | 工具协同与扩展能力 | YAML 工具/MCP/Skills/Workflow 四级插件 + `tool_search` 动态装配 |
| G3 | 每步决策可见、可控、可追溯 | 决策逻辑与可解释性 | reasoning 流式展示 + HITL 审批 + monitor 执行记录 + audit 平台审计 |
| G4 | 部署即用、安全默认、合规可接入 | 系统架构与工程实现 / 创新 | 单体一键部署 + 127.0.0.1 默认 + 国内备案模型 + 预留安恒 AI 安全网关接入 |

---

## 3. 系统总体架构

### 3.1 分层架构

```mermaid
flowchart LR
    U["Web / Robot / API 用户"] --> R["Gin Router + 认证/RBAC"]
    R --> H["Handlers"]
    H --> DB[("SQLite data/*.db")]
    H --> A["Agent 层<br/>Eino ADK 单代理 / Deep / Plan-Execute / Supervisor"]
    A --> M["MCP Server 桥<br/>(internal/mcp + einomcp)"]
    M --> T["工具池<br/>90×YAML tools + Go 内置 + Skills FS(23) + 外部 MCP 联邦"]
    A --> K["知识库检索<br/>SQLite 向量 + rerank"]
    H --> W["Workflow 工作流引擎"]
    H --> C2["内置 C2 / WebShell / Terminal"]
    H --> AU["HITL 审批 + Monitor + Audit"]
```

层次职责与代码位置：

| 层 | 职责 | 关键代码 |
|---|---|---|
| 接入层 | Web(SSE)/8 类 IM 机器人/OpenAPI/批量队列 | `cmd/server`、`internal/app/app.go`、`internal/robot/`、`internal/handler/openapi.go` |
| 编排层 | 任务拆解、多代理调度、工具选择 | `internal/multiagent/`（Eino ADK）、`internal/agent/`、`agents/*.md` |
| 执行层 | 工具调用、命令执行、沙箱边界 | `internal/mcp/`、`internal/einomcp/`、`tools/*.yaml`、`internal/security/` |
| 数据层 | 会话/工具执行/HITL/审计/知识/业务持久化 | `internal/database/`（SQLite） |
| 横切层 | HITL、监控、审计、RBAC、reasoning、trace | `internal/hitl/`、`internal/monitor/`、`internal/audit/`、`internal/reasoning/` |

### 3.2 一次对话的真实路径（以 `/api/eino-agent/stream` 为例）

1. Gin 路由 → 认证与 RBAC 中间件；
2. Handler 解析会话、角色、附件、WebShell 上下文；
3. Agent 组装模型输入：历史消息 + 角色提示 + **项目事实（facts 黑板）** + 工具白名单；
4. Eino Runner 调国内备案模型（qwen/deepseek，支持 retry/failover 多通道）；
5. 模型需要工具 → 走 MCP Tool 桥（`einomcp`）；工具列表过长时 `toolsearch` 中间件按阈值动态裁剪；
6. 高危工具调用前触发 **HITL 审批**（off/approval/review_edit 三态，全局默认 off，演示/生产可开）；
7. 工具结果经 reduction 截断/落盘后回填，写入 monitor 与过程详情；
8. 推理链（thinking/reasoningChain/planning）经 SSE `thinking_stream_*` 事件实时推送前端时间线；
9. 会话、消息、过程详情、用量摘要（`eino_usage_summary`）落 SQLite。

完整链路在 `internal/multiagent/eino_*` 系列中均有类型化实现（Agentic typed agent、TurnLoop、checkpoint/resume）。

---

## 4. 关键技术设计

### 4.1 任务理解与执行设计

- **多形态输入**：自然语言对话、附件上传、OpenAPI 批量任务、WebShell 上下文、IM 机器人消息。
- **角色化理解**：`internal/roles/` + `agents/*.md` 让同一句任务可被不同角色（recon/渗透/应急/加固/报告…）按各自视角解析执行。
- **执行闭环**：`internal/attackchain`（攻击链生成）+ `internal/projectprompt`（项目事实）+ `internal/agentfinalizer`（收尾）构成"计划→执行→归因→收尾"闭环。
- **结构化任务输入（评审举证项）**：已支持通用附件上传与内容注入；赛题加分项"压缩文件/结构化文件自动解析→执行计划"列为答辩前演示必补场景（见 §7.3），仓库预留附件上下文通道（`internal/handler/chat_uploads.go`）。

### 4.2 多智能体编排（Eino ADK）

入口 `POST /api/multi-agent/stream`，请求体 `orchestration` 指定模式：

| 模式 | 定位 | 装配方式 | 典型用法 |
|---|---|---|---|
| `eino_single` | 单代理 ReAct 直答 | `RunEinoSingleChatModelAgent`（`/api/eino-agent*`） | 机器人默认、轻量问答 |
| `deep` | 复杂任务主代理 + task 子代理协作 | `deep.NewTyped[*schema.AgenticMessage]`，主代理读 `agents/orchestrator.md` | 大型安全测试拆解 |
| `plan_execute` | 目标明确的"规划→执行→重规划"闭环 | Eino 官方 `planexecute.Config` + Agentic Executor | 有明确步骤链的任务 |
| `supervisor` | 专家路由：主代理把子任务转派给专业子代理 | `agents/orchestrator-supervisor.md` + transfer/exit 约束 | 多域并行的专家调度 |

要点：

- 子代理 = Markdown 声明式（`agents/` 下 18 个文件：orchestrator 主代理 ×3 变体 + 15 个场景子代理），可配 `bind_role` 继承角色工具；运行时 CRUD（`/api/multi-agent/markdown-agents*`）。
- 全部走 **Agentic typed 栈**（Eino v0.9.14 官方 typed middleware）：patchtoolcalls、toolsearch、plantask、reduction、filesystem、skill、summarization；模型侧启用原生 ModelRetry 与 ModelFailover 多通道容错。
- **断点续跑**：checkpoint_dir + Eino TurnLoop（`adk.TurnLoop` bridge），中断/超时可恢复，长任务不因单次失败全丢。
- 机器人/批量队列可复用同套编排（`robot_default_agent_mode`、`batch_use_multi_agent`）。

### 4.3 工具协同与扩展能力（四层插件化）

1. **YAML 工具层**（`tools/*.yaml`，90 个）：声明式定义命令、参数、平台/依赖约束、风险分级；覆盖 recon、web、云、kube、二进制/移动、内存取证、区块链、AD 域等 20+ 攻击面。
2. **Go 内置工具层**（`internal/app/*_tools.go`）：平台无关的高频能力（文件、HTTP、知识检索、`analyze_image` 视觉等），随二进制分发、零外部依赖。
3. **外部 MCP 联邦**（`internal/mcp/`）：支持接入任意 MCP Server，带连接恢复与审计；Web/设置页可管理。
4. **Skills/工作流**：`skills/`（23 个攻防技能包）在需要时经 Eino `skill` 工具按需加载（渐进式披露，省上下文）；`internal/workflow` 可视化编排 start/agent/tool/condition/hitl/output/end 节点，非程序员也能把多工具串成流水线。

**动态装配**：`toolsearch` 中间件按阈值拆分超长工具列表，模型"先见入口、按需解锁"，配合 `tool_search_always_visible_tools` 保证关键工具常驻。

### 4.4 决策逻辑与可解释性

- **推理可见**：reasoning 中间件产出 `thinking/reasoningChain/planning` 结构化字段；SSE 以 `thinking_stream_*` 流式呈现；前端时间线展示每步 thought/工具事件/用量（含 `eino_model_retry` / `eino_model_failover` / `eino_usage_summary`）。
- **人机协同 HITL**（`internal/hitl/`，对应终审"3 名队员 + AI Agent 人机协同"）：approval / review_edit 两种审批原语，全局默认 `off`，演示配置可一键开启；工具调用前统一拦截点，审批记录入库。
- **全程审计**：`internal/audit/` 记录平台管理动作；`internal/monitor/` 记录每次工具执行（含调用链、耗时、结果摘要），支撑任务取消、复盘、通知。
- **可解释上下文管理**：长对话自动 typed summarization，携带用户意图 ledger 与事实索引（fact index），压缩历史后仍保留"为什么在做什么"。

### 4.5 记忆与知识

- **项目事实黑板（project facts）**：`internal/projectprompt` 将项目级事实注入每次 Agent 上下文，跨对话保持目标一致性（防跑偏）。
- **知识库 RAG**（`internal/knowledge/`）：Markdown/文本 ingest → chunk → embedding → SQLite 向量索引 → multi-query 扩展 + rerank 精排 + 检索日志；命中后向 Agent 暴露知识检索工具，用于把团队沉淀的靶场/漏洞库/复盘文档喂给智能体。
- **Checkpoint**：会话级断点，配合 TurnLoop 支持人工中断后继续。

### 4.6 安全与合规默认

- **网络默认安全**：`config.example.yaml` 默认 `server.host: 127.0.0.1`（仅本机），需外联才显式放开并配网络层访问控制；TLS 可选自签/受信证书。
- **凭据管理**：`config.example.yaml` 仅占位模板（真实 `config.yaml` 已 gitignore）；支持 `${VAR}` 环境变量展开与同名 env fallback（`internal/config` `envsecrets.go`/`robots_env.go`），**密钥不落盘、不入库、不提交**；机器人 8 通道凭据不全时仅 Warn 并软禁用，不 panic。
- **权限与边界**：RBAC（`internal/rbac`）、认证/限流（`internal/security`）、Shell 命令流处理；高危能力（Terminal/WebShell/C2/外部 MCP/Skill FS）文档化强调需 HITL + 部署隔离（`docs/zh-CN/security-model.md`、`tool-execution-governance.md`）。
- **模型合规**：默认通义 qwen / DeepSeek（国内备案）；支持把 base_url 指向主办方指定 AI 安全网关（`docs/zh-CN/ai-gateway-compliance.md`），满足终审"报备模型 + 经安全网关接入"约束。

### 4.7 部署与运维

- **一键启动**：`start.bat`（Windows）/ `run.sh`（Linux）/ 预编译 `secautomind-ai.exe`（150MB 单文件，内嵌前端与内置工具）。
- **Python 工具可选**：`setup_venv.bat` 建立 venv 后解锁 Python 系工具（nuclei/msf 等外部工具按 tools YAML 的依赖声明选用）。
- **云部署**：`deploy_tencent_lighthouse.sh` + `腾讯轻量云部署指南.md` 提供受控云环境方案，支撑"在线可测试地址"材料。

---

## 5. 创新点凝练

1. **统一 Agentic 多编排且可运营**：单代理 / Deep / Plan-Execute / Supervisor 四条执行路径共用一套 typed 中间件栈、SSE 协议与 checkpoint/TurnLoop 边界，模式可配置切换（聊天/机器人/批量一致），是国内竞赛作品中少见的"编排即产品功能"而非 demo 拼装。
2. **四级插件化 + 工具搜索动态装配**：YAML 工具 / MCP 联邦 / Skills / Workflow 四层均可热扩展；`toolsearch` 让模型在超长工具池上"渐进可见"，兼顾能力宽度与上下文成本。
3. **从"执行"到"可解释、可管控"的完整闭环**：结构化 reasoning + HITL 全局拦截 + monitor/audit 双记录，同时支撑演示可解释性与终审人机协同合规。
4. **长程任务韧性**：typed summarization（意图 ledger + fact index）+ checkpoint/TurnLoop 断点续跑 + 多通道模型 retry/failover，把"一次对话失败全丢"变成"可恢复、可复盘"。
5. **合规优先的工程形态**：国内备案模型默认、AI 安全网关预留接入、127.0.0.1 安全默认、凭据纯环境变量注入、8 类 IM 机器人无公网回调（Stream 长连接）——"随处下发任务"与"受控合规"兼得。
6. **低门槛分发**：单体 Go + SQLite + 内嵌前端单文件 150MB，离线可跑通核心链路，现场演示不赌网络。

---

## 6. 工程验证现状（可复现证据）

| 项 | 结果 | 证据 |
|---|---|---|
| 静态检查 | `go vet ./...` 退出码 0 | `docs/evidence-build-test-20260903.txt` |
| 单元/集成测试 | 26 个含测试包全部 `ok`；仓库 226 个 `*_test.go`（覆盖 config 环境变量注入、HITL、审计、多代理 typed 栈、知识库、WebShell 流等） | 同上 + `internal/` 各包 |
| 三平台构建 | linux/darwin/windows 原生 CGo 构建工作流 | `.github/workflows/release.yml` |
| 代码规模 | Go 613 文件；90 工具 YAML；23 技能包；18 agents md | `tools/`、`skills/`、`agents/` |
| 功能验证 | 8 IM 通道软启用与凭据缺失降级、自动多模型 failover、${VAR} env 展开均有测试覆盖 | `internal/config/robots_env_test.go` 等 |

> 注：以上为**工程正确性**证据。反映智能体"能力提升"的对照实验（如多代理 vs 单代理成功率、工具调用准确率）尚未在受控靶场跑出可信基线，见 §7。

---

## 7. 待验证项与答辩前补强计划（诚实声明）

以下内容**当前无实测数据**，未写入任何"效果提升"结论；计划在 9/20 初审前于受控靶场完成并以修订版替换 §6。

### 7.1 对照实验（对应评分维度五"创新验证"）
- **实验设计**：固定同一批靶场任务（如 CTF/靶机 Web 打点 × N 个场景），同一模型（qwen-max）下对比：单代理 eino_single vs deep vs supervisor 的成功率、轮次、工具调用准确率、token 消耗；每组 ≥3 次重复取均值。
- **预期基线**：deep/supervisor 在高拆解度任务上的成功率应高于单代理直答（该结论待数据支撑，不作预设）。
- **交付物**：实验记录 md + 原始 JSON 留存（`experiments/results/`）。

### 7.2 关键演示场景补齐（对应 §4.1 评审缺口）
- "上传 zip 压缩任务包 → 自动解包 → 自动生成执行计划并执行"端到端演示；
- "应急响应/蓝队"场景跑通（`agents/incident-response.md`、`defense-hardening.md` 已存在角色，需录制真实案例）。

### 7.3 合规实测
- 向主办方报备模型清单 + 实测经安恒 AI 安全网关（base_url 指向网关）完成一次完整任务链；
- HITL 开启状态下录制"审批 → 审计轨迹回看"片段。

---

## 8. 与赛题评分维度映射

| 维度 | 本文支撑章节 | 核心证据文件 |
|---|---|---|
| 任务理解与执行设计 | §4.1、§7.2 | `agents/`、`internal/attackchain`、`internal/handler/chat_uploads.go` |
| 系统架构与工程实现 | §3、§4.7 | `internal/app`、`.github/workflows/release.yml`、`evidence-build-test-20260903.txt` |
| 决策逻辑与可解释性 | §4.4 | `internal/hitl`、`internal/reasoning`、`internal/audit`、`docs/zh-CN/security-model.md` |
| 工具协同与扩展能力 | §4.3 | `tools/`(90)、`internal/mcp`、`skills/`、`internal/workflow` |
| 创新与附加价值 | §5、§6、§7 | 本文档 + 方案设计文档 + 演示视频 |

---

*附录：仓库文档索引（供评审交叉核验）*：`docs/zh-CN/architecture.md`（架构）、`MULTI_AGENT_EINO.md`（多代理改造）、`robot.md`（IM 机器人与环境变量）、`configuration.md`、`security-model.md`、`hitl-best-practices.md`、`deployment.md`、`ai-gateway-compliance.md`、`README_CN.md`。
