# SecAutoMind 方案设计文档

**赛题**：挑战杯"揭榜挂帅" XH-202609《具备自主决策能力的通用网络安全智能体技术研究》
**发榜单位**：杭州安恒信息技术股份有限公司
**版本**：v1.7.25｜2026-09-03 版

> 本文件为独立"方案设计文档"（区别于仓库内的架构说明 `docs/zh-CN/architecture.md`）：面向评审说明"为什么这么设计、解决了什么问题、如何验证"。代码级细节可交叉引用架构/开发/测试文档。

---

## 1. 设计目标与约束

### 1.1 设计目标

| 目标 | 说明 | 验收口径 |
|---|---|---|
| 通用性 | 覆盖攻击面枚举、渗透、应急响应、防护加固、漏洞研判、报告整改等攻防两侧 | 18 个角色化 agents + 5 大攻击面工具族 |
| 自主决策 | 大模型驱动任务拆解、工具选择、循环执行，少人工干预 | 三种多代理编排可跑通完整任务链 |
| 可解释 | 决策链可见、可审计、可回放 | HITL/audit/monitor/reasoning 全链路记录 |
| 可扩展 | 非程序员可新增工具/技能/子代理/工作流 | 四层插件化 + 运行时 CRUD |
| 合规可控 | 国内备案模型、受控部署、安全默认 | 默认 127.0.0.1、密钥不入库、网关预留 |

### 1.2 设计约束（来自赛题与终审要求）

1. Agent 部署于**受控环境**，联网模型须**提前报备国内备案大模型 API** 并经主办方指定 **AI 安全网关**接入；
2. 终审为"3 名队员 + 自研 AI Agent"**人机协同**解题 → HITL 是硬需求而非可选；
3. 演示可能处于无公网/弱网环境 → 核心链路需**零公网回调**、可离线运行；
4. 现场评审时间有限 → **一键部署 + 预编译单文件**优先于分布式架构；
5. 材料需包含方案设计/技术报告/测试文档/用户手册/PPT/演示视频/声明函 → 设计文档需与其他材料互相印证。

### 1.3 关键取舍（Trade-off）

| 取舍 | 选择 | 理由 | 代价与补偿 |
|---|---|---|---|
| 架构形态 | 单体 Go + SQLite + 内嵌静态前端 | 一键部署、离线可跑、便于受控环境隔离 | 横向扩展受限 → 通过 MCP 联邦把重活外置，文档明确边界 |
| 安全模型 | 能力收敛 + 分层管控（RBAC→HITL→monitor/audit） | 高危工具与 Web 面同进程，必须纵深防御 | 需在部署隔离上补强（见 §7） |
| 上下文策略 | 动态裁剪 + 摘要压缩 + 断点续跑，而非无限扩窗 | 控制 token 成本、支撑长任务韧性 | 摘要可能丢细节 → 意图 ledger + fact index 兜底 |
| 智能体技术栈 | Eino ADK（typed Agentic 栈） | 编排能力（Deep/Plan-Execute/Supervisor）+ 官方中间件生态 | 较自研编排重 → 已用 adapter 隔离边界 |

---

## 2. 需求分析

### 2.1 功能需求（FR）

| 编号 | 需求 | 优先级 | 落点 |
|---|---|---|---|
| FR1 | 自然语言/附件/WebShell 上下文接收任务并自动拆解 | P0 | `internal/multiagent`、`internal/handler` |
| FR2 | 支持 4 种执行模式（单代理/Deep/Plan-Execute/Supervisor）且可配置 | P0 | `multi_agent.enabled`、`orchestration` |
| FR3 | 90+ 内置工具 + 外部 MCP + 技能包 + 工作流组合执行 | P0 | `tools/`、`internal/mcp`、`skills/`、`internal/workflow` |
| FR4 | 高风险工具 HITL 审批（approval / review_edit） | P0 | `internal/hitl` |
| FR5 | 工具执行监控与平台审计可查询 | P0 | `internal/monitor`、`internal/audit` |
| FR6 | 知识库 RAG（ingest→chunk→embed→检索→rerank） | P1 | `internal/knowledge` |
| FR7 | 项目事实（facts）跨对话注入，维持目标一致 | P1 | `internal/projectprompt` |
| FR8 | 8 类 IM 机器人接入（wechat/wecom/dingtalk/lark/telegram/slack/discord/qq） | P1 | `internal/robot`（凭据不全软禁用） |
| FR9 | 批量任务队列与 WebShell AI 模式 | P1 | `internal/handler`、队列 |

### 2.2 非功能需求（NFR）

| 编号 | 需求 | 指标/约束 |
|---|---|---|
| NFR1 | 可解释性 | 每次模型调用留存 thinking/reasoningChain/planning；工具事件 SSE 流式可见 |
| NFR2 | 安全 | 默认仅本机监听；密钥仅 env；危险命令有 guard；工具结果脱敏替换 |
| NFR3 | 可靠性 | 模型 retry/failover 多通道；任务断点续跑；崩溃后 SQLite 持久化不丢会话 |
| NFR4 | 性能 | 单机满足演示规模（并发 ≤ 数十会话）；流式首字延迟由模型主导 |
| NFR5 | 部署 | Windows/Linux/macOS 预编译；start.bat / run.sh 一键；Python 工具为可选增强 |
| NFR6 | 合规 | 默认国内备案模型；base_url 可指向 AI 安全网关；模型 API 预报备 |

---

## 3. 总体架构设计

### 3.1 逻辑架构

```
┌───────────── 接入层 ─────────────┐
│ Web UI(SSE) │ 8×IM Robot │ OpenAPI │ 批量队列 │
└──────────────┬──────────────────┘
               ▼
┌────────── Gin Router + Auth/RBAC/限流 ──────────┐
│ Handler：agent / workflow / knowledge /          │
│          webshell / c2 / audit / monitor /       │
│          project / vulnerability / config / openapi│
└───────┬──────────────┬──────────────┬───────────┘
        ▼              ▼              ▼
┌─ 编排层(Eino ADK) ─┐ ┌─ Workflow ─┐ ┌─ 业务子模块 ─┐
│ eino_single        │ │ start/agent │ │ C2 WebShell   │
│ deep               │ │ tool/cond   │ │ Terminal      │
│ plan_execute       │ │ hitl/output │ │ attackchain   │
│ supervisor         │ │ end         │ │ project facts │
└──────┬─────────────┘ └─────┬──────┘ └──────────────┘
       ▼                     ▼
┌─ 执行层 MCP Tool 桥 ───────────────────────────┐
│ YAML工具(90) │ Go内置 │ 外部MCP联邦 │ Skills(23) │
└──────┬─────────────────────────────────────────┘
       ▼
┌─ 横切：HITL 拦截 → Monitor 记录 → Audit 审计 ─┐
┌─ 数据层：SQLite（会话/过程/工具/HITL/审计/知识/业务）┐
```

### 3.2 模块清单（internal/ 顶级包 → 职责）

| 包 | 职责 | 关键子文件/说明 |
|---|---|---|
| `agent` | MCP/工具层：`ToolsForRole`、工具执行 | 单代理能力供给 |
| `multiagent` | Eino 多编排 + typed 中间件 + TurnLoop/checkpoint | `runner.go`、`eino_orchestration.go`、`eino_*` 系列 |
| `agents` | 内置子代理模板装配 | 配合 `agents/*.md` 运行时 CRUD |
| `app` | 服务组装、路由、内置工具注册、机器人启动 | `app.go`、`startRobotConnections` |
| `handler` | HTTP/SSE 业务处理 | `multi_agent.go`、`eino_single_agent.go`、`workflow*.go` 等 |
| `mcp`/`einomcp` | MCP Server/外部接入/断线恢复；Eino Tool 适配 | 工具调用统一出口 |
| `workflow` | 可视化工作流引擎 | start/agent/tool/condition/hitl/output/end |
| `hitl` | 人机协同审批 | approval/review_edit；全局默认 off |
| `reasoning` | 推理链结构化 | thinking/reasoningChain/planning |
| `monitor`/`audit` | 工具执行监控；平台审计 | 支持任务取消/复盘/通知 |
| `knowledge` | 知识库 RAG | SQLite 向量、multi-query、rerank、检索日志 |
| `projectprompt` | 项目事实黑板注入 | 跨对话目标一致性 |
| `robot` | 8 类 IM 机器人 | Stream 长连接零公网回调；env 凭据软启用 |
| `security` | 认证/限流/Shell 执行/命令流 | 平台安全边界 |
| `database` | SQLite 封装与 schema 演进 | `data/conversations.db` 等 |
| `c2`/`webshell`/`attackchain` | 专项能力 | 高风险模块，需 HITL + 隔离 |
| `vision` | `analyze_image` 视觉工具 | 独立 Vision 模型（qwen-vl-max） |
| `llm` | 多通道模型容错 | retry/failover |

### 3.3 关键接口

| 接口 | 方法 | 说明 |
|---|---|---|
| `/api/eino-agent/stream` | POST(SSE) | 单代理流式对话 |
| `/api/multi-agent/stream` | POST(SSE) | 多代理流式（`orchestration` 选模式） |
| `/api/multi-agent/markdown-agents*` | CRUD | 子代理 Markdown 管理 |
| `/api/workflow*` | CRUD+Run | 工作流管理与执行 |
| `/api/config` | GET/PUT | 运行态配置热应用 |
| `/api/audit`、`/api/monitor` | GET | 审计/监控查询 |
| `/api/openapi` | — | OpenAPI 接口文档与批量任务 |
| `/api/robot/...` | — | 机器人通道状态 |

---

## 4. 关键流程设计

### 4.1 多代理编排（deep）时序

```
用户 ──任务──▶ Orchestrator(deep)
   │  拆解 → 子任务1..N
   ├──task(子代理)──▶ 执行工具(MCP) ──▶ 结果
   ├──task(子代理)──▶ ...（可并行/串行，视 Eino task 契约）
   │  汇总 + 收尾(finalizer)
   └──▶ 最终答复(SSE: progress/thinking/tool/response/delta)
```

### 4.2 HITL 审批时序（approval 模式）

```
Agent → 发起高危工具调用
  → HITL 拦截：写入审批待办 + SSE 通知前端
  → 队员在前端审阅参数 → 批准/拒绝/编辑(review_edit)
  → 批准后执行工具；拒绝则 Agent 收到"已拒绝"并换路
  → 决策与审批记录入库（audit/monitor）
```

### 4.3 工具搜索与动态装配

```
工具池(90+ MCP defs) → toolsearch 中间件按阈值裁剪
  → 模型可见 Top-K 工具 → 需要更多时经入口工具解锁
  → 命中工具 → patchtoolcalls 修正 → 执行 → reduction 截断结果 → 回填
```

---

## 5. 数据设计

SQLite 单机持久化，库文件见 `config.yaml → database`，默认 `data/`。

| 数据域 | 主要实体 | 说明 |
|---|---|---|
| 会话 | conversations、messages、process 详情 | 含 role/mode/orchestration |
| 工具 | tool executions、monitor 事件 | 每次调用留痕 |
| 审批 | HITL 请求/决定 | approval/review_edit 全记录 |
| 审计 | audit log | 平台管理动作 |
| 知识 | chunks、vectors、检索日志 | SQLite 向量索引 |
| 业务 | projects、vulnerabilities、webshell、c2、batch | 任务成果沉淀 |
| 配置 | config.yaml（真实配置 gitignore） | 环境变量优先 |

schema 演进须兼容旧库（`internal/database` 有版本化约定）。

---

## 6. 配置与安全设计

### 6.1 配置三层

1. `config.example.yaml`（模板，提交）：占位符 `sk-xxxxxxx` 等，**不含真实密钥**；
2. `config.yaml`（真实，gitignore）：本地/部署环境实际配置；
3. 环境变量：`${VAR}` 展开 + 同名 env fallback（`internal/config/envsecrets.go`），以及机器人通道表驱动覆盖（`robots_env.go`：`DING_APP_KEY/SECRET`、`LARK_APP_ID/...`、`WECHAT_BOT_TOKEN`、`TELEGRAM_BOT_TOKEN` 等），优先级 **env > yaml**。

凭据不完整时：仅 Warn 日志 + 软禁用该通道（`EnabledButIncompleteRobots()`），主服务正常启动，杜绝 panic。

### 6.2 安全默认

| 项 | 默认 | 备注 |
|---|---|---|
| 监听 | 127.0.0.1:8080 | 外联需显式修改 + 网络层访问控制 |
| TLS | 自签/受信可选 | `--http` 明文仅供受控内网 |
| HITL | off（全局） | 演示/生产按需 approval/review_edit |
| 引导管理员密码 | 随机生成、控制台打印一次、不落盘 | 演示环境可配固定引导密码 |
| 密钥 | 仅环境变量/yaml(不入库不提交) | `.gitignore` 覆盖 config.yaml/.env/*.pem 等 |
| 危险参数 | model-output guard 替换为 recovery marker | 流式 tool-call 参数保护 |

### 6.3 合规设计

- 模型层 `llm` 支持 provider/base_url 覆盖 → 指向安恒 AI 安全网关；文档 `ai-gateway-compliance.md` 给出指引；
- 默认 `qwen3-max`（阿里 DashScope，通义 qwen 系列）/ DeepSeek，均为国内备案；
- 演示前需按主办方流程报备模型 API 与部署地址。

---

## 7. 部署与运维设计

| 场景 | 方式 | 文件 |
|---|---|---|
| 评委本机（Win） | 双击 `start.bat` → 预编译 exe | `secautomind-ai.exe` |
| Linux 服务器 | `run.sh` / 预编译二进制 | 腾讯轻量云指南 |
| 可选 Python 工具 | `setup_venv.bat`（Python 3.10+） | venv 后解锁 python 系 tools |
| 在线演示地址 | 轻量云 + 域名 + TLS | `deploy_tencent_lighthouse.sh` |
| Docker | 镜像化部署（可选） | 配置/数据卷挂载 |

运维要点：数据目录 `data/` 定期备份；`server.out.log` 收集运行日志；变更配置走 Web 设置页热应用（写回 config.yaml）。

---

## 8. 可测试性与扩展性设计

- **可测试**：278 个 `*_test.go`（config env 注入、HITL、typed 多代理、审计、流式回放、知识库、WebShell）；`docs/evidence-build-test-20260903.txt` 留存 36 包全绿与 vet exit 0。
- **扩展点（给评委/二次开发）**：
  1. 加工具：`tools/foo.yaml` 声明命令与参数即可（平台/依赖可选）；
  2. 加子代理：`agents/foo.md` 写角色与指令（或 Web 端 Agents 管理）；
  3. 加技能：`skills/foo/` 目录 + SKILL.md；
  4. 接系统：任意 MCP Server（Web 设置页配置外部 MCP）；
  5. 编排流水线：可视化工作流编辑器（无需写代码）。

---

## 9. 与赛题材料要求对照

| 赛题材料项 | 对应产出 | 状态 |
|---|---|---|
| 方案设计文档 | 本文档 | ✅ |
| 技术报告 | `技术报告_SecAutoMind_202609.md` | ✅（草稿） |
| 开发/测试/用户文档 | `docs/zh-CN/developer-guide.md`、`testing.md`、`SHARE_README.md` | ✅ |
| 演示视频 | `演示视频脚本_SecAutoMind_202609.md` → 录制 | 脚本 ✅ / 录制待办 |
| 声明函 | `原创性与保密性声明_模板_SecAutoMind.md` | 模板 ✅ / 签署待办 |
| 一键部署/在线地址 | start.bat + 轻量云指南 | 地址待托管 |

---

*关联文档*：`docs/zh-CN/architecture.md`、`MULTI_AGENT_EINO.md`、`robot.md`、`security-model.md`、`hitl-best-practices.md`、`deployment.md`、`testing.md`。
