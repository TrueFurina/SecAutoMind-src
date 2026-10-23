# Security Triage Agent MCP

[English](README.md)

**防御侧**安全事件研判与误报剔除 MCP 服务。SecAutoMind 可通过它把一条**安全告警**送进完整研判链路，拿到结构化结论（事件类型 / 风险等级 / 置信度 / 是否误报 / 证据 / 处置建议），并继续生成处置预案与工单。

与其他 MCP 的定位差异：本服务提供的是**防守视角**的能力面——告警分诊、误报剔除、处置编排。它与 SecAutoMind 既有的攻击侧能力（侦察 / 渗透 / 后渗透 / C2 / CTF 求解）互补，覆盖「通用网络安全智能体」中防守侧的空白。

## 工具说明

共 11 个工具，默认暴露 10 个（`command_executor` 需显式开启）。

| 工具 | 说明 | 入参依赖 |
|------|------|---------|
| `asset_lookup` | 资产画像查询（负责人 / 重要性 / 维护窗口 / 基线进程） | `event` |
| `log_lookup` | 关联日志检索（按主机与账号） | `event` |
| `intel_lookup` | 外联情报查询（IP / 域名信誉） | `event` |
| `history_alert_lookup` | 历史告警检索 | `event` |
| `ioc_search` | IOC 命中检索（情报 + 知识库） | `event` |
| `false_positive_check` | 误报线索判定（维护窗口 / 基线进程 / 变更单 / 白名单） | `event` + `asset_observation` + `log_observation` |
| `incident_triage` | **研判引擎**：LLM 决策 + 规则回退，产出风险分级与结论 | `event` + 5 个 `*_observation` |
| `playbook_matcher` | 处置预案匹配（按误报/风险等级分支） | `event` + `analysis` |
| `ticket_generator` | 工单生成（低置信降级为「待复核记录」） | `event` + `analysis` |
| `host_isolation_simulator` | 主机隔离建议（模拟执行，需人工审批落地） | `event` + `analysis` |
| `command_executor` | 命令执行（**默认关闭**） | `command` |

> **入参依赖是硬约束，不是可选提示。** 见下方「调用链路」。

## 调用链路（重要）

这些工具是**流水线内工具**：后段工具要把前段工具的输出**原样回传**，服务端会把它还原成内部对象。只传 `event` 去调 `incident_triage` 会返回可操作的错误提示，而不是结论。

```text
event（JSON）
  │
  ├─► asset_lookup ──────────┐
  ├─► log_lookup ────────────┤  阶段 1：上下文获取（各自只需 event）
  ├─► intel_lookup ──────────┤
  ├─► history_alert_lookup ──┤
  └─► ioc_search ────────────┘
                             │  把上游返回的 JSON 原样放进 arguments
                             ▼
                 false_positive_check（需 asset + log observation）
                             │
                             ▼
                 incident_triage（需全部 5 个 observation）
                             │  产出 analysis
              ┌──────────────┼──────────────┐
              ▼              ▼              ▼
      playbook_matcher  ticket_generator  host_isolation_simulator
```

两种事件传入方式都支持：

- **按 id 取权威事件**：`{"event": {"id": "EVENT-001"}}` —— 从服务自带样例库取字段最全的那条，适合演示与回归。
- **现场构造事件**：`{"event": {"host": "...", "process": "...", "raw_log": "...", ...}}` —— 传入任意自有告警字段，适合接入真实告警源。

## 依赖

- Python 3.13+（3.10+ 亦可运行，以仓库实际测试为准）
- **工具层零第三方依赖**：核心链路只用标准库，不需要 `mcp` 包，也不需要 PyYAML——`pip install` 失败也能跑。
  唯一例外是 `incident_triage` 的 LLM 路径需要 **httpx**（可选依赖，代码内 `try/except` 导入）：
  未安装时该路径自动降级为规则引擎回退，其余 9 个工具不受影响。

## 配置

默认读取本目录下的 `security_triage_agent_config.yaml`。可用 `--config /path/to/config.yaml` 覆盖。

配置格式限制与优先级见该文件内注释（支持顶层 `key: value`；**环境变量 > 配置文件 > 代码默认值**）。

其中真正影响本服务对外行为的只有 `command_tool_enabled`：

- `false`（默认）→ 暴露 10 个只读 / 研判类工具；
- `true` → 额外暴露 `command_executor`（会执行传入的命令文本，仅在隔离环境且调用方可信时开启）。

## 在 SecAutoMind 中接入

1. **Web 界面** → **设置** → **外部 MCP** → **添加外部 MCP**，填入以下 JSON（把路径替换成你的实际路径）：

```json
{
  "security-triage-agent": {
    "command": "/你的绝对路径/venv/bin/python3",
    "args": [
      "/你的绝对路径/SecAutoMind/mcp-servers/security_triage_agent/mcp_security_triage_agent.py",
      "--config",
      "/你的绝对路径/SecAutoMind/mcp-servers/security_triage_agent/security_triage_agent_config.yaml"
    ],
    "description": "防御侧安全事件研判与误报剔除：告警进、结论与处置建议出",
    "timeout": 120,
    "external_mcp_enable": true
  }
}
```

   - `command`：项目 venv 中的 Python，或系统 `python3`。工具层零第三方依赖，任意 Python 3.10+ 均可（LLM 路径需可选依赖 httpx）。
   - `args`：**必须是绝对路径**。
   - `timeout`：建议 120。研判含 LLM 调用时会慢一些；纯规则回退很快。
   - 保存后点击该 MCP 的 **启动**。

2. **建议同时做的事**：
   - `command_executor` 默认关闭。若要开启，**不要**把它加入 HITL 免审批白名单。
   - 若外部 MCP 工具较多，可用 `multi_agent.eino_middleware.tool_search_*` 把本服务的工具交给 `tool_search` 动态解锁，避免常驻上下文。

3. **使用流程示例**：
   - SecAutoMind 调 `asset_lookup({"event": {"id": "EVENT-001"}})` 拿资产画像。
   - 把返回 JSON 放进 `false_positive_check` 的 `asset_observation`。
   - 串起 5 个 observation 后调 `incident_triage`，拿到风险等级与结论。
   - 把结论作为 `analysis` 传给 `playbook_matcher` / `ticket_generator`。

## 本地自检（接入前建议先跑）

```bash
python mcp_security_triage_agent.py --selftest
```

跑一次**全工具出口矩阵**：动态遍历 `tools/list`，逐个工具做双向断言——按工具自己声明的最小必需参数集必须调得通，且抽掉任一声明必需的参数必须调用失败并**点名缺的是哪个参数**；同时校验 `inputSchema.required` 与工具自身声明同源、协议层的 observation 还原清单完备。

这取代了早先「列出工具 + 真调一次 `asset_lookup`」的自检：那种写法照不出「工具坏了」——本项目已三度踩中同一族缺陷（能力实现了但出口没接线，或被 fail-open 吞掉契约错配后报成功）。新增工具自动纳入，无需改自检代码。

`--selftest` 会显式打开命令工具（11 个而非默认 10 个）以便验证它的契约；对外服务的 `tools/list` 仍以配置中的 `command_tool_enabled` 为准。

用于区分「服务本身有问题」与「客户端配置有问题」——避免只在客户端里看到一句「启动失败」而无从排查。

## 出口契约（每条结论自带可信度声明）

2026-10-19 起，`tools/call` 的每个成功出口都会在业务字段旁**追加**一个 `_contract` 对象。原始字段（`tool_name` / `summary` / `details`，或 `ioc_search` 的数组）结构不变，老客户端按原格式解析不受影响。

```json
{
  "tool_name": "asset_lookup",
  "summary": "已获取 DC-01 的资产画像",
  "details": ["..."],
  "_contract": {
    "schemaVersion": "tool-contract/1",
    "authority": "observed",
    "authorityMeaning": "直接读取落盘事实（知识库 / 命令输出），未经推断加工",
    "coverage": { "status": "complete", "truncated": false, "omittedCount": 0 },
    "degraded": false,
    "degradationReason": null,
    "limitations": ["仅覆盖知识库已纳管主机；未纳管主机返回空结果，不代表主机不存在"],
    "evidence": {
      "tool": "asset_lookup",
      "toolVersion": "0.1.0",
      "inputDigest": "sha256:4a82c5c5157c5c9f",
      "generatedAt": "2026-10-19T14:26:24+00:00"
    }
  }
}
```

| authority（等级，非工具） | 含义 | 当前工具 |
|---|---|---|
| observed | 直接读取落盘事实，未经推断加工 | asset / log / intel / history_alert / ioc_search / command_executor |
| derived | 由确定性规则推导，可复现 | false_positive_check / playbook_matcher / ticket_generator / host_isolation_simulator |
| inferred | 由模型或启发式推断，存在不确定性 | incident_triage |
| unknown | 本次调用未形成结论（降级 / 异常 / 证据缺失） | 任一工具降级时 |

三条硬规则：

1. **降级必须自报**。`degraded=true` 时，`authority` 强制为 `unknown`、`coverage.status` 不得为 `complete`、`degradationReason` 必须非空。允许降级，不允许**假装没降级**——这正是 `incident_triage` 兜底分支此前的缺陷（返回 `isError=false` + `risk_level=medium`，实际一步研判都没做）。
2. **空结果 ≠ 不可用**。`ioc_search` 的空数组保留「检索过、未命中」原语义；「事件四个指标全为空所以没检索」这层歧义由 `limitations` 写明。
3. **契约层不持有工具知识**。等级由工具自己声明（`Tool.authority` / `Tool.limitations`），出口层只负责搬运；契约层自身出错只会降级为 `unknown` 并写明，不会让工具不可用。

对应门禁：

```bash
python contract_test.py                 # 53 条断言，含 5 类坏契约的变异自检
python mcp_security_triage_agent.py --selftest   # 出口矩阵 208 条（原 164 + 契约 44）
```

## 边界与诚实声明

接入前请知悉以下事实，避免对能力产生误判：

1. **不影响单二进制部署**。本服务是**独立进程 + 外部 MCP 联邦**接入，不进入 SecAutoMind 主二进制，也不引入 Go 侧依赖。主程序仍是单二进制；未配置本 MCP 时功能不受影响。代价是需要目标机器有 Python 运行时——**无 Python 环境时本服务不可用，这是可选增强而非必需组件**。
2. **工具层不调用大模型**。10 个工具均为规则 / 检索实现。`incident_triage` 内含 LLM 路径，但无可用 LLM 时自动降级为规则引擎回退并在 `reasoning_summary` 中明确标注「AI 不可用，使用规则引擎回退研判」——不会静默假装是 LLM 结论。
3. **自带样例数据集**。服务读写本目录下 `security_agent/data/` 的样例告警、资产、情报与台账（约 101 KB）。这是**演示与回归数据集**，不是生产告警库。要接自有数据，替换该目录下的 JSON，或改用「现场构造事件」模式传字段。
4. **会写本地台账**。每次工具调用都会向 `security_agent/data/ledger/` 追加审计记录（可溯源设计）。若不需要，删除该目录即可（会自动重建）。
5. **`command_executor` 是真执行**。它通过 shell 执行传入的命令文本，不是模拟。默认关闭。`host_isolation_simulator` 则是**模拟**，只输出建议、不落地动作。

## 许可

与上游仓库一致，详见仓库根目录 `LICENSE`。
