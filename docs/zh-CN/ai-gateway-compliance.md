# AI 模型合规与安全网关接入指南

> 对应挑战杯"揭榜挂帅" XH-202609 赛题要求：**模型须为国内备案大模型，终审所有 Agent 必须经主办方指定 AI 安全网关（安恒恒脑）接入**。本说明覆盖：模型支持、密钥注入、网关切换、报备清单。

## 1. 国内备案模型支持（默认满足）

系统默认 AI 通道为国内已备案大模型，无需本地部署模型：

| 通道 | 提供方 | base_url | 说明 |
|---|---|---|---|
| `qwen-max`（默认） | 阿里云 DashScope | `https://dashscope.aliyuncs.com/compatible-mode/v1` | 通义千问系列 |
| `deepseek` | DeepSeek | `https://api.deepseek.com/v1` | DeepSeek-V3/R1 |
| 其他 OpenAI 兼容端点 | 智谱 / 百川 / 月之暗面等 | 各自 compatible 端点 | 配置 `ai.channels.<name>` 即可 |

切换默认通道：`config.yaml` → `ai.default_channel`。

## 2. API Key 注入方式（三选一，推荐 ①）

### ① 环境变量自动回退（零配置，推荐）

config 中 `api_key` 保留占位符（如 `sk-xxxxxxx`）时，系统按 base_url 自动回退到约定环境变量：

| base_url 包含 | 依序回退的环境变量 |
|---|---|
| dashscope / aliyun | `DASHSCOPE_API_KEY` → `DASHSCOPE_KEY` → `QWEN_API_KEY` → `ALIYUN_API_KEY` |
| deepseek | `DEEPSEEK_API_KEY` → `DEEPSEEK_KEY` |
| anthropic / claude | `ANTHROPIC_API_KEY` → `CLAUDE_API_KEY` |
| siliconflow | `SILICONFLOW_API_KEY` |
| 兜底 | `OPENAI_API_KEY`、`DASHSCOPE_API_KEY` 等 |

也可以显式引用任意环境变量（与 Claude Desktop / Cursor / VS Code 同语法）：

```yaml
api_key: "${DASHSCOPE_API_KEY}"
# 支持默认值：${DASHSCOPE_API_KEY:-sk-fallback}
```

> 优点：密钥不落盘、不进代码仓库；系统敏感字段（api_key/token/password 等）均支持该语法。

### ② 直接写入 config.yaml

适合单机演示；注意分发/提交前清理真实 key。

### ③ 启动脚本注入

`start.bat` / `run.sh` 中 `set DASHSCOPE_API_KEY=sk-...` 后启动。

## 3. 安恒 AI 安全网关接入（终审要求）

终审现场所有模型调用必须经主办方指定安全网关。系统所有通道均为 OpenAI 兼容协议，切换只需改 `base_url` + `api_key`：

```yaml
ai:
  default_channel: qwen-max
  channels:
    qwen-max:
      api_key: "<安恒网关分配的 Key>"
      base_url: "https://<安恒网关地址>/v1"   # 以主办方现场提供为准
      model: "qwen-max"                        # 模型名以网关注册为准
```

**接入验收清单**（赛前完成）：

- [ ] 网关连通性：`curl <网关>/v1/chat/completions` 带分配 Key 返回 200
- [ ] 系统内任一 Agent 对话走网关成功（观察网关侧流量日志）
- [ ] 网关审计/限流策略对调试行为（如代码解释、批量扫描）不误伤
- [ ] 断网/网关故障时系统降级行为明确（错误提示 vs 静默重试）

## 4. 模型预报备清单（提交/答辩前填写）

| 项 | 内容 |
|---|---|
| 使用模型 | 通义千问 qwen-max（阿里云，已备案）；备选 DeepSeek-V3（已备案） |
| 提供方 | 阿里云计算有限公司 / DeepSeek（杭州深度求索） |
| 接入方式 | HTTPS API（OpenAI 兼容协议），终审经安恒 AI 安全网关 |
| 数据出境 | 无（模型与网关均在境内） |
| 本地部署 | 无（纯 API 调用，无本地模型推理） |

## 5. 安全设计要点（答辩可讲）

- 敏感字段（api_key/token/password）支持 `${VAR}` 环境变量注入，密钥不落明文配置。
- 占位符 key 识别：系统检测到 `sk-xxxxxxx` 等占位符时不会用其发起请求，自动回退环境变量。
- 模型侧无本地缓存敏感对话；对话数据存本地 SQLite（`data/conversations.db`），支持审计清理（`internal/audit` 的 retention/sanitize）。
