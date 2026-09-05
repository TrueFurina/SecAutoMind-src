# SecAutoMind IM 机器人（多端通道）接入指引

> 版本基线：v1.7.25 ｜ 适用代码：`internal/robot/*` + `internal/config/robots_env.go` + `internal/app/app.go:startRobotConnections`
> 本文面向「想让 SecAutoMind 通过微信/钉钉/飞书/企业微信/Telegram/Slack/Discord/QQ 接收任务」的同学，给出**从开放平台申请凭据 → 填入配置 → 启动验证**的完整步骤。

---

## 0. 一句话结论（先读）

| 通道 | 实现状态 | 连接模式 | 是否需要公网 | 凭据来源 |
|---|---|---|---|---|
| 钉钉 dingtalk | ✅ 已实现 `StartDing` | **Stream 长连接**（免回调） | ❌ 不需要 | 钉钉开放平台 |
| 飞书 lark | ✅ 已实现 `StartLark` | 长连接（WebSocket） | ❌ 不需要 | 飞书开放平台 |
| 微信 iLink wechat | ✅ 已实现 `StartWechat` | iLink 长轮询 | ❌ 不需要 | 微信 iLink 平台 |
| Telegram | ✅ 已实现 `StartTelegram` | 长轮询 / Webhook | ❌（轮询） | @BotFather |
| Slack | ✅ 已实现 `StartSlack` | Socket Mode（WebSocket） | ❌ 不需要 | api.slack.com |
| Discord | ✅ 已实现 `StartDiscord` | Gateway（WebSocket） | ❌ 不需要 | discord.com/developers |
| QQ | ✅ 已实现 `StartQQ` | WebSocket | ❌ 不需要 | q.qq.com |
| **企业微信 wecom** | ⚠️ **仅回调骨架**（`HandleWecomGET/POST`，**无 `StartWecom`、无 `wecom.go`**） | 需公网 HTTPS 回调 | ✅ 需要 | 企业微信管理后台 |

> ⚠️ **企业微信是当前唯一不能"开箱即连"的通道**：配置段、`WECOM_*` 环境变量、HTTP 回调路由都已就位，但**没有主动建立连接的代码**。若要在答辩里演示企业微信，需先补一个 `internal/robot/wecom.go` 的 `StartWecom`（见 §9）。其余 7 个按本文配置即可运行。

---

## 1. 通用机制（所有通道一致）

### 1.1 优先级：环境变量 > config.yaml
- `config.Load()` 阶段调用 `ApplyRobotsEnvOverride()`，**环境变量存在且非空时覆盖 yaml**。
- 推荐做法：**把真实凭据放环境变量**（或填 `config.yaml`），让 `config.example.yaml` 只留占位符，永远别把真实密钥提交进 git。
- 演示/现场/容器场景用环境变量最省事（见 §8 模板）。

### 1.2 启用开关
- 每个通道 yaml 里 `enabled: false`，可被同名环境变量开启：
  `DINGTALK_ENABLED=true`、`LARK_ENABLED=true`、`WECHAT_ENABLED=true`、`WECOM_ENABLED=true`、`TELEGRAM_ENABLED=true`、`SLACK_ENABLED=true`、`DISCORD_ENABLED=true`、`QQ_ENABLED=true`
- 值 `true/1/yes/on` 开启；`false/0/no/off` 关闭；非法值忽略。

### 1.3 安全红线（务必遵守）
- `config.yaml` 已在 `.gitignore` 中，**真实凭据只进 `config.yaml` 或环境变量**，不进 `config.example.yaml`、不进代码、不进 git。
- 凭据缺失的通道**不会让主系统崩溃**：`startRobotConnections()` 先对 `EnabledButIncompleteRobots()` 的每个通道打 `Warn` 日志并跳过，主 Agent 照常工作。
- 任何通道崩溃都被各自的 goroutine + `reconnect.go` 兜底重连，不影响主进程。

### 1.4 验证是否连上
启动后看日志关键字：
- 钉钉：`dingtalk stream connected` 一类的连接成功日志
- 飞书：`lark ... connected`
- 其余类推。
- 或在 Web 界面「设置 → 机器人」里逐个测试；API：`POST /api/robot/test`，body `{"platform":"dingtalk","user_id":"test","text":"帮助"}`。

---

## 2. 钉钉（dingtalk）— 推荐答辩演示通道

**为什么推荐**：Stream 长连接**无需公网回调地址**，笔记本本地就能跑，最适合现场"用钉钉给智能体下任务"的演示。

### 2.1 申请凭据
1. 打开 https://open.dingtalk.com/ → 登录 → **开发者后台**。
2. **应用开发 → 企业内部应用 → 创建应用**（H5 微应用 / 小程序均可），填名称（如 `SecAutoMind`）。
3. 创建后在**应用信息**里拿到 **ClientID**（旧称 AppKey）和 **ClientSecret**。
4. 开通 **Stream 长连接** 能力（钉钉开放平台「Stream 模式」文档，需应用具备「机器人」相关权限）。
5. （可选）在「权限管理」勾选：接收会话消息、发送消息等。

### 2.2 写入配置
**方式 A：环境变量（推荐，优先）**
```bash
export DINGTALK_ENABLED=true
export DING_APP_KEY=dingxxxxxxx        # 即 ClientID
export DING_APP_SECRET=xxxxxxxx         # 即 ClientSecret
# 别名也可用：DINGTALK_CLIENT_ID / DINGTALK_CLIENT_SECRET
```
**方式 B：config.yaml**
```yaml
robots:
  dingtalk:
    enabled: true
    client_id: "dingxxxxxxx"
    client_secret: "xxxxxxxx"
```

### 2.3 验证
- 启动后在钉钉里给该应用发消息「扫描 192.168.x.x 的 Web 服务」，智能体应回任务计划。
- 日志应出现连接成功；API 测试 `POST /api/robot/test {"platform":"dingtalk",...}` 应返回执行结果。

---

## 3. 飞书（lark）

### 3.1 申请凭据
1. https://open.feishu.cn/ （国内）/ https://open.larksuite.com/ （海外） → **开发者后台**。
2. **创建企业自建应用** → 填写名称。
3. **凭证与基础信息** 拿到 **App ID** 和 **App Secret**。
4. **应用功能 → 机器人** 开启；**事件订阅** 选择「长连接（WebSocket）」模式（免公网），并记录 **Verification Token（verify_token）**。
5. 权限：开通「接收消息」「发送消息」等。

### 3.2 写入配置
```bash
export LARK_ENABLED=true
export LARK_APP_ID=cli_xxxxxxxx
export LARK_APP_SECRET=xxxxxxxx
export LARK_VERIFY_TOKEN=xxxxxxxx
```
或 config.yaml：
```yaml
robots:
  lark:
    enabled: true
    app_id: "cli_xxxxxxxx"
    app_secret: "xxxxxxxx"
    verify_token: "xxxxxxxx"
```

---

## 4. 微信 iLink（wechat，个人微信 ClawBot）

### 4.1 申请凭据
1. 平台 https://ilinkai.weixin.qq.com （微信智能对话 / ClawBot 开放平台）。
2. 创建机器人，拿到 **bot_token**，以及本机绑定的 **ilink_bot_id / ilink_user_id**。
3. `base_url` 默认 `https://ilinkai.weixin.qq.com`，一般无需改。

### 4.2 写入配置
```bash
export WECHAT_ENABLED=true
export WECHAT_BOT_TOKEN=xxxxxxxx
```
config.yaml：
```yaml
robots:
  wechat:
    enabled: true
    bot_token: "xxxxxxxx"
    ilink_bot_id: ""
    ilink_user_id: ""
```
> 注：`auth.mode: user_binding` 表示绑定真实微信用户身份；若做专用服务号改 `service_account` 并务必配 `allowed_external_users` 限制发送者，避免被滥用。

---

## 5. Telegram

### 5.1 申请凭据
1. 在 Telegram 找 **@BotFather** → `/newbot` → 按提示命名 → 拿到 **bot_token**（形如 `123456:ABC-DEF...`）。
2. 默认长轮询（`getUpdates`），**无需公网**；如需 Webhook 才要公网 HTTPS。

### 5.2 写入配置
```bash
export TELEGRAM_ENABLED=true
export TELEGRAM_BOT_TOKEN=123456:ABC-DEFxxxx
```
config.yaml：
```yaml
robots:
  telegram:
    enabled: true
    bot_token: "123456:ABC-DEFxxxx"
    bot_username: "SecAutoMindBot"   # 可选
```

---

## 6. Slack

### 6.1 申请凭据
1. https://api.slack.com/ → **Create App** → From Scratch。
2. **OAuth & Permissions** 添加机器人作用域（如 `chat:write`, `im:history`, `app_mentions:read`）；安装到工作区得到 **Bot User OAuth Token**（`xoxb-` 开头）。
3. **Socket Mode** 开启 → 生成 **App-Level Token**（`xapp-` 开头），用于免公网长连接。

### 6.2 写入配置
```bash
export SLACK_ENABLED=true
export SLACK_BOT_TOKEN=xoxb-xxxxxxxx
export SLACK_APP_TOKEN=xapp-xxxxxxxx
```

---

## 7. Discord

### 7.1 申请凭据
1. https://discord.com/developers → **New Application** → 进入 **Bot** 标签 → **Reset Token** 拿到 bot_token。
2. **Privileged Gateway Intents** 开启 `Message Content Intent`（如需读消息正文）。
3. 邀请机器人到服务器（OAuth2 → URL Generator → `bot` scope）。

### 7.2 写入配置
```bash
export DISCORD_ENABLED=true
export DISCORD_BOT_TOKEN=xxxxxxxx
```

---

## 8. QQ 机器人

### 8.1 申请凭据
1. https://q.qq.com/ → **QQ 开放平台 / 机器人** → 创建机器人。
2. 在机器人「开发设置」拿到 **AppID** 和 **密钥（ClientSecret）**（QQ 机器人走 WebSocket 长连接，免公网）。
3. 权限/能力按需要开通。

### 8.2 写入配置
```bash
export QQ_ENABLED=true
export QQ_APP_ID=xxxxxxxx
export QQ_CLIENT_SECRET=xxxxxxxx
```

---

## 9. 企业微信（wecom）— ⚠️ 当前未实现主动连接

### 9.1 现状（诚实说明）
- `config.example.yaml` 有 `wecom` 段；`robots_env.go` 有 `WECOM_*` 环境变量映射；`app.go:967-968` 注册了 `GET/POST /api/robot/wecom` 回调路由（`HandleWecomGET/POST`）。
- **但 `startRobotConnections()` 里没有 `go robot.StartWecom(...)`，仓库也没有 `internal/robot/wecom.go`**。
- 结论：配置与回调入口已就绪，**主动拉取/接收消息并连通智能体的代码还没写**。现在即使配了 `WECOM_ENABLED=true`，企业微信侧也只会把消息 POST 到你的回调 URL，而服务端没有处理链路。

### 9.2 接入前必须补的代码
1. 新建 `internal/robot/wecom.go`，实现 `func StartWecom(ctx, cfg, h, logger)`：
   - 企业微信回调需**公网 HTTPS** 接收 `HandleWecomGET`（URL 校验）/ `HandleWecomPOST`（消息加解密，用 `Token` + `EncodingAESKey` + `CorpID`）。
   - 解密后把消息转成统一 `MessageHandler` 调用；回包走企业微信「被动回复」或主动 API（`secret` 换 `access_token` 调发送接口）。
2. 在 `app.go:startRobotConnections` 的循环里加 `go robot.StartWecom(...)`（仿照其他通道）。
3. 企业微信需要公网回调地址——本地演示要么用内网穿透（如 frp/ngrok/cloudflared），要么部署到带域名的服务器。

### 9.3 凭据（申请步骤，供补完后填）
1. https://work.weixin.qq.com/ → 企业微信管理后台 → **我的企业** 拿到 **CorpID**。
2. **应用管理 → 自建 → 创建应用** 拿到 **Secret** 和 **AgentId**。
3. 应用详情里配置「接收消息」：填回调 URL（公网）、**Token**、**EncodingAESKey**。

```bash
export WECOM_ENABLED=true
export WECOM_CORP_ID=wwxxxxxxx
export WECOM_SECRET=xxxxxxxx
export WECOM_TOKEN=xxxxxxxx
export WECOM_ENCODING_AES_KEY=xxxxxxxx
```

> 答辩建议：企业微信依赖公网回调，现场不稳定。**优先用钉钉（Stream 免公网）做演示**；企业微信作为"已规划、配置就位、待补连接实现"在材料里诚实说明，不要摆拍。

---

## 10. 现场 / 容器一键启动模板（环境变量方式）

把要演示的通道凭据放进一个 `.env` 文件（**此文件不提交 git**），`source` 后启动：
```bash
# robots-demo.env（仅本地，勿提交）
export DINGTALK_ENABLED=true
export DING_APP_KEY=dingxxxx
export DING_APP_SECRET=xxxx
export LARK_ENABLED=true
export LARK_APP_ID=cli_xxx
export LARK_APP_SECRET=xxx
export LARK_VERIFY_TOKEN=xxx

source robots-demo.env
./secautomind-ai.exe          # 或 go run cmd/server/main.go
```
Docker 等价：
```bash
docker run -e DINGTALK_ENABLED=true -e DING_APP_KEY=dingxxxx -e DING_APP_SECRET=xxxx \
  -p 8080:8080 your/secautomind:1.7.25
```

---

## 11. 故障排查

| 现象 | 可能原因 | 处理 |
|---|---|---|
| 启动日志大量 `Warn ... incomplete robot` | 该通道 enable 了但凭据缺 | 检查对应 env 变量是否 export / config.yaml 是否填 |
| 钉钉/飞书连不上 | Stream 模式权限未开 / ClientID 错 | 回开放平台确认「机器人」「长连接」能力已开通 |
| 企业微信完全无反应 | 代码未实现 `StartWecom` | 见 §9，先补 `wecom.go`；或改用钉钉演示 |
| 消息无回复 | `auth.mode: user_binding` 限制了发送者 | 确认发消息的账号在绑定名单；或改 `service_account`+`allowed_external_users` |
| 主系统照常、仅某通道挂 | 正常降级（reconnect 兜底） | 看该通道日志，不影响主 Agent |

---

## 12. 与代码的对应（方便二次开发）
- 启用/降级逻辑：`internal/app/app.go:823 startRobotConnections` + `EnabledButIncompleteRobots()`
- 环境变量映射：`internal/config/robots_env.go`（表驱动，加新通道照此加一行）
- 各通道连接：`internal/robot/{ding,lark,wechat,telegram,slack,discord,qq}.go`
- 重连/消息拆分/主动推送：`internal/robot/{reconnect,split,proactive}.go`
