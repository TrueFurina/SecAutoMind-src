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
| **企业微信 wecom** | ✅ 已实现（`HandleWecomGET` 验签回 echostr + `HandleWecomPOST` 解密→路由→回复） | **HTTP 回调**（企业微信平台**没有**长连接模式，故无 `StartWecom` 是正常的，不是缺失） | ✅ 需要（HTTP / HTTPS 均可） | 企业微信管理后台 |

> 📌 **8 个通道全部已实现**；表格里企业微信那行的"无 `StartWecom`"**不是缺功能，而是平台特性**：
> 钉钉有 Stream、飞书有 WebSocket、微信 iLink 有长轮询、Slack/Discord/QQ 有 Gateway ——
> 这些平台**提供长连接**，所以各自要有一个 `Start*` 去建立并维持连接。
> **企业微信只提供「HTTP 回调 + 主动调用接口」，压根没有长连接可建**，它的"连接"就是
> 平台把消息 POST 到你的回调 URL。因此判断它实现与否的标准是「回调入口 + 验签/解密 + 处理链路 + 回包通道」齐不齐，
> 而不是有没有 `StartWecom`。上述四件套在 `internal/handler/robot.go` 均已完成并通过单测，详见 §9。
>
> ⚠️ 但它确实是**唯一需要公网地址**的通道：回调 URL 必须让企业微信服务器能访问到，且跑的实例不能是旧于 v1.7.28 的版本（回调路由在那之后才加入）。

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
3. 在左侧「开发中」栏点 **「凭证与基础信息」**（注意是带"**凭证**"二字的那个，不是上面的「基础信息」）：
   - **Client ID**（原 AppKey / SuiteKey）—— 一长串、常带 `ding` 前缀，直接复制即可。
   - **Client Secret**（原 AppSecret）—— 默认掩码，点旁边 **「查看」** 复制**完整值**（形如 `GZufM6...W2Y2iYdqaz`，中间**没有 `*`**）。⚠️ 后台默认显示的是 `GZufM6Vtdx****W2Y2iYdqaz` 这种**遮挡态**，中间 `****` 是钉钉打的码，**不能直接用**，必须点「查看」拿完整串。
4. 确认应用具备 **「机器人」能力** 并已开通 **Stream 长连接**：
   - 左侧「应用能力 → 机器人」里确认 **Stream 模式 / 实时通讯** 已开启；若没有则在「添加应用能力」里加「机器人」。
   - 在「权限管理」勾选：接收会话消息、发送消息等。
5. 🔴 **保存并发布（最易被漏，漏了就永远连不上）**：钉钉改配置**不发布不生效**。点左上 **「版本管理与发布 → 保存并发布」**，把"待发布内容"里的机器人能力发布出去。应用处于「开发中」、机器人显示「待发布内容」时，**即便 ClientID/Secret 完全正确，Stream 握手也会卡住/失败**——这是现场演示前最常见的坑。

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
**① 凭据秒验（启动前，不硬编码密钥）**——读环境变量调钉钉 `gettoken`：
```bash
curl -s "https://oapi.dingtalk.com/gettoken?appkey=$DING_APP_KEY&appsecret=$DING_APP_SECRET"
# 返回 {"errcode":0,"access_token":"..."} 即凭据有效
# 返回 errcode:40096 "不合法的appKey或appSecret" → 多半是复制到了带 * 的遮挡值，回到 §2.1 第 3 步重新「查看」复制
```
**②-2 启动连接（务必绕过代理）**——注入环境变量后启动（详见 §2.2 方式 A）。若本机挂了系统代理（见 ②-1），**必须先 unset 代理**，否则 exe 仍走代理、被拦截：
```bash
unset HTTP_PROXY HTTPS_PROXY http_proxy https_proxy   # Linux/Mac
Remove-Item Env:HTTP_PROXY,Env:HTTPS_PROXY             # Windows PowerShell
export DINGTALK_ENABLED=true DING_APP_KEY=... DING_APP_SECRET=...
./secautomind-ai            # Windows: secautomind-ai.exe
```
- 日志出现 `robot/ding.go:46 "钉钉 Stream 正在连接…"` 表示已走到建连；出现连接成功日志即大功告成。

- 🔴 **②-1 "正在连接…"不停循环——先分清是代码还是网络**
  > ⚠️ **本节旧版写过的"DNS 不通 / 代理拦截 / 改 hosts"结论已作废**，那是用失效的检测通道
  > （Google DoH `dns.google` 返回空）造成的误读。真实端点由网关动态下发，**也不叫 `stream-open`**。

  **唯一成功标志**：日志出现 **`钉钉 Stream 连接成功，已进入长连接守护`**（`robot/ding.go`）。
  有这句 = 已建连，此后不应再出现"正在连接…"；没有这句却在反复打印"正在连接…" = 异常。
  **现象**：日志只有"正在连接…"循环、既无成功也无 `Warn 长连接断开`，`netstat` 可见多条到钉钉端点的 ESTABLISHED 且**不断累积**。

  **根因 A（代码层 —— 本项目的真实病因，已修于 commit `9ce1041`）**
  SDK 的 `StreamClient.Start()` 是**同步**的：`dialer.Dial` 成功 → 启动 `processLoop` → `return nil`；
  且 SDK 默认 `WithAutoReconnect(true)`，断线由 `reconnect()` 每 3 秒重试直到成功（`client.go:311`）。
  若外层循环在 `Start()` **成功后仍重建 client**，就会在健康连接上反复重连——
  **表现与"连不上"一模一样，但网络其实是好的**。
  判定：`Start()` 返回 `nil` 就代表**已连上**；此时不应再出现第二次"正在连接…"。

  **根因 B（网络/DNS 层 —— 罕见，但排查时极易误判）**
  WebSocket 端点**不是固定域名**，而是由网关动态下发。取真实端点：
  ```bash
  curl -sS --noproxy '*' -X POST https://api.dingtalk.com/v1.0/gateway/connections/open \
    -H 'Content-Type: application/json' \
    -d '{"clientId":"<ClientID>","clientSecret":"<ClientSecret>","subscriptions":[]}'
  # 返回体里的 endpoint 字段即真实 wss:// 地址（形如 wss://wss-open-connection.dingtalk.com:443/connect）
  ```
  拿到端点后再测它能否解析：`getent hosts wss-open-connection.dingtalk.com`（能出 39.x 即正常）。

  ⚠️ **诊断陷阱（本节旧结论就栽在这三条上）**：
  1. **不要用单一 DNS 通道下结论**。`dns.google` 这类 DoH 在部分网络返回空，会被误读成"域名不存在"。
     **务必做阳性对照**——同时查一个已知能解析的域名（如 `oapi.dingtalk.com`），并用 ≥2 种 DNS（本机 / `223.5.5.5` / `nslookup`）。
  2. **`ssl_verify=0` 不能证明该 IP 服务于该主机名**。钉钉边缘用**泛域名证书 `*.dingtalk.com`**，
     任何 dingtalk 子域在任何阿里边缘节点上都会 `ssl_verify=0`。
  3. **代理通常不是元凶**：SDK 走 `websocket.DefaultDialer`，**不读 `HTTP_PROXY` 环境变量**。
     只有代码里显式 `WithProxy(...)` 时，才需确认该代理放行钉钉端点。

  🗑️ **已作废、请勿再照做**：给 `stream-open.dingtalk.com` 加 hosts 条目**无效**（真实端点由网关下发、且不叫这个名字）。
  若按旧版指引加过，请从 `C:\Windows\System32\drivers\etc\hosts` 删除该行并 `ipconfig /flushdns`。

- 🔴 **铁证（判断是否真连上）**——两条同时满足才算成功：
  1. **日志**：出现 `钉钉 Stream 连接成功，已进入长连接守护`，且 `钉钉 Stream 正在连接…` **只出现一次**。
  2. **连接**：`Get-NetTCPConnection -OwningProcess <PID>` 可见到钉钉端点（`39.x.x.x:443`）的 **ESTABLISHED**，
     且数量**稳定在 1 条**。
     ⚠️ 若连接数**不断累加**（2、3、4…条）→ 那正是"连接被反复重建"（根因 A），
     此时网络其实是好的，别再去折腾 DNS/hosts/代理。

- 🔴 **构建 exe 的坑（否则你可能根本跑不起来，误判成"连不上"）**
  本机用 Go 1.25 直接 `go build` 生成的 exe 可能报 **`%1 不是有效的 Win32 应用程序`**，
  原因是链接器给 DWARF 调试节分配了越界虚拟地址（`0xFFC00000` 超出 `SizeOfImage`），
  导致 Windows 判定 PE 无效。**加 `-ldflags "-w -s"` 去掉调试信息即可**：
  ```bash
  CGO_ENABLED=1 go build -trimpath -ldflags "-w -s" -o secautomind-ai.exe cmd/server/main.go
  ```
  实测对照（2026-09-05）：不加 `-w -s` → 157~159MB，`BAD_EXE_FORMAT` 无法运行；
  加上 → 86MB，正常启动。
- 在钉钉里给该应用发消息「扫描 192.168.x.x 的 Web 服务」，智能体应回任务计划；API 测试 `POST /api/robot/test {"platform":"dingtalk",...}` 应返回执行结果。

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

## 9. 企业微信（wecom）— HTTP 回调模式（已实现，非"待补"）

> 本节在 2026-10-13 重写。旧版写着「未实现主动连接、需补 `internal/robot/wecom.go`」——那是把
> 「企微没有长连接」误判成「没做」，与代码现状不符（详见 §0 的说明）。

### 9.1 已实现清单（均在 `internal/handler/robot.go`，且有单测覆盖）

| 环节 | 实现 | 说明 |
|---|---|---|
| 回调路由 | `internal/app/app.go:749-750` → `GET/POST /api/robot/wecom` | 与其它通道同前缀 |
| URL 校验 | `HandleWecomGET` + `signWecomRequest` | 后台保存配置时发 GET，须正确回 echostr |
| 防重放 | `acceptFreshWecomRequest` | 时间戳新鲜性 + nonce 去重 |
| 加解密 | `wecomDecrypt` / `wecomEncrypt` | AES-256-CBC + EncodingAESKey；明文与加密两种模式都支持 |
| 取 Token | `wecomRequireToken` | 未配 Token 直接拒绝（fail-closed） |
| 消息处理 | `HandleWecomPOST` | 解密后转统一处理链路；内置命令走被动回复，AI 消息异步处理后走主动 API |
| 回包通道 | `sendWecomReply`（被动回复）+ `sendWecomMessageViaAPI`（主动 API 推送） | `wecomLooksLikeMarkdown` 自动判断 markdown 类型 |
| 主动告警 | `internal/robot/proactive.go: sendWecomProactive` | 用 Secret 换 access_token 再调发送接口 |
| 配置层 | `RobotWecomConfig` + `WECOM_*` 环境变量 + 校验 + YAML 序列化 | 环境变量见 §9.3 |
| 前端面板 | 设置 → 机器人 → 企业微信，全字段可填 | 含 enabled 开关 |

**单测证据**（本机实测）：`go test ./internal/handler/ -run Wecom -count=1 -v` → 4 项全 PASS：
`TestHandleWecomGET_rejectsWhenTokenEmpty`、`TestHandleWecomPOST_rejectsWhenTokenEmpty`、
`TestHandleWecomPOST_rejectsPlaintextWhenEncryptionConfigured`、`TestWecomReplayGuardRequiresFreshUniqueRequest`。

### 9.2 接通步骤（纯配置，无需写码）

1. **先确认你能进管理后台**：企微后台要求账号归属某个企业。若提示"当前微信账号未注册企业"，可免费以个人身份创建企业，**注意不要选「个人组建团队」**（该模式官方明确不支持登录管理后台，选了就永远拿不到 CorpID）。
2. **我的企业 → 企业信息**：拿 **CorpID**。
3. **应用管理 → 自建 → 创建应用**：拿 **AgentId** 与 **Secret**（Secret 需点"查看"）。
4. **应用 → 接收消息 → 设置 API 接收**：
   - URL：`http(s)://<公网可达地址>/api/robot/wecom`（**路径必须完整**；HTTP 与 HTTPS 官方都支持）
   - Token 自编随机串，EncodingAESKey 点"随机生成"
   - 点**保存**：企微会真的向该 URL 发一条 GET 验签，由 `HandleWecomGET` 应答
5. **服务端填入同一份凭证**（CorpID / Secret / AgentID / Token / EncodingAESKey），网页端或环境变量二选一，重启服务。
6. 若发送消息后回复 `errcode 60020`：把服务器公网 IP 加入应用的「**企业可信IP**」。

### 9.3 凭据（环境变量方式）

```bash
export WECOM_ENABLED=true
export WECOM_CORP_ID=wwxxxxxxx
export WECOM_SECRET=xxxxxxxx
export WECOM_TOKEN=xxxxxxxx
export WECOM_ENCODING_AES_KEY=xxxxxxxx
```

> 答辩建议：企业微信是 8 路里**唯一依赖公网回调**的一路，现场网络不稳时风险最高，**演示优先级仍建议钉钉/飞书**（免公网）。
> 但材料口径要说准：企业微信是**已实现且已端到端验证**的第 8 路（2026-10-04 打通），
> **不要**再写成"待补连接实现 / 仅回调骨架"——那是旧文档的过时说法，会被评委按代码当场核对出不一致。

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
  -p 18086:18086 your/secautomind:1.7.25
```

---

## 11. 故障排查

| 现象 | 可能原因 | 处理 |
|---|---|---|
| 启动日志大量 `Warn ... incomplete robot` | 该通道 enable 了但凭据缺 | 检查对应 env 变量是否 export / config.yaml 是否填 |
| 钉钉/飞书连不上 | Stream 模式权限未开 / ClientID 错 | 回开放平台确认「机器人」「长连接」能力已开通 |
| 企业微信无反应 | ① URL 不带 `/api/robot/wecom`；② Token/EncodingAESKey 两端不一致；③ 跑的实例版本早于 v1.7.28（那时还没有回调路由，返回 404）；④ 公网 18086 未放行 | 逐项核（见 §9.2）：先看 `GET <公网>/api/robot/wecom` 是 404（路由/版本问题）还是 400 `invalid signature`（正常信号，说明已到 handler） |
| 消息无回复 | `auth.mode: user_binding` 限制了发送者 | 确认发消息的账号在绑定名单；或改 `service_account`+`allowed_external_users` |
| 主系统照常、仅某通道挂 | 正常降级（reconnect 兜底） | 看该通道日志，不影响主 Agent |

---

## 12. 与代码的对应（方便二次开发）
- 启用/降级逻辑：`internal/app/app.go:823 startRobotConnections` + `EnabledButIncompleteRobots()`
- 环境变量映射：`internal/config/robots_env.go`（表驱动，加新通道照此加一行）
- 各通道连接：`internal/robot/{ding,lark,wechat,telegram,slack,discord,qq}.go`
  （企业微信**不在此列**——它没有长连接可维护，HTTP 回调处理在 `internal/handler/robot.go`，见 §9）
- 重连/消息拆分/主动推送：`internal/robot/{reconnect,split,proactive}.go`
