# CTF² Agent 竞技场接入报告（1024 线上快闪赛 · AI Agent 赛道）

> 日期：2026-10-23 ｜ 状态：接入完成并真机验证 ｜ 正式赛：10-24 19:00–20:00

## 一、完成事项总览

| 项 | 结果 | 验证方式 |
|---|---|---|
| CTF² 平台登录与竞技场开通 | ✅ user_mdn15apo 已登录；Agent 竞技场可用 | 浏览器实测 |
| Agent 创建 | ✅ **SecAutoMind**（id `e268e589-4824-48fb-afdb-216496c4c1e5`，运行中，claude-sonnet-5） | 平台页面 |
| 「允许参加比赛」开关 | ✅ 已开启 | 平台页面 + `/api/open/v1/user/agent/me/` 返回 `competition_enabled=true` |
| 访问 Token | ✅ 已创建并写入用户级环境变量 `CTF2_AGENT_TOKEN`（69 字符，只显示一次，已保存） | 环境变量回读 |
| REST 协议真源 | ✅ 官方 OpenAPI 已落地 `docs/ctf2_user_openapi.json`（56 端点，Agent 端点 24 工具齐全） | 平台 `/api/openapi/v1/user.json` |
| Go 客户端 `ctf2.go` | ✅ 完整实现 PlatformAPI + BackoffAdvisor + SetAntiBlock | `go build ./...` RC=0；`go vet` 通过 |
| 生产接线 `app.go` | ✅ CTF² 配置齐全时优先选用（否则回退 DASCTF 挑战杯） | 全量构建 RC=0 |
| 真机冒烟 | ✅ 拿题/题详情/附件生成下载全部通过 | `TestCTF2LiveSmoke` PASS |
| 靶机链专项 | ✅ 开环境→取地址→回收全通 | `TestCTF2LiveTargetChain` PASS（5.8s） |
| 调试赛参赛 | ✅ SecAutoMind 已出现在调试赛 Agent 榜单（进行中） | 平台 flag 比赛 tab |
| 正式赛预配 | ✅ `CTF2_COMPETITION_ID=b10634a1-7534-46af-950e-8395367bab6b` 已写入用户级环境变量 | 环境变量回读 |

## 二、协议要点（CTF² 与西湖论剑/DASCTF 的差异）

- **端点前缀**：`/api/open/v1/user/agent/`（比赛模式 `competitions/{id}/stages/{stageId}/challenges/...`），
  **不是**西湖论剑的 `/slab-match/api/v1/agent/`。
- **鉴权**：`Authorization: Bearer <CTF2_AGENT_TOKEN>`，不是 `X-Agent-AccessKey`。
- **提交防误交**：submit 请求体必须带 `confirmation: true`。
- **附件下载链**：题详情 `files[]`（`file_id/file_name/kind`）→ `attachments/{fileId}/url/` 拿签名 URL（5 分钟过期）→ 直链下载。
- **个人附件/动态 flag**：`kind=assigned/generated` 为按人变体；`personal_files_status` 有
  `join_required/pending/ready` 状态（附件题需先参赛生成）。
- **配额**：每 Agent 同时 1 靶机（max_environments=1）；读 120/min、写 30/min；429 尊重 `retry_after_ms`。
- **环境生命周期**：`environment/start/`（首启自动参赛）→ `environment/`（查状态/地址）→
  `environment/extend/`（续期）→ `environment/` DELETE（回收）。无 reset 端点。

## 三、环境变量配置清单（用户级，已持久化）

| 变量 | 值 | 用途 |
|---|---|---|
| `CTF2_BASE_URL` | `https://ctf2.dasctf.com` | CTF² 平台地址 |
| `CTF2_AGENT_TOKEN` | `ctf2_e16967ca…`（已保存，页面不再可见） | Agent Bearer 凭证 |
| `CTF2_COMPETITION_ID` | `b10634a1-7534-46af-950e-8395367bab6b` | 1024 快闪赛·正式赛 |
| `CTF2_STAGE_ID` | （未设；比赛开始后自动发现） | AI Agent 赛道阶段 |
| （原有）`DASCTF_BASE_URL/DASCTF_TOKEN/CTF_AGENT_PLATFORM_TOKEN` | `https://pro.dasctf.com` + 挑战杯 token | 挑战杯决赛（不受影响） |

## 四、运行/验证命令

```bash
# 真机冒烟（拿题/详情/附件/比赛信息）
CTF2_BASE_URL=https://ctf2.dasctf.com CTF2_AGENT_TOKEN=$CTF2_AGENT_TOKEN go test ./internal/ctfplatform/ -run TestCTF2LiveSmoke -v

# 靶机链专项（开环境→取地址→回收）
CTF2_BASE_URL=https://ctf2.dasctf.com CTF2_AGENT_TOKEN=$CTF2_AGENT_TOKEN go test ./internal/ctfplatform/ -run TestCTF2LiveTargetChain -v

# 全链路（拿题→开环境→取地址→提交，决赛演练同款）
# 需 CTF_POLL_ENABLED=true + CTF_AUTOSOLVE_SUBMIT=true（自动提交，正式赛慎用误交）
```

Go 前置（AGENTS.md 第五条）：`APPDATA`、TMP/TEMP/TMPDIR 分开设 `D:\tmp_gotest`、go=`D:\DevCache\go\bin\go.exe`。

## 五、正式赛情报（COMP-2026-0903，b10634a1-7534-46af-950e-8395367bab6b）

- **规模**：60 分钟、**19 道题**、满分 **1024 分**（静态分不衰减，各赛道一血独立）。
- **AI Agent 赛道**：1024 系列实战题 + Agent 能力题；Agent 首次开环境或提交时自动参赛；
  **只接受 Agent 程序自动提交，人工代交取消成绩**。
- **时间敏感机制**：
  - 「1024 秒闪电战」仅 `19:10:24–19:27:28` 开放，窗口内得分翻倍；
  - 「19:24 卡点题」`19:24:00–19:24:59` 提交满分，其他时间减半；
  - 彩蛋：每赛道第 1024 次正确提交 +50 分（仅 1 人）。
- **flag 规则**：`DASCTF{...}` 区分大小写须完整提交；短时间大量错误提交触发冷却；
  靶机启动有频率限制；有靶机的题按人生成动态 flag，部分附件题按人生成附件。
- **提交时限**：20:00 准时关闭提交入口；20:00–20:30 复核期。
- **纪律**：禁止代打/多账号；禁止对靶机与平台 DDoS/扫描渗透；泄题取消成绩。

## 六、赛时建议（基于平台规则与本次实测）

1. **开赛前不启动 poller**（`CTF_POLL_ENABLED` 保持 false），19:00 开赛后再启，避免 WAF 冷却。
2. **请求节流**：实测过密请求会触发平台 403 WAF 风控（冷却 5 分钟）。poller 拉题为只读 GET，
   正式赛间隔 10s 起步（见下方正式赛参数块）；靶机启动（写操作）排队分散。
3. **优先价值排序**：闪电战窗口内的题（双倍分）> 卡点题（19:24 精准提交）> 常规题。
   建议 poller 开启时按 `Extra["score_multiplier"]` 排序。
4. **动态 flag 题**：环境就绪后 flag 与靶机绑定，poller 的 InstanceChain 已覆盖（演练验证过）。
5. **附件题**：调试赛实测 `kind=generated` 个人附件可下载（`AutoFetchAttachment=true` 时自动并入描述）。
6. **WAF 冷却已内建**：客户端检测 403 自动冷却 5 分钟并跳过请求，防雪崩封禁。

### 6-b 快闪赛正式赛参数块（2026-10-24 19:00-20:00，冠军目标=最短时间做完 19 题）

启动 SecAutoMind 时设置以下环境变量（一次设置，零闪失口径）：

```
CTF_POLL_ENABLED=true          # 启用轮询
CTF_POLL_INTERVAL=10           # 拉题间隔 10s（开赛后尽快发现全部题目）
CTF_AUTOSOLVE_SUBMIT=true      # 解出即自动提交（正式赛必须）
CTF_SOLVE_TIMEOUT=120          # 单题求解超时 120s（默认 300s×2 并发数学上做不完 19 题）
CTF_MAX_CONCURRENCY=4          # 跨题并发 4（本地求解+LLM，平台仅受提交/起靶机影响）
CTF_MAX_RETRY_SUBMIT=1         # 错误提交会触发平台冷却，候选重试收敛为 1
CTF_AUTO_BUILD_ENV=true        # 靶机题自动起环境（CreateInstance→GetAccess 真机链已验证）
CTF_AUTO_FETCH_DETAIL=true     # 详情补全（列表描述是摘要，完整题干/靶机标记在详情）
CTF_AUTO_FETCH_ATTACHMENT=true # 附件自动下载并入描述（CTF² 附件端点真机可用）
CTF_AUTO_RELEASE_ENV=true      # accepted 后回收靶机，释放平台配额
```

**吞吐核算**：19 题 × 120s 上限 ÷ 4 并发 ≈ 9.5 分钟求解主体；静态题（presolve 秒级）经
「静态优先排序」先做完，靶机题（起环境有延迟）排后——60 分钟内全做完有充分余量。

**得分策略**：解出即提交（简单可靠）；19:10:24-19:27:28 闪电战窗口内解出的题自然拿双倍分；
不做延迟批量提交（复杂机制引入赛时风险，且与"最短时间做完"目标冲突）。

**零闪失 checklist（开赛前 10 分钟逐项核对）**：
1. `CTF2_BASE_URL` 非空（=https://ctf2.dasctf.com，2026-10-23 曾因缺失导致 CTF2Configured()=false 会误选 DASCTF，已写回 User 级）
2. `CTF2_COMPETITION_ID` 指向正式赛（b10634a1-…bab6b，非调试赛 4604a758-…）
3. `CTF2_AGENT_TOKEN` 可读（回读确认非空）
4. `CTF_POLL_ENABLED=true` 后再启动；开赛前保持 false 防 WAF
5. 平台网页端 Agent SecAutoMind（e268e589-…）仍"允许参加比赛"勾选
6. 浏览器已登录 ctf2.dasctf.com（user_mdn15apo），用于人工兜底查榜

## 七、遗留与风险

- **stage_id 自动发现**：正式赛阶段未开放前无法预取；19:00 开赛后首次 `ListChallenges`
  自动发现（已预配 competition_id，不会误选调试赛）。若发现失败，手动设 `CTF2_STAGE_ID`。
- **WAF 风控是真实的**：2026-10-23 多次快速探测触发 403 冷却 5 分钟；赛时务必节流。
- **choice 题（知识快答单选）**：每次提交消耗 1 次机会（attempts_left）；poller 目前对
  `submission_type=choice` 走同一 SubmitFlag 路径，正式赛建议对 choice 题只提交高置信答案。
- **羊城杯**：官方赛程显示线上初赛 10-17 已结束、线下决赛 10-31 初定；"明天的羊城杯"指向未确认（待用户澄清）。

## 八、引用文件

- 协议真源：`docs/ctf2_user_openapi.json`（平台官方 OpenAPI，2026-10-23 下载）
- 客户端：`internal/ctfplatform/ctf2.go`（新增）
- 冒烟：`internal/ctfplatform/ctf2_live_smoke_test.go`（新增）
- 接线：`internal/app/app.go`（424-432 行平台选择）
- 日志：`logs/ctf2_smoke_run.log`、`logs/ctf2_targetchain_run.log`、`logs/ctf2_final_check.log`
- 对比文档：`决赛对标分析_SecAutoMind_vs_西湖论剑.md`
