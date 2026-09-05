# T1 实测证据包索引（docs/evidence-20260905）

> 实测时间：2026-09-05 02:58–03:25 · 环境：独立沙盒实例（127.0.0.1:18099，完整资源目录，Fresh 全新数据目录）
> 方法：REST API 实测（pypdf 无关），原始响应存于 `raw/`（token 已脱敏）。
> 用途：为 PPT "实测验证"宣称提供逐条可指证据。每条标注对应评分维度与 PPT 页。
> 🔒 脱敏记录（2026-09-05 03:58 终扫）：`raw/13_config_snapshot.json` 11 个密钥字段（api_key/secret 等）已替换为 `***REDACTED***`（通道名/模型名/结构保留，证据价值不受影响）；`raw/30_login_final.json` 会话 token 已打码。全 docs/ + PPT 目录 sk-/AKIA/ghp 终扫 = 0 残留。主 config.yaml 已被 gitignore（真 key 从未入 git），config.example.yaml 无真实 key。

## 证据总表

| # | 宣称（PPT 出处） | 实测结果 | 证据文件 | 评分维度 |
|---|------------------|----------|----------|----------|
| E-01 | 首启向导：首次启动生成一次性管理员初始凭据（S8/S9） | ✅ 全新启动输出 `ADMIN SETUP REQUIRED` + admin 用户名 + 一次性密码，落盘 `data/admin_initial_password.txt`（文件头注明"仅首次启动生成，登录后请立即修改"） | `raw/00_setup_state.json` + 沙盒 server3.log | ②架构工程（部署便捷） |
| E-02 | 登录返回权限 scopes（RBAC 生效） | ✅ 200，返回 `permission_scopes` 全量映射 + expires_at | `raw/01_login_with_initial_password.json` | ④人机协同 |
| E-03 | RBAC 创建用户（`roles` 复数数组） | ✅ 200，`POST /api/rbac/users {"username":"auditor_evd","roles":["auditor"]}` | `raw/03_rbac_create_auditor.json` | ④人机协同 |
| E-04 | **auditor 写操作 → HTTP 403**（S5/S9 宣称，此前 docs 无证据 ⚠️） | ✅ **403**（auditor 身份 `POST /api/rbac/users` 创建用户被拒） | `raw/06_auditor_WRITE_expect_403.json` | ④人机协同 17-20 档 |
| E-05 | 高风险接口权限隔离 | ✅ **403**（auditor `POST /api/terminal/run` 被拒） | `raw/07_auditor_terminal_expect_403.json` | ③可解释/④协同 |
| E-06 | auditor 只读权限放行 | ✅ 200（auditor `GET /api/audit/summary` 正常） | `raw/08_auditor_READ_audit_summary.json` | ④人机协同 |
| E-07 | HITL 配置态：审批模式/工具白名单/待审队列 | ✅ 200×3：`/api/hitl/default-config`、`/hitl/tool-whitelist`、`/hitl/pending` | `raw/09,10,11_*.json` | ④人机协同 |
| E-08 | **初始密码一次有效**（S16"安全不裸奔"） | ✅ 改密后旧初始密码登录 → **401**；新密码登录 → 200 | `raw/15_relogin_initial_password_EXPECT_FAIL.json`、`raw/16_*.json` | ②架构工程 |
| E-09 | **全链路审计留痕 + 拒绝事件入审计**（S8 审计回放） | ✅ 审计日志完整记录本次实测全部动作：`login → create_user → access_denied ×2 → change_password → login`；summary：total=10 / failures=3 | `raw/24_audit_logs_v2.json`、`raw/23_audit_summary_v2.json` | ③决策可解释性 17-20 档（"可追溯"） |
| E-10 | 审计回放按条件筛选 | ✅ `?action=access_denied` → 精确过滤 2 条；`?action=create_user` → 1 条 | `raw/audit_filter_*.json` | ③可解释性 |
| E-11 | 工具规模"90 工具"（全篇） | ✅ 磁盘 90 个 YAML 配方；**运行时可调用工具共 140 个**（90 YAML + 50 内置/MCP，`/api/config/tools` total=140）。**建议 PPT 升级口径："90 个 YAML 安全工具配方，运行时可调用工具 140+"** | `raw/tools_names_full.txt`、`raw/27,31,32_*.json` | ④工具协同 |
| E-12 | 多 LLM 通道（S19 草稿页"8 通道"） | ✅ 运行时通道恰好 8 个：`ark / deepseek / moonshot / openai / qianfan / qwen-max / siliconflow / zhipu` | `raw/ai_channels.txt`、`raw/13_config_snapshot.json` | ②架构 / ⑤创新 |
| E-13 | 三端产物（S18/S9：Setup 33.6MB / 绿色版 158MB） | ✅ 实测 `installer/SecAutoMind-Setup-1.7.25-x64.exe` = 33MB；绿色版主程序 = 152MiB ≈ 159MB（口径相符） | 本文件 + installer 目录 | ②架构工程 |
| E-14 | 90 工具 × 18 Agent × 13 角色 | ✅ 磁盘实测：`tools/*.yaml`=90、`agents/*.md`=18、`roles/*.yaml`=13 | 磁盘清点 + `raw/roles_final` | ④工具协同 |
| E-15 | **三种编排模式全部实测**（S6/S7"Deep/Plan-Execute/Supervisor 自动选型"） | ✅ deep=1.7s 应答；plan_execute=63 事件全链（E-T2）；supervisor=78.4s 完成多子代理任务（修复后） | `raw/supervisor_conversation.json`、`raw/supervisor_process_details_*.json`、沙盒 task_*.json | ①任务理解 17-20 档"多策略选择" |
| E-16 | **审计层保守拒绝（fail-closed）+ 不产生幻觉结论** | ✅ supervisor 实测中审计 Agent 自身 LLM 故障 → 工具调用被**保守拒绝**（而非放行），主 Agent **如实报告"无法读取"并列出已确认信息**，未编造文件清单 | `raw/supervisor_process_details_*.json`（含 audit agent: LLM 调用失败，保守拒绝） | ③可解释性 17-20 档"能有效应对干扰" |
| E-17 | 🔴→✅ **P0 修复：supervisor 编排此前 500**（`agents/defense-hardening.md`、`incident-response.md` 缺 front matter 首行 `---`，加载器一票否决整个目录） | 已修复（2026-09-05 04:0x，补首行后 18/18 通过，supervisor 实测跑通）。**评审若在提交版仓库上跑 supervisor 会直接 500——这两个文件必须进今天提交的代码包** | 本文件 + git commit（仅 2 文件） | ②架构工程 / ①多策略 |
| E-18 | **端到端 HITL 审批门 + 拒绝后行为可控 + 不编造不绕过**（S5"人机协同"全链实证） | ✅ 真实任务"执行 whoami"：5 次 exec 全部被 HITL 门拦截（事件链 `hitl_audit_agent_started → hitl_audit_agent → hitl_rejected`，保守拒绝因审计 Agent LLM 走默认 qwen 通道故障）；Agent 明确**不尝试绕过**（拒绝伪装参数/WebShell/C2 间接通道）、**不编造结果**（"无输出原文，本轮不写入事实，避免无依据落库"）、诚实建议"稍后重试或人工确认"。待审队列 API 正常（total=0，因保守拒绝不排队直接拒） | `raw/hitl_trigger_task_resp.json`、`raw/hitl_e2e_conversation.json`、`raw/hitl_e2e_process_details_*.json`、`raw/hitl_pending_before/after.json` | ④人机协同 17-20 档 / ③"能有效应对干扰、不产生幻觉" |
| E-19 | **多通道 failover 语义边界实测**（S19"8 通道容错"的精确口径） | ✅ 代码级根因链钉死：①空配置时自动兜底所有已激活通道（`resolveEinoFailoverChannels`，eino_model_resilience.go:429 "开箱即用"）；②但 `ShouldFailover` 以 `isEinoTransientRunError` 为唯一判据（eino_transient_retry.go:30），**仅 408/409/425/429/5xx/网络类可切换**（isRetryableHTTPStatus:105）；③永久性 4xx（阿里云欠费 400）→ 不重试不切换 → 硬 500（实测 0.9-1.2s 失败，错误体 "overdue-payment, node path: [node_1, ChatModel]"）。**结论：failover 对瞬时故障有效、对通道级永久失效（欠费/无效 key）按设计不接管** | `raw/failover_qwen_forced_resp.json`、`raw/failover_default_chain_resp.json`、`raw/failover_default_chain_fixed_resp.json` | ②架构工程 / ⑤创新（诚实口径素材） |

## ⚠️ 诚实性备注（答辩口径统一用）

1. **E-04/E-05 现在有实证了**：S5/S9 的"实测返回 HTTP 403"可以保留原话，证据指向本文件。
2. **端到端 HITL 审批触发（带 LLM 的真实任务→审批队列→拒绝路径→倒计时挂起）**：本包未覆盖（需真实 LLM 任务驱动，避免重复消耗，由 A 线实验 E4 同步覆盖）；配置态证据（E-07）已齐。
3. **多通道"失败自动轮询"**：配置与代码依据在（`ai.channels` 8 通道 + `fallback`），端到端断言留给 A 线 E4（抗干扰实验）。
4. **沙盒说明**：本次实测在独立沙盒（拷贝 exe + 完整 tools/skills/agents/roles + 全新 data/），未污染项目 data/ 与并行会话工作区；沙盒管理员密码已重置为强密码，提交材料不受影响。

## 🔧 改进建议（赛后实施，答辩可引用）

- **P2｜通道级永久失效的 failover 升级**：当前 `ShouldFailover` 对所有 4xx 一律不切换。建议区分"请求级 4xx"（参数错误，不应浪费其他通道）与"通道级 4xx"（overdue-payment/invalid_api_key 等，故障在通道不在请求 → 应切下一通道）。实现位：`internal/multiagent/eino_transient_retry.go` 新增通道级 4xx 分类 + `eino_model_resilience.go:365` ShouldFailover 分支。当前规避手段：充值 qwen 或把 `default_channel`（config.yaml:95）切到可用通道。

## 复现步骤（评委/队友可重跑）

```bash
# 1) 沙盒：复制 exe + config.yaml + tools/ skills/ agents/ roles/ 到独立目录
# 2) 改 config.yaml: server.port=18099, mcp.port=18098
# 3) 启动 secautomind-ai.exe，读取 data/admin_initial_password.txt 中的初始密码
# 4) 按 raw/ 中 01→26 的 API 序列重放（登录→建 auditor→403 断言→审计回放）
```
