# 决赛就绪度自检清单（11 月实战赛备战）

> 用途：初审材料中"3 队员 + Agent 协同 / AI 安全网关接入"两类宣称的落地依据 + 11 月实战赛前逐项勾选。
> 对应赛题 XH-202609：终审所有 Agent 必须经主办方指定 AI 安全网关接入；以"3 名队员 + 自研 AI Agent"形式现场协同解题、赛题量超出纯人工处理能力。
> 更新：2026-09-11（B 线：网关适配器已就绪；协同 C1–C5 **已实现并通过机验**，见 §二落地证据）

---

## 一、AI 安全网关接入（B1）——4 项验收

**现状**：适配器为"配置级"（OpenAI 兼容通道天然可切换），不重编译、零业务代码改动；验收清单已脚本化。

| # | 验收项 | 脚本/载体 | 当前状态 | 临场操作 |
|---|---|---|---|---|
| G1 | 网关连通性（分配 Key 返回 200） | `bash scripts/verify_gateway.sh [1/4]` | ✅ 已脚本化，待现场实跑 | 填网关 base_url + Key 后执行 |
| G2 | 平台内 Agent 对话经网关（网关流量日志复核） | `verify_gateway.sh [2/4]` → `scripts/experiments/gw_probe.sh` | ✅ 探针已就绪（登录+最小任务+闭环判定），待网关开放后实跑 | 发探针 → 网关控制台核对本条流量 |
| G3 | 审计/限流策略对调试行为不误伤 | `verify_gateway.sh [3/4]`（代码解释+批量特征探测，200/429/403 分流） | ✅ 已脚本化，待现场实跑 | 若 429/403 → 网关侧调限额/加白 |
| G4 | 网关故障降级行为明确 | `verify_gateway.sh [4/4]`（错误 Key 注入应显式 401/403） | ✅ 已脚本化，待现场实跑 | 结果 401/403 = 显式报错不静默挂起 |

**配置位**：`config.yaml → ai.gateway`（enabled=false → 现场置 true，填 base_url/api_key；required=true 即 fail-closed 启动）。
**说明文档**：`docs/zh-CN/ai-gateway-compliance.md` §3（验收清单 ↔ 脚本 ↔ 操作说明已双向挂钩）。

**G 线临场 30 秒**：拿到网关地址+Key → `bash scripts/verify_gateway.sh --base-url <网关>/v1 --api-key <Key>` → 4/4 绿 → 演示。

---

## 二、3 队员 + Agent 协同作战（B2）——5 项验收

**已实现（2026-09-11）**，落地位 `internal/collab/` + `internal/database/collab.go`，REST 挂 `/api/collab/*`。协同 = 应对"超出纯人工处理能力"的题量，瓶颈不是单题能力而是任务分配与并发。

| # | 协同项 | 现有底座（可直接复用） | 缺口（internal/collab 实现） | 验收标准（11 月前勾选） |
|---|---|---|---|---|
| C1 | **席位模型**：3 队员席位 + N Agent 工作台 | `conversations` 表按会话隔离；`run_agent(role=...)` 已有角色透传；13 个 `roles/*.yaml` 角色（Web/二进制/取证/CTF…） | 席位概念层：席位 ↔ 会话 ↔ 角色的绑定与切换 API；队员席只读他人进度 | 3 人各开一席 + 2 个 Agent 工作台同时在线，各自下发任务互不串扰 |
| C2 | **任务池与原子领取**（防重复领取） | `projects`/`conversations` 已有归属概念 | 任务表（题目入池→状态机 待领/进行中/已完成/卡死退回）；原子领取（DB 事务 UPDATE…WHERE status=待领，防双人/双 Agent 互踩——西湖论剑教训：并发互踩 stuck_loop 7410 次） | 并发 5 个领取者抢 10 个任务，0 重复领取 |
| C3 | **并行进度总览**（一屏全览） | `process_details`/`tool_executions`/`hitl` 已逐题留痕 | 总览 API：任务×负责人(人/Agent)×状态×耗时×卡点聚合 | 演示现场一屏列出全部在途任务负责人/状态/耗时，卡点置顶 |
| C4 | **冲突与降级** | `audit` throttling、超时链路已有 | 并发上限、单任务墙钟硬限、卡死自动放弃并退池重领 | 人为注入卡死任务 → 墙钟到点自动退池，不阻塞其它任务 |
| C5 | **协同全程入审计**（维度③可追溯） | `audit.Entry`、`hitl` 裁决表已全量留痕 | 任务领取/放弃/结论写入审计（谁-何时-领何题-结论） | 赛后可按任务回放完整协同链（人 + Agent 各做了什么） |

**事实黑板**：`attack_chain_nodes` + `attack_chain_edges`（攻击链节点/边）可作为跨席位共享事实库（A 席发现的目标指纹/B 席的凭据直接喂给 C 席的后续利用），C 线无需新建表。

**演示口径**（初审材料可写，有底座支撑）：协同五要素 = 席位隔离 / 原子领取防互踩 / 一屏总览 / 卡死降级 / 全程审计。

**落地证据（2026-09-11，全部为机验，非宣称）**

| 验收项 | 机验证据 | 结果 |
|---|---|---|
| C2 原子领取 | `internal/database/collab_test.go` + `internal/collab/collab_test.go`：并发 5 领取者抢 10 任务，断言每任务恰好 1 个赢家、落败 40 次 | ✅ 通过 |
| C4 卡死回收 | 注入伪时钟越过墙钟硬限 → `ReapOnce` 精确回收 1 条；续期任务不被误杀且仍可完成 | ✅ 通过 |
| C1/F4 席位隔离 | 队员席冒用他人席位 → `ErrSeatForbidden`；非领取者完成/放弃 → `ErrNotAssignee`；读进度放行 | ✅ 通过 |
| C3 总览聚合 | 任务×负责人×状态×耗时×卡点；卡点置顶，席位负载与按状态计数断言 | ✅ 通过 |
| C5 全程审计 | `audit.Entry` 落 `collab` 分类；按 `resource_id`（任务 ID）可回放领取+完成链 | ✅ 通过 |
| **变异验证** | 移除领取 WHERE 的 `status` 守卫 → 并发测试 FAIL（「被领取 5 次」）；移除 reaper 的墙钟守卫 → 回收数变 2，续期保护 FAIL | ✅ 两处均被测试捕获 |

接口面：`/api/collab/{overview,seats,seats/:id,tasks,tasks/:id,tasks/:id/{claim,complete,abandon,renew},reaper/run}`，权限复用既有 `tasks:read|write|delete`，未新增权限项。

---

## 三、模型预报备清单（终审前填表）

| 项 | 内容 | 状态 |
|---|---|---|
| 使用模型 | 通义千问 qwen-max（阿里云，已备案）/ DeepSeek-V3（已备案） | 通道已配；**当前默认 deepseek（qwen 欠费 400，演示前充值或保持 deepseek）** |
| 提供方 | 阿里云计算有限公司 / 杭州深度求索 | — |
| 接入方式 | HTTPS API（OpenAI 兼容），终审经安恒 AI 安全网关 | G1-G4 脚本验证 |
| 数据出境 | 无（模型与网关均在境内） | — |
| 密钥管理 | `${VAR}` 环境变量注入不落盘；`config.yaml` 已 gitignore | ✅ |

---

## 四、提交/演示前最终自检（T-0 Checklist）

```bash
# 1. 网关（若已拿到现场网关）
bash scripts/verify_gateway.sh --base-url <网关>/v1 --api-key <Key>      # 期望 4/4 PASS

# 2. 平台健康（本地演示态）
bash scripts/experiments/gw_probe.sh --message "输出OK"                   # 期望 finalized=True

# 3. 密钥零残留（打包前必跑）
# ⚠️ 2026-09-08 修正：旧的 grep -E "sk-[A-Za-z0-9]{16,}" 匹配不到 sk-ws-H.xxx
#    （第 4 位是连字符即断匹配），一把真实存活的 key 正是从这个洞漏过去；
#    且旧命令只扫 docs/ PPT/，完全漏掉 config.yaml（被 gitignore 但会进交付包）。
#    现统一改用 scripts/secret_guard.py：全仓扫描 + 自动区分占位符/测试夹具/CTF flag + 输出打码。
python scripts/secret_guard.py          # 期望 [PASS]；exit 1 表示发现真实凭证，禁止打包
```

| 勾 | 项 | 依据 |
|---|---|---|
| □ | 网关 4/4 绿（或现场未发网关时 enabled=false + 已演示降级路径） | verify_gateway.sh 输出 |
| □ | 协同 5 项：至少 C1/C2/C5 已演示（席位隔离 + 原子领取 + 审计留痕） | 演示录像/截图 |
| □ | 模型报备表已填、密钥已脱敏、`config.yaml` 不进提交包 | 提交包结构与发送清单 |
| □ | 三编排实测数据回填报告第四章（E1/E2/E3/E5） | evidence_index / 实测数字速查卡 |

---

## 五、工具链依赖口径（答辩必答，务必主动讲清）

> 证据：`docs/evidence/tool-dependency-audit-20260905.{json,md}`，一键复跑 `python scripts/experiments/audit_tools.py`

**绝不能只报一个"91 个工具只有 18% 能跑"**——那会把两类完全不同的东西混为一谈，既低估自己，也经不起追问。正确口径是三分类：

| 类型 | 总数 | 本机可跑 | 说明 |
|---|---|---|---|
| **自研内联脚本** | 17 | **12** | 实现以 Python 内联在 YAML 中，属平台自带能力，跨平台、零二进制预装要求 |
| **外部二进制契约** | 73 | **3** | nuclei / nmap / sqlmap 等，环境有则用，无则自动降级（契约层设计） |

**一键满血路径**：自研脚本不可用的 5 个，**全部**只因通用第三方包缺失（无一是二进制依赖）：
`pip install chardet charset_normalizer h2 httpx requests` → 自研工具可达 **17/17（100%）**。
（本机未装，以保持"纯净环境"这一最严格的基线口径；现场环境通常自带 requests 等。）

**答辩答法（"你的 91 个工具都能跑吗？"）**：
1. 17 个是**我们自研的**纯 Python 实现，写在工具定义里，跨平台零二进制依赖；
2. 73 个是**外部工具契约**，环境装了就用，没装自动降级、不阻塞任务；
3. 本机纯净环境实测：自研 12/17、外部 3/73 —— **Agent 在 70 个外部工具缺失的条件下，仍完成端到端闭环并达到漏洞召回 5/6**，这正是降级能力的实证；
4. 想满血只需一条 pip 命令（依赖极轻）。

---

## 附：11 月实战前实现路线（post-初审）

1. `internal/collab/`：任务表 + 原子领取（DB 事务）+ 席位绑定 + 总览聚合 API + 墙钟硬限（接入现有 audit/超时链路）。
2. 网关现场适配：拿到真实网关地址后实跑 G1-G4，按 429/403 结果在网关侧调策略（我方代码零改动预期）。
3. 3 人协同演练：按 C1-C5 验收标准做一次"10 题混发 + 3人2Agent"全流程彩排，卡点与互踩实测清零。
