# 决赛日 Runbook（v0.2 · 2026-10-25 runner_v4 实栈固化）

> 用途：下一场目标赛事（2027-03-01 决赛及之前任何一场）开赛前后的**执行清单**。
> 来源：羊城杯（25 次提交教训）+ CTF² 快闪赛（9/9 但两起事故）+ 两晚工程善后 + runner_v4 三层链 + main 合并实栈。
> 铁律：**拿分是唯一目标**；每 15 分钟自问"这一步直接产生分吗"，答否就停。
> v0.1 → v0.2 变更：runner_v4 三层链替代引擎式 runner；tar+scp 部署链；env vars 表；force-claim/dry-run flag；L3 untested risk；事故树增进程冲突行。旧架构（ctf-agent/引擎式）已废弃。

---

## runner_v4 快速卡（贴墙上）

### 部署链（github 直连 443 timeout；Gitee 镜像未建前用这条）
```bash
# 本机（Windows PowerShell）
tar czf "$env:TEMP/runner_cmd.tar.gz" -C cmd runner
tar czf "$env:TEMP/ctfplatform.tar.gz" -C internal ctfplatform
scp "$env:TEMP/runner_cmd.tar.gz" "$env:TEMP/ctfplatform.tar.gz" user@172.16.222.99:~/

# 服务器（172.16.222.99，user 账号）
ssh user@172.16.222.99
  export PATH=/usr/bin:/usr/local/bin:/home/user/go1.25.4/bin:$PATH
  cd ~/sm_dev_20261020
  tar xzf ~/runner_cmd.tar.gz -C cmd/
  tar xzf ~/ctfplatform.tar.gz -C internal/
  export GOPROXY=https://goproxy.cn,direct
  go build -o ~/ctf_run/runner_v4 ./cmd/runner
  ~/ctf_run/runner_v4 --help   # 验证：--dry-run + --force-claim
```

### 启动（服务器）
```bash
# 先看环境变量 → runner_v4 启动
export CTF2_AGENT_TOKEN=sk-xxx
export CTF2_COMPETITION_ID=xxx
# L3（可选；没 API key 就跳过，L1+L2 仍工作）
export RUNNER_LLM_FALLBACK=true
export RUNNER_LLM_API_KEY=sk-deepseek-xxx
# 赛前 dry-run（解题不提交）
~/ctf_run/runner_v4 --dry-run
# 正式开跑
~/ctf_run/runner_v4
# 检测到已有 runner → 拒绝启动（exit 1）；强抢：
~/ctf_run/runner_v4 --force-claim
```

### env vars 表
| env | 必填 | 默认 | 说明 |
|---|---|---|---|
| `CTF2_AGENT_TOKEN` | ✅ | - | 平台认证 |
| `CTF2_COMPETITION_ID` | ✅ | - | 比赛 ID |
| `RUNNER_LLM_FALLBACK` | | false | 启 Layer 3（无 API key 跳过） |
| `RUNNER_LLM_API_KEY` | | - | L3 必须（deepseek） |
| `RUNNER_LLM_BASE_URL` | | `api.deepseek.com/v1` | |
| `RUNNER_LLM_MODEL` | | `deepseek-reasoner` | |
| `RUNNER_LLM_TIMEOUT_SEC` | | 60 | |
| `RUNNER_LLM_MAX_TOOL_CALLS` | | 5 | |
| `RUNNER_LLM_MAX_ROUNDS` | | 3 | |
| `CTF_POLL_INTERVAL` | | 30 | |
| `CTF_SOLVE_TIMEOUT` | | 300 | 单题总超时 |
| `CTF_MAX_CONCURRENCY` | | 2 | 并发题数 |
| `CTF_AUTOSOLVE_SUBMIT` | | true | 赛时默认自动提交 |
| `CTF_AUTO_BUILD_ENV` | | true | 自动起靶机 |
| `CTF_AUTO_FETCH_ATTACHMENT` | | false | 附件默认关（需显式开） |
| `CTF_AUTO_FETCH_DETAIL` | | true | 题干详情默认开 |
| `CTF_AUTO_RELEASE_ENV` | | true | 解出后自动回收靶机 |

### 三层求解链（Solver 闭包）
```
Layer 1: Presolve 189 Go solver         → ch.SolvedBy = "presolve"       0 token
Layer 2: Python skill bridge (angr/pwntools) → ch.SolvedBy = "python_skill"  0 token
监督反思（L1+L2 后）→ ABANDON: 跳 L3 省 LLM token / SWITCH: 打 warning
Layer 3: LLM fallback + 工具绑定（execute_python + read_attachment）→ ch.SolvedBy = "llm" 烧 token
监督短路：ReflectSupervision 每轮后决策
```

### 已知风险（L3 untested）
- **Layer 3 工具绑定 loop 从未真机跑过**：`tc.Function.Name` / `schema.NewParamsOneOfByParams` API surface 是从 Eino docs 逆向推出，可能静默 fail。
- **Mitigation**：L1+L2 独立工作；监督 ABANDON 省 L3 token；runner 不崩溃——最差情况 L3 跳过、前两层照常解。
- **决赛前 smoke test**（有 deepseek API key 必跑）：`RUNNER_LLM_FALLBACK=true RUNNER_LLM_API_KEY=sk-xxx ~/ctf_run/runner_v4 --dry-run` 等 3 题看 SolvedBy 有没有 "llm"。

### 归因字段（看板侧消费）
`Challenge.SolvedBy` / `PollRecord.SolvedBy` → `"presolve"` / `"python_skill"` / `"llm"`。**严禁冒充**：presolve 真命中不许写 llm（立尺 E3 实证 14/15 冒充链路能力）。

---

## T-24h（赛前一天，工程冻结前）

- [ ] 跑赛前预检：`python scripts/race_preflight.py`（GO 才上场；NO-GO 逐项修，
      确属误报才处理并在复盘留痕）
- [ ] 确认 runner_v4 部署到服务器：`~/ctf_run/runner_v4 --help` 输出 flag 帮助
- [ ] **L3 smoke test**（有 deepseek key 必跑）：`export RUNNER_LLM_FALLBACK=true; export RUNNER_LLM_API_KEY=sk-xxx; ~/ctf_run/runner_v4 --dry-run`；等 3 题看 SolvedBy
- [ ] Docker 在跑、`ctf-sandbox:latest` 镜像在；磁盘 >10G（Windows 本机腾内存 >4G）
- [ ] 提交格式注册表已核对目标平台；**表里没有的平台，赛前用已知正确串裸/带壳各试一次**
- [ ] runner 起飞内存预检阈值合理；本机关掉非必要 IDE/Agent 进程

## T-30min（开赛前）

- [ ] 令牌探测：`GET /api/open/v1/user/agent/me/` 返回 agent active ✓
- [ ] 比赛 entered=true（没有就 enter，别等开赛才发现没进场）
- [ ] 拉题目列表，按三色分类：**已解（跳过）/ 附件源码题（最优先，presolve 确定性）/
      容器交互题（排后，起靶机有启动延迟+平台频率限制）**
- [ ] **提交通道打通**：用已知正确串走完整提交链路，确认返回码形态
      ——"解题不需要令牌，提交才需要"；开赛第一件事是提交，第二件才是解题

## T-0（开赛）

- [ ] 启动顺序：预检 GO → 确保 entered → 服务器拉题目列表 → `~/ctf_run/runner_v4`
      （**一场比赛只允许一个 runner；runner 内置 detectConflictingProcs 自动拦截重复启动**）
- [ ] 进程冲突：启动若报 `已有进程在跑，拒绝启动` → 先查是不是自己人（ps -ef | grep runner），
      确认是残留僵尸就 `~/ctf_run/runner_v4 --force-claim` 强抢
- [ ] runner 参数：env vars 全部就位后直接 `~/ctf_run/runner_v4`，不需要额外 flag
- [ ] 前 30 分钟盯三件事：首轮 poll 是否拉到题、前几次提交 HTTP 状态与 flag 格式、
      **SolvedBy 分布是否异常**（presolve 全中 → L2/L3 没用上；全 miss → presolve 该加 solver）

## 赛中（每 15 分钟一个节拍）

- [ ] 自问：这一步直接产生分吗？（读日志/看板/调格式都不直接产分——设时限）
- [ ] 提交失败：**先疑格式/通道，不疑答案**。连续 3 次同形态失败 → 停下来做通道对照
      （裸/带壳各发一次），不要在内容上继续枚举（羊城杯 25 次的教训）
- [ ] runner 猝死（零日志）：先查内存（`free`），再查是否被并行会话误杀；
      重启前先腾内存或减并发
- [ ] 单题卡住 >超时值：poller 自动退避换题——**别人工抱着难题啃**，分值要让位给能拿的分
- [ ] 环境槽位 409：退出时交还机制应已处理；若仍在，`DestroyInstance` 手动释放再重试

## 赛后（30 分钟内）

- [ ] 平台 entry 页截图（战绩数字只认平台：score/rank/solve_count，**自算合计会错——
      快闪赛标分 974 vs 平台 1049**）
- [ ] 归档：trace/作战板/提交记录/成本汇总（`logs/cost_*.json`）→ 复盘文档
- [ ] 复盘三问：哪一步直接产生了分？哪一步是代理指标（看着在推进其实不产分）？
      哪个事故能变成明天的纪律/代码？（今晚：内存守卫、格式注册表、租约，都这么来的）
- [ ] Runner 收尾：服务器 `pkill -f runner` 进程清理；靶机确认已回收

## 事故决策树（速查）

| 症状 | 第一怀疑 | 动作 |
|---|---|---|
| 提交全错 | 格式/通道 | 裸/带壳对照实验 |
| runner 秒退零日志 | 内存耗尽被杀 | 腾内存；看 dmesg/OOM |
| runner 秒退有日志 | 令牌/比赛状态 | 看 stderr 首行；agent/me 探测 |
| 启动被拒（已有进程） | 残留僵尸进程 | `~/ctf_run/runner_v4 --force-claim`（先 ps 确认是僵尸） |
| 容器 409 | 环境槽位未交还 | 手动 DestroyInstance |
| solver 不动 | 假卡死误判 | 看 stderr 时间戳+CPU+容器，三者有一活跃即别杀 |
| 双会话互踩 | 无租约 | 一场一 runner；runner 内置冲突检测自动 gate |
| SolvedBy 全 miss | presolve 没命中 | 赛后补 solver；赛中跳过等下一轮 |
| L3 报错但 L1/L2 正常 | API key / deepseek 限流 | 不致命；L1+L2 继续拿分；赛后修 |
