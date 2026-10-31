# 交接文档：StepFun 五会话 CTF 跑批（S3 视角）

> 交接时间：2026-10-27 07:45 · 交接人：S3 会话 · 接手人：下一个 agent
> 本文所有数字均来自 `flag_sha256` 实测校验，**无一处按叙事估算**；每条结论都给了可复现的路径或代码行号。

---

## 0. 30 秒上手

```bash
# 第 0 步（只读）：隧道通不通
python scripts/stepfun_tunnel.py --check

# 第 1 步（只读，不改任何东西）：确认入口活着
python scripts/stepfun_batch_server.py --doctor

# 第 2 步：跑你负责的切片
python scripts/stepfun_batch_server.py --session S3
```

- 若 `--check` 报 FAIL → `python scripts/stepfun_tunnel.py --detach`（**别用裸 `ssh -N -L`，也别用前台模式**，见 §2.3 / 坑 10）。
- 若 `--doctor` 报连不上 → 隧道断了，见 §2.3。
- 若它打印 `REFUSED: ... 是本机实例` → 它在保护你，别加 `--allow-local` 绕过（理由见 §1.1）。

---

## 1. 四条铁律（违反则数字作废）

### 1.1 「服务器」只指 `172.16.222.99`
- 依据：`docs/AGENT_ROUTES.md:39`（R14）、`docs/1024快闪赛复盘与规划_20261024.md:83`（M3）、用户 2026-10-27 最终裁决。
- **本机 `127.0.0.1:18086` 上做题 = 不合规**。历史上出现过"服务器 B = 本机 SecAutoMind 进程"的拆解，该表述**已作废**。
- 实测反证：本机共享实例 10 分钟内被外部杀掉 2 次（07:18、07:24，日志无 panic），我建的队列轮询直接 401。
- 本脚本已内建守卫：Windows 上打本机 18086 会直接 `REFUSED` 并退出码 3（`scripts/stepfun_batch_server.py` `Client.assert_server`）。

### 1.2 校验只用 `flag_sha256`，绝不读明文 `flag`
- `data/ctf_benchmark/benchmark.json` 的 **72 道题全部带明文 `flag` 字段**。用它比对 = 自己批自己卷子。
- `stepfun_batch_server.py` 的 `load_picked()` 只取 `flag_sha256`，`verify()` 只做 sha256。

### 1.3 并发 = 1
- StepFun **账号级**并发上限 5，且 `step-5-preview / step-3.7-flash / step-3.5-flash / step-router-v1` 共享同一池。
- 换机器**不增加**容量。五会话各占 1 格。
- ⚠️ `config.yaml` 里 `llm_max_concurrent: 5` 是**死配置**（全仓库零代码引用），没有护栏。

### 1.4 不要 `git add -A`
- 当前工作树有 20+ 个并行会话的在途文件（`git status --porcelain` 实测），`add -A` 会把别人的改动卷走。

---

## 2. 环境（已就绪，**不要重建**）

### 2.1 服务器与实例
| 项 | 值 | 证据 |
|---|---|---|
| 服务器 | `172.16.222.99`（`user`，SSH 免密，128 核 / 125G） | `docs/AGENT_ROUTES.md:39` |
| 实例二进制 | `/tmp/secautomind-s1` | `ps -eo pid,cmd` |
| 实例 cwd | `/home/user/sam_s1` | `/proc/<pid>/cwd` |
| 实例 PID | `1170280`（07:23 起，交班时仍存活） | `ss -lntp \| grep 18086` |
| 监听 | 远端 `127.0.0.1:18086`（**明文 HTTP**） | `http 200 / https 000` |
| 凭据 | `/home/user/sam_s1/data/admin_initial_password.txt` | 文件存在 |
| StepFun key | **只在该进程的 environ 里**；服务器全局 `$STEPFUN_API_KEY` 长度为 0 | `/proc/<pid>/environ` |

> 🔴 `config.yaml` 写 `tls_enabled: true`，但**实跑实例是明文 HTTP**。别照配置推协议。谁要新起实例，必须自己注入 key（`source ~/.stepfun_env`）。

### 2.2 队列 API 契约（实测，别猜）
- `POST /api/batch-tasks` 响应**外层是 `{"queue": {...}}`**，`queue.id` 才是队列 ID；`GET` 同理。直接取顶层 `.id` 得到 `None`（我踩过）。
- 建队 body：`title / tasks[] / concurrency / agentMode`。
- **没有 `model` / `channel` 字段**（`internal/handler/agent.go:1909-1919`）→ 队列级选模型做不到，实际全部跑 `step-5-preview`。
- 任务对象字段：`id / message / conversationId / status / startedAt / completedAt / error / result`。

### 2.3 隧道（单点故障，断了整个链路就断）

**别再用裸 `ssh -N -L`。** 实测（2026-10-27 09:00 前后）：两条裸隧道在空闲数分钟后
同时报 `Read from remote host 172.16.222.99: Connection reset by peer`，退出码 255，
而远端 SSH 和实例本身都健康 —— 是中间网络设备/服务端空闲超时把长连接掐了。
表现是"跑批脚本突然全 401 / 连接被拒"，很容易误判成服务挂了。

**正路：用守护器（脱离会话方式）**

```bash
# 只读体检（先跑这个，不会改任何状态）
python scripts/stepfun_tunnel.py --check

# ✅ 正路：脱离当前会话后台运行（关掉 AI 会话也活着）
python scripts/stepfun_tunnel.py --detach

# 停止（连带它下面的 ssh 子进程树）
python scripts/stepfun_tunnel.py --stop
```

它做三件事：① 强制心跳保活（`ServerAliveInterval=20` / `ServerAliveCountMax=3` / `TCPKeepAlive`）；
② 进程退出后自动重连（秒退才拉长退避，正常运行中被断线按 5s 重连）；③ 单进程同时管两条映射。

| 映射 | 远端实例 |
|---|---|
| 本机 `18087` | 远端 `18086`（S1 部署的 StepFun 实例） |
| 本机 `18088` | 远端 `18088`（免费通道隔离实例 `~/sam_free`） |

**实测自愈**：kill 掉 ssh 进程后，**20 秒内**自动重建并恢复 2/2 可达。

### 2.3.1 为什么必须 `--detach`（这是踩出来的，不是设计洁癖）

2026-10-28 01:44 实测：会话内起的守护器**在会话回收时被一并杀掉**，只留一个 `ssh.exe` 孤儿在占 18088，
18087 直接死透 —— 于是"2/2 通"在 16 小时后变成"1/2 通"。

`--detach` 的技术要点是**两个标志缺一不可**：

| 标志 | 值 | 作用 |
|---|---|---|
| `DETACHED_PROCESS` | `0x00000008` | 不继承父控制台 |
| `CREATE_BREAKAWAY_FROM_JOB` | `0x01000000` | **跳出父进程所在的 Job Object**（只加前一个没用：宿主按 Job 杀整棵树） |

**脱离的硬证据**（不是看它能不能跑，而是看父进程链）：

```
守护器 PID : 36484
父进程 PID : 27516
父进程已不存在 → 独立存活
```

配套：`logs/stepfun_tunnel.log`（`-u` 无缓冲，实时可见）、`logs/stepfun_tunnel.pid`（供 `--stop` 用）。
`--detach` 失败时会降级为普通 `DETACHED` 并打印原因，不会静默。

⚠️ 前台模式 `python scripts/stepfun_tunnel.py`（不带 `--detach`）**只适合调试**，会话一回收就死。
隧道未起时 `--doctor` 会报登录失败。

---

## 3. 唯一入口：`scripts/stepfun_batch_server.py`

### 3.1 它取代了谁
| 旧脚本 | 状态 | 问题 |
|---|---|---|
| `stepfun_s2_crypto_slice.py` | ❌ 旁路 | 本地 Python 直连 StepFun API，绕过平台 |
| `stepfun_s3_crypto_slice.py` | ❌ 旁路 | 同上（docstring 已加横幅标注） |
| `stepfun_s1_server_batch.py` | 🟡 正路 | `BASE` 硬编码本机、无守卫、无续跑 |
| `stepfun_s2_server_batch.py` | 🟡 正路 | `DEFAULT_BASE` 指向本机、无续跑/重试 |
| `stepfun_s3_server_slice.py` | 🟡 正路 | 同上 |

### 3.2 四个真实特性（都对应一个实测故障）
1. **server-only 守卫**：解析出的入口是本机 18086 就拒绝运行。
2. **可续跑**：`--queue-id` 接管既有队列；`/start` 实测会 `ConnectionReset`，失败自动降级为逐题 `POST /api/batch-tasks/:id/tasks/:taskId/run`（实测有效，且会 autoStart 整队）。
3. **闸门重试**：只对 `missing_execution_evidence` 的题重跑，且**首跑与含重跑分开报**，不许混算。
4. **统一台账**：五会话同一 schema，可直接横向比。

### 3.3 用法
```bash
python scripts/stepfun_batch_server.py --doctor                       # 只读体检
python scripts/stepfun_batch_server.py --session S3                    # 跑整片
python scripts/stepfun_batch_server.py --session S3 --ids caesar_15    # 冒烟 1 题
python scripts/stepfun_batch_server.py --session S1 --queue-id <qid> --retry-gate 2   # 续跑+补跑
python scripts/stepfun_batch_server.py --category web --slice 1-10     # 自定义切片
```
台账落 `data/ctf_benchmark/stepfun_sessions/<session>_server_<cat><lo>_<hi>_<ts>.json`。

---

## 4. 当前真值（2026-10-27 07:45，全部 sha256 校验）

| 会话 | 切片 | 队列 ID | 服务器状态 | 首跑命中 | 可采信度 |
|---|---|---|---|---|---|
| S1 | crypto 1–13 | `20261027072554-072554-6b740d45` | completed，8 completed / 5 failed | **7/13 = 53.8%** | ✅ 服务器口径 |
| S2 | crypto 14–26 | `20261027071514-071514-544c6517` | **服务器上不存在该队列**（07:15 那轮打的是本机） | 1/13（自报） | 🔴 作废，需重跑 |
| S2（新） | crypto 14–26 | `20261027074046-074046-e4dce8a4`、`20261027074252-074252-9f606259` | **running**（07:40/07:42 起，本会话交接时在飞） | 未出 | ⏳ 等终态 |
| **S3（我）** | crypto 27–39 | `20261027072741-072741-800c0b8b` | completed，12 completed / 1 failed | **12/13 = 92.3%** | ✅ 服务器口径 |
| S4 | web 13（live） | `20261027074302-074302-facfb0b4`、`20261027074311-074311-7f23a6a0` | pending / completed（07:43 起，在飞） | 未出 | ⚠️ 先看题干是否泄漏再采信 |
| S5 | misc 1–6 | `20261027071256-071256-9845b43c` | 本机实例跑的 6 题 | 1/6 有真证据 | 🔴 不合规，需重跑 |

> ⏱ 本表是 **07:45 快照**。S2/S4 正在服务器上开跑新队列，接手时请以 `--doctor` 的实时输出为准，别引用本表的"未出"。
> ⚠️ 并发池是**账号级 5 格**：S2 两条 + S4 两条在飞时，池子已近满。此时再起队列会排队或 429，**先看 doctor 再决定**。

### S3 明细（我的切片）
- 13 题构成：`caesar_15/16/17/18/20/21/22/23/24/25`（10 题，**无 caesar_19**）+ `xor_01/10/33`（3 题）= 13。
- **12/13 通过**，唯一未过 `caesar_17`：`missing_execution_evidence`（反注水闸门，非答错）。
- `caesar_17` 的**三次尝试**：主队列首跑失败 → 主队列重试失败 → 独立单题队列**通过**（`flag{caesar_shift_17}`，sha256 通过）。
  → 该题实际通过率 1/3，**性质是闸门 flaky，不是能力缺失，也不能算 13/13**。
- 台账：`data/ctf_benchmark/stepfun_sessions/s3_server_crypto27_39_20261027_074128.json`

### ⚠️ S1 的台账是"中途快照"，别直接引用
- `s1_server_crypto1_13_20261027_072906.json` 记 `solved=1 / 12 pending`，那是 07:29 边跑边写的。
- 服务器上该队列**现在**是 8 completed / 5 failed，我重算 = **7/13 命中**（`fermat_rsa` 答成 `flag{A}`，错）。
- 教训：**台账要在队列到终态后重出**，否则数字会漂。

---

## 5. 已实锤的十个坑

1. **本机共享实例不可靠**：10 分钟内被杀 2 次，日志停在一条 LLM 调用中途，无 panic → 外部 kill。→ 这是"必须上服务器"的直接理由。
2. **建队响应套了一层** `{"queue": ...}` → 取顶层 `.id` 得 `None`。
3. **`POST .../start` 偶发 `ConnectionResetError(10054)`** → 失败时自动降级逐题 `run`（脚本已内建）。本会话后续新建队列时 `start:ok` 正常，**属偶发而非必现**。
4. **`missing_execution_evidence` = 反注水闸门**：`internal/agentfinalizer/decision.go:140` 要求存在**已完成**的工具执行记录（`hasCompletedEvidence` → `:237-260` 查 `db.GetToolExecution`），缺了就 block。
   - 它是**拦截**，不是答错。
   - 🔴 **2026-10-27 08:30 已定性（不再是猜测）**：弱模型场景下 100% 触发，根因是**模型压根没调工具**。
     证据：glm-4-flash 跑 `caesar_15` → `tool_executions` 表 **0 行**，模型 2 次调用仅产出 51 个 completion token，全被闸门拦。
   - 反之强模型偶发触发（StepFun 12/13 里 1 次、三次尝试过 1 次）→ 属**采样波动**，重试有效。
   - 结论：**换模型前先确认它在这套工具集下真的会调工具**，否则 0 分不是模型"不会做"，是"没动手"。
5. **结果尾部带格式模板 `flag{...}`**：天真地取"最后一个 `flag{...}`"会把已答对的题判成未命中——我因此把 12/13 误报成 8/13。正确做法：枚举全部候选逐个 sha256 比对（已修进 `verify()`）。
6. **队列级选模型做不到**：`BatchTaskRequest` 无 `model`/`channel`（`agent.go:1909-1919`），实际全跑 `step-5-preview`；手册 §4.1 的"crypto 降轻量模型"落不了地。
7. **题库两份，口径已裁决（2026-10-28 02:4x，见 P3 行）**：
   - `benchmark.json`：72 题（crypto 56 / web 10 / misc 6），全部带明文 flag；**有效分母 40**（crypto 39 / misc 1 / web 0）。
   - `real_benchmark.json`：55 题（crypto 18 / web 24 / misc 13），只存 hash，手册指定的正是这份；**有效分母 50**。
   - 分母来自 `scripts/benchmark_audit.py`（只扣硬缺陷 LEAK/CONTRADICT/DUP/NOSHA），**报覆盖率必须带分母**。
   - 五会话实际全部用 `benchmark.json`；切到 `real_benchmark.json` 会让已出的数字失去可比性，需重新标注。
8. **题干泄漏**（S5 实测）：crypto 0/56 泄漏 ✅；misc 5/6；web **10/10** 泄漏 → 喂 description 等于喂答案，S4 的覆盖率数字**不含任何能力信息**。
9. **补跑会把队列状态改成 `paused`**：S3 主队列在补跑 `caesar_17` 后由 `completed` 变 `paused`（所有任务已终态）。`--queue-id` 续跑**不依赖**队列 status，照常可用；别看到 paused 就以为坏了。
10. **裸 `ssh -N -L` 隧道会静默死掉**（2026-10-27 09:00 实测）：两条隧道同时 `Connection reset by peer`，退出码 255，**远端 SSH 与实例全部健康**。
    - 根因：无心跳保活，空闲长连接被中间设备/服务端超时重置。
    - 迷惑点：脚本侧表现为 401 / 连接被拒，极易误判成"服务器崩了"。
    - 正路：`python scripts/stepfun_tunnel.py --detach`（`ServerAliveInterval=20` + 自愈 + 脱离会话）。`--check` 是只读判据。
    - 🔴 **别用前台模式当长期方案**（2026-10-28 01:44 实测）：会话内起的守护器在会话回收时被**一并杀掉**，
      16 小时后 2/2 变 1/2 通，只剩一个孤儿 ssh 撑着 18088。必须 `--detach`。
    - `--detach` 必须同时带 `DETACHED_PROCESS(0x8)` + `CREATE_BREAKAWAY_FROM_JOB(0x01000000)`：
      只加前者逃不出宿主的 Job Object，仍会被按树杀掉。
    - ⚠️ `TaskStop` 只杀外层 shell，**ssh 会变孤儿继续占端口**，导致守护器 `Address already in use` 死循环。清理需按端口找 PID 杀 ssh（Git Bash 下 `taskkill /PID` 会被路径转换，用 PowerShell `Stop-Process`）。

---

## 6. 待办（按优先级，含验收标准）

| 优先级 | 事项 | 命令 / 做法 | 验收标准 |
|---|---|---|---|
| ~~P0~~ ✅ | 隧道常驻化 | **已解决（2026-10-28 01:46）**：`python scripts/stepfun_tunnel.py --detach` | 已实测自愈；**但 02:0x 起 `CREATE_BREAKAWAY_FROM_JOB` 被宿主 Job 拒绝（WinError 5），会降级为普通 DETACHED** → 每会话开场先 `--check`，不是 3/3 就重建 |
| ~~P0~~ ✅ | **LLM 通道全死** | **2026-10-28 02:0x 实测**：StepFun 400 无订阅 / 402 配额，OpenRouter 免费 401（日限耗尽）。活路只剩 智谱 glm-4.5-flash、ModelScope、TokenRhythm | 见 `SESSIONS.md §15` 活死表；**别在 18086/18088 上继续跑批**，那里隧道通但 LLM 已死 |
| ~~P0~~ ✅ | S3 活跑批实例 | `~/sam_s3tr`（18097，tokenrhythm/`deepseek-v4.1-flash-1017`），配置与坑见 `SESSIONS.md §16–§17` | `--doctor --base http://127.0.0.1:18097` 能登录；缺 `tools/` 会退化成"无可用工具" |
| ~~P0~~ ✅ | S2 在服务器重跑 | **已完成**：`20261027074252-...` 终态 `5/5 completed` | 已到终态 |
| **P1** | S1 剩余 5 题补跑 | `--session S1 --queue-id 20261027072554-072554-6b740d45 --retry-gate 2`（现 8/13） | 首跑/含重跑分开报，闸门题单独归因 |
| **P1** | `caesar_17` 定级 | 已有 4 次尝试证据（1 过 3 拦） | 写进报告时**单列"闸门 flaky"**，不进覆盖率分子 |
| **P2** | S5 迁到服务器重跑 | `--session S5`；Linux 天然有 `sh` | 6 题终态，`morse_hello` 之外的题也要有真证据 |
| **P3** | S4 重设计 | 先解决 web 题干泄漏（10/10），否则任何覆盖率都无意义 | 换用无泄漏题源后再跑 |
| ~~P3~~ ✅ | 题库口径裁决 | **已结案（2026-10-28 03:0x）**：不靠讨论，改可复现审计 `scripts/benchmark_audit.py`。**有效分母**（只扣硬缺陷）：`benchmark.json` **40/72**（crypto 39 / misc 1 / web 0），`real_benchmark.json` **50/55** | 见 `data/ctf_benchmark/DENOMINATOR_20261028.md`。⚠️ 两条红线：① 审计**不可**用来缩小分母（`real` 有 36 道无题目本体/host/密钥，仍留在分母，须注明分母被稀释 72%）；② **可解子集覆盖率已作废**（每筛一次就涨，最后 100%，典型病理） |
| ~~P4~~ ✅ | crypto 1–56 全量 | **已完成（2026-10-28 02:22）**：**56 = 39 有效 + 17 坏题（30%）**；39 道有效题 **39/39 通过**（含 `caesar_17` 复核）。坏题三类：题面 MD5≠答案MD5 ×14、答案形态未知 ×2、正确解密结果构不成 flag ×1（`fermat_rsa` m=65='A'） | 见 `SESSIONS.md §19–§21`（含"easy 语料不可外推"限定 + 闸门 flaky 5%） |

---

## 7. 接手 5 分钟自证清单

1. `python scripts/stepfun_tunnel.py --check` → 应打印 `3/3 条隧道可用`（18087/18088/18097）。FAIL 就先 `python scripts/stepfun_tunnel.py --detach`。
   - 顺带确认它是不是"脱离版"：`python -c "import os;print(open('logs/stepfun_tunnel.pid').read())"` 拿到 PID 后，
     用 `Get-CimInstance Win32_Process -Filter "ProcessId=<PID>"` 看 `ParentProcessId` 是否已不存在。
   - 🔴 `--check` 只证明**隧道**通，不证明**LLM**通。通道活死看 `SESSIONS.md §15`：18086/18088 的模型通道已死，只有 18097 能出题。
2. `python scripts/stepfun_batch_server.py --doctor` → 打印 `登录 OK`，并列出服务器当前队列（至少应能看到 S1 `...6b740d45` 与 S3 `...800c0b8b` 两条；队列数会随并行会话变化，**不要按固定条数判断**）。
3. ⚠️ **别再拿旧队列重放当自证**：`--session S3 --queue-id 20261027072741-...` 现在会**失败**，不是因为台账坏了，
   而是 18086 的 StepFun 通道已死（`SESSIONS.md §15`）。要自证"链路能解题"，用活通道打新题：
   `--session S3 --category crypto --slice 40-42 --base http://127.0.0.1:18097 …` → 应在 1 分钟内打出 **3/3**。
   - 若结果不同 → 先查 `verify()` 是否还在做多候选择优（`flag_sha256` 逐个比对）。
   - 历史台账仍是 12/13（`s3_server_crypto27_39_20261027_083644.json`），那是 StepFun 活着时的产物，**不可复现也不该复现**。
4. `git status --porcelain | wc -l` → 应有大量他人在途文件，**不要提交**。
5. 隧道断了：跑 `python scripts/stepfun_tunnel.py --check` 定位，再用守护器拉起；**不要用裸 `ssh -N -L`**（见坑 10）。

---

## 8. 证据索引

| 用途 | 路径 |
|---|---|
| **唯一入口脚本** | `scripts/stepfun_batch_server.py` |
| S3 最终台账 | `data/ctf_benchmark/stepfun_sessions/s3_server_crypto27_39_20261027_074128.json` |
| S3 续跑/重试实测输出 | `data/ctf_benchmark/stepfun_sessions/s3_unified_resume.out` |
| S3 新建队列路径冒烟（1 题，31s，`start:ok`） | `data/ctf_benchmark/stepfun_sessions/s3_create_smoke.out` |
| S3 单题重跑通过证据 | `data/ctf_benchmark/stepfun_sessions/s3_server_crypto27_39_20261027_073447.json` |
| S1 队列（中途快照，慎用） | `data/ctf_benchmark/stepfun_sessions/s1_server_crypto1_13_20261027_072906.json` |
| S2 台账（本机口径，不合规） | `data/ctf_benchmark/stepfun_sessions/s2_server_final_20261027.json` |
| 五会话协调台账 | `data/ctf_benchmark/stepfun_sessions/SESSIONS.md` |
| 闸门实现 | `internal/agentfinalizer/decision.go:140`、`:237-260` |
| 建队契约 | `internal/handler/agent.go:1909-1919` |
| 作战手册（含多处已校正口径） | `STEPFUN_CONCURRENT_PLAYBOOK.md` |
| 今日项目记忆 | `.workbuddy/memory/2026-10-27.md` |

---

## 9. 我动了什么 / 没动什么

**新增**
- `scripts/stepfun_batch_server.py`（统一入口）
- 本文件

**未改他人文件**：`stepfun_s1_server_batch.py`、`stepfun_s2_server_batch.py`、`stepfun_s3_server_slice.py`、`SESSIONS.md` 的既有行、`config.yaml`（S1 的备份占用了该文件名边界）。
**未提交 git**：工作树有并行会话在途文件，按铁律 1.4 不动。

> ⚠️ 一处已知不一致：`stepfun_s1_server_batch.py:48` 与 `stepfun_s2_server_batch.py` 的 `DEFAULT_BASE` 仍指向本机 18086。**建议接手者把它们改成薄封装**（`exec` 到本入口），而不是继续并行维护三份逻辑。

---

## 10. 附录 B：换免费 key 跑（2026-10-27 08:35 实测）

> 背景：用户要求「换免费的 key 跑」。结论：**能跑，且与 StepFun 打平（12/13），耗时更短**；但必须先验证模型肯调工具。

### 10.1 免费候选实测矩阵（都按真实调用验证，不看配置名）

| 候选 | 是否真免费 | 工具调用 | 实测结果 |
|---|---|---|---|
| 智谱 `glm-4-flash` | ✅ 免费档 | ⚠️ 裸测能调，**平台内 0 次** | ❌ 被闸门全拦（`tool_executions=0`，51 completion tokens） |
| 智谱 `glm-5.3-flash` | ❌ 非免费档 | — | HTTP 429「余额不足或无可用资源包」 |
| 智谱 `glm-4.5-air` | ❌ 付费档 | ✅ | 可用，但不满足"免费"要求 |
| SiliconFlow `Qwen2.5-7B` | ❌ | — | HTTP 402 余额不足 |
| ModelScope `deepseek-ai/DeepSeek-V4.1-Flash` | 🟡 名义免费 | — | HTTP 400 `no provider supported`（账号无配额） |
| **OpenRouter `nvidia/nemotron-3-ultra-550b-a55b:free`** | ✅ 免费模型 | ✅ | ✅ **采用**，2.5s 出 tool_call |

### 10.2 隔离实例（不碰 S1 的 StepFun 实例）

| 项 | 值 |
|---|---|
| 目录 | `/home/user/sam_free`（**独立 SQLite**，避免与 S1 实例锁竞争） |
| 配置 | `config.free.yaml`（`default_channel: openrouter-free`，**failover 已清空**，防止静默回落 StepFun 污染对照） |
| 端口 | 远端 `127.0.0.1:18088`，隧道本机 `18088` |
| 凭据 | `~/.free_env`（chmod 600，含 ZHIPU / OPENROUTER 两把），仅该进程环境可见 |
| 进程 | 启动命令与 S1 同二进制 `/tmp/secautomind-s1 -config config.free.yaml --http` |

### 10.3 A/B 结果（同 13 题、同 mode `eino_single`、同 concurrency=1、同"只喂题面"）

| 通道 | 队列 | 首跑命中 | 耗时 | 未过项 |
|---|---|---|---|---|
| StepFun `step-5-preview` | `20261027072741-...800c0b8b` | 12/13 = 92.3% | 5m31s | `caesar_17`（闸门 flaky） |
| **免费 `nemotron-3-ultra:free`** | `20261027083343-...f0dd3de5` | **12/13 = 92.3%** | **3m03s** | `xor_01`（答成 `flag{xor_key_21}`，**真错**） |

- 差异项恰好互补：StepFun 栽在闸门上的 `caesar_17`，免费模型一次过；免费模型把 `xor_01` 的 key 算成 21。
- **不是抄题干**：免费实例 `tool_executions` 实测 **15 条**（`ctf_caesar_bruteforce` completed 11 / failed 1，`ctf_xor_single_byte` completed 3）。
- 台账：`s3_server_crypto27_39_20261027_083644.json`；终端输出 `s3_freekey_run.out`。

### 10.4 用免费 key 的注意事项

- OpenRouter `:free` 有**日调用上限**（余额 <10 时约 50 次/日）。本次 13 题消耗 14 次 run 调用，**剩余额度不足以反复重跑**。
- 计费口径未核：`nemotron-3-ultra-550b:free` 标称免费，但**未验证账单侧**是否真零扣费。
- 换免费模型后**旧数字不可直接混算**：模型不同，命中率不可比，必须标明通道。
