# 交接卡 · 2026-10-27（服务器口径固化 + S5/misc 阻塞）

> 用途：本项目**最优先的上下文**。下一个 agent 接手本仓库后，**先读本卡 → 再读 `AGENTS.md` 第零条 → 再读 `.workbuddy/memory/MEMORY.md`**。
> 本卡解决一个反复被踩的坑：用户已裁决「服务器」在本项目**只有一种含义**，新 agent 不必再向用户确认。

## 1. 项目快照

- **仓库 / 分支 / HEAD**：`E:/Program/SecAutoMind` / `docs/race-day-card` / `78927f1`（注：当前在并行会话分支上，**不要 `git add -A`、不要代提交他人 WIP**）
- **本轮时间窗**：2026-10-27 07:xx（S5 会话）
- **当前阶段**：活跃期（S1–S5 多 agent 并发跑题；服务器口径刚完成多文件固化）
- **一句话现状**：服务器口径已固化进 5 处必读文件（见 §4）；misc 6 题本机冒烟跑完但**不合规**，待服务器重跑；服务器前置（key / 实例）未就绪。

## 2. 目标任务

- **目标**（逐字抄需求原文）：「要求是开启新 agent 做项目，都能够知道在服务器 `172.16.222.99` 跑实验和解题，而不是每次都要我特别强调」。
- **明确不做**：不在本机 `127.0.0.1:18086` 起实例跑题（= 不合规）；不代提交他人在途 WIP；不把 key 明文落盘。
- **完成定义**（已达成 ✅）：新 agent 启动即能从 `AGENTS.md` 第零条（自动注入）得知服务器口径，无需用户口头强调。**本轮目标已闭环**；下一步是「在服务器上真正跑题」。

## 3. 最快实现路径（下一个 agent 上服务器跑 misc 6 题）

按顺序，**每步可复制粘贴执行**：

1. **连服务器**：`ssh user@172.16.222.99`（ed25519 免密；主机名 `ubantu`）。
2. **部署 SecAutoMind**：服务器 `/home/user/SecAutoMind` 是**非 git 副本**，部署走 `git bundle`（详见 `docs/服务器实机验证_Runbook_20261020.md`），**不要在该目录直接 git 操作**。
3. **注入 `STEPFUN_API_KEY`**：key 只在本机 HKCU 注册表（`STEPFUN_API_KEY`，len=65，前缀 `1EKg2K`）。搬运走 **stdin / 环境变量注入，不落盘、不进命令历史、不写 `config.yaml`**，避免被 `scripts/secret_guard.py` 扫到。
4. **构建并起服务**：Go 1.25.4 在 `~/go1.25.4`；`go build -o secautomind-ai ./cmd/server` → 起 HTTP 服务（默认 `:18086`）。
5. **跑题**：用共用客户端 `scripts/experiments/sam_client.py::SamClient`，`agentMode=eino_single`、`concurrency=1`（账号级并发池 = 5，留 buffer），**只喂 `description`**。

## 4. 涉及文件（具体路径）

| 路径 | 作用 | 本轮是否已改 |
|---|---|---|
| `AGENTS.md` | **第零条 · 服务器口径**（自动注入新会话，违反即作废效力） | ✅ 已升格为编号条款（259 行） |
| `docs/QUICKSTART_NEXT_AGENT.md` | 新 agent 接手先看什么；已加 §0 服务器口径 + 修正记忆路径 | ✅ 已改 |
| `.workbuddy/memory/MEMORY.md` | 现行长期记忆：服务器规格/前置/坑/评测纪律 | ✅ 已建（31 行） |
| `STEPFUN_CONCURRENT_PLAYBOOK.md` | S1–S5 作战手册；红线 7/8/9 含服务器口径 | ✅ 已改（205 行） |
| `docs/templates/交接卡模板.md` | §6 已内置服务器口径固定字段（本卡据此填） | ✅ 已改 |
| `docs/服务器实机验证_Runbook_20261020.md` | 服务器部署流程 | 未改（引用） |
| `scripts/experiments/sam_client.py` | 共用解题客户端 | 未改（引用） |
| `data/ctf_benchmark/benchmark.json` | 72 题基准（crypto56/web10/misc6） | 未改 |

## 5. 已知陷阱（具体事故形态）

| 陷阱 | 具体形态（什么时候会咬人） | 规避动作 |
|---|---|---|
| 打本机跑题 | 在本机 `127.0.0.1:18086` 起实例跑题 = **不合规**，且服务进程 PATH 易缺 `sh` → 依赖 shell 的题假 FAIL | 一律上 `172.16.222.99`；见 `AGENTS.md` 第零条 |
| 题干泄漏 | `benchmark.json` 72 题中有 **15 道**把正确 flag 明文写在 `description`（web 10/10 全泄漏、misc 5/6、crypto 0/56）。喂 `description` = 喂答案 | web/misc 命中**不计入能力证据**；只报真实解题题（misc 仅 `morse_hello`） |
| 读明文 flag 自验 | 用 `flag` 字段比对 = 自己批自己卷子，违反纪律 | 校验只用 `flag_sha256` |
| 服务进程缺 `sh` | `internal/security/shell_execute_stream.go:23` 走 `exec.LookPath("sh")`；本机 PATH 曾 499 字符无 PortableGit 段 → 报 `shell streaming 需要 sh` | 上 Linux 服务器天然满足；本机起须把 `D:\WorkBuddy\resources\vendor\PortableGit\usr\bin` 前置进 PATH（**AGENTS.md 旧写 `C:/Users/Lenovo/.workbuddy/binaries/PortableGit/versions/1.2.0` 已不存在**） |
| 服务器非 git 副本 | `/home/user/SecAutoMind` 报「不是 git 仓库」，直接 git 操作会污染部署 | 部署走 `git bundle`（Runbook） |
| 路径硬编码反斜杠 | Linux 上 `filepath.Join` 缺失 → Runner Layer 2 静默失效 | 拼接一律 `filepath.Join`，禁硬编码 `\` |
| 服务器无 Docker | 依赖容器化的题跑不了；但有 Ollama（qwen 系列，OpenAI 兼容 `/v1`）可作零成本 L3 fallback | 纯文本题（crypto/misc）不受影响 |
| 代提交他人 WIP | `git add -A` 卷进并行会话未跟踪文件 | 只提交自己改动；本仓库当前在 `docs/race-day-card` 分支 |

## 6. 依赖与约束

- **服务器口径**（固定事实，照抄即可，勿留空）：**跑实验 / 解题都在 `172.16.222.99`**（`ssh user@172.16.222.99` 免密）；**本机只做编排与日志**。在本机 `127.0.0.1:18086` 起实例跑题 = **不合规**。上机前置与坑见 `.workbuddy/memory/MEMORY.md`。
- **前置依赖**（工具链 / 数据 / 服务）：服务器需先具备 ① `STEPFUN_API_KEY`（本机有、服务器缺，待搬运）；② SecAutoMind 实例（服务器缺，待 bundle 部署）；③ `sam_client.py` 跑题链路。
- **不可动的东西**：并行会话在途 WIP（工作树很脏）、`config.yaml`（含敏感项，改后跑 `secret_guard.py`）、他人的未跟踪文件。
- **环境坑**（照抄 `AGENTS.md` 第五条即可）：Git Bash 实际路径已变更（`D:\WorkBuddy\resources\vendor\PortableGit\usr\bin`）；`go` 命令前先 `export APPDATA="$USERPROFILE/AppData/Roaming"`；`STEPFUN_API_KEY` 已 `setx` 进 HKCU 但旧 shell 未继承。

## 7. 验收标准（可测）

- [x] `AGENTS.md` 第零条含 `172.16.222.99` 且带「违反即作废」效力（已实测：259 行，关键词命中）
- [x] `docs/QUICKSTART_NEXT_AGENT.md` / `.workbuddy/memory/MEMORY.md` / `STEPFUN_CONCURRENT_PLAYBOOK.md` / 交接卡模板 §6 均含服务器口径
- [ ] 服务器上 misc 6 题按 `flag_sha256` 校验跑通（依赖服务器前置就绪，待用户授权搬运 key）
- [ ] 反向验证：新开 agent 会话，不口头提示即能说出「解题在 172.16.222.99」

## 8. 默认假设（未拍板项，可被推翻）

| # | 假设 | 若被推翻的影响 |
|---|---|---|
| 1 | 泄漏题（web10/misc5）**照原样跑完再标注「不计入能力证据」**，而非先剔除 | 若先剔除，则服务器只跑 51 题（含 misc 1 道真解题） |
| 2 | 搬运 `STEPFUN_API_KEY` 上服务器需用户授权（凭证跨机操作，agent 不擅自动） | 若用户拒绝，则服务器跑题阻塞，只能本机冒烟（不合规） |
| 3 | 下一 agent 接手目标 = 在服务器重跑 misc 6 题 | 若接手别的目标，本卡 §3 路径仍适用（通用上机流程） |

## 9. 上下文元数据

- **生成者 / 时间**：S5（misc 1–6 会话） / 2026-10-27 07:38
- **上一份交接**：`docs/evidence/2026-10-26_交接卡_本会话成果与阻塞.md`
- **相关文档**：`docs/服务器实机验证_Runbook_20261020.md`、`STEPFUN_CONCURRENT_PLAYBOOK.md`、`.workbuddy/memory/MEMORY.md`
- **未验证 / 仍未知**：服务器当前是否有 SecAutoMind 残留实例、key 搬运后 StepFun 在服务器网络是否可达（本机实测 `api.stepfun.com` 可达但 401 无凭证）
