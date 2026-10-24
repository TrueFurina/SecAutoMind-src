# AGENT_ROUTES · 任务路由索引（P-01）

> **用途**：任务一进来，先在表里找"任务说法"，直接得到该改的文件。**命中即用，未命中才允许精确搜索。**
> **这不是教程**，是坐标表。教程在 `docs/`（见 `docs/INDEX.md`），本表只回答"改哪儿、别踩什么"。
> **路径全部由 `scripts/check_agent_docs.py` 校验存在性**——表里写不存在的路径，门禁直接红。

---

## 0. 三步定位法（照做，别自由发挥）

1. **抽动词+名词**：是"加/改/删"还是"查/解释"；对象是工具、求解器、基准、材料数字、前端、平台对接。
2. **查下表**：命中一行 → 读"核心文件"那 1–3 个 → 改。
3. **未命中**才 `grep -rn "<关键词>" internal/ cmd/` 精确搜索。**搜到就停**，不许顺手全仓遍历。

**三条禁令**（每条都对应一次真实烧掉的会话）：
- 禁止结构遍历（`ls -R` / 全仓 `find`）；
- 禁止全量列目录（先查表，别先 `ls internal/`）；
- 禁止"先跑一遍确认环境"（环境坑见 `AGENTS.md` 第五条，照抄即可）。

---

## 1. 路由表

| # | 任务说法 | 子系统 | 核心文件（真实路径） | 已知陷阱 |
|---|---|---|---|---|
| R1 | 加/改/删一个工具配方、`tools/*.yaml`、工具描述 | 工具层 | `tools/` · `internal/config/config.go`（`LoadToolsFromDir`）· `internal/handler/config_read.go`（`GetTools`） | ① 增删 yaml 会让 `internal/config/tools_metadata_test.go` 的数量断言变红；② `scripts/count_stats.py` 与 `scripts/audit_asset_metadata.py` 两套口径不同（后者解析 name+command），别把 89/90 当成谁坏了 |
| R2 | 工具元数据徽章、许可/上游、设置页工具列表 | 前端 + API | `internal/app/web/static/js/settings.js` · `internal/app/web/static/css/style.css` · `internal/handler/config_read.go` | **前端双副本**：`go:embed` 的是 `internal/app/web/`，根 `web/` 是工作副本；改一处必跑 `scripts/check_web_asset_parity.py` |
| R3 | CTF 平台对接、拉题、提交 flag、起/收靶机 | 竞赛平台 | `internal/ctfplatform/dasctf.go` · `internal/ctfplatform/types.go` · `internal/ctfplatform/`（poller/编排） | 定义齐全 ≠ 接线：改完按 `AGENTS.md` 第八条 grep 生产调用点，别只跑组件单测 |
| R4 | 确定性求解器、`ctf_*` 工具、预解层 | 求解器 | `internal/ctfplatform/`（solver 注册表）· `cmd/presolve/` | 求解器数属对外口径，改动后必须跑 `scripts/count_stats.py --json`，不许手写数字 |
| R5 | 基准集、benchmark、判分一致性 | 基准 | `data/ctf_benchmark/` · `data/questions_real_bench/` · `data/questions_external_bench/` · `scripts/`（bench 相关门禁） | 基准集分 Python/Go 双实现，改一侧必须跑 `suite-parity` 类门禁；`data/` 被 gitignore，干净检出会缺数据 → 先 `cp -r data/. <检出>/data/` |
| R6 | 材料数字、口径、PPT/官网数字对不上 | 口径 | `scripts/count_stats.py` · `scripts/check_material_numbers.py` · `scripts/check_artifact_numbers.py` · `docs/口径修复清单.md` | 唯一真值源是 `scripts/count_stats.py --json`；写死数字必漂。修产物前先跑门禁拿清单，别逐个手改 |
| R7 | 新增/修改 HTTP 接口、路由、鉴权 | 服务层 | `internal/handler/` · `internal/app/app_lifecycle.go`（路由装配）· `cmd/server/main.go` | 接口形状有统一网关约定，别自造一套；改路由后跑 `go build ./...` |
| R8 | 配置项、环境变量、`config*.yaml` | 配置 | `internal/config/config.go` · `internal/config/envexpand.go` · `config.example.yaml` · `config.share.yaml` | 端口真值 18086（`config.share.yaml`）；`8080` 只是未设端口时的兜底，写进文档会扩散成事故 |
| R9 | 数据库、迁移、会话存储 | 数据层 | `internal/database/database.go` · `internal/database/`（按表分文件） | 迁移文件放进目录 ≠ 会执行，必须登记执行清单；`database/rbac*` 常被并行会话改动 |
| R10 | Agent 定义、角色、技能 | 编排资产 | `agents/` · `roles/` · `skills/` · `internal/agents/` | 这三处属 P3 范围，**决赛冻结窗口内不动**；改完跑对应加载测试 |
| R11 | MCP 工具、外部 MCP 接入 | MCP | `internal/mcp/client_sdk.go` · `mcp-servers/` · `cmd/mcp-stdio/` | 工具分级注册有既定方案（`docs/MCP工具分级注册方案-2026-10-19.md`），别另起一套 |
| R12 | 冻结纪律、能不能动架构 | 纪律 | `config.share.yaml`（`freeze:` 段）· `scripts/freeze_gate.py` | 先 `python scripts/freeze_gate.py --status` 看窗口；窗口内改 `internal/ agents/ cmd/` 会被 BLOCK |
| R13 | 打包、交付包、安装包、证据包 | 交付 | `scripts/make_delivery_package.py` · `scripts/package_workspace.py` · `scripts/secret_guard.py` | 打包前必跑 `scripts/secret_guard.py`（exit 1 = 禁止打包）；交付包排除面必须覆盖 `.workbuddy-ai/`（曾把账号口令发给评委） |
| R14 | 部署、服务器、上线 | 运维 | `docs/腾讯轻量云部署指南.md` · `docs/服务器实机验证_Runbook_20261020.md` · `deploy_tencent_lighthouse.sh` | 服务器是 `172.16.222.99`；本机 `git push` 到 github 走代理会失败，用 `gh api` 绕行 |

---

## 2. 跨任务必查的三条

改任何东西之前，这三条与任务无关但会咬人：

1. **冻结窗口**：`python scripts/freeze_gate.py --status`。窗口内 `internal/ agents/ cmd/` 免谈。
2. **提交纪律**：**禁止 `git add -A`**（会卷进并行会话 WIP）。显式列路径，提交后 `git show --stat` 复验。
3. **改完必须验证**：Go 改 `go build ./...`；Python 改实跑脚本看退出码；文档改 `grep` 复验落盘。

---

## 3. 未命中时（唯一允许的搜索方式）

```bash
# 精确搜索，命中即停
grep -rn "<关键词>" --include=*.go internal/ cmd/ | head -20
# 找定义而不是找用法
grep -rn "func .*<方法名>" --include=*.go internal/
```

搜完**立刻回到执行**。不许"顺便看看整体结构"——那是下一次会话预算的黑洞。

---

## 4. 维护规则

- 新增子系统或改变职责边界时，**同轮**更新本表（改代码不改表 = 下一个人踩空）。
- 表里只写**已验证存在**的路径；不确定的先 `ls` 确认再写，门禁会拦不存在的路径。
- 本表保持 ≤ 200 行。超过就该拆到 `docs/` 并按需加载，别把常驻区撑大。
