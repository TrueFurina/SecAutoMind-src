# 一屏速览：下一个 agent 从这里开始

> 这是入口卡，不是全量交接。**全量事实以 `docs/HANDOFF_2026-10-18.md` 为准**，本卡只负责"30 秒内知道该干什么、不能碰什么"。
> 生成于 2026-10-18，所有数字均为当日实跑值；过期后以脚本输出为准，不要相信卡上的字。

---

## 0. 阅读顺序（按此顺序，别跳）

1. `AGENTS.md` —— 八条协作宪章，尤其第一条「诚实高于一切」。**违反即本次工作作废**。
2. `.workbuddy-ai/memory/MEMORY.md` —— 长期记忆（已于 2026-10-18 校正冻结日期）。
3. `docs/HANDOFF_2026-10-18.md` —— 全量交接：改了哪些文件、验证门禁、五个语义决策。
4. `docs/Octop_取精去糟与反哺清单_20261018.md` §7.4 —— 上游 PR/Issue 状态。

---

## 1. 项目是什么

SecAutoMind：Go 单体（`cmd/server`）+ 嵌入式前端（`internal/app/web/`，`go:embed`）+ YAML 工具/角色/技能配置。
本阶段两条工作流均已完工：**A · P0 工具资产元数据**、**B · Octop 取精去糟 + 反哺**。

---

## 2. 五分钟自检（除 §4 已知红灯外应全绿）

```bash
export APPDATA="$USERPROFILE/AppData/Roaming"          # ← 不设这条，go 命令全废（见 §5）
export PATH="/d/DevCache/go/bin:$PATH"

python scripts/freeze_gate.py --status                  # 应 PASS，窗口 2027-02-15~03-01
python scripts/audit_asset_metadata.py --check          # 口径会变：2026-10-18 16:54 实测 89 配方 / license 65/89 / upstream 70/89 / 不一致 0
python scripts/check_web_asset_parity.py                # rc=0
go build ./...                                          # rc=0
node --test internal/app/web/static/js/tool-meta-badges.test.cjs   # 8/8
```

判成败一律 `cmd > out.txt 2>&1; echo "RC=$?"`，**不要用管道**（`| grep -v ^ok` 会吞掉 FAIL 行）。

---

## 3. 五条红线

| 红线 | 说明 |
|---|---|
| **决赛 2027-03-01，冻结 2027-02-15~03-01** | 窗口内 `internal/ agents/ cmd/` 改动被闸门 BLOCK。`roles/ skills/` 不在闸门内，但 P3 纪律性推迟赛后。破例走 `--freeze-override` + `FREEZE_OVERRIDE_ACK=1` 并留审计。 |
| **禁止 `git add -A`** | 工作树常驻大量并行会话 WIP（2026-10-18 实测 112 项）。只 stage 显式路径，提交后用 `git show --stat` 复验零交集。 |
| **前端双副本** | `go:embed` 的是 `internal/app/web/`，root `web/` 是工作副本。改任一处必跑 parity，否则改动静默失效。 |
| **勿擅删 `hashpump` / `lightx`** | 属语义变更。**现状：工作树已被并行会话执行（hashpump 置灰、lightx 已删），未提交**——见 §4，不要代提交或回滚。 |
| **勿把单向不变量改双向** | `tools_metadata_test.go`：已核 license ⇒ 必有 upstream。反向不成立——gdb/objdump/strings 是「上游已核、许可未核」的正当状态。 |

---

## 4. 两个语义决策：**工作树里已有人执行，但未提交**

> 2026-10-18 16:50 起工作树出现下列变更（`tools/hashpump.yaml` mtime 可证），非本卡作者所为，属并行会话在途 WIP。
> **接手方不要代提交、不要回滚**，先与用户/该会话确认意图。

1. **`hashpump`**：已**置灰**（`enabled: false` + 配置头「⚠️ 已置灰（2026-10-18 人工定夺）」注释，文件保留留档）。上游 `bwall/HashPump` 确已消失（gh api 404 + 网页 404 + Kali 未收录）。
2. **`lightx`**：`tools/lightx.yaml` 已被**删除**（`git status` 显示 ` D`，未暂存未提交）。

**⚠️ 由此产生的已知红灯（重要）**：`internal/config/tools_metadata_test.go:15` 硬编码 `len(tools) != 90`，删除 lightx 后实际 89 →
`go test ./internal/config` **FAIL**：`工具配方数量应为 90，实际 89（是否增删了 tools/*.yaml？）`。
这是守卫按设计报警，不是代码 bug。**处置前提是用户确认删除**；确认后把 90 改为 89（或改为读目录计数并单独断言期望值）。
在此之前 `handler`/`app` 两包仍为 `ok`，`go build ./...` 仍 rc=0。

其余三项（binutils 三件套 / dnsenum / waybackurls 的 license 留 unknown）**是正确状态，不要"补全"**。

---

## 5. 本机坑（照抄，别再踩）

- **`go` 命令全废**：本 shell 缺 `%AppData%` → go 读不到 `GOENV`，GOPATH 回落空缓存，报"downloading / module lookup disabled"。先 `export APPDATA="$USERPROFILE/AppData/Roaming"`。
- **Go 工具链不在 PATH**：`D:\DevCache\go\bin\go.exe`（go1.25.0）。`GOPROXY=https://goproxy.cn,direct`。
- **`git push` 到 github.com 失败**（代理）。上游提交用 `gh api` 重建 commit 绕行（`D:/tmp_pr/push_via_api.py`）。
- **CGO 测试**报 `cgo.exe exit 2`：先 `export PATH="/d/miniconda3_new/Library/mingw-w64/bin:$PATH"`。
- **C 盘空间**紧张时全量测试假 FAIL：`export TMP=TEMP=TMPDIR=D:/tmp_gotest`，并 `go list ./... | grep -v ctfplatform` 分流跑。
- **Python**：`C:/Users/Lenovo/.workbuddy/binaries/python/envs/default/Scripts/python.exe`。

---

## 6. 上游状态（不用人工轮询）

`72fbc708` 自动化每两天只读巡检，仅在出现"请修改"评论或 merged/closed 时提醒。

- PR #83（octop-harness 规则）：**mergeable**，等合并。
- PR #2170（Octop docs）：open，等评审。
- Issue #2171（`OCTOP_HOME` 口令）：**已被社区 `legend91019` 认领**，本方无需再提 PR。
- Issue #84（枚举缺 `defense_evasion`）：待认领，低优先级。

---

## 7. 默认下一步（若用户没给新指令）

1. 跑完 §2 自检，确认基线绿。
2. 把 §4 两项整理成待确认清单递给用户——**不要自己动手**。
3. 除此之外没有必须做的事；`§5 非阻塞观察`（JS 测试接 CI、服务器全量测试、source 徽章配色）择机做，都非阻塞。
