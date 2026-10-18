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

## 2. 五分钟自检（全部应绿）

```bash
export APPDATA="$USERPROFILE/AppData/Roaming"          # ← 不设这条，go 命令全废（见 §5）
export PATH="/d/DevCache/go/bin:$PATH"

python scripts/freeze_gate.py --status                  # 应 PASS，窗口 2027-02-15~03-01
python scripts/audit_asset_metadata.py --check          # license 65/90, upstream 70/90, 不一致 0
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
| **勿擅删 `hashpump` / `lightx`** | 属语义变更，等用户拍板（见 §4）。配置里已加 ⚠️ 注释，**未改 enabled、未删文件**。 |
| **勿把单向不变量改双向** | `tools_metadata_test.go`：已核 license ⇒ 必有 upstream。反向不成立——gdb/objdump/strings 是「上游已核、许可未核」的正当状态。 |

---

## 4. 只有用户能拍板的两件事

1. **`hashpump`**：`enabled:true` 但上游 `bwall/HashPump` 已消失（gh api 404 + 网页 404 + Kali 未收录）。风险最高的一条——对外提供了一个宿主机上很可能不存在的工具。建议置灰或删。
2. **`lightx`**：全仓 grep + requirements + run.sh 均无此工具，疑幻影条目。建议删 `tools/lightx.yaml` 并清 `tools/risk_policy.yaml` 引用。

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
