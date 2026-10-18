# 一屏速览：下一个 agent 从这里开始

> 这是入口卡，不是全量交接。**全量事实以 `docs/HANDOFF_2026-10-18.md` 为准**，本卡只负责"30 秒内知道该干什么、不能碰什么"。
> 生成于 2026-10-18，所有数字均为当日实跑值；过期后以脚本输出为准，不要相信卡上的字。
> **最近一次更新：2026-10-18 22:45（第十一轮提交 + 第十二轮安装包重建与收尾，已无待拍板事项、无已知红灯）。**

---

## 0. 阅读顺序（按此顺序，别跳）

1. `AGENTS.md` —— 八条协作宪章，尤其第一条「诚实高于一切」。**违反即本次工作作废**。
2. `.workbuddy-ai/memory/MEMORY.md` —— 长期记忆（冻结日期、两套口径、CI 坑）。
3. `docs/HANDOFF_2026-10-18.md` —— 全量交接：改了哪些文件、验证门禁、决策执行记录（§4 / §10 / §11）。
4. `docs/Octop_取精去糟与反哺清单_20261018.md` §7.4 —— 上游 PR/Issue 状态。

---

## 1. 项目是什么

SecAutoMind：Go 单体（`cmd/server`）+ 嵌入式前端（`internal/app/web/`，`go:embed`）+ YAML 工具/角色/技能配置。
两条工作流均已完工：**A · P0 工具资产元数据**、**B · Octop 取精去糟 + 反哺**。

---

## 2. 五分钟自检（**应当全绿**，无已知红灯）

```bash
export APPDATA="$USERPROFILE/AppData/Roaming"          # ← 不设这条，go 命令全废（见 §5）
export PATH="/d/miniconda3_new:/d/DevCache/go/bin:$PATH"   # conda 在前：它带 pycryptodome/pypdf/yaml/pptx

python scripts/freeze_gate.py --status                  # 应 PASS，窗口 2027-02-15~03-01
python scripts/audit_asset_metadata.py                  # 89 真实配方 / license 69/89 / upstream 70/89 / 不一致 0
python scripts/check_material_numbers.py                # 应 PASS（材料数字 vs count_stats 真值）
python scripts/check_artifact_numbers.py                # 应 PASS（9 个 PPT/PDF 产物内数字）
python scripts/build_championship_evidence.py --check   # 应 PASS（冠军证据包）
python scripts/check_final_artifacts_freeze.py          # 应 PASS（产物与生成器哈希已上锁）
python scripts/check_web_asset_parity.py                # rc=0
go build ./...                                          # rc=0
go test ./internal/config ./internal/handler            # rc=0
node --test internal/app/web/static/js/*.test.cjs       # 17 文件 / 131 例全过（已接 CI：web-js-tests）
```

> 慢门禁（各约 2–5 分钟，跑前务必先设好上面两行 PATH，否则会假红）：
> `python scripts/check_quant_effect.py --full`（10 条陈述）、`python scripts/check_suite_parity.py --check`（22 集）。
> `python scripts/check_binary_version.py`（现为 **PASS**：exe 构建自 HEAD、无 dirty）。
>
> **重建安装包的纪律（2026-10-18 实测，提交后必读）**：`installer/*.exe` 必须构建自**干净树**，
> 否则 Go 会打 `+dirty` 戳，门禁直接 BLOCK。而本仓工作树常驻并行会话 WIP，
> **在主工作树里重建必然带 `+dirty`**；且**任何一次新提交都会让已构建 exe 的戳记失效**。
> 正确做法是在**真克隆**里构建（注意：`git worktree` **不行**——linked worktree 的 `.git` 是文件，
> Go 的 VCS 探测取不到，buildinfo 里直接没有 `vcs.*` 行，版本退化成 `(devel)`，门禁同样红）：
> ```bash
> git clone --shared E:/Program/SecAutoMind D:/tmp_clone   # --local 跨盘会因硬链接失败
> cd D:/tmp_clone && export PATH="/d/miniconda3_new:/d/DevCache/go/bin:$PATH"
> python installer/build_installer.py --makensis D:/nsis_env/NSIS/makensis.exe
> # 期望看到 vcs.modified=false 与 v1.7.28-0.<时间戳>-<sha>
> go version -m installer/secautomind-ai.exe | grep -E 'mod\s|vcs\.'
> cp installer/secautomind-ai.exe installer/SecAutoMind-Setup-*-x64.exe E:/Program/SecAutoMind/installer/
> cd E:/Program/SecAutoMind && python scripts/check_binary_version.py
> ```
> 重建后 exe 体积可能变化——**复跑 `check_material_numbers.py`**，体积也是口径锚点
> （本次 89.5→89.6 MB 就曾让 caliber-gate 红，见 HANDOFF §15.1）。

判成败一律 `cmd > out.txt 2>&1; echo "RC=$?"`，**不要用管道**（`| grep -v ^ok` 会吞掉 FAIL 行）。

---

## 3. 五条红线

| 红线 | 说明 |
|---|---|
| **决赛 2027-03-01，冻结 2027-02-15~03-01** | 窗口内 `internal/ agents/ cmd/` 改动被闸门 BLOCK。`roles/ skills/` 不在闸门内，但 P3 纪律性推迟赛后。破例走 `--freeze-override` + `FREEZE_OVERRIDE_ACK=1` 并留审计。 |
| **禁止 `git add -A`** | 工作树常驻**上百项**并行会话 WIP（2026-10-18 实测 113 项，持续变动）。只 stage 显式路径，提交后用 `git show --stat` 复验零交集。 |
| **前端双副本** | `go:embed` 的是 `internal/app/web/`，root `web/` 是工作副本。改任一处必跑 parity，否则改动静默失效。 |
| **`hashpump` / `lightx` 已定案，勿再动** | 用户已批准：`hashpump` 置灰留档（`enabled: false`）、`lightx` 配方已删除。**不要恢复、也不要再改口径**。 |
| **勿把单向不变量改双向** | `tools_metadata_test.go`：已核 license ⇒ 必有 upstream。反向不成立——「上游已核、许可未核」是正当状态。 |

---

## 4. 语义决策：**已由用户拍板并执行完毕**（无待办）

| 项 | 决定 | 现状 |
|---|---|---|
| `hashpump` | 置灰保留 | `enabled: false`，配置头注明人工定夺，文件留档 |
| `lightx` | 删除配方 | `tools/lightx.yaml` 已删；`risk_policy.yaml` 中原有的 5 行 lightx 条目也已一并删除（旧说法「原本无引用」不成立，见 HANDOFF §14.7） |
| `gdb` | 换数据源核实 | `GPL-3.0-or-later`（Alpine aports `main/gdb`） |
| `objdump` / `strings` | 换数据源核实 | `GPL-2.0-or-later`（Alpine aports `main/binutils`） |
| `dnsenum` | 换数据源核实 | `GPL-2.0-or-later`（上游 `dnsenum.pl` 头「version 2 or later」） |
| `waybackurls` | 换数据源核实 | **确证上游无许可**（API `license=null`、无 LICENSE、`main.go` 无版权头）→ 留 `unknown`，这是"查到了没有"，不是"没查到" |

**⚠️ 两套口径别当成谁算错了**：`count_stats.py` 的 `tools_yaml` = **90**（把 `_shared_args.yaml` 这个 YAML anchor 文件按历史约定计入，**对外材料用这个数**）；
`audit_asset_metadata.py` 与 Go 加载器只认带 `name`+`command` 的真实配方 = **89**。
**改 `tools/*.yaml` 后别只信口径门禁，必须跑 `go test ./internal/config`**——实测删 lightx 后口径门禁反而转 PASS，只有 Go 守卫会红。

---

## 5. 本机坑（照抄，别再踩）

- **`go` 命令全废**：本 shell 缺 `%AppData%` → go 读不到 `GOENV`，GOPATH 回落空缓存，报"downloading / module lookup disabled"。先 `export APPDATA="$USERPROFILE/AppData/Roaming"`。
- **Go 工具链不在 PATH**：`D:\DevCache\go\bin\go.exe`（go1.25.0）。`GOPROXY=https://goproxy.cn,direct`。
- **`git push` 到 github.com 失败**（代理）。上游提交用 `gh api` 重建 commit 绕行（`D:/tmp_pr/push_via_api.py`）。
- **CGO 测试**报 `cgo.exe exit 2`：先 `export PATH="/d/miniconda3_new/Library/mingw-w64/bin:$PATH"`。
- **C 盘空间**紧张时全量测试假 FAIL：`export TMP=TEMP=TMPDIR=D:/tmp_gotest`，并 `go list ./... | grep -v ctfplatform` 分流跑。
- **Python**：`C:/Users/Lenovo/.workbuddy/binaries/python/envs/default/Scripts/python.exe`（系统 python 无 PyYAML，校验 yml 时用它）。
- **CI 仿真**：`git archive HEAD` 在 `core.autocrlf=true` 下**仍导出 CRLF**；要纯 LF 必须 `git -c core.autocrlf=false archive HEAD`。

---

## 6. 上游状态（不用人工轮询）

`72fbc708` 自动化每两天只读巡检，仅在出现"请修改"评论或 merged/closed 时提醒。

- PR #83（octop-harness 规则）：**mergeable**，等合并。
- PR #2170（Octop docs）：open，等评审。
- Issue #2171（`OCTOP_HOME` 口令）：**已被社区 `legend91019` 认领**，本方无需再提 PR。
- Issue #84（枚举缺 `defense_evasion`）：待认领，低优先级。

---

## 7. 默认下一步（若用户没给新指令）

1. 跑完 §2 自检，确认基线全绿（含 `check_binary_version.py`，现 PASS）。
2. **提交已完成**（2026-10-18）：`55585c9` 修 HEAD 断链 → `7f50c82` robot 卡片 → `3c776a8` P0 资产元数据+口径治理（141 文件）→ `a6ab198`/`024eaac` 文档 → `3083860` 体积同步与 argparse 修复。安装包已由 HEAD `3083860` 重建。详见 `HANDOFF_2026-10-18.md` §14/§15。**没有待拍板事项。**
   剩余未提交的只有并行会话的在途 WIP（`scripts/verify_live_contract.py` 重写、`scripts/mock_sim_platform.py`、`docs/` 三篇、`.workbuddy-ai/`），不归本任务。
   ⚠️ 提交任何东西之前想清楚：**提交后 exe 戳记即失效**，要再按 §2 的方法重建一次。
3. 非阻塞项（择机做，都不影响交付）：修 `check_material_numbers.py` 的 `strip_html` 盲区（HTML 属性值里的数字扫不到，见 HANDOFF §14.4）；赛前在 `172.16.222.99` 跑一次全量 `go test ./...`（分流避开 ctfplatform）；source/trust 徽章配色由蓝改橙（既有行为，独立议题）。
