# 一屏速览：下一个 agent 从这里开始

> 这是入口卡，不是全量交接。**全量事实以 `docs/HANDOFF_2026-10-18.md` 为准**，本卡只负责"30 秒内知道该干什么、不能碰什么"。
> 生成于 2026-10-18，所有数字均为当日实跑值；过期后以脚本输出为准，不要相信卡上的字。
> **最近一次更新：2026-10-20（新增冻结期干净检出门禁仿真脚本 `clean_checkout_gate_sim.sh`，见 §5；§8 缺口审计/演练基线为 10-20 实测）。**

---

## 0. 阅读顺序（按此顺序，别跳）

1. `AGENTS.md` —— 九条协作宪章，尤其第一条「诚实高于一切」。**违反即本次工作作废**。
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
python scripts/check_material_numbers_test.py           # 应 PASS（门禁自测 19 例：防空洞绿/恒红/属性值盲区）
python scripts/fix_material_numbers_test.py             # 应 PASS（修复器自测 13 例，含真实仓库 dry-run）
python scripts/check_artifact_numbers.py                # 应 PASS（9 个 PPT/PDF 产物内数字）
python scripts/build_championship_evidence.py --check   # 应 PASS（冠军证据包）
python scripts/check_final_artifacts_freeze.py          # 应 PASS（产物与生成器哈希已上锁）
python scripts/check_web_asset_parity.py                # rc=0
python scripts/css_shadow_audit.py --check              # 应 PASS（2026-10-19 新增：无可证明安全的 CSS 影子块）
python scripts/css_shadow_audit_test.py                 # 应 PASS（24 例：importance 反向变异/级联/端到端 --apply）
go build ./...                                          # rc=0
go test -p 1 ./internal/...                             # rc=0（必须 -p 1！本机并行链大测试二进制会 OOM：
                                                         #  errno=1455 VirtualAlloc 失败 → 8 个包假红 [build failed]）
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
- **C 盘空间**紧张时全量测试假 FAIL：**三条分开** `export TMP=D:/tmp_gotest; export TEMP=D:/tmp_gotest; export TMPDIR=D:/tmp_gotest`（⚠️ `export TMP=TEMP=TMPDIR=x` 多重赋值在本 shell 会变成字面量垃圾串，TEMP/TMPDIR 根本没设上，还能在仓库根建出怪目录——2026-10-14 与 10-19 各中过一次），并 `go list ./... | grep -v ctfplatform` 分流跑。
- **🔴 全量 `go test ./internal/...` 会 OOM 假红**（2026-10-19 实测）：并行链多个大测试二进制时 `VirtualAlloc ... errno=1455`，`internal/handler` 等 8 个包报 `[build failed]`。**加 `-p 1` 串行链即全绿**（实测 8/8 ok，41 秒）。这不是代码问题，别去"修"代码；判红前先看报错是 OOM 还是真 FAIL。
- **🔴 多会话并行时的口径纪律（2026-10-23 实测，被"追着跑"三轮才总结出来）**：
  1. **别在别人还在写 Go 时刷新口径**——一轮 `fix_material_numbers` + `fix_artifact_numbers` + `freeze --update` + `evidence` 要 2–3 分钟，对方一次提交就全废。动手前先确认 `find . -name "*.go" -newermt "-3 minutes"` 为空。
  2. **顺序不能反**：口径数字若包含**别人未提交**的 WIP，只提交文档会让干净检出红（HEAD 里没那些文件）。正确顺序是 **先把对方 WIP 验证并提交进版本库 → 再刷新口径 → 再提交**（2026-10-23 就是这样处理 `presolve_chain.go`：先 `692c498`，后 `52adf02`）。
  3. **合并别人的 WIP 前必须自证**：`go build ./...` + 它自己的测试全过 + `secret_guard` rc=0，且在提交信息里如实写"并行会话完成、本会话验证后入库"。
  4. **parity 假红先怀疑并发构建**：`go test 退出码 1` + 命中集合为空，但用门禁**精确命令**单独复跑（`go test ./internal/ctfplatform/ -run "^(TestXxx)$" -count=1 -v -timeout 600s`）却 PASS —— 那是别人同时在编译抢资源，不是你的镜像坏了。
- **Python**：`C:/Users/Lenovo/.workbuddy/binaries/python/envs/default/Scripts/python.exe`（系统 python 无 PyYAML，校验 yml 时用它）。
- **CI 仿真**：`git archive HEAD` 在 `core.autocrlf=true` 下**仍导出 CRLF**；要纯 LF 必须 `git -c core.autocrlf=false archive HEAD`。
- **🔴 冻结期"干净检出门禁仿真"一键脚本**（2026-10-20 新增）：`bash scripts/clean_checkout_gate_sim.sh [--go|--full|--preflight]`。
  它用 `git -c core.autocrlf=false archive HEAD` 抽一份**纯 LF 干净检出**（默认 `/d/tmp_ci_sim`），自动设好 `APPDATA` / `PATH`（conda 在前）/ `TMP`·`TEMP`·`TMPDIR`（三件套分开 `export`，别用多重赋值）三件套，再跑 `local_gate_check.py`（CI 门禁的本地镜像：只读 `.github/workflows/ci.yml` 的 `run:` 行，只跑 python+node 类，go/`${{ }}`/pip/apt 类按原因跳过，单一事实源不重复命令表）。
  核心价值：**根治 §2 里 `check_golden_freeze.py` / `check_final_artifacts_freeze.py` 的 autocrlf 假红**——这俩对 golden 文件做**原始字节哈希**，本机 CRLF 检出必红、纯 LF 检出才绿，而 CI 是纯 LF 所以 CI 绿；用本脚本可让"本地 == CI"成立。
  参数：`--list` 仅列出待跑门禁不执行；`--preflight` 加跑 `finals_preflight.py --phase pre`（rehearsal+caliber+secret+evidence+switches 总检）；`--go` 加跑 build+rehearsal；`--full` 加跑 `go test -p 1 ./...`（最慢，数十分钟）。失败封闭：缺 `git`/`tar`/`python` 或 archive 失败 → rc=2。`bash -n` 语法通过、`--list` 实测 rc=0。
  **⚠️ 五类门禁在此仿真里会被 `local_gate_check.py` 自动 SKIP（归档无 `.git` / 纯 LF，结构性不可验或易误红），请走真实克隆或 CI 核验**：**binary-gate**（`check_binary_version.py`，入口即 `git rev-parse HEAD` + exe 是 gitignored 产物；本地实跑 PASS：`8010deb` 构建）、**line-endings-gate**（`check_line_endings.py`，默认 `git ls-files` 列文件 + 纯 LF 归档会把 `.bat/.cmd/.ps1` 误判为应 CRLF；本地实跑 PASS）、**cross-bench-manifest-gate**（`check_cross_bench_manifest.py`，C7 需 `git check-ignore`/`git ls-files`；本地实跑 PASS）、**suite-parity-gate**（`check_suite_parity.py --check`，**25 个 wired 集**各跑 python judge + `go test ./internal/ctfplatform/ -timeout 600s`；台账 26 集已**全部 wired**，static 集由独立脚本负责；go test 依赖 gitignored 基准夹具，归档里缺 → 结构性失败，真仓 ~6min；本地实跑 PASS）、**quant-gate**（`check_quant_effect.py --full`，重型真跑、CI 专用、CI 实测 ~19s）。**自测**（`*_test.py`）多数不依赖 git/重型环境，仍在归档里照常 `[RUN]`（`check_suite_parity_test.py` 只跑纯函数 + 读受跟踪台账/汇总，19/19 PASS）；**例外是 line-endings 的自测** T7 跑默认（git）模式也需 `.git`，故与主门禁一并 SKIP。

---

## 6. 上游状态（不用人工轮询）

`72fbc708` 自动化每两天只读巡检，仅在出现"请修改"评论或 merged/closed 时提醒。
**2026-10-19 人工复核（gh api 实测）**：

  - PR #83（octop-harness 规则）：open、mergeable、**1 评论（本方 TrueFurina 跟进说明：篡改类规则暂用 `code_execution`，已提 #84 提议补 `defense_evasion` 枚举；无维护者评审）**，等合并。
  - PR #2170（Octop docs）：open、**无维护者评审**，mergeable_state=`unstable`（该 head 的 CI check-run 为 0 条，非我方改动所致），1 评论亦为本方交叉引用（开 #2171 + 指出 `.env.example:18` 同款错路径）。等评审合并。
- Issue #2171（`OCTOP_HOME` 口令）：**已被 `legend91019` 认领并修复，[PR #2174](https://github.com/TencentCloud/Octop/pull/2174) 已于 2026-10-19 复核确认 `merged`**
  （2026-10-18 07:19 交叉引用；无 assignee，认领以评论为准）。我方已评审：集成测试更新到位
  （正是 #2171 提醒的阻塞点）、legacy 回退逻辑正确（复用旧密码不生成冲突密钥 + 原子 0o600 写）、
  base 是 `develop`。**PR #2174 已合并，`#2171` 反哺闭环完成**（CHANGELOG 由上游维护者随合并处理，本方无需再跟）。
  - ⚠️ **`.env.example` 残留 → 已提 [Issue #2230](https://github.com/TencentCloud/Octop/issues/2230)**：PR #2174 合并时未改 `.env.example:18`（旧错路径未修、且未同步 relocation 新逻辑）。本方收尾跟进，等上游处理，非本仓库待办。
- Issue #84（**octop-harness**，枚举缺 `defense_evasion`）：open、0 评论，待认领，低优先级。
  ⚠️ 编号撞车提醒：`TencentCloud/Octop` 另有一个**无关**的 #84（远程桌面致出站流量死，
  2026-07-29 已 completed）——两个仓库的 #84 不是同一件事，查状态前先确认仓库。

---

## 7. 默认下一步（若用户没给新指令）

1. 跑完 §2 自检，确认基线全绿（含 `check_binary_version.py`，现 PASS）。
2. **提交已完成**（2026-10-18）：主体为 `55585c9` 修 HEAD 断链 → `7f50c82` robot 卡片 → `3c776a8` P0 资产元数据+口径治理（141 文件）→ 若干文档与体积同步修正（SHA 以 `git log` 为准）。安装包已按 §2 方法由提交时的 HEAD 重建、binary-gate PASS。详见 `HANDOFF_2026-10-18.md` §14/§15。**没有待拍板事项。**
   剩余未提交的只有并行会话的在途 WIP（`scripts/verify_live_contract.py` 重写、`scripts/mock_sim_platform.py`、`docs/` 三篇、`.workbuddy-ai/`），不归本任务。
   ⚠️ 提交任何东西之前想清楚：**提交后 exe 戳记即失效**，要再按 §2 的方法重建一次。
3. 非阻塞项（择机做，都不影响交付）：~~修 `check_material_numbers.py` 的 `strip_html` 盲区~~ **已修**（第十三轮，属性值补扫 + 旧运行时数 143 的写法进 BANNED，自测 19/19，见 HANDOFF §14.4）；~~source/trust 徽章配色由蓝改橙~~ **已修**（第十五轮，级联覆盖所致，见 HANDOFF §16）；~~收敛 CSS 影子块~~ **已做可证明安全子集**（第十六轮后，35 块已删 + 三层等价性验证 + `css-shadow-gate` 接 CI，剩余 102 组"部分存活"是需人工判定的技术债，见 HANDOFF §17）；赛前在 `172.16.222.99` 跑一次全量 `go test -p 1 ./...`（分流避开 ctfplatform，需实机）。

## 8. 缺口审计与演练基线（2026-10-20 实测）

**§8 缺口审计**（AGENTS.md 第八条；生产调用点计数，排除 `_test.go` 与接口定义文件）：

| 方法 | 生产调用 | 结论 |
|---|---|---|
| ListChallenges / GetChallenge / CreateInstance / GetAccess / DownloadAttachment / SubmitFlag / DestroyInstance | 1–2 | 已接线 |
| **ResetInstance** | 0 | **非缺口**——被 `DestroyInstance` 复用（`dasctf.go:1075`），DestroyInstance 在 `handleChallenge` 回收靶机时有生产调用（`poller.go:350`）。计数 0 是排除 dasctf.go 的假阴性 |
| **GetMatchInfo / GetOverview** | 0 | **观测类，不影响得分，按纪律不接线**：比赛起止由 runbook 控制、平台会拒绝窗口外提交；排名纯观测不改我方分数。硬接线只为刷非零计数属注水，不做 |

**演练基线**：`go test -p 1 -count=1 -run TestRehearsal ./internal/ctfplatform/` → **RC=0（2.087s）**，"拉题→解题→提交→判分"关键链通过。

**口径门禁（干净检出）**：HEAD 干净 worktree 上 `check_material_numbers.py` → **RC=0 PASS**。工作树若红，先查是否**未跟踪的并行 WIP 文档**引用了旧数字（门禁 BANNED 按"数字紧跟单位词"抓，引用旧值须让数字不紧跟单位词，见 AGENTS.md 第一条坑）。

**ctfplatform 整包为何慢（2026-10-20 实测定位）**：三个慢源，**均为设计如此、非 bug**——
- `TestLLMAutoSolve`（`llm_autosolve_test.go`）：检测到 `DEEPSEEK_API_KEY`（或 `LLM_EVAL_API_KEY`）时**真调 LLM** 跑 13 题 × 22 步评测（含 4 次退避重试），本机有 key 时数分钟；无 key 自动 SKIP。
- `TestSSRFAttackAgainstRange` / `TestSSRFAttackViaProductionText`：各约 **62s**（起真实 Python SSRF 靶场 + 真实利用），实测**均 PASS**（`ok ... 124.228s`）。
故日常全量用 `go list ./internal/... | grep -v ctfplatform` 分流（37 包 RC=0）；要跑整包须给足超时（`-timeout 900s`，300s 会不够）并 `env -u DEEPSEEK_API_KEY`（跳过 LLM 评测）；单独跑 LLM 评测用 `LLM_EVAL_LIMIT=3 go test -run TestLLMAutoSolve ./internal/ctfplatform/`。

**🔴 冻结期想在"纯 LF 干净检出"上跑全部门禁**（含 autocrlf 敏感的 `check_golden_freeze.py` / `check_final_artifacts_freeze.py`）：用 §5 的 `bash scripts/clean_checkout_gate_sim.sh`，别再手动 `git worktree`——worktree 的 `core.autocrlf` 仍可能导出 CRLF，而脚本用 `git -c core.autocrlf=false archive HEAD` 保证纯 LF，让"本地 == CI"。
