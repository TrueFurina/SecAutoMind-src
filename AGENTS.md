# AGENTS.md — 本仓库的 AI 协作宪章

> 任何在本仓库工作的 AI agent（含并行会话、子代理、未来新会话）**必须先读本文件**。
> 本文件的每一条都由本项目的**真实事故**倒逼写成，不是通用套话。违反任意一条 = 本次工作作废。

> 🟢 **唯一主体声明（2026-10-23）**：本项目 = 唯一参赛/维护主体。`E:\Program\西湖论剑` 已被全量吞并并
> **冻结为只读知识库**（README 已加冻结横幅）。凡涉"两套项目对比/迁移/合并"的工作，先读
> `docs/merge_xhlj_roadmap_20261023.md`（盘点+缺口+分阶段路线），再动手。

---

## 第一条 · 诚实高于一切（最高优先级）

**AI 在本仓库最常见的失败模式不是"做不出来"，而是"做出来了但报告是假的"。**

### 1.1 禁止幻觉，禁止伪造证据
- 没跑过的命令，**不许说跑过**。没打开的文件，**不许描述它的内容**。
- 没验证的结论，必须显式写「**未验证 / 未能确认**」。这不会扣分，伪造才会。
- 引用行号前必须真的 `Read` 过那段代码。**编造行号是最恶劣的行为**——它看起来最像证据。
- 子代理/并行会话的结论**一律视为待验证的线索**，主 agent 必须亲自复核后才能写进报告。

### 1.2 失败必须报失败
- 命令返回非 0，就说非 0。**不许把 FAIL 说成"基本通过"**。
- **严禁用过滤命令掩盖失败**（本项目真实事故）：`go test ./... | grep -v "^ok"` 这类管道在缓冲/截断下会吞掉 FAIL 行，导致"看起来全绿"。
  正确做法：**把完整输出落盘再统计**，例如 `go test ./... > out.txt 2>&1; grep -c '^ok' out.txt; grep '^FAIL' out.txt`。
- **退出码同样会被管道吞掉**（09-09 实锤变体）：`secret_guard.py | tail -8; echo $?` 打印的是 **tail 的 0**，门禁真实 **rc=1**（config.yaml 两把真 key）被完全掩盖。
  判任何门禁成败一律：`cmd > out.txt 2>&1; echo "RC=$?"`，**落盘后再 grep 看细节**。
- 部分完成就说部分完成，不许用"收官/完成/全部搞定"概括未完成的工作。

### 1.3 区分「代码 bug」与「环境故障」（本项目 2026-09-09 实证）
- 环境故障（磁盘满、网络断、代理失效、工具链缺组件）导致的失败，**必须归因到环境**，不许算成代码缺陷。
- 反之，**不许拿环境当借口掩盖真 bug**。二者都不能偷懒：先排除环境干扰，再谈代码。
- 实证：C 盘仅剩 93M 时全库测试报 10 FAIL；把 `TMP/TEMP` 指到 D 盘后需重测才能定性。

### 1.4 度量工具本身也会骗人
- **引用任何工具给的数字之前，先验证一次**。实证：`gofmt -l` 报 281 个文件未格式化，
  `gofmt -w` 后 git 只记录 **52** 个有实质变化——其余 229 个是 CRLF/LF 行尾误报（Git Bash + autocrlf）。虚高 5 倍。
- 同理适用于 wc -l、cloc、测试计数等一切"看起来很客观"的数字。

### 1.5 不许注水，也不许为挑刺而挑刺
- 报告可以短，**不可以假**。凑数的"问题"和隐瞒的问题一样有害。
- 做得干净的部分要明确承认（例如"TODO/FIXME 真命中 0"），避免为了显得有产出而硬挑。

---

## 第二条 · 数字单一真值源

**所有对外的代码规模 / 能力数字，只能来自脚本实跑，禁止手写、禁止凭记忆、禁止"大概是"。**

```bash
python scripts/count_stats.py --json     # 唯一权威口径
python scripts/verify_evidence.py        # 证据/口径门禁
```

- 已作废旧口径（出现在材料里即为违规）：`662/242/123,149/153,987`、`677/250/125,954/158,247/166`、`151 求解器`、`140 工具`、`613 文件`。
- **140 是"三不管数字"的典型**：它既不等于 91（YAML 工具数）也不等于 143，凭空漂移却看起来像有依据。
  这类数字最危险。**宁可写"91 YAML + 52 内置 = 143 运行时"，也不要写没有分解式的整数。**
  （本行的示范值由 `scripts/check_doc_facts.py` 对齐 count_stats 真值——写死的示范数字正是本条纪律要防的漂移：
  2026-10-23 删除 `tools/lightx.yaml` 使真值从 91/143 降到 90/142，本行**恰好**蒙对；
  2026-10-24 新增 `tools/bkcrack.yaml` 使真值回到 91/143，本行立刻又错。故本次同步为 91/143。）
- 数字会实时过期：本项目出现过**三次**漂移全靠人肉发现。写死的数字在提交完成的下一秒就可能错。
- **文档是快照，不是实时真值**（REA #89/#90）：本文件与 `docs/` 里写死的数字/结论一律视为
  「上次核对时的快照」，引用前跑一次上面的真值源命令。快照与实测不一致时**改文档，不改命令**。
- **doctor 不是仪式**：`python scripts/doctor.py --json` 的 `head` / `ran_at` 是执行基线。
  `head` 与你要引用的版本不一致 ⇒ 等价于「没跑过」——重跑，不要沿用旧结论。

---

## 第三条 · 改完必须验证（Edit 会假成功）

- 本项目已出现 **3 次** Edit 工具报成功但内容未落盘。**改完必须 `grep`/`Read` 复验。**
- Go 改完必须 `go build`；Python 改完必须实跑脚本并由退出码判定。
- 报告里写"已修复"之前，必须能给出**修复后的验证输出**。

---

## 第四条 · 门禁不是装饰品

- 写了一个门禁脚本，**必须把它接进 CI**。没接 CI 的门禁等于没锁（本项目实证：`secret_guard.py` 写好却没进 release 流程）。
- 门禁自身必须有回归测试。**失效的门禁比没有门禁更危险**——它会持续给出假的安全感。
  实证：旧打包前 grep 正则 `sk-[A-Za-z0-9]{16,}` 匹配不到 `sk-ws-H...`（第 4 位是连字符），
  一把真 key 从洞里漏过而门禁报 CLEAN。
- 现有门禁（`ci.yml` 共 **25** 个 job，以下 7 个为核心）：`test`（vet + `-race` 全测 + 构建）· `capability-gate`（求解器真实执行 + 反注水）·
  `evidence-gate`（基准双语言机验 + `verify_evidence`）· `secret-gate`（密钥三件套：门禁本体 + 自测 + 变异验证）·
  `caliber-gate`（材料数字 vs `count_stats` 真值）· `evidence-package-gate`（冠军证据包一致性 + 变异验证）·
  `freeze-gate`（决赛冻结纪律，见第七条）。
- **门禁的通用纪律**：① 门禁自身必须有回归测试；② 关键门禁必须有**变异验证**（注入错误必须变红，
  否则"测试有效"无从证明）；③ 取不到真值时必须 **fail-closed** 或显式降级并留痕，不许静默放过。
- 🔴 **"冻结哈希"类门禁必须用干净检出做一次 CI 仿真**（2026-09-24 实锤）：证据包对 golden 文件做
  **原始字节**哈希，而 Windows 工作树那份是生成器写出的 **LF**、CI/Linux 检出（core.autocrlf=true）
  是 **CRLF** → 本地永远绿、**CI 必然 BLOCK**，本地怎么测都测不出来。
  做法：`git worktree add D:/tmp_wt_clean HEAD` → 把包与脚本复制进去 → 在提交态跑 `--check`。
  修法：哈希前做行尾归一化（`_sha256_file_lf`）。**凡"本地与 CI 环境不同"的门禁，都必须仿真一次。**

---

## 第五条 · 本仓库已知环境坑（照抄即可，别再踩）

| 坑 | 正解 |
|---|---|
| `git push` 凭证 | `git -c credential.helper= -c credential.helper=manager push origin refs/heads/main:refs/heads/main` |
| `refs/tags/main` 歧义 | 必须写全 `refs/heads/main:refs/heads/main` |
| 远程跟踪引用被静默吞 | `.git/refs/remotes/**` 写入（**含 `git update-ref`**）在本环境 rc=0 但 ref 不变。判 ahead/behind 不可信本地引用，以 push 输出或 `git ls-remote` 为准。绕行：备份后整文件覆盖 `.git/packed-refs` |
| CGO 测试报 cgo.exe exit 2 | 先 `export PATH="/d/miniconda3_new/Library/mingw-w64/bin:$PATH"` |
| Go 工具链 | 实测 `D:\DevCache\go\bin\go.exe`（go1.25.0，2026-10-18 复核 `go build ./...` rc=0）；~~`.workbuddy/toolchain/go/bin/go.exe`~~ 该路径**已不存在**；`GOPROXY=https://goproxy.cn,direct` |
| 🔴 **本 shell 缺 `%AppData%` → 所有 go 命令失效**（2026-09-16 实锤） | 症状：`go build/list/test` 报 `go: downloading ...` 或 `module lookup disabled by GOPROXY=off`，**极易误判成"模块缓存被删/网络断了"**。真因：go 找不到自己的 GOENV 配置文件 `%AppData%\go\env`（内含 `GOPATH=D:\DevCache\gopath`、`GOPROXY=goproxy.cn`、`GOTOOLCHAIN=local`）→ GOPATH 回落到空的默认缓存。**正解：先 `export APPDATA="$USERPROFILE/AppData/Roaming"`**（实测 `go list ./...` rc=1→**0**，42 包；`go build ./cmd/server` 恢复 rc=0）。`scripts/count_stats.py` 已内置该回退（`_go_env()`），故 `go_packages` 不再退化为 null。 |
| Python venv | `C:/Users/Lenovo/.workbuddy/binaries/python/envs/default/Scripts/python.exe` |
| C 盘空间告警 | `/tmp` 在 C 盘。空间紧张时**三条分开**设：`export TMP=D:/tmp_gotest; export TEMP=D:/tmp_gotest; export TMPDIR=D:/tmp_gotest`。
| 🔴 **禁止 `export TMP=TEMP=TMPDIR=x` 多重赋值**（2026-10-14 事故，2026-10-19 又中一次） | 本 shell 会把它变成一个字面量垃圾串赋给 TMP（TEMP/TMPDIR 根本没设），Go `t.TempDir()` 据此 mkdir 失败 → 一致场景假 FAIL；更糟的是它可能在**仓库根建出名为 `TEMP=TMPDIR=D://tmp_gotest` 的怪目录**。必须逐变量分开 export。 |
| 🔴 **禁用 `git add -A` / `git add -A <dir>`**（09-24 事故） | 会把并行会话的**未跟踪在途文件**一并卷进提交，违反"不代提交他人 WIP"。一律显式列文件路径，或先 `git status --porcelain` 逐条确认。误加后纠正：`git reset --soft HEAD~1` → `git restore --staged <文件>` → 显式列路径重新提交，并用 `git show --stat HEAD` 复验零交集。 |
| `官网/` 曾整目录被排除 | **2026-10-18 已入库**（`3c776a8`，`.gitignore` 注记同步更新）：数字纳入 `check_material_numbers.py` 机验、由 `pages.yml` 部署。历史上它既不受门禁约束也无法分发的状态才是坑 |

---

## 第六条 · 交付红线

- **打包前必跑** `python scripts/secret_guard.py`（exit 1 = 禁止打包）。它会扫**磁盘真实文件**，包括被 gitignore 却会进交付包的 `config.yaml`。
- 落盘必须内置打码；日志写 key 只用占位符。
- 用户原创项目**一律不要 LICENSE 文件**。

---

## 第七条 · 决赛冻结纪律（<14 天不动架构）

决赛前最大的风险不是"能力不够"，而是**临阵改架构**——动一处内部接口，全库测试、交付包、
exe、官网数字、PPT 口径全部要重刷，而时间只剩几天。此前这条只写在文档里，现在有闸门。

- **武装**：决赛日期确定后，把 `config.share.yaml` 的 `freeze.enabled` 置 `true` 并填 `final_date`（YYYY-MM-DD）。
  窗口 = `final_date - freeze_days`（默认 14）~ `final_date`；窗口结束后自动解除。
- **效果**：窗口内任何 `internal/` `agents/` `cmd/` 改动一律 BLOCK；材料/证据/文档/配置/scripts 不受限。
- **用法**：`python scripts/freeze_gate.py`（查暂存区，pre-commit 用）· `--worktree`（查工作树，pre-push 用）·
  `--base <sha>`（查 PR 区间，CI 用）· `--status`（只看窗口状态）· `--json`。
- **冻结期只做四件事**：构建 + 全测 + 交付包自检 + **演练**。演练用：
  `go test -count=1 -v -run TestRehearsal ./internal/ctfplatform/`（CI job `finals-rehearsal`，
  仿真平台 + 真实 Poller 跑"拉题→解题→提交→判分"，含限流注入/并发/去重/无解题不提交）。
- **逃生阀（仅安全官/主理人）**：`--freeze-override "<≥20 字理由>"` **且** `FREEZE_OVERRIDE_ACK=1`，
  二者缺一不可；触发后自动追加审计到 `docs/freeze-override-log.md`（可追溯谁在何时为何破例）。
- **配置写错即 fail-closed**：`enabled=true` 但 `final_date` 缺失或非法 → 直接 BLOCK，不静默放行。
- 自测：`python scripts/freeze_gate_test.py`（16 项用例，含"把 protected_paths 置空后同文件必须放行"的因果验证）。

---

## 第八条 · 缺口审计：定义齐全 ≠ 接线

本项目最致命的问题从来不是"没写"，而是**写了、测了、但生产链路没人调用**——组件级单测全绿，
上场照样 0 分。已实锤四例：`CreateInstance/GetAccess`（起靶机）、`DownloadAttachment`（附件）、
`GetChallenge`（题干补全）、`DestroyInstance`（靶机回收）。

**审计方法**（决赛前对每个接口面至少做一遍）：
```bash
# 逐个方法 grep 生产调用点：排除接口自身的定义文件与 *_test.go
for m in ListChallenges GetChallenge CreateInstance GetAccess DownloadAttachment \
         SubmitFlag ResetInstance DestroyInstance GetMatchInfo GetOverview; do
  printf "%-20s " "$m"
  grep -rn "\.$m(" --include=*.go internal/ cmd/ | grep -v "_test.go" \
    | grep -vE "^internal/ctfplatform/(dasctf|types)\.go" | wc -l
done
```
- 计数 0 = 生产零调用 → 判断它是否影响得分/资源，影响则修（配置开关默认关 + 演练覆盖 + 反向对照）。
- 演练替身要**嵌入接口**（`type fake struct { PlatformAPI }`）：被测方一旦新增调用，缺失方法会
  nil panic 立刻暴露，不会静默跳过。

---

## 第九条 · 前端样式：禁止再造同名顶层块

2026-10-18 实证：`style.css` 里有**两个同名同特异性的 `.external-tool-badge` 定义**
（11329 行橙色药丸 / 29325 行蓝色小标签），CSS 后定义者胜 → 后者把全局徽章刷成蓝，
设置页的来源/信任级徽章一直显示错色。这类回归**文本断言测试完全看不见**
（js 测试只查 JS 输出的 HTML 字符串），只能靠浏览器计算样式兜底。

- **新增样式前先 grep 同名选择器**：`grep -n "^\.your-class" internal/app/web/static/css/style.css`。
  已存在就**改原处**，不要在文件别处再写一份——同名顶层块靠出现顺序决胜，是样式回归的典型形态。
- **必须分场景时用作用域前缀**（如 `.role-tool-item .external-tool-badge`），不要写裸类名。
- **改样式必须浏览器验**：计算样式断言脚本放 `.workbuddy/tmp/`，跑过再提交；肉眼截图不算验证。
- 存量技术债：2026-10-19 已清掉**可证明安全**的 35 个同名顶层块（判定=每属性都被更靠后、
  `!important` 重要性不更低的同选择器块覆盖），其余 **102 组「部分存活」**未清理
  （如 `.chat-input-container` 两套互斥布局）——人工判定方法见 `docs/HANDOFF_2026-10-18.md` §17，
  **只禁止新增，不要求顺手清理**。
- CI `css-shadow-gate` 会拦新增的「可证明安全」影子块（`scripts/css_shadow_audit.py --check`）；
  要合法收敛存量时用 `--apply`（自带等价性验证，失败不落盘）+ 浏览器计算样式复验，三步都别省。

---

*本文件随事故更新。发现新的"AI 骗了自己"的案例，就补进第一条。*
