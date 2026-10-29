# SecAutoMind 项目认知报告（2026-10-26）

> 执行者：本会话（用户指令「深度理解」→ 认知报告 + 记忆更新 + 文件夹盘点 + 缺口风险）。
> 基线：`git head=5462133`（分支 docs/race-day-card），`count_stats.py --json` 当日实跑。
> 性质：**一次性认知快照 + 待拍板方案**——数字是落盘当日真值，引用前重跑真值源。
> 放 `docs/specs/` 子目录（顶层只减不增门禁）；子目录不逐份登记 INDEX。

---

## ⚡ 2026-10-29 增补（本会话后续轮次实况修正，优先级高于下文 10-26 快照）

落盘三天内项目已再次演进，以下为 10-29 本会话**亲自实跑**核实的事实：

| 10-26 快照说 | 10-29 实况 | 证据 |
|---|---|---|
| static 集 20/55=36.4% | **real_static 16/55=29.1%**（脱敏真值）；benchmark 53/72=73.6%；cross_text 0/88 | answer-leak-gate 实跑输出 |
| 破晓瓶颈=附件断链+1道可跑 | **服务器无 docker**，Python 侧 bench 整体不可用；唯一可行 LLM 路径=`internal/runnerl3`+新入口 `cmd/llmbench`；且 LLM 通道仅剩 tokenrhythm（~¥2.27） | `.workbuddy/memory/2026-10-29.md`（他 session 结论，runnerl3 测试已亲验 RC=0） |
| CI 29 job、GATES.md 一致 | **33 job**：+flag-eval-gate/session-gate/answer-leak-gate + capability-denominator 步骤；C6 曾红（地图未重生成），本会话已 `gen_gates_map.py --write` 修复转绿 | check_agent_docs RC=0 |
| — | **同族静默漏报已系统治理**：flag 评测 13 脚本全部迁移统一口径 `flag_util.flag_sha256_hit`，挂账清零（此前 morse_hello 输出 `FLAG{}` 被判 False、runnerl3 只匹配 `flag{` 漏 picoCTF——两起同构） | flag-eval-gate 8/8 命令本机预检全过 |
| — | 新坑入 AGENTS.md 第五条：**本地跑 Python 门禁必须 `PYTHONIOENCODING=utf-8`**（GBK 控制台 emoji 假红，5 门禁同日中招；CI ubuntu 不受影响） | 5 个 rc=1 全为 UnicodeEncodeError，加编码后全绿 |

**自进化建议落地对照**：flag-eval-gate（≈建议 #9 判据口径统一）、session-gate（≈建议 #10 台账数字化）、answer-leak-gate + preflight（≈P0 泄漏防线）——项目在自发长出同类机制，且全部带变异验证。

**三创赛三份文件**（一页纸/演示脚本/答辩QA，b7352d6 入库）：仅工作树本地删除、HEAD 完整可恢复、全仓零引用——恢复与否待拍板。

---

## 一、项目是什么

双体 CTF 安全智能体，唯一参赛主体（西湖论剑 ctf_agent、Security-Agent 均已全量并入并冻结只读）：

| 体 | 位置 | 职责 |
|---|---|---|
| Go 单体头 | `cmd/server` + `go:embed` 前端 `internal/app/web/` | 平台对接（dasctf/ctf2）、拉题、起收靶机、提交判分、确定性求解器、CI 门禁体系 |
| Python 融合线 | `CTF-Agent_融合/ctf_agent`（代号「破晓」） | LLM 主链自主推理 |

当日真值（`scripts/count_stats.py --json`，head=5462133）：
go_files **880** / total_lines **198448** / 49 Go 包；tools_yaml **91**（declared **90**）/ runtime_tools **143**；ctf_solvers **203**（real **144** / detectors 59）；exe **89.8 MB**。

> ⚠️ 求解器数字属**存量快照**：战略转向后不再是冲刺 KPI（见二）。

## 二、战略现状（最关键认知）

**战略转向已获用户批准**（commit 59fe89b，2026-10-25 登记）：

- 确定性求解器线**冻结**，≥210 求解器目标**作废**，周审停止对标 210；
- 定位收窄为两条腿：**平台编排 + 破晓 LLM 线**；
- 唯一 KPI = **heldout 真题解出数**（引用必声明分母）；
- 第一病史红线：**严禁把 presolve 命中或自产/合成靶场冒充 LLM 解出**。

## 三、当前真实瓶颈（数据，不是能力）

- heldout 真题**只有 1 道真正可跑**（`real_reverse_js`）；34 道候选中 33 道附件缺失（2026-08-26 归档清理永久损失的延伸，hg2022/RSA Attack 2·3 亦断链）。
- 破晓 LLM **解出 = 0**：4 次真跑全部 `wallclock_timeout / wallclock_killed`（122–150s），单题成本 ~25,604 tokens / 122.6s。
- E3 证据注入埋点恒 False 的根因：模型不主动调 `file_analyze` → `attachment_evidence` 恒空 → 机制未生效（「开关打开 ≠ 机制生效」）。
- **推论：当前「LLM 解出=0」主要由「n=1 + 附件断链」造成，不能直接解读为模型能力不足。铺路线（找回 33 道附件）是解锁统计意义的唯一钥匙。**

## 四、组织方式：6 角色 × 文件边界

| 角色 | 使命 | KPI |
|---|---|---|
| 刀锋 | 确定性求解器攻坚 | 新链 REGRESS_PASS |
| 立尺 | 测量与诚实守门（一票否决） | 口径零事故 |
| 听风 | 监督消费 + 赛时策略 | 监督消费率 / 演练绿 |
| 破晓 | LLM 主链 0→N | heldout 纯 LLM 解出数 |
| 铺路 | 平台/部署/CI/发布 | 赛时链路可用 |
| 观澜 | 多会话协同仲裁 | 冲突事故数 / 在飞收口率 |

分工按**文件边界**切（踩过并行会话同文件互踩 + 分支被 reset 重建的坑）。最新周审（立尺 2026-10-25）：**WARN**（6 PASS + 1 WARN 归因分桶待跑批，零 FAIL）；基准 26/26 达冻结基线；static 集 20/55（36.4%）。

## 五、工程纪律体系（本仓最重资产）

- **29 个 CI job**（`docs/GATES.md` 自动派生）：caliber-gate / truth-source-gate（材料数字 vs count_stats 真值）、freeze-gate（**窗口 2027-02-15~03-01**，禁改 `internal/ agents/ cmd/`）、secret-gate、agent-docs-gate（docs 顶层只减不增 + INDEX 登记）等。
- 数字**单一真值源** `scripts/count_stats.py --json`，写死必漂（已三次人肉发现漂移）；**只在发布节点刷**，改代码期间红了不刷。
- 环境坑（照抄）：`export APPDATA` + conda/go PATH 先行；`go test -p 1`（否则 OOM 假红）；判成败 `cmd > out.txt 2>&1; echo RC=$?` 不用管道；`git add -A` 禁用。

---

## 六、缺口与风险清单

### 🔴 高优先

| # | 缺口/风险 | 影响 | 归属建议 |
|---|---|---|---|
| 1 | 33 道 heldout 附件缺失，部分或永久损失；破晓一切实验在 n=1 上无统计意义 | 头号阻塞 | 铺路（B 车道，未开工） |
| 2 | secret_guard 21 处系统性假阳性（`CTF-Agent_融合/` PyCryptodome 测试向量 + 合成样本）→ 每次提交都 `--no-verify`，持续削弱密钥门禁 | 安全防线实质降级 | 需单开 scope 做白名单（改错会放真 key，需变异验证） |
| 3 | `solved_by` 语义隐患：故障路径填值不一致（timeout→`main_agent_llm`，killed→`unknown`），且 `solved=False` 也填值——按它聚合会把「尝试」当「解出」，与第一病史同构 | 口径事故温床 | 立尺已裁定：改名 `attempted_by` 或仅 solved=True 填值；待改 |

### 🟡 中优先

| # | 缺口/风险 | 说明 |
|---|---|---|
| 4 | `QUICKSTART_NEXT_AGENT.md` 停在 10-20，仍指向「以 HANDOFF_2026-10-18 为准」，与 10-25 战略转向/角色体系脱节 | 新会话入口卡会误导 |
| 5 | 12 个 CI job 无变异验证（GATES.md 标「无」） | 「有注释」≠「真能变红」 |
| 6 | 供应链门禁不做 CVE 扫描；`requirements.txt` 仍是 `>=` 浮动无 lockfile | 只有 G-02 一半 |
| 7 | 分支在途 117 项改动（66 未跟踪）为并行会话 WIP，收口状态不明；`docs/specs/` 三份三创赛材料呈删除态（D） | 删三创赛材料是否有意，需确认 |

### 🟢 低优先 / 待拍板

- ACC2026 网关硬期限 2026-10-25 18:00、余额 ~$215 用途未定（可能已过期）。
- `data/work_web/10716`（19827 文件/83MB）去留待决；西湖论剑源仓物理删除等观察期（最早 11-07，按 `_MIGRATION_NOTES` §三）。
- 强模型接入未开始（需用户决策充值/申领 key）。

---

## 七、文件夹盘点与整理方案（**未执行任何移动/删除，待拍板**）

### 7.1 盘点结论（顶层 31 目录 / 19 文件）

| 类别 | 目录 | 性质 | 动作建议 |
|---|---|---|---|
| 不可动 | `Security-Agent_融合/` | **源已删的唯一副本**（挑战杯留存，1.4M） | 绝对不动 |
| 不可动 | `CTF-Agent_融合/` | 破晓 LLM 主链，在途 WIP 所在 | 只按车道纪律动 |
| 不可动 | 西湖论剑源仓 `.git` | 21040 归档独有文件 + work_web/10716 提取源 | 绝对不动 |
| 受门禁 | `installer/`（106M）、`SecAutoMind_PPT/`（172M）、`官网/`、`docs/` | binary-gate / caliber-gate 锚点 | 不建议动 |
| gitignore 临时区 | `dist/`（171M）、`work/`、`logs/`、`scans/`、`chat_uploads/` | 可再生的运行产物 | **唯一值得清的**，见 7.2 |
| 疑似冗余（根目录） | `runner.exe`、三份 README、三份 config | 二进制躺在仓库根；README/config 各司其职待确认 | 待确认后归并 |

### 7.2 三个待选方向（用户拍板后执行）

1. **只清 gitignore 临时区**（`dist/work/logs/scans/chat_uploads`，~175M+）：用 `host_safe_delete` 走回收站，逐项列清单再删。风险低（gitignored、可再生），但需确认无并行会话正在写 `data/results/` 相邻产物。
2. **只做认知整理**：同步 QUICKSTART 到 10-25 战略现状（改文档需登记 INDEX、跑 agent-docs-gate）。
3. **都不动**：本报告作为盘点结论留档。

### 7.3 整理红线（为什么不顺手 sweep）

- 分支在途 117 项是并行会话 WIP，`git add -A` 与全目录 sweep 均会卷进他人工作；
- docs 顶层只减不增 + INDEX 登记门禁；
- AGENTS.md 第十/六条：删资产、改对外口径必须先拿用户明确授权。

---

## 八、取证边界声明（收尾清单 §二）

- **没查的**：29 个 CI job 未逐一实跑（仅读 GATES.md 派生地图）；`dist/work/logs/scans/chat_uploads` 内部内容未逐项清点（仅判定 gitignore 性质与体积）；六角色各会话当前实际在飞状态未逐一核验；三创赛三份删除态文件是有意归档还是误删未确认。
- **查了但没覆盖的**：真值数字以 `count_stats.py` 当日一次实跑为准，未做二次复核（RC=0）；117 项在途改动的逐文件归属未判定。
- **仍未知 / 仍待用户拍板的**：整理方向三选一（§7.2）；33 道附件找回渠道是否需要用户账号授权；强模型接入的充值/申领决策；ACC2026 网关余额处置。

---

## 附：本会话已完成动作

1. 通读常驻区六份地图文档（ROUTES / INDEX / QUICKSTART / 收尾清单 / GATES / LessonsLearned）+ specs 三份战略文档 + 立尺周审。
2. 实跑 `count_stats.py --json`（RC=0，数字见 §一）。
3. 盘点顶层 31 目录 git 跟踪/忽略性质 + 根目录 19 文件。
4. 项目认知已更新至助手长期记忆（MEMORY，跨会话生效）。
5. 本报告落盘 `docs/specs/`（本文档）。
