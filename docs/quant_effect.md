# quant_effect.md —— 对外量化陈述真值表

> 建立目的：验收第 8 条「对外量化陈述 100% 可指回」。
> 一条对外数字若不能回答「哪台机器、跑什么命令、在哪个基准集上得出的」，
> 它就不是证据，只是修辞。本表把每条对外量化陈述钉到可复现的命令上。

---

## 0. 🔴 先读这一节：基准集不可混用（本项目最大的虚报风险）

本项目存在**多个基准集**，数字之间**不可互相替换**。把自研集的高分说成
"赛题能力"，是本项目最容易发生、也最难被发现的失信。

| 基准集 | 文件 | 题数 | 来源 | 用途 |
|---|---|---|---|---|
| **真题集** | `data/ctf_benchmark/real_benchmark.json` | 55 | 真实赛题 | ✅ **对外能力声称只能用这个** |
| 自研集 | `data/ctf_benchmark/benchmark.json` | 72 | `source: 自研` | 内部回归防退化，**不得用于对外能力声称** |
| 执行集 | `data/ctf_benchmark/execution_benchmark.json` | 17 | 自研 | 执行层链路可用性 |
| Web 集 | `data/ctf_benchmark/web_benchmark.json` | 10 | 自研 | Web 实战链路可用性 |
| 附件集 | `data/ctf_benchmark/attachment_benchmark.json` | 10 | 自研 | 附件取证链路可用性 |
| 同卷立尺 | `data/questions_real_bench/cross_bench.json` | 88 | 西湖论剑真题 | A/B 同卷比较；**尺本身残缺**（见 §3 注） |

**同一时刻的实测对照（2026-10-13）**：

- 自研集 `judge.py` → **70/72 = 97.2%**
- **自研集 真求解器口径 → 55/72 = 76.4%**（70 个命中里 15 个是「题面即答案」伪解，见 §3）
- 真题集 生产路径 → **20/55 = 36.4%**
- 真题集 注册表路径 → **20/55 = 36.4%**（2026-10-15 复测；§3 旧记的 19/55 = 34.5% 已过时，见下）
- **真题集 真求解器口径 → 16/55 = 29.1%**（剔除 4 道「题面即答案」伪解后的能力口径，见 §3）

若只写"覆盖率 97.2%"而不标注基准集，读者会误认为是赛题能力 ——
实际相差 2.7 倍。本表因此把"基准集"列为每条陈述的必填字段。

---

## 1. 机验声明表（由 `scripts/check_quant_effect.py` 逐条复跑比对）

> ⚠️ **跑之前先做一步**：执行层 17 题中有 **2 题是 git 仓库型**（`judge_exec.py` 真跑
> `git log -p` 挖历史泄露的 flag），这类嵌套 `.git` fixture **按设计不入库**，
> 必须先生成，否则执行层实测只有 **15/17**（本机因跑过所以显示 17/17 ——
> 首次挂 CI 门禁就是被这条打红的，且极容易被误判为"平台能力差异"）：
>
> ```bash
> python data/ctf_benchmark/regen_exec_fixtures.py
> ```
>
> CI 的 `quant-gate` job 已内置该步骤。

```yaml
claims:
  - id: real_static_shipped
    陈述: 生产路径 Presolve 真题覆盖率
    基准集: 真题集(55)
    期望: 20/55 = 36.4%
    command: go test ./internal/ctfplatform/ -run TestRealBenchmark_ShippedPresolve -v
    pattern: '(\d+)/(\d+) = ([\d.]+)%'
    实测: 2026-10-13 20/55 = 36.4%
    状态: 已验证
    耗时类: quick

  - id: real_static_registry
    陈述: 注册表路径 PresolveWithRegistry 真题覆盖率（对外材料"静态 36.4%"取的就是这条）
    基准集: 真题集(55)
    期望: 20/55 = 36.4%
    command: go test ./internal/ctfplatform/ -run TestRealBenchmark_RegistryPresolve -v
    pattern: '(\d+)/(\d+) = ([\d.]+)%'
    实测: 2026-10-15 20/55 = 36.4%
    状态: 已验证
    耗时类: quick

  - id: real_static_real_solver
    陈述: 真求解器口径真题覆盖率（剔除 4 道「题面即答案」伪解后的**能力口径**）
    基准集: 真题集(55)
    期望: 16/55 = 29.1%
    command: go test ./internal/ctfplatform/ -run TestRealBenchmarkHitNotInflatedByPlaintextFlag -v
    pattern: '真求解器\s*(\d+)/(\d+)\s*=\s*([\d.]+)%'
    实测: 2026-10-15 16/55 = 29.1%
    状态: 已验证
    耗时类: quick
    注: 全量 20/55 中有 4 题 description 直接写 flag 明文、由 flag_scan 正则命中，
        不构成解题能力；本条扣除它们，是**建议对外使用的主口径**。

  - id: selfgen_static
    陈述: 自研基准集确定性求解覆盖率（**内部回归用，不得对外作为赛题能力**）
    基准集: 自研集(72)
    期望: 总数 72 · 命中 70 = 97.2%（注：judge.py 先输出总数后输出命中，pattern 顺序同此）
    command: python data/ctf_benchmark/judge.py
    pattern: '总数:\s*(\d+)[\s\S]*?确定性命中[^:]*:\s*(\d+)'
    实测: 2026-10-13 总数 72 · 命中 70 = 97.2%
    状态: 已验证
    耗时类: quick

  - id: selfgen_static_real_solver
    陈述: 自研集**真求解器**覆盖率（剔除 15 道「题面即答案」伪解）
    基准集: 自研集(72)
    期望: 55/72 = 76.4%（真求解器口径；全量 70/72 = 97.2% 含伪解，不得单独作为能力证据）
    command: python scripts/check_benchmark_plaintext_answer.py
    pattern: '真求解器 benchmark\.json:\s*(\d+)/(\d+)\s*=\s*([\d.]+)%'
    实测: 2026-10-16 55/72 = 76.4%（全量命中 70，伪解 15）
    状态: 已验证
    耗时类: quick

  - id: exec_layer
    陈述: 执行层基准（实时起靶利用 SQLi/SSTI）
    基准集: 执行集(17)
    期望: 17/17 = 100.0%
    command: python data/ctf_benchmark/judge_exec.py
    pattern: '总数:\s*(\d+)\s*命中:\s*(\d+)'
    实测: 2026-10-13 17/17 = 100.0%
    状态: 已验证
    耗时类: slow

  - id: external_control
    陈述: 外部真题对照尺（Google CTF 2021–2025，**载荷齐全 38/40**）——「自产集高分 ≠ 解题能力」的机验对照
    基准集: 外部尺(40)
    期望: 0/40 = 0.0%
    command: go test ./internal/ctfplatform/ -run TestExternalBench_TextOnly -v
    pattern: '合计：生产路径 (\d+)/(\d+) = ([\d.]+)%'
    实测: 2026-10-17 0/40 = 0.0%（文本口径；有数据口径含/剔答案形态同为 0/40）
    状态: 已验证
    耗时类: quick
    注: 本条的用途是**对照组**，不是战果：与自产集 97.2% 并置，实证「自产集不得作能力证据」。
        归因已核——34/40 题实际喂入文本附件，另 6 题附件全为二进制（ELF/图片/压缩包）属
        presolve 已声明的能力边界，故 0/40 是真实能力差距而非测量管道缺陷
        （详见 docs/external_bench_report.md §4）。数字变好需先在口径修复清单登记再改期望值。

  - id: web_layer
    陈述: Web 实战命中率
    基准集: Web集(10)
    期望: 10/10 = 100.0%
    command: python data/ctf_benchmark/judge_web.py
    pattern: '命中率:\s*(\d+)/(\d+)'
    实测: 2026-10-13 10/10 = 100.0%
    状态: 已验证
    耗时类: slow

  - id: attachment_layer
    陈述: 附件取证基准
    基准集: 附件集(10)
    期望: 10/10 = 100.0%
    command: python data/ctf_benchmark/judge_attachment.py
    pattern: '(\d+)/(\d+)\s*=\s*([\d.]+)%'
    实测: 2026-10-13 10/10 = 100.0%
    状态: 已验证
    耗时类: slow

  - id: benchmark_suite_green
    陈述: 基准集套件达标数（对外材料旧称「二十基准集全绿」，当前实测 **26 项**）
    基准集: 全套件(26)
    期望: 26/26
    command: python data/ctf_benchmark/run_all_benchmarks.py
    pattern: '【汇总】基准集达标 (\d+)/(\d+)'
    实测: 2026-10-23 26/26
    状态: 已验证
    耗时类: slow
```

> 🔴 **`benchmark_suite_green` 这条是本表补的最后一块拼图，也是此前最大的虚报入口**：
> 2026-10-14 之前，`run_all_benchmarks.py` 跑完 22 个基准集后**无论结果如何都 exit 0**，
> 而对外材料写着「二十基准集全绿」——某项从 3/3 掉到 1/3 时 CI 照样绿、对外陈述照样"全绿"。
> 现由 `docs/benchmark_baseline.json` 冻结每项达标地板，
> 跑完逐项比对，**任一项未达标即 exit 1**（缺失/空基线同样计红，见 §4）。
> 因此本条期望值里的"22"是**当前套件项数**，今后新增基准集必须同步登记基线
> （未上锁的项按 fail-closed 计红），否则本条会红——这是设计内的。

**项数口径说明**：对外材料（如 `evidence-championship-20260909.md`）写「**二十**基准集」，
那是 **2026-09-09 时点**的口径（4 基础集 + 16 类利用层）；当前已扩到 **22 项**
（新增题目感知渗透 `web_hints` 与 CRC32 伪造 `crc32_forge`）。
历史证据文档保留当时口径（它记录的是当时事实），**对外陈述一律以本表 22 项为准**。

机验命令：

```bash
python scripts/check_quant_effect.py            # quick：只跑秒级项（应急降级用）
python scripts/check_quant_effect.py --full     # 全量 8 条（CI 用这档）
```

实测全量：补入 `benchmark_suite_green`（真跑全套基准集，约 88s）后由 19s 升至
**约 110s**，仍在 CI 单点可接受范围内，故继续跑 `--full`：拆档只会给"少跑几条"留借口。
脚本保留 quick/slow 分档能力，仅在基准集膨胀到分钟级时应急降级。

---

## 2. 需人工核验的对外陈述（脚本暂不覆盖，给出证据位置）

| # | 对外陈述 | 数值 | 证据位置 | 状态 |
|---|---|---|---|---|
| 1 | 工具/技能/Agent 数量 | 90 YAML + 52 内置 = 143 运行时；技能包 23；Agent 18 | `python scripts/count_stats.py` | 已由 `check_material_numbers.py` 覆盖 |
| 2 | 8 条 IM 通道全部已实现 | 8/8 | `docs/zh-CN/IM机器人接入指引.md`；企微见 `internal/handler/robot.go` | 已订正（09-03 入仓，此前材料误写"7+1"） |
| 3 | A/B 同卷立尺 | 1/88 = 1.1% | `docs/cross_bench_report.md` | ⚠️ **不具备决策效力**，见 §3 |
| 4 | 基准集套件达标 | 26/26 | `run_all_benchmarks.py` + `benchmark_baseline.json` | ✅ **2026-10-14 已补入机验表**（`benchmark_suite_green`），且任一项未达标即 exit 1 |

---

## 3. ⚠️ 不得对外使用的数字（写了就是误导）

- **97.2%（自研集）**：不可表述为"赛题覆盖率/解题能力"。只能说"自研回归集覆盖率"。
- **1/88 = 1.1%（同卷立尺）**：不可表述为"B 只能解 A 的 1.1%"。
  实测 A 侧 **76/88 题的挑战数据（附件）已缺失**，题目描述中位数仅 71 字符，
  该数字是"文本口径下限"，反映输入残缺而非能力。详见 `docs/cross_bench_report.md`。
- **34.5% 与 36.4% 的取舍（2026-10-15 修正）**：旧文写「对外取 34.5%（注册表路径）」
  已过时——复测两条路径**同为 20/55 = 36.4%**，34.5% 不再存在，原取舍前提消失。
- **⚠️ 真正该修的是分子侧（2026-10-15 发现）**：20/55 的 20 个命中里有 **4 个是「题面即
  答案」**——`flag_in_html` / `flag_in_json_api` / `flag_in_cookie_set` / `flag_in_log_data`
  四题的 `description` **直接写着 flag 明文**（例 `<!-- secret: flag{html_comment_flag} -->`），
  `flag_scan` 正则一扫即命中，`sha256` 校验确实通过，**但不构成解题能力**：答案被抄在了题目上。
  这正是 `all_benchmarks_summary.json` 里 `flag_scan_only: 4` 的来源——早被统计出来，
  却从未从命中里剔除，也没有门禁守着（现已补，见下）。
  分母侧同样注水：39/55 题面只有一句话摘要、无密文/附件/目标 ⇒ 判据**不可达**恒 MISS。
  两端各踩一条「空洞绿」形态 ⇒ **36.4% 是双向失真、对能力涨落不敏感，不具度量能力**。
  建议对外统一表述为：
  「真实赛题静态确定性求解 **16/55 = 29.1%**（真求解器口径，已剔除 4 道 flag 提取题）；
   含 flag 提取的全量口径为 20/55 = 36.4%，该口径**不得**单独作为能力证据」。
  机验：§1 条目 `real_static_real_solver`；门禁：
  `internal/ctfplatform/miss_attribution_test.go` 的
  `TestRealBenchmarkHitNotInflatedByPlaintextFlag`（含 5 个变异用例）。

---

## 4. 维护约定

1. 任何对外材料新增/修改量化数字，**必须**在本表登记或更新对应条目。
2. 新增条目必须给出 `command` 与 `pattern`；无法自动复跑的，进 §2 并注明证据位置。
3. 数字漂移时**改材料而非改期望值**——除非能证明是测量口径变了（此时须在
   `口径修复清单.md` 登记）。
