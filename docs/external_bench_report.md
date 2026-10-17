# 外部真题对照尺报告（external-bench）

> 产物：`data/questions_external_bench/external_bench.json`（生成器 `scripts/build_external_bench.py`）
> 跑分：`go test ./internal/ctfplatform/ -run TestExternalBench -v`
> 门禁：`scripts/check_external_bench.py`（自测含 10 条变异用例）
> 生成时间：2026-10-17
<!-- AUTO-CHECK: total=40 payload_complete=38 -->
<!-- 上一行是机验锚点：由 scripts/check_external_bench.py 的 C9 判据比对产物，
     防止报告与实物脱节（报告与实物脱节是本项目 P0 红线，见 data_incomplete_claim_test.go）。 -->

## 0. 一句话结论

**B 的静态求解器在「载荷齐全的外部真题」上 0/40（Google CTF 2021–2025）。**
这个数字**不是战果，是对照证据**：它与自产集 70/72 = 97.2% 并置，
实证「自产集高分 ≠ 解题能力」——此前这条禁令只有文案声明，没有机验支撑。

## 1. 为什么要再立一把尺

| 尺 | 来源 | 载荷 | 数字 | 可被这样辩解 |
|---|---|---|---|---|
| 自产集 72 题 | B 自己造 | 完整 | 70/72 = 97.2% | ——（**开卷考试**：按求解器能力造的） |
| A 库真题 55 题 | 西湖论剑真题 | 完整 | 真求解器 16/55 = 29.1% | ——（**对外唯一有效尺**） |
| cross-bench 88 题 | A 库真题 | **12/88** | 1/88 = 1.1% | 「附件缺失，是数据问题不是能力问题」 |
| **external-bench 40 题** | **Google CTF 2021–2025** | **38/40** | **0/40** | **辩解不成立（载荷齐全）** |

前三把尺都有可被质疑的出口：自产集是开卷、cross-bench 缺载荷。
**external-bench 关闭了"缺数据"这个出口**，因此它是唯一能干净回答
「那 97.2% 到底算不算能力」的尺。

## 2. 数据集

| 项 | 值 |
|---|---|
| 题数 | **40** |
| 分类 | crypto 26 / misc 14 |
| 来源 | google-ctf-2021 (9) / 2022 (10) / 2023 (7) / 2024 (8) / 2025 (6) |
| 授权 | Apache-2.0（`source_repo` 逐题可溯源） |
| 真值 | 逐题 `flag_sha256`（64 位 hex），命中判定用 sha256 比对 |
| 载荷 | 声明 40 题有附件，**38 题齐全**；不全 2 题：`ext_gctf2022_enigma`（5/7）、`ext_gctf2024_otp`（1/287） |
| 入仓附件 | 100 个文件，约 20 MB（目录 `_attachments/`） |

## 3. 实测结果

| 口径 | 输入 | 生产路径 | 注册表路径 |
|---|---|---|---|
| 文本口径 | 仅 `description` | **0/40 = 0.0%** | **0/40 = 0.0%** |
| 有数据口径（含答案形态） | description + 文本附件 | **0/40** | — |
| 有数据口径（剔除答案形态） | description + 文本附件 | **0/40** | — |

附件缺失记账：预期缺失（git 排除的答案文件）0｜异常缺失 0 —— **清单与实物无脱节**。

答案形态附件 4 个（`ext_gctf2023_least-common-genominator` 的 `flag.txt`、
`ext_gctf2025_filtermaze` 的 `flag`、`ext_gctf2025_numerology` 与 `ext_gctf2025_bpfbox` 的
`flag.txt`），按 cross-bench 同口径在「剔除答案形态」口径中跳过。
经 sha256 逐文件校验：**四者均不含本题 flag 明文**（3 个是占位符 `CTF{flag}`、
1 个是二进制密文产物）⇒ **不进 git 排除集**（git 排除 = 0），PUBLIC 仓红线未触发。

另：磁盘↔清单双向核对——除清单登记文件外，`attachments/` 下**无任何游离文件**（0 个未登记）。

### 4.1 CI 首次运行暴露的两处真问题（2026-10-17 修复，如实留痕）

PR #44 首轮 CI 抓到两个**本机看不见**的缺陷，均已在修复提交中闭环：

1. **`go vet ./...` 失败**：载荷里有 Google CTF 的 `.go` 源码（tiramisu / tonality / bpfbox），
   被当作**模块内包**编译，其 import（`crypto-tiramisu/pb` 等）不在 std ⇒ vet 直接红。
   **修法**：载荷目录改名 `attachments/` → **`_attachments/`**（下划线前缀，
   Go 工具链对 `_` 开头的目录一律不递归；与 A 库 `data/questions_real/_attachments` 同约定）。
2. **清单↔实物脱节（fail-closed 报红）**：`public.pem` 与 `.pyc` 被 `.gitignore` 的
   `*.pem` / `*.py[cod]` 拦下，CI 检出缺 2 个文件 ⇒ 载荷台账钉子 `TestExternalBench_PayloadLedgerHolds`
   与附件子集的「异常缺失」判据**正确报红**（这正是门禁该干的事）。
   **修法**：在 `.gitignore` **末尾**加否定块 `!data/questions_external_bench/_attachments/**`
   （gitignore 以最后匹配者为准——写在 `*.pem` 之前无效，此点已实测踩坑）。

> 教训：**"本地全绿" 不含 CI 检出语义**。本机跑测试时文件在工作树上，而 CI 从 git 检出；
> 凡入仓载荷，必须用 `git ls-files` 数一遍，不能只数工作树。

## 4. 归因：是「真实能力缺口」，不是「测量管道缺陷」

项目三根因方法论要求先排除管道缺陷，再谈能力缺口。核对结果：

- **34/40 题实际喂入了文本附件**（题面 + 源码/数据），并非"没东西可喂"；
- 其余 **6 题附件全为二进制**（ELF `.so` / 图片 / 压缩包），presolve 是静态文本分析，
  不喂字节——这属于**已声明的能力边界**，不是管道截断导致的假 miss；
- 附件按 512 KB/文件、1 MB/题 截断（与 cross-bench 同口径），异常缺失 0；
- 未命中题的共性是需要**交互靶机**（如 `pythia` 的 oracle 查询）、**高级数学**
  （`mceliece` / lwe / zkpok）或**二进制逆向**——均超出 B 现有静态求解器能力集。

→ **0/40 归因于真实能力差距**，测量管道无缺陷。**不做任何口径修饰。**

## 5. 用途边界（硬约束，门禁守护）

1. **不得写入对外材料当战果**（`honesty.not_a_kpi`，门禁 C4/C5 禁止其混入
   `data/ctf_benchmark/*.json` 与 `all_benchmarks_summary.json`）。
2. **不得并入 KPI 基准**：本尺存在的意义是对照，混入即污染对外数字。
3. **不设通过阈值**：只报告不断言命中率（§2.2 纪律：不为转绿改阈值）。
4. **唯一正当用途**：与自产集 97.2% 并置，作为「自产集不得作能力证据」的机验支撑；
   以及为"要不要把能力层往上堆"提供真实差距基线。

## 6. 复现

```bash
python scripts/build_external_bench.py --src <A库>/data/questions_external
go test -count=1 -v -run TestExternalBench ./internal/ctfplatform/ -timeout 600s
python scripts/check_external_bench.py                      # 产物一致性（CI 用）
python scripts/check_external_bench.py --src <A库>/...       # 追加生成器↔产物核对（本地）
python scripts/check_external_bench_test.py                 # 10 条变异用例
```

> ⚠️ CI 无 A 库（真源仓库不入 CI），故 CI 侧**不核对生成器↔产物一致性**，
> 该判据显式记 `SKIP`（不静默放行）；需本地带 `--src` 复跑。
