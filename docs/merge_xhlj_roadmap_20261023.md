# SecAutoMind 全量吞并西湖论剑路线图（2026-10-23 决策记录）

> **决策（用户 2026-10-23 拍板）**：SecAutoMind 全量吞并西湖论剑项目。最终结果 =
> 西湖论剑**永久冻结**（参考仓库，不再作为参赛主体/维护对象），**唯一 SecAutoMind**，
> 且各项能力达到最强。
> 本文档是这次吞并的正式架构决策记录 + 资产盘点 + 分阶段迁移路线图。

---

## 一、决策背景

- 两套项目功能重叠的根因（详见 `ctf2_arena_integration_20261023.md` 讨论）：SecAutoMind
  为"能参赛"按 2026-09-06 对标路线补了 presolve + 平台对接 + 求解器（7→189），
  与西湖论剑 ctf_agent（79 skills + presolve + race 系统）在"求解器/presolve/平台客户端"层重合。
- 用户结论：保留一个最强主体 = SecAutoMind；西湖论剑冻结。
- **赛前（1024 快闪赛 10-24 19:00）不做深度链移植**——经评估（见 §三）所有深度攻击链
  均为题绑定型或重度依赖 Python 数学栈（numpy/sympy/flint/PARI），赛前移植高风险低收益。

## 二、西湖论剑资产盘点（2026-10-23 实地核查）

### 2.1 求解器 skills（79 个 py，按题型）

| 题型 | 数量 | 代表项 |
|---|---|---|
| Crypto | 22 | complex_mult_group（复数组特殊曲线 RSA）、coppersmith、enigma_crib、hastad_broadcast、high_exponent、knapsack_mhk、lattice_attack、lcg_recover、legendre_phi、modinv_factor、pkcs1_improved、pkcs1_padding_oracle、zip_bkcrack、cycling、keyboard_path、primes_subset、electric_mayhem_cls、h1_buggy_rng、ecb_block_attack、enigma |
| Misc | 20 | grid_resample、traffic_analysis、disk_forensics、deflate_huffman、pcap_ezrat_chat、jpeg_padding_stego、zip_fake_encryption、qr_matrix、bigfile_analysis/traffic、morse（ab/decoder）、lfsr_filter_recover、svg_path_text、zip_chain、emoji_binary、mbr_sse_verify |
| Web | 14 | sqli、ssrf、xxe_file_read、ssti_detect、jwt_prototype、second_order_injection、race_condition、source_audit、upload_bypass、multi_step_chain、target_interact、java_deserialization_flow、java_nashorn_response、php_unserialize_pop |
| Pwn | 6 | exploit_flow、libc_fingerprint、nogdb_flow、ret2dlresolve、sandbox_escape、tcache_safelinking |
| Reverse | 10 | angr_solver、elf_general、go_apk、js_methodology、obfuscation、router、pyc_decompile、const_compare、xor_verify、thoroughlystripped |
| 通用 | 2 | task_analyzer、hash_crack |

### 2.2 真题验证链（REAL_SOLVES_LEDGER，13 道 offline_verified 严格 KPI）

> **口径更新（2026-10-24 复核，以台账为准；本节正文保留 10-23 记录原文不改写）**
>
> - 严格 KPI 实为 **14 道**（A 类 6 + B 类 8），不是 13 道；「未覆盖 8 道」= 部分覆盖 4 + 未覆盖 4，该数仍成立。
> - **A 类名册偏差**：`10732`/`10735` **不在**严格 KPI 内（二者可机器复现、REGRESS_PASS，但无题面官方
>   sha256 锚，台账单列「可机器复现但不进 KPI」）；严格的 A 类 6 道为 specialcurve2 / 10733 /
>   vnctf_flag / xuanhun_signin / **sheng / upx**（后两道下文未列）。
> - **B 类为 8 道**：下文列 7 道，漏 `real_reverse_vnctf_cm1`（Android XXTEA，未覆盖）。
> - **覆盖为 6 道直接覆盖**（10733 / vnctf_flag / ezrsa / simplelegendre / exciting_inverse / filterrandom），
>   另有 4 道部分覆盖（xuanhun_signin / anwang_crypto1 / ezmult / qiangwang_classic，原语存在但链路未验证）。
> - 权威口径：`data/ctf_benchmark/xhlj_legacy/ledger_index.md` 与 `coverage_map.json`（`summary` 字段）。

A 类完整攻击链（6）：10733 高偶指数 RSA（=SecAutoMind `rsa_hint_high_exp` 已覆盖）、
specialcurve2 复数组 RSA、10732 PKCS#1、10735 logbool 流量、vnctf_flag 网格重采样
（=`grid_resample` 已覆盖）、xuanhun_signin JPEG 嵌入。
B 类 presolve 确定性（7）：anwang_crypto1、ezmult、filterrandom（=SecAutoMind
`lfsr_correlation` 已覆盖）、qiangwang_classic、ezrsa（=`hastad` 已覆盖）、
simplelegendre（=`legendre_phi` 已覆盖）、exciting_inverse（=`rsa_phi_pinv` 已覆盖）。

→ **13 道验证链中，SecAutoMind 已直接覆盖 5 道**（同名/同数学攻击已注册）；
其余 8 道为题绑定链（特殊曲线 DLP、MHK 背包、Enigma、logbool 等，见 §三 缺口评估）。

### 2.3 非求解器资产

- `core/presolve.py`（207KB）：presolve 管线 + 特殊数学工具（coppersmith、lattice、
  saturated_kernel/LLL、marginal_value、confidence）
- `core/main_agent.py`（102KB）+ supervisor_agent + 7 类错误分类 + 墙钟止损：
  **监督反思/错误分类机制（SecAutoMind poller 无同等实现）**
- `core/race_orchestrator.py` + `race_strategy.py` + `start_race.bat`：
  **首血扫描→稳定轮询→终报（限时赛冲刺调度，SecAutoMind poller 无同等实现）**
- `benchmarks/`（cybench / external_unseen / local_real）+ `heldout_evidence/` + `eval/`：
  基准与留出证据体系
- `ctfplatform/dasctf.py`：pro.dasctf.com 平台客户端（SecAutoMind `dasctf.go` 已逐字对齐）
- `platform_ctf2.py`：CTF² **练习场**适配（`/api/v1/practice/` + JWT，非 Agent 竞技场协议）

## 三、缺口评估（赛前 vs 赛后）

### 3.1 已覆盖（无需迁移）
SecAutoMind solver_registry 157 注册 + 189 求解器（130 真 + 59 检测）已覆盖：
hastad_broadcast / high_exponent_variant / legendre_phi / modinv_factor / rsa_phi_pinv /
rsa_hint_high_exp / lfsr_correlation / grid_resample / traffic_analysis / disk_forensics /
zip_fake_enc / zip_chain / aes_ecb / morse / jwt / ssti / xxe / sqli / ssrf /
race_condition / deserialization / web_source_audit / keyboard_path / padding_oracle /
hash_crack / hash_length_extension / lcg_predict / elliptic_curve / ecdsa_nonce_reuse /
go_binary / python_reverse / obfuscation_detect / pwn_libc_fingerprint / ret2syscall /
ret2csu / sandbox_escape / tcache_safelinking 等。

### 3.2 真缺口（赛后迁移候选）

| 缺口原语 | 西湖论剑来源 | 依赖 | 迁移成本（Go 化） | 赛后优先级 |
|---|---|---|---|---|
| 复数组特殊曲线 RSA（(Z/nZ)[i]） | complex_mult_group | factordb/DLP | 中（DLP 需外部或 BSGS 平滑阶） | P1 |
| Merkle-Hellman 背包（MHK2 等价密钥） | knapsack_mhk | **flint LLL/HNF** | 高（Go 无现成 255 维 LLL） | P2 |
| Enigma M3 crib 攻击 | enigma_crib | numpy 海选 | 高（题绑定 crib，通用价值低） | P2 |
| RSA 循环攻击 | cycling | 纯算法 | 低（**题绑定**：依赖题设特殊 n 结构，通用价值低） | **P2 文档沉淀** |
| ZIP 已知明文（bkcrack） | zip_bkcrack | bkcrack 二进制 | 低（外调） | P0 |
| logbool SQL 布尔盲注流量解析 | verify_10735 | pcap/鲁棒解码 | 中 | P1 |
| Deflate/Huffman 隐写解析 | deflate_huffman | 纯算法 | 高（RFC1951 位级解析，题绑定 GoogleCTF2021 lipogram） | P1 |
| pcap 聊天协议解析（ezrat） | pcap_ezrat_chat | pcap | 中 | P1 |
| 监督反思/7 类错误分类 + 墙钟止损 | core/main_agent + verify/error_classifier | LLM/规则 | 中（Go 化进 poller） | P1 |
| race 首血→稳定轮询→终报 | core/race_orchestrator | 纯逻辑 | 中（融入 poller 策略） | P0 |
| benchmarks/heldout_evidence 体系 | benchmarks/ | 纯数据 | 低（入库复用） | P0 |

## 四、分阶段迁移路线图

### 赛前（1024 快闪赛 10-24 前）—— 冻结执行
- ✅ CTF² Agent 竞技场接入（`ctf2.go` + Token + 真机验证）——已完成
- ✅ 正式赛 ID 预配（CTF2_COMPETITION_ID）
- ✅ **数据资产索引迁移**：西湖论剑 14 道严格 KPI + 2 可复现题的 flag_sha256 锚/验证命令/覆盖对照
  已落盘 `data/ctf_benchmark/xhlj_legacy/`（ledger_index.md + coverage_map.json；纯索引，未复制字节、
  未动 SecAutoMind 基准 JSON，避免基线漂移影响赛前材料口径）
- ✅ **求解资产物理迁移**（用户「凭什么不现在」质询后执行）：西湖论剑 79 个 Python skills + 2 个 core
  依赖（coppersmith/lattice）+ 93 道真题题面 JSON + 16 个附件集已原样迁入
  `data/ctf_benchmark/xhlj_legacy/`；vigenere 冒烟验证可运行（SMOKE_OK，解密正确）。
- ✅ **Python 兜底接入生产链路**（用户「凭什么不现在」拍板后 10-23 执行完毕）：
  - `data/ctf_benchmark/xhlj_legacy/runner.py`：遍历 79 skills 的确定性兜底执行器（统一
    `{'text': <题干>}` 调用；SKIP 交互/二进制依赖类；coroutine 与单 skill 异常捕获；40s 预算；
    flag 形态过滤，只收 `DASCTF{..}/flag{..}` 等）
  - `internal/ctfplatform/presolve_python.go`：fail-closed 通道（开关
    `SECAUTOMIND_PYTHON_FALLBACK` 默认开；python 缺失/目录缺失/超时/输出非法一律 nil；进程超时
    `SECAUTOMIND_PYTHON_FALLBACK_TIMEOUT_MS` 默认 45s；候选去重 + flag 外形过滤）
  - 接入点两处：`PresolveWithRegistry`（registrySweep miss 后）、`Presolve`（best==nil 后）
  - **验证**：`go build ./...` RC=0；`presolve_python_test.go` 5 用例全 PASS（Vigenere 直接命中
    2.28s / 开关关闭 / 空文本 / 普通文本无误报 / 端到端经注册表解出期望明文）；赛前关键回归
    （CTF² 真机链 + presolve + 新兜底）RC=0
  - 设计意图：Go 求解器优先，Python 兜底仅在 Go 全 miss 后触发（实测 registry sweep 先命中
    base64_multilayer 即属正常）；赛时如超时拖累可用 `SECAUTOMIND_PYTHON_FALLBACK=0` 关闭
- ✅ **深度链评估落定**（逐源码核对）：specialcurve2（factordb/DLP+写死 e）、enigma（硬编码
  GoogleCTF2022 crib）、knapsack（flint LLL）、cycling（题设特殊 n 结构）、deflate（GoogleCTF2021
  lipogram）均为题绑定/数学栈依赖 → 赛前一律不移植
- 🚫 **不做深度链移植**（题绑定/数学栈依赖，风险 > 收益）
- 执行：保持现成链路稳定，开赛即用

### 赛后 P0（快闪赛结束后 1 周内）
> **执行状态（2026-10-24 赛前提前完成，用户指令）**：以下 1/3/4 项已落地。口径说明：
> 全部为**增量改动**——新文件 / 新配置字段（默认关闭）/ 纯数据，不触及既有求解器路径；
> `go build ./...` RC=0，新增 10 个确定性测试全 PASS。
> - 1 ✅ `internal/ctfplatform/bkcrack_adapter.go`（fail-closed 外调：`ErrBkcrackUnavailable`、
>   密钥解析、5 分钟超时）+ `tools/bkcrack.yaml`（攻击模式 recipe，Zlib 许可）
> - 3 ✅ `PollerConfig.FirstBloodWindow/FirstBloodInterval` + `pollWait` 纯函数
>   （窗口内短间隔抢首血、窗口后回落；两字段默认 0=关闭，语义倒挂在启动日志告警）
> - 4 ✅ `data/ctf_benchmark/heldout_evidence/`（48 JSON + PROVENANCE 逐字节复制，
>   sha256 自校验 A=aa30d3c1… B=6ce3bfe0…；README 写明历史快照/非本仓复跑/不作废口径混用）
> - 2 未动（评估后降 P1 备选，维持原计划）
> - 5 ✅（2026-10-24 补记）：源仓根 AGENTS.md 已置 FROZEN 冻结横幅；本项目 AGENTS.md
>   已有唯一主体声明（2026-10-23）——两份文件即原计划第 5 项的落地形态
> - 6 ✅（2026-10-24 执行，**合成口径**）：4 道「部分覆盖」链验证完成——原始附件已随
>   源仓 2026-08-26 归档清理永久丢失（93 题库仅 11-12 题附件齐全），端到端原始验证
>   不可执行；改为**同构合成载荷**验证链路：4/4 PASS（skill 原语 + runner.py 桥端到端，
>   anwang 链经生产桥命中合成 flag）。产物：`data/ctf_benchmark/xhlj_legacy/
>   verify_chains_synthetic.py` + `chain_verify_20261024.json`；coverage_map/ledger 同日
>   更新为 chain_verified_synthetic + KNOWN_DATA_LOSS 登记。同日完成**阶段 1 验收可测
>   切片**：A 侧 5/11 vs B 侧 5/12 持平且命中互补，见 `stage1_acceptance_20261024.md`。

1. ZIP 已知明文（bkcrack 外调适配器，Go exec 封装）
2. Deflate/Huffman 隐写解析 Go 化（题绑定 GoogleCTF2021，评估后降 P1 备选）
3. race 首血策略融入 poller（`PollerConfig` 增加首血扫描模式）
4. benchmarks/heldout_evidence 结构复用进 `data/ctf_benchmark/`
5. 更新 AGENTS.md：西湖论剑冻结声明 + 唯一主体确认
6. 4 个「部分覆盖」链（xuanhun_signin/anwang_crypto1/ezmult/qiangwang_classic）用迁移资产做链路验证

### 赛后 P1（P0 后 2 周内）
7. 复数组特殊曲线 RSA（含 DLP 平滑阶 BSGS 或外部服务适配）
8. logbool 流量解析、ezrat 协议解析
   **✅ 2026-10-25 logbool 半项落地**：`pcap_boolblind` 求解器（真实 10735 pcap 端到端命中，
   2678 对/2631 谓词→169B RAR→flag，与 A 库 338-hex 锚一致）；**✅ 2026-10-25 落地**：`pcap_ezrat_chat` 求解器（真实 data_siege 端到端命中：14 密文帧→真口令 mean=0.958→43 字节 flag，0.13s）
9. 监督反思/错误分类机制 Go 化（poller 单题止损 + 策略切换）
   **✅ 2026-10-25 落地**：`internal/ctfplatform/supervision.go`——A 库 error_taxonomy
   （truncated/non-retryable/瞬时三口径单一真值源）+ budget_reflection（CONTINUE/
   SWITCH/ABANDON 纯规则，含候选硬信号与 token 双口径门）移植；PollRecord.ErrorClass
   接线；9 单测镜像 A 库实战边界。消费方：终报/看板按 truncated 区分能力判负与被掐断；
   上层重试循环按 non-retryable 短路；agent 求解循环每 N 步调 ReflectSupervision。
10. 逐 skill 过一遍：仍有价值的通用链继续 Go 化
    **部分 ✅ 2026-10-24**：reverse_static 双经验已 Go 化（bin_flag_repair 垃圾打断修复 +
    bin_flag_concat 分离串拼接，真实 upx/sheng 端到端命中）；同日并行会话将
    anwang/ezmult/qiangwang 三条文本链 Go 化（REGRESS_PASS）。

### 赛后 P2（按需）
11. MHK2 背包（评估引入外部 LLL 后端 vs 保持 Python 工具链）
12. 深度题绑定链（enigma 等）评估：不值得 Go 化则归档，攻击知识沉淀为文档

### 冻结执行（全程）
- 西湖论剑仓库 `E:\Program\西湖论剑\` 只读冻结：README 顶部加冻结声明，不再提交新功能
- 求解器发展一律在 SecAutoMind（solver_registry + presolve_*）进行
- 对西湖论剑的任何未来改动仅限"bug 修复以支撑既有赛事数据复盘"

## 五、验收口径（"各项能力达到最强"如何证明）

1. `python scripts/count_stats.py --json`：ctf_solvers 持续增长（现 189，目标吞并后 ≥ 210）
2. 基准集：西湖论剑 14 道严格 KPI 中未覆盖的 8 道（部分覆盖 4 + 未覆盖 4），Go 化后逐道入基准（REGRESS_PASS 口径）
3. `go test ./internal/ctfplatform/` 全绿无回归（含 TestCTF2LiveSmoke/TestCTF2LiveTargetChain）
4. poller 具备 race 首血策略 + 单题止损（`PollerConfig` 新字段）
5. 西湖论剑冻结声明落地（README + AGENTS.md），两套并存的文档歧义清零

## 六、风险与边界

- **Python 数学栈 vs Go 单二进制**：LLL/coppersmith 等深度工具 Go 化成本高；P2 阶段若评估
  不划算，保留"可选外部工具链"模式（SecAutoMind 主二进制外调），不牺牲主链路稳定性。
- **赛前绝不因吞并动 internal/ 求解器核心**（1024 快闪赛 = 用已验证版本直接参赛）。
- **冻结不是删除**：西湖论剑保留为只读知识库（攻击链、writeup、验证脚本、基准数据），
  其资产通过迁移路线图逐步并入 SecAutoMind。

---

## 七、融合完成记录（2026-10-24 收尾会话闭环）

> 本节为路线图的终点记录：**迁移已全部完成**。细节证据链：
> `CTF-Agent_融合/_MIGRATION_NOTES.md`（并行会话缺口补齐）→
> `CTF-Agent_融合/MIGRATION_DELTA_20261024.md`（收尾会话三方比对）→
> `docs/specs/西湖论剑融合移交_20261024.md`（移交总纲）。

- **资产**：源仓 1943 文件口径全量对账（差 -13 有逐项解释）；113 项未提交变更三方比对 =
  112 已同步 + 1 有意分叉（融合副本 README 改写为留存说明）；`wt-core-bare-guard` 独占护栏
  commit `77bf094c` 已 cherry-pick 回源仓主线（`02e6f998`）并同步 2 文件入融合副本。
- **数据保全**：`KPI_BASELINE.json` / `submitted_flags.json` 两侧 sha256 一致；93 题库 +
  race_attachments + heldout_evidence 全量在册。台账所称 `verified_flags.json` 不存在（文件名
  陈旧，实际即 `submitted_flags.json`）。
- **知识蒸馏**：血训 14 条 → `docs/runbooks/赛前检查清单_事故模式库_20261024.md`（常驻防线）；
  治理机制差距表 / IDEA 移交 / 架构决策 / 阶段性验收阈值 → `docs/specs/西湖论剑融合移交_20261024.md`；
  2027 备战已由 `docs/2027决赛作战规划.md` 吸收（含 9/17 证伪勘误）。
- **源仓终态**：冻结收编 3 commit（`a9cd01ac`/`8d0da7f1`/`02e6f998`）后推远端；worktree 清理；
  大文件（21GB bundles 等）保留至用户验收融合结果后彻底删除（用户 2026-10-24 拍板"完全定死"）。
- **验收阈值**（裁定终审修订）：阶段 1 = presolve 层解出数 ≥ ctf_agent presolve 终态；
  阶段 2 = 完整链路 ≥ ctf_agent 完整链路终态（held-out 外部基准口径）。详见移交总纲 §一。

---

## 八、止损决策（2026-10-25，用户批准"可以，先尝试"）

**决定**：自研求解器移植线（账本 🔧 队列）**即时冻结**；求解器 ≥210 计数目标**作废**
（自建叙事下的虚荣指标——原提出者刀锋自行收回）；SecAutoMind 定位收窄到实测真壁垒：

1. **平台编排层**（IM/HITL/看板/测量体系）——借引擎替代不了的部分；
2. **赛时运维**（preflight/演练/看门狗——1024 实测：与榜首的差距全是自伤运维事故，可修）；
3. **破晓线（LLM 真推理 0→N）**——唯一可能拉开差距的自研方向，即刻开第一枪（≤5 样本纪律）。

**求解策略改为"借引擎为主 + 自有兜底"**：比赛用跑通的组合（1024 实测 9/9 全解），
自研求解器冻结在"已追平 ctf_agent presolve 层"状态（阶段 1 达标，测试钉死），
不再追加移植。P2 格运算/沙箱立项 → 转入待评审池（无预授权）。

**账本状态**：`data/ctf_benchmark/xhlj_legacy/p1_10_inventory.md` 🔧 队列冻结注记已落盘
（18 可移植项：6 完成 / 12 停止，边际价值趋零实证见 §七）。
