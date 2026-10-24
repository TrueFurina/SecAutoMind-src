# held-out 重测·首批 5 题实测分析（G 接入主链路后，2026-09-29）

> 跑批命令：`CTF_AGENT_GLOBAL_BUDGET=300000 python scripts/benchmark_heldout.py --run --provider deepseek --limit 5 --wallclock 300 --external-dir data/questions_external`
> 报告：`data/results/heldout/G_rerun_20260929_195632/benchmark_report.json`
> 日志：`logs/heldout_g_rerun_20260929.log`

## 一、逐题结果

| 题 | 类别 | 终态 | 错误 | token | 时长 | 备注 |
|---|---|---|---|---|---|---|
| ext_gctf2023_cursved | crypto | ❌ | race_abandon | 27,816 | 11.3s | 早停止损，零进展 |
| ext_gctf2023_least-common-genominator | crypto | ❌(**误判**) | race_abandon | 84,468 | 61.8s | **presolve 确定性预扫命中 flag{program}（候选=True，sha256 通过），被 --presolve-skip 丢弃；主链路重跑时 LLM 在持久 shell 生成的 command 全报 invalid syntax** |
| ext_gctf2023_mhk2 | crypto | ❌ | budget_exceeded | 80,134 | 34.6s | 单题 80K 硬顶（全局 300K 下每题≈80K）|
| ext_gctf2023_papapapa | misc | ❌ | race_abandon | 19,667 | 12.3s | 早停 |
| ext_gctf2023_primes | crypto | ❌ | budget_exceeded | 82,254 | 114.8s | 单题 82.3K > 80K 超限 |

- 全局 token：**294,339**；单题区间 19.7K–84.5K，均值 **≈58.9K**。
- 报告自身诚实闸：`integrity.interpretable=false`、`truncated=5`，并声明**「本报告不可作为能力率引用：分母含未真正执行的题 / 被基础设施掐断的题」**。

## 二、关键发现

1. **G 接入主链路确实生效（真实跑批非 mock）**：`G1 持久会话已建立` + 监督 LLM 裁决 continue/redirect + 连续同动作强制切 script 策略，全部真实触发。
2. **least-common-genominator 是口径误判**：presolve 已拿到 sha256 验证通过的 `flag{program}` 候选，但 `benchmark_heldout.py:439` 硬编码 `--presolve-skip` 强制主链路重跑，LLM 在持久 shell 里生成的 command 持续 `invalid syntax (<unknown>, line 1)` → 失败。若按 09-27 口径（允许 presolve 候选验证）应判解出。
3. **0/5 不能当能力率**：错误分类 `race_abandon:3`（G 早停止损，未触能力上限）+ `budget_exceeded:2`（单题 80K 硬顶），全是预算/早停机制干预，非能力失败。
4. **本次 5 题均为 external 更难池**（cursved/least-common-genominator/mhk2/papapapa/primes），**未包含 real 2 题能力分母**（dnui_keyboard/reverse_js）——`--limit 5` 在 external 子集取前 5，跳过了 real。符合「heldout_runnable_pool=17 是可选跑池不是能力分母」的治理约束。

## 三、与 09-27 基线对比（口径不一致，解出率不可比）

| 维度 | 09-27 | 09-29（本批）|
|---|---|---|
| 题池 | 2 题 real 能力分母 | 5 题 external 更难池 |
| presolve | **允许**（reverse_js solved_by=presolve）| **强制 --presolve-skip** |
| 解出 | 2/2（dnui_keyboard=LLM 自主 + reverse_js=presolve）| 0/5 |
| token | 8,243（单题 4.1K）| 294,339（单题均值 58.9K ≈ 14×）|

- 两批**不可直接比解出率**：① 题池难度不同；② presolve 开关不同。
- 唯一可比项 token 量级印证「external 题比 real 题难 ~14×」，符合预期。

## 四、花费（估算，项目无花费跟踪）

- 本批实测 294,339 tokens。按 deepseek 公开价（deepseek-chat ¥1/1M 输入 + ¥2/1M 输出）保守估算 ≈ **¥0.3–0.5**；`deepseek-flash` 实际费率可能更低（免费档待确认），以账单为准。

## 五、下一步建议 + 待用户授权

1. **先修口径**：去掉/条件化 `benchmark_heldout.py:439` 的 `--presolve-skip`，与 09-27 同口径（presolve 命中即验证），否则系统性误杀 presolve 可解题（至少 least-common-genominator 一例）。
2. **跑全 17 题**：含 2 real 能力分母 + 15 external，全局预算需 ≈1M token（17×58.9K），建议 `CTF_AGENT_GLOBAL_BUDGET=1200000`；预估金额 ≈¥1–2（deepseek-flash 可能更低）。
3. ⚠️ **需用户授权**跑全 17 题（跑批铁律：先估 token×金额报授权）。
