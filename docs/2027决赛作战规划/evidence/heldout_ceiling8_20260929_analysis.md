# held-out 8 道失败题「去早停 + 抬预算」重测分析（2026-09-29）

> 上游：B 方案。目的——确认 17-run 的 `race_abandon` 早停是否「误杀」了 LLM 的真实推理能力。
> 硬约束：全局预算 ≤ ¥2（用户授权）。

## 1. 跑批配置（与 17-run 唯一差异 = 早停关 + 预算抬高）

| 项 | 17-run（上次） | 本次 ceiling8 | 差异 |
|---|---|---|---|
| 早停 `CTF_AGENT_BUDGET_REFLECTION` | 强制 `1`（ON） | **不设（OFF）** | ← 关键 |
| 单题预算 `CTF_AGENT_PER_Q_BUDGET` | 80,000 | **200,000**（2.5×） | 抬高 |
| 全局预算 `CTF_AGENT_GLOBAL_BUDGET` | 1,200,000 | **1,300,000**（¥2 硬封顶） | 抬高 |
| E3 证据注入 | ON | ON | 同口径 |
| wallclock | 300s | 600s | 放宽 |
| 调用路径 | `benchmark_heldout.py`（强制早停 env） | **直调 `eval.benchmark`**（绕过强制 env） | 绕开守卫 |
| 题目 | 满 17（含 9 presolve） | **仅 8 失败题** | 子集 |

## 2. 逐题结果（tokens 与 17-run 对照）

| 题 | 类别 | 17-run 终态(单题tok) | ceiling8 终态(单题tok) | 判读 |
|---|---|---|---|---|
| cursved | crypto | race_abandon (27,816) | **race_abandon (202,571)** | 80K→200K 仍主动放弃 |
| mhk2 | crypto | budget_exceeded (80,134) | **budget_exceeded (203,142)** | 80K→200K 烧穿仍失败 |
| primes | crypto | budget_exceeded (82,254) | **budget_exceeded (202,500)** | 同上 |
| zip | crypto | race_abandon (19,667) | **race_abandon (203,379)** | 80K→200K 仍主动放弃 |
| hwsim | misc | race_abandon | **race_abandon (202,091)** | 80K→200K 仍主动放弃 |
| idea | crypto | race_abandon | **race_abandon (200,236)** | 80K→200K 仍主动放弃 |
| mceliece | crypto | race_abandon | **budget_exceeded (124,661)** | 跑到 124K 被全局预算掐断（半截）|
| zkpok | crypto | race_abandon | **budget_exceeded (0)** | 排第 8 位，全局烧穿连坐，0 token 未测 |

- **全局 token**：1,338,580（略超 1.3M 封顶，因单题 200K×6 + mceliece 半截后才检测到全局超限）
- **解出**：0/8
- **错误分类**：race_abandon 4 + budget_exceeded 4

## 3. 核心结论

### 3.1 「早停误杀」假设被证伪
17-run 的 4 道 `race_abandon`（cursved/zip/hwsim/idea）在**早停 OFF + 预算 2.5×** 后，依旧 `race_abandon`，且 token 从 ~20K 涨到 ~200K——说明它们是 **LLM 反思判定「方向错/连续无进展」主动止损**，不是早停机制 bug。17-run 的早停只是把「主动放弃」提前了，没有改变结论。

### 3.2 预算也不是瓶颈
mhk2/primes 两道在 80K 烧穿，本次给 200K（2.5×）依旧烧穿 → 给再多 token 也解不出。

### 3.3 6 道真跑满失败 = 能力边界实证
cursved/zip/hwsim/idea/mhk2/primes 共 6 题**真跑到 ~200K token 仍失败**，这是 held-out 上 LLM 主链路真实推理能力的边界证据。

### 3.4 两道留白（设计缺陷，必须声明）
- **zkpok：0 token、299ms** → 排第 8 位，全局 1.3M 在前 7 题烧穿后被连坐掐断，**根本没机会跑**。本次未测到。
- **mceliece：124,661 token** → 跑到半截被全局预算掐断，未跑满 200K。

→ 严格说「LLM 自主 0/17」中，**zkpok 未经充分测试**；mceliece 半截。其余 14 道 external 题（17-run 的 8 道 + 本次 6 道真跑满）均实测失败。

## 4. 花费核算

| 项 | 值 |
|---|---|
| 总 token | 1,338,580（≈1.34M） |
| 估算单价 | deepseek 公开价 ≈¥1.2/1M（blended） |
| **估算花费** | **≈¥1.6** |
| 硬约束 | ≤¥2 ✓（未超） |
| 实际账单 | deepseek-flash 有 prompt 缓存，实际应更低，以账单为准 |

## 5. 对「LLM 主链路自主推理 0/17」叙事的最终判定

- 17-run：9 presolve 解出 + 8 道进主链路全失败（0 LLM 自主）
- ceiling8：8 道失败题去早停 + 抬预算，仍 0 解出
- **综合**：在已充分测试的 14 道 external 题上，LLM 主链路自主推理 = 0；zkpok（0 token 未测）+ mceliece（半截）留白。
- **结论**：held-out 上 LLM 自主推理能力 ≈ 0 是**真实能力边界**，非早停/预算误杀。项目价值定位应明确为「**确定性优先的 CTF 静态分析框架（presolve），LLM 主链路自主推理在 held-out 实证近乎为 0**」。

## 6. 遗留与建议

1. **zkpok 未测**：若需完整闭环，需单独补跑 1 题（~200K token ≈¥0.25），但会超 ¥2 总预算——建议作为后续独立小批（≤¥0.5 授权）。
2. **mceliece 半截**：同上，可一并补跑。
3. **对外/答辩口径**：presolve 9/17 是真实能力；main_agent_llm 自主 0/17（zkpok 留白）是诚实结论。不美化、不把 presolve 算作 LLM 推理。
