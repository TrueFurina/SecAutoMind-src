# 53 文件池 presolve 确定性基线刷新（2026-10-14，¥0）

> 方法论与 10-08/10-09 基线逐字一致：`core.presolve.presolve(q, registry=<full>,
> answers=None, force=True)`（= `run.py` 生产入口）；判真伪 = `sha256(candidate)
> == question.flag_sha256`（独立复算，不用 presolve 内部判据）。
> 驱动脚本：`data/results/_presolve_resweep_20261014.py`（临时件，方法已记录于此）。
> 原始结果：`data/results/presolve_resweep_20261014.json`（gitignored，按惯例）。

## 1. 刷新动机

MEMORY ③ 的「41 池 8 题」是 10-09 快照。此后发生三件事使其过期：
① h1/papapapa/data_siege/david 四道 B1 接线落地（10-13）；
② `heldout_run/` 池重建 41→53 文件（cybench/NYU 并入 + 审计器 ae7e95a1 新判据）；
③ KPI `heldout_runnable_pool` 41→40。
按「计数写文档前先定义口径并实跑」纪律，全池重测。

## 2. 结果（生产口径：presolve 默认单题墙钟 300s）

```
TRUE  3/53（ext 3/53，real 0/53）  —— 全部是 10-13 新接线题
  ✅ ext_cybench_..._data_siege   5.1s   （EZRAT C2 三段拼 flag）
  ✅ ext_gctf2021_david-and-the-tree  1.3s （DEFLATE Huffman 树隐码）
  ✅ ext_gctf2021_h1              0.7s   （弱 PRNG nonce ECDSA）
FALSE 3/53（占位词诱饵，非能力问题）
  ❌ ext_gctf2025_bpfbox / filtermaze / numerology → 均返回 CTF{flag}
NO_HIT 47/53
```

## 3. 五个变化项逐一定性（重要：都不是「能力回归」）

### 3.1 五道 10-09 旧解出题离开池子（cycling/emcls/lcg/mhk2/dnui）——池重建的设计行为
- 现状：五题**不在** 53 文件池，但源数据完好（`data/questions_external/`、
  `data/questions_real/` 均在）。
- 机制：`scripts/benchmark_heldout.py:select_candidates` 的排除链
  （trained(KPI) / answer_disclosed / known-leak / source-leaked / dup）——
  解出且答案已公开的题按设计从「未见」池剔除（防自证泄漏）。
  与 data_siege 离开 external_unseen（10-13，规则 4）同型。
- ⇒ 不是能力丧失，是池子口径变化；「8/41」与「3/53」**分母不同，不可比**。

### 3.2 zip NO_HIT @300.0s——全局单题墙钟压过 skill 声明墙钟（环境性）
- 现象：`ext_gctf2023_zip` 跑满 300.0s 被杀。10-09 同题 TRUE @1561s。
- 根因：`6a6e508d`（presolve 挂死守卫，10-09 之后落地）引入全局
  `config.per_question_wallclock` 默认 **300s**，压过 ziphard 接线的
  `WALLCLOCK_ZIPHARD=3600`（bkcrack 已知明文攻击 OpenMP 全核需 ~26-38min）。
- 附件完好：`hard.zip` sha256=`bd7584ab…` = google-ctf 原版逐字一致。
- 复跑验证（官方覆盖通道 `CTF_AGENT_PRESOLVE_WALLCLOCK=3600`，代码注释指定的
  CI/调试用途）：`data/results/_zip_rerun_20261014.py`，结果见 §4。

### 3.3 reverse_js NO_HIT @1.3s——10-12 删除事件的数据丢失伤（永久）
- 现象：`real_reverse_js` 1.3s 返回 None。10-09 TRUE（flag=cslhahldlnst0day，sha 吻合）。
- 根因：附件 `index.html` 在 **10-12 02:22-02:27 未知删除事件**中丢失
  （与 may_12/may_14 enigma 密文、多池 `_attachments/` 同一波），
  且该目录**从未入 git**（`git ls-files` 为空）→ 不可恢复。
- 佐证：flag 的源头在 index.html（09-17 起该题就是「扫描到 flag」1319ms）；
  幸存 `coso.js` 内有**三个 `var wincode` 声明**（第 1/460/1000 行，后者遮蔽前者），
  node 权威执行 `delog(wincode)` = `flag{lmjKhKbdjbbgJHkjkG}`，
  与库存 flag_sha256（`aec640f0…`）**三者全不符** → 从幸存数据不可复现。
- 🔴 纪律警告：flag 明文存在于历史日志/resweep JSON 中，**严禁回填**让求解器
  「通过」（从 flag 反推伪造输入的变体）；本题如实记 NO_HIT + 数据丢失定性。

### 3.4 其余 NO_HIT（47 题）——无异常
含 12 道 10-12 起新增的 cybench/NYU 题（本来就不在 10-09 的 41 池里）。

## 4. zip 复跑结果（能力口径）

`_zip_rerun_20261014.py`（官方覆盖通道 `CTF_AGENT_PRESOLVE_WALLCLOCK=3600`）：

```
第一次（08:34，与 Enigma 分析并发）→ NO_HIT @3600.0s：bkcrack OMP 全核攻击
  在 CPU 争抢下未跑完（墙钟耗尽，1 路未完成）——环境性失败，非能力问题。
第二次（09:44，无争抢重跑）→ ✅ TRUE @1733.3s：
  CTF{y0u_u5ed_3xtr@_pl@1nt3xt_t0_d3t3rm1n3_k3ys}
  sha256 = d3109ddee2… == 题库真值 ✓（与 10-09 的 1561s 同量级）
```

结论：zip 能力不变（10-09 TRUE / 10-14 TRUE），300s 生产墙钟是唯一约束；
bkcrack 攻击需 ~29 分钟**无争抢**全核时间，3600s 预算充足但不容争抢。

## 5. 诚实基线口径（唯一合法引用方式）

| 口径 | 定义 | 数字 |
|---|---|---|
| 生产口径 | presolve 默认墙钟 300s/题，当前 53 文件池 | **3/53** |
| 能力口径 | `CTF_AGENT_PRESOLVE_WALLCLOCK=3600` 覆盖（ziphard 声明预算内），当前池 | **4/53**（+zip，1733.3s 实证） |

- 两个口径都必须带分母与定义；禁单独引用「N 题」。
- 10-09 的「41 池 8 题」作废（池构成已变）；引用 presolve 能力只许用本表。
- 两个口径都**与 LLM 自主能力无关**（presolve = 确定性工具链）；
  KPI canonical 实跑未动：offline_verified=14 / real_corpus=93 /
  heldout_candidates=1 / runnable_pool=40 / skills=77 / regression_checks=16。
- 同日另完成 B1 第八道 enigma（不在本池，见 §6）。

## 6. 同日附带战果：B1 第八道 enigma 完整破译（¥0）

- **资产**：10-09 提取的 may12_flag.az（2641 字母）与 google-ctf 仓库原版
  逐字一致；题目目录消息文件已在 10-12 删除事件清空（may_12 的
  flag.ciphertext.txt / flag.fernet.txt 已从公开仓库恢复并校验）。
- **源书**：may_09 明文 = 古腾堡 #18471 Gelpke 书中连续段（实证），但
  may_12（flag 消息）不是书中段落（无自加密碰撞滑书零幸存）。
- **攻击**（已知明文 crib，来自挑战公开仓库的 flag.plaintext.txt）：
  crib 匹配数分层海选（numpy 向量化 210 海军约束序 × 26³ 位置）→ 环量扫描
  → 插板爬山 → **2641/2641 逐字母全中**；恢复设置串
  `VII IV I ATN AH BO CL DU FW GM JY KZ PV QX CLR` 与官方 settings **逐字一致**。
- **flag**：fernet 解密（PBKDF2-SHA256 390000 轮，密钥=归一化设置串）→
  原始德语消息 → 解析得 `CTF{DU HAST GETAN, WAS TURING NICHT KONNTE}`，
  sha256 == 题库真值 ✓。
- **工程化**：`skills/crypto_enigma_crib.py`（numpy 海选 + 纯标准库
  Fernet/AES-CBC）+ presolve 接线（WALLCLOCK_ENIGMA=900）+ 测试
  （`tests/test_crypto_enigma_crib.py` 11 例 + wiring slow e2e）。
- 诚实口径：crib 为本题开发期标定的已知明文（公开数据），密钥由求解器
  搜索恢复（未内嵌设置/flag）；属 B1 工具链补齐产物，不代表 LLM 自主能力。

## 6. 复现命令

```bash
cd ctf_agent
# 全池刷新（生产口径）
.venv/Scripts/python.exe data/results/_presolve_resweep_20261014.py
# zip 单题能力口径复跑
.venv/Scripts/python.exe data/results/_zip_rerun_20261014.py
# KPI 真值
.venv/Scripts/python.exe scripts/_kpi_canonical.py
```
