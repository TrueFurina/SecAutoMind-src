# F-04 判分假阴性修复（2026-11-07）

> 对应 `E:\Program\VibeCoding\失败解剖_SecAutoMind_20261107.md` §2 F-04，
> 以及该文 §4「如果重来一次」的**第 2 步**——此前被跳过的那一步。

## 0. 一句话

`candidate_variants()` 从来不产生裸内容变体，导致「真值登记为 `sha256(裸内容)`」的题
**答对永远判不中**。已补 `allow_shell_strip`，正向用例接进 `flag_util` 自测（17 例，
其中 5 例是本次新增的 F-04 专属用例），并**用真实判分路径**复算历史结果：
`purellm_full176` 由 **1 → 6**，增量 5 题与 11-06 的预测逐题一致。

## 1. 改了什么

| 文件 | 改动 | 机验 |
|---|---|---|
| `scripts/experiments/flag_util.py` | 新增 `strip_shell()`；`candidate_variants()` 加 `allow_shell_strip=True`，裸内容变体排在**最后**（保向后兼容）；`flag_hit_mode()` 增 `bare` 三类区分 | 自测 **17/17 PASS** |
| `scripts/audit_scoring_variant_gap.py` | 根因已修 ⇒ 本脚本转为**回归哨兵**；新增 `format_gap` 类别（同值不同零填充宽度），与 `false_negative` 分开计 | 自测 **12/12 PASS** |
| `scripts/gen_private_pool_v1.py` | 删掉自带的第 10 份判分正则副本，改为 `from flag_util import FLAG_RE` | `check_flag_eval_regex.py` 本文件违规清零 |
| `.github/workflows/ci.yml` | 步骤名用例数 `7` → `17`（陈旧标签，本次实际新增 10 例） | — |

## 2. 为什么排在最后（向后兼容论证）

变体顺序：`原文 → 全小写 → 前缀归一 → 前缀归一+小写 → **裸内容** → 裸内容+小写`。

真值若登记为**带壳**形态，更靠前的带壳变体会先命中，返回值与历史读数一字不变；
只有带壳全不中时才落到裸内容 ⇒ **只修假阴性，不改已判中的题**。

实测印证：私有池 v1/v2 共 8 个结果文件、110 行，**0 翻转**。

## 3. 影响面（真实判分路径重算，不是模拟）

对仓库内全部 `.result.json` 逐行用 `ctf_stepfun_orchestrator.verify_flag()` 复算：

| 结果文件 | 行数 | 原判命中 | 重算命中 |
|---|---|---|---|
| `docs/evidence/private_pool_v1_20261107/agentic_run_a` | 10 | 10 | 10 |
| `docs/evidence/private_pool_v1_20261107/agentic_run_b` | 10 | 10 | 10 |
| `docs/evidence/private_pool_v1_20261107/run_a` | 10 | 3 | 3 |
| `docs/evidence/private_pool_v1_20261107/run_b` | 10 | 2 | 2 |
| `docs/evidence/private_pool_v1_20261107/run_c` | 10 | 3 | 3 |
| `docs/evidence/private_pool_v2_20261107/agentic_s1` | 40 | 37 | 37 |
| `docs/evidence/private_pool_v2_20261107/agentic_s2` | 40 | 33 | 33 |
| `docs/evidence/private_pool_v2_20261107/agentic_s3` | 40 | 36 | 36 |
| `docs/evidence/capability_eval_20261105/smoke3` | 3 | 0 | 0 |
| `scripts/purellm_full176.result.json` | 176 | **1** | **6** |
| **合计** | **349** | **135** | **140** |

新增命中的 5 题（全部落在公开 176 池，与 11-06 记录的 5 题逐题一致）：

```
real_misc_sheng2022_traffic_bruteforce_count
real_misc_sheng2022_traffic_enable_pwd
real_misc_sheng2022_traffic_ftp_dataconn_count
real_misc_sheng2022_traffic_ftp_port
real_misc_sheng2022_traffic_telnet_pwd
```

**关键副作用**：`purellm_full176` 的历史读数 `1/176` 实际是 `6/176 = 3.4%`。
但 `scripts/purellm_full176.result.json` 与全部 verdict **一律不回写**——
它们是当时的判分产物，改写等于伪造历史。本文件是唯一的重算记录。
且该池 **176/176 全公开**，`3.4%` 仍然**不是能力率**（锐评 F-02 未变）。

**私有池读数不受影响**：v2 三轮 `37/33/36 = 106/120 (88.3%)` 全部 0 翻转，原读数成立。

## 4. 检测器跟着判分器一起错（本轮新发现，已修）

`pp_v2_30_vm_bytecode_trace`（s3）交 `flag{00004908}`：值 `0x4908` **完全正确**，
但题面要求 **16 位零填充**，模型只给了 8 位。

- 判分判未命中 —— **这是对的**，它违反了输出契约，不该算解出；
- 但 `audit_scoring_variant_gap` 当时报 `false_negative_count=0`，等于
  「连存在一个值正确的答案」这件事都看不见 ⇒ 空洞绿（F-06 的一个新实例）。

已把这一类单列为 `format_gap`：**不计入 `false_negative`**（因为判分没错），
但必须可见。修复后重扫三轮：s1 = 0、s2 = 0、s3 = **1（`pp_v2_30`）**。
未解三分类与 `rate` 均不变 —— 本次没有放宽任何判分口径。

## 5. 顺带修掉一处 CI 红（我自己引入的）

`check_flag_eval_regex.py` 在 HEAD 上报 **RC=1 / BLOCK**，其中一条来自
`scripts/gen_private_pool_v1.py:42` —— 第 15 轮我造池时自带了一份只认小写
`flag{...}` 的正则副本并直接比 sha256，等于仓库里**第 10 份判分正则**。
该 job（`flag-eval-gate`，`ci.yml:911`）确实在 CI 里，RC=1 即红。
正解不是加豁免，而是不再维护副本 —— 已改 `from flag_util import FLAG_RE`。
改后两个池的 sha256 逐字节未变（`26dd0dee…` / `bce2478…`），生成器自测 5/5、8/8。

## 6. 遗留红（**不属于本轮，未修，需人决定**）

`check_flag_eval_regex.py` 仍有 3 条违规，全部在 `scripts/check_redaction_consistency.py`
（`:75` `:76` 两条 `A:lower-only-regex` + `:75` 一条 `B:no-normalization`）。
该文件最后改动是 `R6`/`R10` 两个提交，**不在本轮提交范围内**；
挂账表 `scripts/flag_eval_allowlist.json` 当前 `entries: []`（10-28 已清零），
即这 3 条**既没修也没挂账**，CI 从那时起就是红的。

未修理由：`ANY_FLAG` 用于全库扫 flag 明文，改成大小写不敏感会改变脱敏账本的比对
结果，可能连带打红另一个门禁 —— 属别人职责范围的口径变更，不代改。
**含 uppercase 的真 flag 当前看不见，这本身是一个泄漏检测盲区，建议认领。**

## 7. 作用域声明

- 本次只改**判分函数与审计层**，未改任何题面、未改池、未改 verdict、未重跑模型。
- 未验证：Go 侧 `internal/runnerl3/llm_solver.go` 是否也有同类「不去壳」漏判
  —— 本文件只覆盖 Python 判分链路。
- `format_gap` 的零填充阶梯是 `{4,8,16,32,64} ∪ {len+1..len+16}`，**不是全覆盖**；
  超出该阶梯的同值异宽仍会漏报。
- 「16 位零填充」判未命中是否合理，取决于题面是否明写宽度 —— 我抽查了 `pp_v2_30`
  题面确有明写，其他题未逐题核对。
