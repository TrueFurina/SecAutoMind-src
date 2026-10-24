# 09-29「9/17 presolve」口径复核 —— 大部分为占位自证假象（2026-10-08）

> 承接 `presolve_baseline_41_20261008.md` §4（池漂移）。本文件把「09-29 的 9/17 为什么在当前池不复现」钉死到证据级。
> **结论：09-29 报告的 9 道 presolve「解出」中，7 道的返回值是与真值无关的占位词（`flag{program}` 类），在当前 canonical 真值下全部判假。当前可信的 presolve 基线 = 41 池 5 题。**

## 1. 证据：09-29 返回 vs 当前 canonical 真值（逐题 sha256 比对）

来源：`data/results/heldout/G_rerun_20260929_203948/benchmark_report.json`（`by_solved_by.presolve.solved_list` 9 题）的 `flag` 字段 vs `data/results/heldout_run/`（当前池）的 `flag_sha256`。

| 题 | 09-29 返回 | 当前 flag_sha256 前 16 位 | sha 吻合 |
|---|---|---|---|
| lcg | `flag{program}` | `69981daf9abdebef` | ❌ |
| papapapa | `flag{this}` | `7f0a7016faa59671` | ❌ |
| totally-not-brute-force | `flag{correct}` | `0f5332246937ffa7` | ❌ |
| auxin2 | `flag{time}` | `36bd44fae041e18a` | ❌ |
| blinders | `flag{missing}` | `099cc26a39b564a4` | ❌ |
| desfunctional | `flag{getting}` | `c1dcdcf4ec349587` | ❌ |
| otp | `flag{fancy}` | `fd7e6ace45e9e02b` | ❌ |
| real_crypto_dnui_keyboard | `flag{CLCKOUTHK}` | （(sha256,set) 形态） | ✅ |
| real_reverse_js | `flag{cslhahldlnst0day}` | ✅ | ✅ |

**7/9 的返回值是单字占位词**（program/this/correct/time/missing/getting/fancy）——与 09-30 发现的 `_try_desc_answer` 假命中（`flag{file}`/`flag{tened}`）**同一形态**：从题面描述抽一个词塞进 `flag{...}`。

## 2. 机制推断（为什么当时被判「解出」）—— ⚠️ 推断非实证，已区分标注
- **可直接实证**：7 道返回值是通用英文单词占位（`flag{this}` 类），与 09-30 在 `_presolve_audit.py` 文档化的 `_try_desc_answer` 假命中形态（`flag{file}`/`flag{tened}`）一致；且 09-29 跑批在 10-03 假命中治理（`7859665`+`5c70e76`）**之前**，该假命中链路当时是开的。
- **推断（无法直查）**：要被判「solved」，当时这批题的真值必须与占位词自洽（明文=占位词，或 sha=占位词之 sha）⇒ 09-29 ingest 真值为占位形态。**09-29 池文件已被后续重建覆盖、`data/` 不入 git，无法直查**——此为最可能解释，非实证事实。
- 这**不是解题**：真题真 flag（如 lcg = `CTF{C0nGr@tz_RiV35t_…}`，canonical sha256 当前池可验）与占位词毫无关系。
- 10-08 的 `flag_matches` 修复（`a9e32fd`）补上第三形态（`flag=None`+`flag_sha256`）判据后，占位自证链路彻底关闭。
- **形态佐证（复算）**：当前 41 池 = `(None,set) 39 + (sha256,set) 2`；**恰好那 2 道 `(sha256,set)` 就是 dnui/reverse_js 两道真解**（旧判据对它们本来就生效），39 道 `(None,set)` external 的判分权则曾被旧 bug 整体废掉——`a9e32fd` 修复真正解锁的正是这 39 道。

## 3. 口径更正（对外/记忆必须改）
| 旧口径 | 更正后 |
|---|---|
| 「presolve 确定性 9/17」 | 🔴 **作废**：9 中 7 为占位自证假象，真解仅 2（dnui/reverse_js） |
| 「当前 41 池 presolve 基线」 | ✅ **5/41**（cycling/emcls/lcg/dnui/reverse_js，全部对 canonical sha256 吻合） |
| 「能力分母 2 题 presolve 2/2」 | ✅ 不变（dnui/reverse_js 两题真解成立） |

- **诚实闸**：引用 presolve 能力只允许说「41 池 5 题（canonical sha256 校验）」；**9/17 永不再引用**。
- **正面含义**：修好判据后测出的 5 题（尤其 3 道 external crypto：cycling/emcls/lcg）是**真解**——比 09-29 的虚高 9 更可信、更值钱。

## 4. 与 NYU 34 池复核（C 项）合并结论
- NYU 34（`data/questions_ext`）：修好判据后重跑 = **A 组 18 真/0 假、B 组 16 真/0 假**，与 10-08 早上报数字**逐字一致** → 该池结论**原样复现、不受 bug 影响**（该池为 `(sha256,set)` 形态，旧判据本就正确）。
- Google CTF 41 池：`(None,set)` 形态 → 是被 `flag_matches` bug 波及的池；修复后基线 5/41 为当前唯一可信口径。
- 两池形态差异本身就是「同 bug 不同表现」的实证：判分函数按字段形态分支时必须穷举所有形态（已固化进 MEMORY）。

## 5. 影响面精确锁定（全库形态普查，2026-10-08）
| 库 | n | 形态分布 | `flag_matches` 旧 bug 影响 |
|---|---|---|---|
| `data/questions_real`（**KPI 分母库**） | 93 | (sha256,set) 88 + (plain,none) 5 | **✅ 零影响** |
| `data/questions`（自产训练） | 53 | (plain,none) 52 + (None,none) 1 | ✅ 零影响 |
| `data/questions_ext`（NYU 34） | 34 | (sha256,set) 34 | ✅ 零影响 |
| `data/results/heldout_run`（41 池） | 41 | (None,set) 39 + (sha256,set) 2 | 🔴 39 题判分权曾被废（`a9e32fd` 已修）|
| `data/questions_external`（Google CTF 源） | 40 | (None,set) 40 | 🔴 全部曾被废（已修）|

- ⇒ **KPI 真值（`offline_verified=14` / `real_corpus=93` 等）不受影响，无需重审**；bug 影响面精确锁定在 Google CTF 扩池（`data/questions_external`，40 题 `(None,set)`）。
- ⇒ 完整因果链闭合：09-29 ingest 占位真值（推断）→ 7 道占位假命中自证通过 → 10-03 re-ingest 成 canonical `(None,set)` → 假命中消失 + 旧 bug 废掉这批题的判分权 → `a9e32fd` 修复 → 当前唯一可信基线 **41 池 5/41**。

*生成：2026-10-08 · 会话 provider-liveness-takeover · 全程零成本*
