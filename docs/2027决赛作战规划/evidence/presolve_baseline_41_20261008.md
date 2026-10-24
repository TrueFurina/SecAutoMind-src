# 41 题池 · presolve 确定性基线（2026-10-08）

> 目的（用户选 B）：不跑 LLM，只用 presolve 对当前 41 题池测「确定性能力」真实水位。**¥0、不依赖任何 provider 存活。**
> 结论：**真命中 5 / 41**（core.presolve 全 registry 口径，sha256 判真伪）。

## 1. 口径与方法
- 池＝`data/results/heldout_run/`（41 题 = 2 real + 39 external Google CTF 2021–2025），与跑批输入逐字相同。
- 引擎＝`core.presolve.presolve(q, registry=<full>, answers=None, force=True)`——即 `run.py:341` 生产路径调用的同一入口（registry 含 flag_scan / crypto_auto）。
- 判真伪＝对每题返回值算 `sha256(candidate) == question.flag_sha256`（**不直接用 presolve 内部判据**，见 §3 的脚本 bug）。
- 工具：临时脚本（带 `if __name__=="__main__"` 守卫，跑完即删）+ `scripts/_presolve_audit.py`（对照）。

## 2. 结果 —— 真命中 5 / 假命中 1 / 无命中 35

| 判定 | 题 | 返回候选 | sha256 |
|---|---|---|---|
| ✅ TRUE | `ext_gctf2022_cycling` | `CTF{Recycling_Is_Great}` | 吻合 |
| ✅ TRUE | `ext_gctf2022_electric-mayhem-cls` | `CTF{W0ckAwocKaWoCka1}` | 吻合 |
| ✅ TRUE | `ext_gctf2023_least-common-genominator` | `CTF{C0nGr@tz_RiV35t_5h4MiR_nD_Ad13MaN_W0ulD_b_h@pPy}` | 吻合 |
| ✅ TRUE | `real_crypto_dnui_keyboard` | `flag{CLCKOUTHK}` | 吻合 |
| ✅ TRUE | `real_reverse_js` | `flag{cslhahldlnst0day}` | 吻合 |
| ❌ FALSE | `ext_gctf2023_primes` | `CTF{YkDOLIStjpjP5Am1SXDt5d2r9es3b5KZP47v8rXF}` | **不符**（题面 sha=df18e59d…）|

- **确定性真命中率 = 5/41 ≈ 12.2%**（2 real 命中 2/2 = 100%；39 external 命中 3/39 ≈ 7.7%）。**必须分层，禁混成一个率。**
- 39 external 里 crypto 26 / misc 13；命中 3 全为 crypto。

## 3. ✅ 判据 bug 已修（`a9e32fd` 实现 + `9bb0678` 测试）——实为 **`flag_matches` 生产 bug**
- 根因：`eval/cases.py::Question.flag_matches` 把「走 sha256 分支」gate 在 `flag_is_placeholder`（要求 `flag` 字段**本身**是 sha256 串）；对「`flag=None` + 只有 `flag_sha256`」的外部题（全部如此，全库**去重**实测 **40 题**）落进明文分支、与 `None` 比对 → **恒 False**。
- 影响面：`run.py:387/407` **生产判分**即经此路径 ⇒ 这 40 题的任何正确答案都被判 `hallucination`。8 个审计脚本 + 2 个测试同受影响。
- 修复：直接取 `expected_sha256`（优先级「flag_sha256 字段 > flag 占位」已由本类定义）。全库形态 `(plain,set)=0` ⇒ 改动**零行为变更**，仅修 `(None,set)` 40 题。（⚠️ 初稿记 79：把派生副本 `heldout_run` 与源库 `questions_external` 重复计入的文件数，去重后 40。）
- 复核：修复后本审计由 `2 真/4 假`（误判）→ **`5 真/1 假/35 无`**（A/B 两组一致），与 §2 手算吻合。已推送远端 `main`。
- ⚠️ 待复核：项目 10-07 用 `_presolve_audit.py` 报的 ext 池数字受此 bug 影响，需用修好的版本重跑核对。

## 4. 🔴 池漂移：当前 41 池 ≠ 09-29 的 17 池（同 id，真值已变）
- 09-29 `G_rerun_20260929_203948` 报 presolve **9/17**，清单含 `papapapa / totally-not-brute-force / auxin2 / blinders / desfunctional / otp / lcg / dnui_keyboard / reverse_js`。
- 当前 41 池：**同为这些 id，但** ① lcg 真值已从 `flag{program}`（09-29）变为 `CTF{C0nGr@tz_RiV35t_…}`（现，sha 吻合）；② papapapa/auxin2/blinders/desfunctional/otp/totally-not-brute-force **在现池 presolve 均无命中**。
- ⇒ **`data/questions_external` 被重新 ingest 过**（真值/附件变），**5/41 与 9/17 不可比**；09-29 的 9 不能当作当前池的能力。
- ⚠️ 待查→**已查结（见 `presolve_9of17_pollution_20261008.md`）**：那 6 题 09-29 的"解"全是占位词假命中（对 canonical sha 全不符），非真值/附件变更导致路由失效——是**假命中消失**，不是能力消失。

## 5. 诚实声明
- 🔴 5/41 是 **core.presolve 引擎单独**的口径（`answers=None`；实测带 sha256 答案表结果同）；**不等于整条主链路的解出数**。
- 🔴 与 09-29 的 9/17 **不可比**（池已漂移，见 §4）。
- 🟡 假命中 1（primes）可能是**题面真值本身有问题**（返回的 `CTF{YkDOLI…}` 说不定才是真 flag，题面 sha 对应另一写法），非 presolve 之错——需人工核。
- ✅ 结论：**当前 41 池的确定性能力 = 5 题**；LLM 侧已另有独立结论（0，见 `heldout_full17_20260929_analysis.md`）。

*生成：2026-10-08 · 会话 provider-liveness-takeover · 零成本*
