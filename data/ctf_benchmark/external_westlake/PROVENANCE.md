# PROVENANCE — 外部真题基准（西湖论剑 CTF-Agent 导出，2026-10-05）

## 这是什么
一套**非自建**的真实历史赛事 CTF 题基准，来源：西湖论剑 CTF-Agent 项目的
`data/questions_real/` 题库（西湖论剑/Anxuan/VNCTF/DASCTF 等系列真题）。
每题带 `flag_sha256` 真值，可机器判真伪；导出前已做**载荷完整性机器校验**。

## 为什么不自建
贵方自建工件基准接近全绿（执行 17/17、附件取证 10/10、自研 70/72=97.2%），
外部公开真题 19/55=34.5% 且 36 个 miss 靠人工判读"缺载荷"。本套补的正是
**外部真值 + 载荷完整**这一格，让"能力数字"不依赖自建工件难度。

## 口径与红线（引用前必读）
1. **只认 SHA-256**：判定见 `judge_external_westlake.py`，禁止"看起来像 flag"计命中。
2. **`trained_in_westlake=true` 的题必须剔除**才能进入贵方"未见题"分母——
   这些题在导出方属已训练/KPI 池，重复计入会让两边同时注水。judge 脚本已
   自动输出剔除该标记后的子集成绩。
3. **载荷完整性已前置校验**：附件未落盘的题在导出阶段即被排除（见
   `export_manifest.json` 的 `payload_missing_on_disk` 条目），避免"缺载荷必然 0"
   的假 miss 重演。
4. **无明文答案**：本目录不含任何明文 flag，只有 SHA-256。
5. **规模与题型**：见 `export_manifest.json` 的 `by_category`（以导出实跑为准）。
6. 附件路径 `attachment(s)` 为**导出方仓库内相对路径**（前缀
   `data/race_attachments/...`）。接贵方引擎时需做路径重定位（复制或挂载附件），
   路径与存在性以 `payload_status` 字段为准。

## 怎么用
```bash
# 1) 校验导出集自身完整性
python judge_external_westlake.py --self-check
# 2) 对结果判真伪（results.json: {"<qid>": "flag{...}"} 或 {"<qid>": ["a","b"]}）
python judge_external_westlake.py --results results.json
```
输出 `judge_result.json`：总命中、未命中、未提交，以及"剔除已训练题后的未见题子集"成绩。

## 维护
- 本目录由导出方脚本 `ctf_agent/scripts/_export_external_benchmark.py` 生成，勿手改
  `benchmark.json`（手改会让导出 manifest 与实际不一致）。
- 需要扩池时请回导出方重新导出，走同一条载荷/真值硬门。

## 8. ⚠️ 必读：64/87 题的附件里直接含答案（2026-10-06 静态分层实测）

导出方对每道题的附件做了**静态扫描**（读附件字节 + SHA-256 比对，零 token 成本），
结果写进 `benchmark.json` 的 `answer_directly_in_attachment` 字段，并生成分层表
`STRATA.md` / `STRATA.json`。分层结果：

| 层级 | 含义 | 题数 | 能否代表推理能力 |
|------|------|------|----------------|
| L0_direct_read | 附件里能直接扫到**真值** | **64（73.6%）** | ❌ 不能，测的是读文件 |
| L1_single_candidate | 附件有 flag 形态串但非真值 | 4 | ⚠️ 需排除抄错候选 |
| L2_pure_reasoning | 附件无 flag 形态串，必须真解题 | **19（21.8%）** | ✅ 能 |

**泄漏来源（抽验 3 例确认）**：部分题的"附件"其实是**答案文件**（如名为 `flag` 的附件）
或**官方 writeup 归档**（`_archive/recovered_external/*_official.txt`）——后者必然含答案。

**因此本基准的正确用法**：
1. 报"外部真题解题率"时，**分母用 L2 的 19 题**（或 L2+L1 并单列），不要用 87；
2. L0 的 64 题只能作为"工程链路/载荷解析"验证，不能算解题能力；
3. 需要不泄漏的外部题时，请向导出方索取 L2 子集（L2 题目 id 见 STRATA.md 明细表）。
