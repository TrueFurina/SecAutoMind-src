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

## 7. 导入本基准时的两个必读陷阱（2026-10-06 实测踩坑）

1. **`flag` 占位字段不可省**：若贵方评测代码用「`flag` 字段是否为 64 位十六进制」来判断
   「本题是否可哈希验证」（本项目 `eval/cases.py:flag_is_placeholder` 即如此），那么只提供
   `flag_sha256` 而不写 `flag` 占位，会让本题走明文比对分支 → **正确解被判 hallucination**。
   我方 5 题探针中 2 道正确解因此被误判，已修复。导入时请把 `flag_sha256` 同时写入 `flag`
   字段作为占位（这不是明文答案，不违反真值红线）。
2. **附件路径需重定位**：`attachment(s)` 为导出方仓库内相对路径（`data/...`）。接入前须复制或
   挂载附件，并用 `payload_status` 字段确认载荷完整性（导出时已机器校验）。
