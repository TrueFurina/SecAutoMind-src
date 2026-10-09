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

## 9. ⚠️ 2026-10-10 基准收缩与口径（务必读，替代 §8 的 87 题口径）

复核发现 10-06 交付的基准有三类问题，**已重新导出**，题数由 87 降至 **80**：

| 问题 | 题数 | 处置 |
|------|------|------|
| 唯一附件是 writeup 文本，而该文本随我方 `_archive/` 清理被删 → 载荷消失 | 8 | **剔除**（`payload_missing_on_disk`） |
| 无可判定真值 | 5 | **剔除**（`no_verifiable_truth`） |
| 附件就是答案键（`flag.txt` 存裸值），初版分层只认 `flag{...}` 形态而漏判 | 8 | 保留但归入泄漏层，**不得计入推理分母** |

**分层现状（80 题）**：L0 答案直读 66 / L1 含诱饵 4 / L2 纯推理 10。

**结论（请勿再引用 87 这个数）**：该基准能用于"推理能力"评测的只有 **14 题**（L2 10 + L1 4），
其余 66 题是读文件即可答。若要报外部真题推理率，分母用 14，且必须标注"L1 含诱饵题"。

**为什么会这样**：我方题库自身存在同类缺陷——93 题里 64 题的唯一附件是 `flag.txt`（答案键）。
已新增题库完整性审计器（`scripts/_audit_corpus_integrity.py`）把这类问题变成门禁，
避免"交付出去的基准悄悄腐烂"。
