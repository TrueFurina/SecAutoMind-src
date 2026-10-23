# heldout_evidence（迁移自冻结仓，结构复用）

> **来源**：`E:/Program/西湖论剑/ctf_agent/heldout_evidence/`（FROZEN 只读知识库，2026-10-23 起）
> **迁移时间**：2026-10-24
> **路线图依据**：`docs/merge_xhlj_roadmap_20261023.md` §赛后 P0-4「benchmarks/heldout_evidence 结构复用进 `data/ctf_benchmark/`」

## 迁移范围

| 内容 | 数量 | 说明 |
|---|---|---|
| `*.json` 评测证据 | 48 | **逐字节复制**，哈希与源一致（`PROVENANCE.md` 的两个 sha256 自校验值实测吻合：A=`aa30d3c1…`、B=`6ce3bfe0…`） |
| `PROVENANCE.md` | 1 | 源仓原始溯源说明，原样保留（含明文 flag 政策说明） |
| 未迁移：`runA_e3off_ext5_20260927_1328/`、`runB_e3off_real2_20260927_1330/` | 2 目录 | 原始跑日志（progress.jsonl / run.log），价值低且体积大，留在冻结仓 |

## 口径与边界（不粉饰）

1. **这是历史测量快照，不是本仓的复跑结果**。本仓不对其中任何数字作「可复现」宣称；
   引用时必须写明来源为 2026-09/10 冻结仓实测。
2. **文件名含 `SUPERSEDED_*` 的是已作废证据**（污染池 / 含来源泄露），保留是为了
   防「悄悄删掉不利证据」的质疑；引用时不得取用作废文件的口径。
3. **明文 flag 按用户政策保留**（2026-08-29 指令：flag 明文公开无实质风险，唯一红线是
   凭据）；本目录不含任何凭据。迁移时**未做任何脱敏**，以保证逐字节自校验成立。
4. 本目录不进任何 CI 计算口径（truth-source 审计扫描到但无 `problems` 类键；
   非 benchmark 本体，不参与 suite parity / external-bench 统计）。
