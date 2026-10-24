# xhlj presolve 审计出处存档（2026-10-24 归档）

> **性质**：历史快照，数字不可当事实（archive 约定）。本目录是 SecAutoMind presolve
> 反注水纪律的**方法论上游出处**，不是活跃证据链——活跃证据链（含 09-29 头版 9/17 的
> 证伪源）已迁至 `docs/2027决赛作战规划/evidence/`。

## 文件 → 消费点映射

| 文件 | 内容 | 对到的现有纪律/代码 |
|---|---|---|
| `skip_audit_20260917.md` | pytest skip 审计（425 passed / 16 skipped，15 条为数据/附件缺失的合法 skip） | 「缺数据不可解」须显式 skip 而非假阳；对应本项目 CTF 静态基准「35 道描述无数据静态不可解」的同类处理 |
| `presolve_audit_heldout41_20261008.json` | 41 池 presolve 审计（修复前） | 占位自证假命中的机器可读留痕 |
| `presolve_audit_heldout41_afterfix_20261008.json` | 41 池审计（`a9e32fd` 修复后） | 修复前后对照 = 反注水断言有效性的证据样板 |
| `presolve_audit_nyu34_afterfix_20261008.json` | NYU 34 池审计（修复后：A 组 18 真/0 假、B 组 16 真/0 假） | `(sha256,set)` 形态池不受 bug 波及的实证 |

## 为什么值得归档（而不是随源仓删除）

`presolve_9of17_pollution_20261008.md`（已迁 evidence/）记录的占位自证模式——
「从题面描述抽一个词塞进 `flag{...}`，恰好与 ingest 的真值形态自洽 → 假命中」——
是 SecAutoMind 26 个基准集全部带**反注水断言**（标准库打不通 / 双 ECB·双 CBC 必拒 /
纯色图不得命中 / safe 变异全拒，见 `internal/ctfplatform/*_parity_test.go`）的直接动因。
将来若有人质疑「反注水是不是过度设计」，本目录 + evidence/ 的证伪链就是答复。
