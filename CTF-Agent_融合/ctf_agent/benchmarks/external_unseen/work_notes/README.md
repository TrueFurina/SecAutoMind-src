# thoroughlystripped 解题过程笔记（work notes）

> **性质**：过程存档，非生产代码。规范解是 `ctf_agent/skills/thoroughlystripped.py`（已随西湖论剑
> skills 迁入，79 个确定性 skill 之一，由 `internal/ctfplatform/presolve_python.go` 兜底通道消费）。
> 本题 json：`../questions/ext_nyu_ctf_bench_2017f_for_thoroughlystripped.json`（forensics，
> 带 flag_sha256 真值 `4f8f5c59…69b1`，无明文）。

## 这是什么题

NYU CTF bench 2017f：一个被 strip 的二进制，`main` 从 `0x4c8` 开始是一连串 `e8 rel32` 直接调用，
调用目标（文件偏移）是 17 个“打印单字符”的函数。字符输出顺序被一个置换表（permutation table）
打乱，需要还原置换才能拼出 flag。

## 脚本链（按解题迭代顺序）

| 阶段 | 文件 | 作用 |
|---|---|---|
| ① 侦察 | `_recon_ts_v5.py` → `_recon_ts_v6.py` → `_recon_ts_v7.py` | 三轮 recon 迭代，定位二进制结构与打印函数布局 |
| ② 反汇编 | `_ts_disasm.txt`、`_ts_disasm2.txt` | objdump 反汇编留痕（`_ts_disasm.txt` 头部含被 strip 二进制的 file format 信息） |
| ③ 找表 | `_ts_find_table.py` → `_ts_find_table2.py` → `_ts_find_table3.py` | 在文件中定位 17 个 printX 的 2 字节 LE 地址对；stride 2..80 全扫描 + 任意 base 的跨步数组探测，恢复完整置换 |
| ④ 定位 | `_ts_locate_pairs.py` | 地址对全量出现位置定位与跨步数组识别 |
| ⑤ 调用扫描 | `_ts_scan_calls.py` | 扫描 `main` 的 `e8 rel32` 调用链 |
| ⑥ 求解 | `_ts_solve.py` → `_ts_solve2.py` | 跟随真实 `e8` 调用，按还原的置换输出 flag |
| 载荷 | `abc_payload.bin`（3K）、`_recon_thoroughlystripped.bin`（449K） | 求解/侦察用二进制样本 |

## 消费方式

- **复现/参考**：需要理解本题解法时按 ①→⑥ 顺序读脚本；
- **生产路径**：不需要——`skills/thoroughlystripped.py` 已是蒸馏后的确定性 skill；
- **真值校验**：任何复现结果须对 `flag_sha256`（见上），sha256 通过才算解出。

> 迁移注记（2026-10-24）：随西湖论剑 logs 剩余价值 triage 迁入。原位置
> `E:/Program/西湖论剑/ctf_agent/logs/_ts_*`（运行时目录，gitignore）。本题 id 在主仓
> `data/ctf_benchmark/heldout_evidence/` 的 8+ 个证据文件中被引用（presolve_audit / leak_provenance 等），
> 本目录是那条证据链的“怎么解出来的”过程侧存档。
