# 西湖论剑 Python 求解资产迁移（FROZEN 来源）

> **来源**：`E:\Program\西湖论剑\ctf_agent\`（2026-10-23 起 FROZEN 只读知识库）
> **迁移时间**：2026-10-23
> **迁移原则**：资产物理搬迁入 SecAutoMind 目录；不复制 gitignored 验证 flag 明文与大附件；
> 数据/证据本体仍以西湖论剑冻结仓库原路径为准（见 `ledger_index.md` / `coverage_map.json`）。

## 迁移内容

| 目录 | 内容 | 数量 |
|---|---|---|
| `skills/` | 确定性求解 skill（run(params)->dict 接口） | 79 个 py |
| `core/` | skills 引用的内部库：coppersmith / lattice（LLL/HNF） | 2 个 py |
| `questions_real/` | 历年真题题面 JSON（crypto23/misc46/pwn2/reverse9/web13） | 93 个 JSON |
| `questions_real/_attachments/` | 真题附件（含 specialcurve2/exciting_inverse/ezrsa/filterrandom 等 16 个附件集，552KB） | 16 集 |

> 迁移说明：题面 JSON 与附件原样复制（2026-10-23）；不含 gitignored 验证 flag 明文
> （`data/results/verified_flags.json` 留在冻结仓库）。

## 依赖面（本机 python venv 已全部可用，2026-10-23 实测）

- 标准库：os/re/json/argparse/zipfile/struct/hashlib/base64/typing/itertools/tempfile…
- 第三方（均可用 ✓）：numpy / PIL / Crypto(pycryptodome) / sympy / gmpy2 / httpx
- 内部：`from core.coppersmith`、`from core.lattice`（已随迁）

## 运行方式

```powershell
# 以 vigenere_decode 为例（纯标准库，冒烟验证已过）
$py = "C:/Users/Lenovo/.workbuddy/binaries/python/envs/default/Scripts/python.exe"
& $py -c "import sys; sys.path.insert(0, r'E:\Program\SecAutoMind\data\ctf_benchmark\xhlj_legacy'); from skills import vigenere_decode as V; print(V.run({'text':'..."}))"
```

## 赛前接入边界（重要）

- **本资产暂不接入 SecAutoMind Go 生产求解链路**（Go 求解器为纯 Go、无外部进程调用；
  赛前改动生产链路有回归风险，1024 快闪赛 10-24 用已验证 Go 链路直接参赛）。
- 本目录当前用途：资产归档 + 基准参照（赛后 P0 按路线图把通用链 Go 化并验证，
  深度链以本 Python 资产为验证基准）。

## 来源与完整性

- 79 个 skills 与西湖论剑 `skills/` 逐字节一致（Copy-Item 原样复制）。
- 西湖论剑 README 已加 FROZEN 横幅（2026-10-23）；本目录为只读参考，改动请遵循
  `docs/merge_xhlj_roadmap_20261023.md` 的迁移路线。
