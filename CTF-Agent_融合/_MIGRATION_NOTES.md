# 西湖论剑 → SecAutoMind 融合迁移索引（2026-10-24）

> 本文件记录 2026-10-24 对 `E:\Program\西湖论剑`（已冻结源仓库）做的**缺口补齐迁移**。
> 迁移原则（用户标准）：**迁过去必须有人消费**——每一项都过了消费检查，不是搬仓库。
> 早前已完成：P0 两目录（questions_real 110 / heldout_evidence 54，diff -r 零差异）、
> 105 个未提交修改中 98 个、logs 7.5M 高价值分析（见 `docs/2027决赛作战规划/`）。

## 一、本次迁入（含消费理由）

| 内容 | 落点 | 消费点 |
|---|---|---|
| `verify/`（15 文件）+ `report/`（6 文件） | `ctf_agent/verify/` `ctf_agent/report/` | **运行时依赖**：`run.py` import `verify.feedback/flag_checker`、`report.generator`；`_smoke_test/_preflight/_race_start/_emergency/_verify_faults` 均 import。不迁则 harness  import 即崩 |
| `data/` 全部题库池（race_attachments 32M / questions_external 22M / questions_ext* 系列） | `ctf_agent/data/` | 证据链原料：race_attachments = 10732/10733/10735 真题附件源（Go 求解器已移植 ← real_benchmark.json ← 附件 ← `_verify_*` 证据）；questions_external = 41/53 池基线分母 |
| `data/results/` 补齐（local_real 跑批 / grid_reveal / goal_log / 5 个证据目录） | `ctf_agent/data/results/` | KPI/跑批证据（含 `_verify_10732_visual` 解密 PDF+flag 截图、`_verify_10735` 7z 已知明文回放——对口 bkcrack 能力） |
| `tests/fixtures/zipcrypto_66688.zip` | `ctf_agent/tests/fixtures/` | zipcrypto 测试夹具（缺则测试跳/红） |
| 根级 `scripts/ docs/ plans/ 2027-prep/ deliverables/ .github/ .gitignore` | 融合副本对应根路径 | 项目结构镜像：ARCHITECTURE/POSTMORTEM、plans/decisions.md 决策记录、git_forensics（09-19 事故取证）、2027-prep 全套备料（B0-bootstrap/CYBENCH 评估/P1 降本体系/T2 基线复现/服务器评估） |
| `ctf_agent/` 级 `docs/ audit/ idea-stage/ git_hooks/ solutions/ _archive_defense/ deliverables/` `2027-prep/` `_tmp/` `benchmark_md5.zip` | `ctf_agent/` 对应路径 | 事故报告/监督审计/合并闸门 hooks（"经合并闸门合入"的机制原件）/KPI 证据 |
| `benchmarks/external_unseen/work_notes/`（15 文件） | 同左 | thoroughlystripped 解题过程链（规范解=skills/thoroughlystripped.py） |

**验证**：资产口径对账——源仓 1943 文件 vs 融合副本 1956（差 -13 = work_notes +15、
`.workbuddy/` 2 个会话状态有意不迁 -2）；所有迁入目录 `diff -r` 字节级一致；
data/ 秘密扫描（ak_/sk_/password/密码模式）零命中。

## 二、有意不迁（无消费点，随源仓删除而消失）

| 内容 | 体积 | 理由 |
|---|---|---|
| `ctf_agent/logs/` | 21G | triage 后仅 7.5M 有值（已迁 docs/2027决赛作战规划/evidence/）；18G 为 git bundle 冗余 |
| `backups/`（data 每日快照） | 491M | data/ 本体已全量迁移，快照是冗余副本 |
| `_tools_ghidra/` | 1.2G | Ghidra 工具安装，非项目资产 |
| `_git_backup_manual_1789759519/` | 4.1M | 手工 git 备份产物；.git 在观察期内完好 |
| `wt-eval-honest-diag/`（worktree） | 11M | 分支内容已被主树超集覆盖（差异分析等独有文件已在根 2027-prep） |
| `.venv/` `.venv.broken_20260826/` | ~4.9 万文件 | 虚拟环境，可重建 |
| `.ruff_cache/` `.pytest_cache/` `.pytest_tmp*`（9 个变体）`.atomcode/` | ~300 文件 | 工具缓存/测试临时产物 |
| `.workbuddy/`（2 文件） | 2.6K | 旧自动化 memory + tmp 扫描脚本，无消费点 |
| `__pycache__/` `*.pyc` `.git/` | — | 编译缓存/版本库（删除序列见下） |

## 三、删除序列（源仓 `E:\Program\西湖论剑`，未执行）

1. ~~补迁缺口~~（本文件即完成记录）
2. `Rename-Item` → `西湖论剑_已归档_待删`（可逆降级，任何遗漏硬引用立即暴露）
3. 观察期 ≥2 周（覆盖 2026-10-24 CTF² 与后续赛事）
4. 用户明确确认后物理删除；删除前列明受影响路径清单

> git 历史说明：旧 full bundle（10-21，34 refs，verified）+ HEAD 工作树（已全量镜像入本副本）
> 覆盖全部文件与至 10-21 的历史；13 笔提交（38833e2a..d76572f2）的元数据已逐字留档于
> SecAutoMind `.workbuddy-ai/memory/2026-10-24.md`，未打新 bundle（无消费点，详见当日日志 16:10 条）。
