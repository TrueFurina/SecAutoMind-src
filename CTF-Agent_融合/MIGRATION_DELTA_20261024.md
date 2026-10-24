# 融合迁移增量比对报告（MIGRATION_DELTA 2026-10-24）

> 执行者：ZCode 收尾会话（zcode-merge-20261024）。
> 上游文档：`docs/merge_xhlj_roadmap_20261023.md`（决策）、本目录 `_MIGRATION_NOTES.md`（并行会话缺口补齐记录）。
> 本报告回答一个问题：**冻结源仓 `E:\Program\西湖论剑` 之前，还有没有资产没进来？结论：没有。**

## 一、113 项未提交变更三方比对（源仓工作树 vs HEAD d76572f2 vs 本融合副本）

方法：逐文件字节级比对（CRLF 归一后 sha256），脚本 `西湖论剑/logs/migration_delta_compare.py`，原始结果 `logs/migration_delta_result.json`。

| 分类 | 数量 | 处置 |
|---|---|---|
| ALREADY_SYNCED（融合副本 == 工作树） | 112 | 无动作。并行会话 `_MIGRATION_NOTES.md` 所称「105 改动中 98 个已迁」实为保守口径，本轮确认 **105/105 全部已同步**，8 个未跟踪新增（_ci_local.sh、_gate_coverage.py、_gate_static.py、_install_snapshot_task.ps1、build_skill_tiers.py、tier-manifest.json、test_static_name_integrity.py、plans/handoff-2026-10-13.json）亦全部在副本内 |
| 有意分叉 | 1 | `README.md`：本融合副本已改写为《CTF-Agent 融合留存说明》（副本自己的门面文档），非过期拷贝。**两边各自保留**，不回灌、不覆盖 |

## 二、本轮补迁动作（源仓侧收编后回灌）

1. 源仓 113 项按 tdd-discipline 门禁拆两笔收编：`a9cd01ac`（实现侧）+ `8d0da7f1`（测试侧）。
2. **`wt-core-bare-guard` worktree 独占 commit `77bf094c` cherry-pick 进源仓主线**（`02e6f998`）——`_git_guard.check_core_bare()` 防主仓被误写 core.bare=true 的事故复发判据 + `_session_boot` ⓪c fail-closed 检查。这两个文件已同步进本融合副本（`ctf_agent/scripts/_git_guard.py`、`_session_boot.py`，diff 零差异）。
3. `wt-eval-honest-diag` worktree 根级 4 个脚本审计：`_git_guard.py`/`_lease.py` 与主树同内容；`_git_snapshot.py`/`_merge_gate.py` 为 **10-16 旧副本**（主树 10-19/10-22 版本更新、含修复注释）→ 无需迁移，验证了并行会话「分支内容已被主树超集覆盖」结论。
4. `wt-core-bare-guard` worktree 5 个 data/questions_real 修改：与主树**内容全同**（纯 index 噪声）→ 无资产。

## 三、唯一副本数据保全核查（彻底删库前的安全前提）

| 文件 | 源仓 | 融合副本 | 结论 |
|---|---|---|---|
| `ctf_agent/data/results/KPI_BASELINE.json` | 9f71b355…c9bf | 同 | ✅ 一致 |
| `ctf_agent/data/results/submitted_flags.json` | 49211453…76a | 同 | ✅ 一致（**台账 REAL_SOLVES_LEDGER.md 所称 `verified_flags.json` 全盘不存在，实际现名即 `submitted_flags.json`**——文件名陈旧，内容无缺口） |
| `data/questions_real/`（93 题库） | 82MB | 已迁（并行会话 diff -r 零差异） | ✅ |
| `heldout_evidence/`（48 JSON） | — | 已迁（sha256 自校验过） | ✅ |
| `data/` 其余（race_attachments/questions_ext*） | 66M | 已迁 | ✅ |

## 四、源仓侧环境注记（冻结前最后一次修复）

- pre-commit 钩子（`core.hooksPath=ctf_agent/git_hooks`）曾因 `.venv` 中 logfire 5.3.0 与 opentelemetry-sdk 1.32.0 不兼容（缺 `ReadableLogRecord`）而崩。本轮已最小对齐：`opentelemetry-api/sdk==1.45.1` + `semantic-conventions==0.66b1`（--no-deps，仅动这 3 个包），钩子全链恢复。venv 本身不入冻结资产（可重建），此项只为冻结 commit 能过钩子。

## 五、源仓最终态（本轮收编后）

```
02e6f998 [无任务:护栏] _git_guard core.bare 判据 + session_boot ⓪c（cherry-pick 自 w/core-bare-guard）
8d0da7f1 [无任务:治理][冻结前终态·②测试侧] 收编测试变更
a9cd01ac [无任务:治理][冻结前终态·①实现侧] 收编未提交工作
d76572f2 （原 HEAD，= 本融合副本基线）
```

源仓工作树 clean（仅 `.zcode/` 为 ZCode 客户端状态，非项目内容，不入库）。
