# ⛔ PPT 永久冻结（2026-10-31 用户令）

> **此目录下的 PPT 产物与生成器已被用户永久冻结。在用户明确解冻前，任何 agent / 并行会话一律不得触碰。**

## 冻结范围（禁止修改）
- `SecAutoMind_PPT/*.pptx`（全部 PPT 产物）
- `SecAutoMind_PPT/make_champion_ppt.py`
- `SecAutoMind_PPT/make_final_ppt.py`
- `SecAutoMind_PPT/make_template_ppt.py`
- `docs/final-artifacts.freeze.json` 中与 PPT / 生成器相关的条目

## 禁止的操作
- 重新生成 PPT（运行任何 `make_*.py`）
- 修改 `make_*.py` 里的任何数字 / 文案
- 运行 `check_final_artifacts_freeze.py --update` 重上锁
- 为「修门禁红」而改动 PPT 或生成器

## 已知状态（用户已接受，**勿"修复"**）
- PPT 产物（.pptx）与生成器（make_*.py）中的规模数字**存在不一致**；
  具体数值见 `docs/final-artifacts.freeze.json` 与产物读回门禁输出。
- 这是冻结时的既有状态，**已被用户明确接受**，不属于"待修复的 bug"。
- 因此 `check_material_numbers.py` / `check_artifact_numbers.py` 对 PPT 的报红是
  **预期的"冻结快照 vs 活真值"差异**，**不得**通过重生成 PPT 来消除。

## 解冻
仅当用户**明确说出「解冻 PPT」**时才可恢复上述操作。
