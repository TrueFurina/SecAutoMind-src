# 预注册：StepFun `json_object` 协议 A/B（2026-11-04）

> 依 `docs/specs/数字单源与预注册.md`：**本文件先提交，后测量**。测量过程中不得修改本文口径。

## 1. 要验的断言（来自 commit 776a383）

1. stepfun 系模型倾向输出散文，导致 `protocol_fail`；开 `response_format={"type":"json_object"}` 可治。
2. `protocol_fail` 与 `empty_reply` 曾双桶重复计数（同一"解析失败"被记两次）。

## 2. 口径（测前锁定，测后不改）

| 项 | 值 |
|---|---|
| 端点 | `https://api.stepfun.com/v1/chat/completions`（`STEP_API_KEY`，provider=stepfun） |
| 模型 | `step-3.5-flash`（单模型；三档不外推） |
| max_tokens | 2000（引擎默认，`ctf_agent/llm/client.py:345`） |
| 温度 | 不传，用端点默认（两臂一致） |
| 臂 A | 不传 `response_format` |
| 臂 B | `response_format={"type":"json_object"}` |
| 样本 | 8 条题型 plan 提示 × 2 次重复 × 2 臂 = **32 次调用** |
| system | 取自 `ctf_agent/core/phases.py:112-133`（真实 plan 提示词，逐字复制） |
| 成功判据 | 引擎原函数 `_extract_json_object` 返回 dict（不另写解析器） |
| 分桶 | `_extract_content` 返回 None → `empty_reply`；非 None 但解析失败 → `protocol_fail`；解析成功 → `ok` |
| 排除项 | HTTP 非 2xx 与超时单独列，**不进协议分母** |
| 判定阈值 | B 臂 `ok` 率 − A 臂 `ok` 率 **≥ 20 个百分点** 才判「json_object 有效」；否则判「未证有效」 |

## 3. 已知混杂（结果里必须原样披露）

- **单模型**：只测 `step-3.5-flash`，不能外推 step-3.7-flash / step-5-preview。
- **只测协议层**：样本是 plan 阶段提示，不是完整 agent 轨迹 → **不测解出率**，不产生"解出率提升"类结论。
- **额外假设**（测前写下，避免事后编故事）：StepFun 响应可能把内容放在 `message.reasoning`（实测样例如此），而引擎 `_extract_content` 只回退 `reasoning_content`。若成立，则 `empty_reply` 与 json_object 无关，需改提取逻辑。

## 4. 产物路径（固定）

- 原始响应：`docs/evidence/stepfun_jsonmode_AB_20261104/raw.jsonl`
- 汇总：`docs/evidence/stepfun_jsonmode_AB_20261104/summary.json`
- 复跑入口：`python scripts/exp_stepfun_jsonmode_ab.py`

## 5. 审计声明

本会话是产出方，**不得自任审计**。本文件产出后的一切数字标「线索级」，需另一会话或独立复跑复核后才可升级为结论。

## 6. 扩展登记（2026-11-04 12:2x，追加模型，未改动上文口径）

- 追加模型：**`step-5-preview`**（队列级实际跑的档位）。其余口径（提示集、臂定义、max_tokens=2000、
  判定阈值 20pp、分桶规则）**逐条不变**，仅换 `model` 字段。
- 动机：§3 已登记"单模型不外推"，step-5-preview 是真实跑批档位，必须单独测一次否则结论不覆盖主用档。
- 产物：`docs/evidence/stepfun_jsonmode_AB_20261104/step-5-preview/`（同 schema）。
- 运行：`EXP_MODEL=step-5-preview python -X utf8 scripts/exp_stepfun_jsonmode_ab.py`。

