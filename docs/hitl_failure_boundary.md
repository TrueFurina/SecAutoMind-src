# HITL 失效边界报告（规划 §4.2）

> 本文件由 `scripts/run_hitl_boundary.py` 生成（**勿手改**；改模式/测试请改脚本后重跑）。
> 生成时间：2026-10-13 16:39 ｜ 结论：**PASS(machine) + OPEN(human)**

## 0. 为什么这份报告分三档而不是「全绿」

§4.2 的施工动机是「HITL 失效边界未实证」。但『失效边界』里有一半（人工误批/误拒）
**本质上需要真人在环的 randomized 评测**，代码测试替代不了。若把这几项也标 PASS，
就是把『没测』伪装成『测过』——这正是本项目最忌的失信形态。故按可验证性分三档，
**machine 档逐条真跑，human 档如实标 OPEN，n/a 档如实标不适用**。

## 1. 失效模式矩阵

| 模式 | 类型 | 机制 | 机验/评审证据 |
|---|---|---|---|
| 审批超时挂死 | `machine`(`PASS`) | 审批未在超时窗口内到达 → 自动拒绝（fail-safe），并留审计痕迹 | `TestHITLWaitDecision_TimeoutAutoRejects / TestC2HITLBridge_TimeoutAutoRejects` |
| 决策落库失败 | `machine`(`PASS`) | 审批/超时/取消任一分支落库失败 → fail-closed（拒绝放行 + 上报错误） | `TestHITLWaitDecisionFailsClosedOnPersistError_Decided / TestHITLWaitDecisionFailsClosedOnPersistError_Timeout / TestHITLWaitDecisionFailsClosedOnPersistError_Cancelled / TestHITLWaitDecisionPassesWhenPersisted / TestC2HITLBridge_FailsClosedWhenPersistFails` |
| 覆盖冲突（重复裁决 / 双击 / 并发） | `machine`(`PASS`) | first-writer-wins：后到的裁决必须被拒，首个决策不得被翻盘 | `TestHITLResolveInterrupt_RejectsSecondDecision / TestHITLResolveInterrupt_RejectsAfterResolved` |
| 越界裁决 | `machine`(`PASS`) | 不存在的中断 / 非法决策值 → 明确报错，不得静默接受 | `TestHITLResolveInterrupt_RejectsUnknownInterrupt / TestHITLResolveInterrupt_RejectsInvalidDecision` |
| 参数篡改（审批被偷换为改参放行） | `machine`(`PASS`) | 非 review_edit 模式必须剥离 editedArguments | `TestHITLWaitDecision_StripsEditedArgsOutsideReviewEdit / TestHITLWaitDecision_KeepsEditedArgsInReviewEdit` |
| 人工误批（放行本应拦截的高危操作） | `human`(`OPEN`) | 需真人在环随机化评测 | false-approve 率 < X%（阈值待 MPU-2 定） |
| 人工误拒（阻断本应放行的安全操作） | `human`(`OPEN`) | 需真人在环随机化评测 | false-block 率 < Y%（阈值待 MPU-2 定） |
| 多 agent 共识分裂 | `n/a`(N/A) | 本项目多 agent 为「规划/执行/审计/复盘」流水线编排，**非投票集成**，不存在可分裂的多数表决 → 该失效模式不适用（不硬凑模式）。 | — |

## 2. machine 档逐条结果

| id | 模式 | 结论 | 证据（测试） | 变异验证 |
|---|---|---|---|---|
| `timeout_hang` | 审批超时挂死 | **PASS** | `TestHITLWaitDecision_TimeoutAutoRejects / TestC2HITLBridge_TimeoutAutoRejects` | 超时分支 reject→approve 后 handler 侧测试 FAIL（已实测） |
| `persist_failure` | 决策落库失败 | **PASS** | `TestHITLWaitDecisionFailsClosedOnPersistError_Decided / TestHITLWaitDecisionFailsClosedOnPersistError_Timeout / TestHITLWaitDecisionFailsClosedOnPersistError_Cancelled / TestHITLWaitDecisionPassesWhenPersisted / TestC2HITLBridge_FailsClosedWhenPersistFails` | 未单独变异（含反向对照 PassesWhenPersisted 防误修为一律拒绝） |
| `override_conflict` | 覆盖冲突（重复裁决 / 双击 / 并发） | **PASS** | `TestHITLResolveInterrupt_RejectsSecondDecision / TestHITLResolveInterrupt_RejectsAfterResolved` | 决策通道缓冲 1→2 后 RejectsSecondDecision FAIL（已实测） |
| `out_of_bounds` | 越界裁决 | **PASS** | `TestHITLResolveInterrupt_RejectsUnknownInterrupt / TestHITLResolveInterrupt_RejectsInvalidDecision` | 未单独变异（直接断言守卫返回值，含合法值反向对照） |
| `param_tampering` | 参数篡改（审批被偷换为改参放行） | **PASS** | `TestHITLWaitDecision_StripsEditedArgsOutsideReviewEdit / TestHITLWaitDecision_KeepsEditedArgsInReviewEdit` | 删除剥离语句后 StripsEditedArgs FAIL、Peer(review_edit) 仍 PASS（已实测） |

> 主路径在 `internal/handler`（waitDecision / ResolveInterrupt）；危险任务 C2 桥接路径在
> `internal/app`（c2_hitl_bridge.go）—— 两路径均已在 `timeout_hang` / `persist_failure` 模式加锁。

## 3. human 档（OPEN，阈值待定）

以下两项**未闭环**，需按 §4.2 招募 ≥8 名外部导师做 randomized 评测后回填：

- **人工误批（放行本应拦截的高危操作）**（`false_approve`）
  - 阈值：false-approve 率 < X%（阈值待 MPU-2 定）
  - 夹具：≥8 名外部导师（跨校随机招募）对同一批高危/安全请求做 blinded 裁决，统计「高危被判放行」占比
- **人工误拒（阻断本应放行的安全操作）**（`false_block`）
  - 阈值：false-block 率 < Y%（阈值待 MPU-2 定）
  - 夹具：同上批次，统计「安全操作被判拒绝」占比（过阻会反噬可用性）

> 阈值 X/Y 由 MPU-2 依「安全优先但不至于过阻」的判据确定；本报告**不预设**，
> 以免出现「先射箭后画靶」。

## 4. n/a 档（如实记录，不硬凑）

- **多 agent 共识分裂**（`consensus_split`）：本项目多 agent 为「规划/执行/审计/复盘」流水线编排，**非投票集成**，不存在可分裂的多数表决 → 该失效模式不适用（不硬凑模式）。

## 5. 覆盖边界（不夸大）

- machine 档覆盖 HITL **主路径**（`internal/handler` 的 waitDecision / ResolveInterrupt）
  与**危险任务 C2 桥接路径**（`internal/app` 的 c2_hitl_bridge.go RequestApproval）。
- **未覆盖**：真机/真导师条件下的 false-approve / false-block 率（见 §3，OPEN）。
- 复现命令：`python scripts/run_hitl_boundary.py`（本地）｜ `--check`（CI，只跑 machine 档）。
