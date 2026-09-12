# `internal/collab` 架构定稿 —— 「3 队员 + N Agent」协同作战

> 对应决赛（11 月实战赛）B2 的 C1–C5 验收项，依据 `final-race-readiness_20260905.md` §二。
> 状态：**已实现并通过机验**（`internal/collab/` + `internal/database/collab.go`；服务层 11 测试、
> DB 层 5 测试全绿，含并发零重复与卡死回收的**变异验证**）。本文件保留为边界与失败模式定稿。
> 更新：2026-09-11

---

## 一、问题定位：为什么不复用 `batch_tasks`

`internal/handler/batch_task_manager.go`（1457 行）已有任务/队列模型，但它解决的是
**「一个人把 N 道题批量喂给一个 Agent 跑完」**——队列持有、串/并发推进、按 index 前进。

决赛要解决的是另一个问题：**「3 名队员 + N 个 Agent 抢同一批题，谁都不能重复领」**。
两者语义冲突点：

| 维度 | batch_tasks（现有） | collab 任务池（新增） |
|---|---|---|
| 归属 | 队列（queue_id NOT NULL） | 池（无队列，人人可领） |
| 推进 | `current_index` 顺序推进 | 领取者自取，无序 |
| 并发安全 | 执行者互斥（`queueExecutors`） | **任务级原子领取**（行级条件更新） |
| 停滞语义 | 无（跑完为止） | **卡死→退池**（墙钟硬限） |

结论：**不改造 batch_tasks**（改它会把批量执行语义搅乱，且影响现有 1457 行与既有测试）。
新增独立表与包，两者并存互不影响。

## 二、模块边界（四块，各司一职）

```
internal/collab/
  collab.go    Service 装配：DB + audit.Service + logger + 时钟（可注入，供测试免真等）
  seat.go      席位：席位 ↔ 会话 ↔ 角色 绑定；队员席/Agent 席；越权判定
  pool.go      任务池状态机：入池 / 原子领取 / 完成 / 放弃退池
  reaper.go    卡死回收：墙钟硬限 → 自动退池（后台 ticker，可启停）
  overview.go  总览聚合：任务 × 负责人 × 状态 × 耗时 × 卡点（卡点置顶）
```

DB 侧：`internal/database/collab.go`（查询与条件更新）+ `database.go`（DDL 与迁移）。

**依赖方向**：`collab` → `database` / `audit`。不反向依赖，不被 `handler` 包反向 import
（handler 只调 `collab.Service` 的公开方法）。

## 三、数据模型（2 张新表；事实黑板不新建表，复用 `attack_chain_nodes/edges`）

```sql
CREATE TABLE IF NOT EXISTS collab_seats (
  id            TEXT PRIMARY KEY,
  kind          TEXT NOT NULL,      -- human | agent
  display_name  TEXT NOT NULL,
  username      TEXT,               -- human 席所属登录账号（越权判定用）
  role_name     TEXT,               -- 复用 roles/*.yaml 的 13 个角色
  conversation_id TEXT,             -- 席位绑定的会话（进度留痕落点）
  status        TEXT NOT NULL,      -- idle | busy | offline
  created_at    DATETIME NOT NULL,
  updated_at    DATETIME NOT NULL
);

CREATE TABLE IF NOT EXISTS collab_tasks (
  id                  TEXT PRIMARY KEY,
  title               TEXT NOT NULL,
  message             TEXT NOT NULL,
  status              TEXT NOT NULL,   -- pending | claimed | done | dead(卡死退回)
  assignee_seat_id    TEXT,            -- 谁领的（人/Agent 席位）
  claim_token         TEXT,            -- 领取令牌：防止「已退池的旧持有者」回写脏结果
  claimed_at          DATETIME,
  wall_clock_deadline DATETIME,        -- 墙钟硬限到点
  started_at          DATETIME,
  completed_at        DATETIME,
  result              TEXT,
  error               TEXT,
  return_count        INTEGER NOT NULL DEFAULT 0,  -- 退池次数（卡点判定依据）
  project_id          TEXT,            -- 复用 projects（跨席位事实黑板归属）
  created_at          DATETIME NOT NULL,
  updated_at          DATETIME NOT NULL
);
```

`claim_token` 是关键设计：任务被回收后旧持有者可能仍持有 goroutine 在跑，若它晚到回写
就会污染状态。所有回写（完成/放弃）都带 `claim_token` 做条件更新，**token 不匹配即静默丢弃**。

## 四、数据流

```
题目 ──入池──▶ [pending]
                 │
        原子领取 │  UPDATE collab_tasks
                 │  SET status='claimed', assignee_seat_id=?, claim_token=?,
                 │      claimed_at=?, wall_clock_deadline=?
                 │  WHERE id=? AND status='pending'      ← 并发安全全在这一行
                 ▼                                         RowsAffected==1 才算领到
              [claimed] ──完成(token 匹配)──▶ [done]
                 │
                 ├── 主动放弃(token 匹配) ──┐
                 │                          ▼
                 └── reaper 墙钟到点 ──▶ 退回 [pending]，return_count+1
                     （清空 assignee/claim_token/claimed_at）
```

事实黑板：A 席在自己会话里产出的目标指纹/凭据，通过 `attack_chain_nodes/edges` 落 project，
B 席/C 席按 `project_id` 读取 —— **跨席位共享靠现有事实黑板，C 线不新建表**。

## 五、失败模式与对策（先定失败，再写码）

| # | 失败模式 | 后果 | 对策 | 验收方式 |
|---|---|---|---|---|
| F1 | 两人/两 Agent 同时领同一题 | 重复劳动、结论互相覆盖（西湖论剑 stuck_loop 7410 次的同源问题） | 原子领取 = 单条条件 UPDATE + `RowsAffected` 判定，**不做「先查后写」** | 并发 5 抢 10，0 重复 |
| F2 | 任务卡死（Agent 死循环/工具挂起） | 占着任务不放，池子枯竭 | 墙钟硬限 + reaper 定期扫描超时 → 退池 | 注入卡死 → 到点自动退池，其它任务不受影响 |
| F3 | 旧持有者晚到回写 | 已完成/已退池的任务被写脏 | 回写一律带 `claim_token` 条件更新，不匹配则丢弃 | token 失配写回必须被拒（变异验证） |
| F4 | 队员席越权改他人任务 | 协同变成互相踩踏 | 席权判定：非本人领取的任务，写操作拒绝、读放行 | 席位隔离测试 |
| F5 | DB 事务失败 / 并发写冲突 | 领取状态与内存不一致 | 领取**只认 DB 结果**，不做内存先写；失败即返回错误让调用方重试 | 领取失败路径测试 |
| F6 | reaper 误杀正在正常跑的长任务 | 白白退池、返工 | 墙钟阈值可配 + 任务可续期（心跳延长 deadline）；退池记 `return_count` 供事后判定 | 长任务续期不被误杀 |

## 六、C1–C5 验收映射

| 验收项 | 落地位置 | 满足方式 |
|---|---|---|
| C1 席位模型 | `seat.go` + `collab_seats` | 3 人席 + N Agent 席并发在线，各自下发任务互不串扰 |
| C2 任务池与原子领取 | `pool.go` + 条件 UPDATE | 并发 5 领取者抢 10 任务，0 重复 |
| C3 并行进度总览 | `overview.go` | 一屏列出 任务×负责人×状态×耗时，卡点置顶 |
| C4 冲突与降级 | `reaper.go` | 墙钟到点自动退池，不阻塞其它任务 |
| C5 协同全程审计 | `collab.go` 挂 `audit.Service` | 领取/放弃/结论全量入 audit，赛后可按任务回放 |

## 七、明确不做（防范围蔓延）

1. **不做前端页面**——本期只交付 API；演示一屏总览由现有前端能力或临时页面承接（另立任务评估）。
2. **不做分布式**——单进程内并发正确性即可满足现场「3 人 + N Agent」；不引入锁服务/消息队列。
3. **不改既有 `batch-tasks` 路由与语义**——零回归风险优先。
4. **不新建事实黑板表**——复用 `attack_chain_nodes/edges`。
