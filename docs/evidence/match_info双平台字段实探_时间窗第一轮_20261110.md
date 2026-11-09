# match_info 双平台字段实探（时间窗驱动·第一轮，2026-11-10）

> **目的**：`GetMatchInfo` 升级为「时间窗驱动策略」的前置取证——评估文档（
> `docs/evidence/网关合规接线缺口_LLM链_20261028.md` 同目录的接线审计 §四）预言
> "map 无 schema 锁定、双平台字段名不保证一致"，本轮用真凭证实探验证。
> **探针**：`internal/ctfplatform/matchinfo_schema_probe_test.go`（门控同 live smoke：
> 无凭证即 Skip，不伪造绿）。**运行位置如实登记**：本机 shell 已持 CTF2/DASCTF env，
> 探针为纯只读 GET（不解题、不占平台额度、不起实例），按第零条属"编排与日志"侧，
> 故本机完成；服务器复跑命令见探针文件头注释。
> **时间**：2026-11-10 06:0x 实跑（输出快照存 `.workbuddy/tmp/probe_local.txt`，
> 该目录 gitignored，关键内容已抄录本文）。

## 一、CTF²（真实字段，全部实值到手）

`GetMatchInfo` → **已解包的业务对象**，12 个 key：

```
description, end_time, entry, id, is_paused, is_public,
max_agents_per_owner, name, requires_invite_code, stages, start_time, status
```

时间窗相关实值（1024 快闪赛样本）：

| 字段 | 实值样例 | 第二轮用途 |
|---|---|---|
| `start_time` | `2026-10-24T19:00:00+08:00`（RFC3339 带时区） | 首血窗口起点 |
| `end_time` | `2026-10-24T20:00:00+08:00` | 停跑时刻 |
| `status` | `"ended"`（可观测取值之一；running 待赛时补采） | **停跑判据主源** |
| `is_paused` | `false` | 暂停感知 |
| `stages[]` | 每段含 `start_time/end_time/status/is_paused/max_targets/name/audience/type` | 多阶段感知 |
| `entry` | `{board_state, entered, frozen_at, published_at, ...}` | 参赛态自检 |

`GetOverview` → 8 个 key：`board_state, frozen_at, items[{agent_slug,name,rank,score,solve_count,last_solve_time,is_me,...}], me, participant_type, published_at, published_version, total`
——排行榜快照接线（P0-3 终报）拿到的就是这套真实字段 ✓。

## 二、DASCTF（探针当日 40403，字段仍未证实）

`GetMatchInfo` / `GetOverview` 返回的都是**裸信封** `{code, data, message}`，
当日实测 `code="40403" message="无权操作"`（该 token 对这两个端点无权限 / 或端点仅赛前开放）。

两个结论：
1. **适配器口径分叉实锤**：CTF² 适配器已解包 `data`，DASCTF 适配器直接返回整封——
   与预言一致，第一轮就避免了"照着 CTF² 字段写通用解析"的错误。
2. DASCTF 时间窗字段名**仍未知**——第二轮对 DASCTF 一律**不启用**推导（fail-safe）。

## 三、第二轮实施方案（本取证支持的最小闭环）

- 判据归属平台适配器：给 CTF² 加 `MatchWindow(ctx)` 类型化方法（解析
  `status/start_time/end_time`，RFC3339），DASCTF **不实现**（字段未证实）。
- Poller 侧用**可选接口**探测（`interface{ MatchWindow(...) }`）：
  未实现 → 特性自动 inert，零行为变化（第八条"替身嵌入接口"同族思路，缺方法立刻暴露）。
- 配置默认关：`DeriveWindowFromMatchInfo`（首血窗口=开赛→开赛+min(15min, 赛程20%)，
  与现 env 手工值并存、显式 env 优先）+ `StopOnPlatformEnd`（status=ended 即停轮——
  落地赛事调度纪律"比赛状态只信平台，本地时钟不可信"，羊城杯 20:01 误判教训的正解）。
- 验证：fake 平台 + 表驱动测试（running/ended/解析失败三分支；解析失败=fail-safe
  保持人工配置，绝不误停）。
- **待补采**：`status` 的 running 态字面量（今天只见到 ended）——实施时把"未知
  status 值"按"不停跑"处理（宁多跑不误停），并在下次真赛时抓一份 running 态样本回填本文。
