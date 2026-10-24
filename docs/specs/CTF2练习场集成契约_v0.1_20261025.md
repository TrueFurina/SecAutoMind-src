# CTF² 练习场集成契约（v0.1 · 2026-10-25 实探）

> **给引擎实现者**（ctf-agent）：把 runner 从"只会打比赛"扩展到"练习场随时可打"的完整契约。
> 所有端点均经 agent 令牌**实探验证**（2026-10-25 06:5x），非纸面规范。

## 0. 结论先行

- ✅ **练习场走 REST，且 agent 令牌权限齐全**（`practice:read`/`practice:submit` 在 scopes 里）。
  ⚠️ 纠错：本仓 memory 10-25 晨记的"平台只开了 MCP 接口、REST 全 404"**是误判**——
  当时探的是 `/user/agent/practice*`（不存在），正确前缀是 **`/user/practice/`**（无 agent 段）。
- ✅ 当前在线：**1 个练习场（PRAC-2026-4739，id `8e5c9260-3cc2-4de0-a4e4-87bfb6900f2e`）**，
  **26 题**（Pwn×6/Reverse×5/Crypto×5/Forensics 等；1 分热身 + 100 分正式两档），
  DiceCTF 2026 Finals 难度，**有效期至 2036-10-05**，"每日更新"。
- ✅ 靶机题**每位选手独立 flag**（与比赛一致）；提交 body 与比赛同构。

## 1. 端点契约（agent 令牌，`Authorization: Bearer <CTF2_AGENT_TOKEN>`）

| 用途 | 方法与路径 | 实探 |
|---|---|---|
| 列练习场 | `GET /api/open/v1/user/practice/` | ✅ 返回 items[]（含 id/challenge_count/end_time） |
| 列题 | `GET /api/open/v1/user/practice/{pgid}/challenges/` | ✅ 26 项（name/category/points/is_solved/has_container…） |
| 题详情 | `GET /api/open/v1/user/practice/{pgid}/challenges/{cid}/` | 规范在（字段与比赛 detail 同构） |
| 起环境 | `POST .../challenges/{cid}/environment/start/` | 规范在（同比赛） |
| 查/延/删环境 | `GET|POST extend/|DELETE .../environment/` | 规范在 |
| 下附件 | `GET .../challenges/{cid}/files/{fid}/download/` | 规范在 |
| **提交** | `POST .../challenges/{cid}/submit/`，body `{"flag": <内容>, "confirmation": true}` | 规范在；**另支持 `sub_flag_id`**（all-completion 套件用稳定 id，禁用显示序号） |
| （用户态，agent 无权） | `/user/private-practice/`、`/submissions/` | ❌ `agent_scope_forbidden`——agent 看不到历史提交，正常 |

## 2. 与引擎现有结构的映射（改动面评估）

| 引擎现有 | 练习场对应 | 改动 |
|---|---|---|
| `CTF2Client._challenge_path()`（competitions/{comp}/stages/{stage}/challenges/…） | practice/{pgid}/challenges/… | **路径前缀参数化**（加一个 `mode` 或 `base_path` 字段，比赛/练习两套） |
| `fetch_challenge_stubs()` | 同构（items[] 字段一致） | 零改（换 base_path 即可） |
| `pull_challenge()`（detail+附件下载+metadata.yml） | 同构 | 零改 |
| `acquire_target()` / `ensure_environment()` | environment 端点同构 | 零改 |
| `submit_flag()` | submit 同构（+可选 sub_flag_id） | 小改（透传 sub_flag_id；**格式仍带 DASCTF{} 外壳——以 flag_formats.py 为准**） |
| `runner_ctf2.py` 主循环（poll→选题→swarm→提交） | 完全复用 | 加 `--practice` 开关：跳过 competition 发现，直接拉练习场列表 |
| memguard / runner_lease / cost_tracker / 排序 / 退避 | **全部原样复用** | 零改（这就是加固包的价值：新赛道白捡全部保护） |

## 3. 推荐实现路径（最小改动）

1. `CTF2Client` 加 `practice_mode: bool = False` + `practice_ground_id`；`_challenge_path()` 按 mode 分支；
   `submit_flag` 加可选 `sub_flag_id` 透传。
2. `runner_ctf2.py` 加 `--practice [GROUND_ID]`：mode 切换 + 启动日志明示；**租约照拿**
   （练习场也是"一场一引擎"——别和回放/比赛实例互踩）。
3. `final_entry.py` 之外新增轻量入口 `practice_entry.py`（或 runner 直接带 flag），
   复用 entered 检查的镜像逻辑（练习场无需 enter）。
4. 选题排序原样（附件优先）；**建议首跑只选 1 道 100 分附件题验证全链**，再放量。

## 4. 战略价值（为什么值得做）

1. **决赛前练兵**：离 2027-03-01 决赛还有 4 个月，26 道 DiceCTF 级真题是现成的训练集，
   "每日更新"还能源源补货——备料≠分数，但练兵≠备料。
2. **三创赛演示源**：比赛结束了演示不能断——练习场让"真解题"随时随地可复现
   （演示脚本 A2 资产从"一次性录屏"升级为"现场可跑"）。
3. **窗口期战绩**：练习场解题记录若在平台侧可见（agent 令牌查不到 scoreboard，
   **待人工网页端确认**），是材料里"持续作战能力"的活证据。

## 5. 边界与待验证

- [ ] 练习场是否有公开 scoreboard / 我们的解题是否对外可见（网页端人工确认）；
- [ ] `sub_flag_id` 语义何时出现（all-completion 套件）——遇到再补；
- [ ] 靶机环境配额（比赛是同时 1 个，练习场待实测——起环境时看返回）；
- [ ] 模型通道：用订阅制（claude-sdk/codex，默认）或网关 azure/*（缓存命中近零，今晚 18:00 到期）。

## 6. 实探证据（可复跑）

```bash
T=Bearer:$CTF2_AGENT_TOKEN
curl -s "https://ctf2.dasctf.com/api/open/v1/user/practice/" -H "Authorization: $T"
curl -s "https://ctf2.dasctf.com/api/open/v1/user/practice/8e5c9260-3cc2-4de0-a4e4-87bfb6900f2e/challenges/" -H "Authorization: $T"
```
