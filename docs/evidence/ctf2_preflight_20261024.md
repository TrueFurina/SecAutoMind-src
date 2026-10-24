# CTF² 赛前复核（2026-10-24 09:30，距 19:00 约 9.5 小时）

> 口径：本文所有结论都来自**本次实探**的 HTTP 响应与仓库代码；未验证项在 §5 单列。
> 令牌值全程未打印（只报形态与长度）。

## 1. 今晚的平台不是 DASCTF，是 CTF²

`docs/ctf2_arena_integration_20261023.md` 记录正式赛在 CTF²（Agent 竞技场）。本次实测确认：

| 项 | 值 |
|---|---|
| Base URL | `https://ctf2.dasctf.com` |
| 鉴权 | `Authorization: Bearer <CTF2_AGENT_TOKEN>`（69 字符，`ctf2_` 前缀） |
| 端点前缀 | `/api/open/v1/user/agent/` |
| `GET agent/me/` | **HTTP 200**（Bearer 鉴权通过） |
| `competition_enabled` | **true**（平台允许该 Agent 参赛） |

**同时配置着 `DASCTF_BASE_URL` / `DASCTF_TOKEN`（`ak_` 前缀），那是另一个平台。** 它的令牌对
`/slab-match/...` 返回 `40403 无权操作`——差分实验证明这是**跨平台无关**，不是今晚的故障：

| 请求 | 响应 |
|---|---|
| 真 `ak_` 令牌 | `{"code":"40403","message":"无权操作"}` |
| 伪造 `ak_xxx` | **完全相同**的 `40403` |
| 不带该头 | `{"code":"40001","message":"X-Agent-AccessKey"}` |

→ 该端点根本认不出这把 `ak_` 令牌（真伪同响应），所以**不能**由它推断今晚不可用。

## 2. 两个赛：调试赛在跑，正式赛还没开

| 赛事 | id | 状态 | entered | auto_join | 结束 |
|---|---|---|---|---|---|
| 赛前调试赛（练习，不计成绩） | `4604a758-0b79-4c90-a252-317dd69dc79b` | **running** | true | false | 17:00 |
| **1024 快闪赛 · CTF 网络安全挑战赛** | `b10634a1-7534-46af-950e-8395367bab6b` | **upcoming** | **false** | false | 20:00 |

正式赛阶段：`031d3cf3-d4f7-4eed-9e03-6fecb334ce44`（**AI Agent 赛道**，19:00–20:00，`max_targets=4`）。

## 3. 现在拉题 403 的真实原因：**阶段未开始，不是 WAF**

`TestCTF2LiveSmoke` 现在报 `403 WAF 风控（冷却 5m0s）` 并 SKIP。但同一时刻、同一 IP：

- `GET agent/me/` → **200**
- 拉题 → **403**

WAF 若按 IP 拦截，不会只拦一个端点。所以 403 是**该阶段尚未开始**所致；而
`internal/ctfplatform/ctf2.go` 的 `StatusForbidden` 分支把 **403 一律**当作 WAF 并进入 5 分钟冷却
——这是**诊断口径过粗**（不是今晚必须修的 bug，但会误导现场判断）。

### 由此得到两条现场纪律

1. **19:00 之前不要启动 poller**。提前启动 → 每轮 403 → 客户端进入 5 分钟冷却，
   有可能把开赛头几分钟一起吞掉（`max_targets=4`、只有 1 小时，几分钟很贵）。
2. 若开赛后仍见 403，先分清两种可能：**(a) 尚未 join / 未开赛**（`agent/me` 里该赛 `entered=false`）
   还是 **(b) 真被 WAF 拦**。判据：`agent/me` 若同时 200，就不是 WAF。

## 4. 正式赛 `entered=false`、`auto_join=false`

平台提供 `POST /api/open/v1/user/agent/competitions/{id}/join/`（见 `docs/ctf2_user_openapi.json`）。

**本次没有替你调用**——报名/参赛属于对外动作，且当前阶段 `upcoming`，提前调用大概率被拒。
建议开赛前 5 分钟（18:55）由你确认一次：若 `agent/me` 里正式赛仍 `entered=false`，
就调用该 join 端点；若已 `entered=true` 则无需操作。

## 5. 未验证项（留空即不可信）

- **19:00 后能否正常拉题/提交**：未跑（阶段未开始，平台侧未开放）。
- **join 是否必需**：未验证。文档称 `environment/start` 会「首启自动参赛」，但当前 `entered=false`
  且 `auto_join=false`，两者关系未实测。
- **附件/靶机链**：未跑（依赖已开始的阶段）。
- **WAF 是否会按频率再触发**：只观测到 1 次 403，无法区分"阶段未开"与"频率触发"的边界。

## 6. 复现命令（全部只读）

```bash
# 1) 平台与鉴权（Bearer，200 即可用）
curl -s -o /dev/null -w '%{http_code}\n' \
  -H "Authorization: Bearer $CTF2_AGENT_TOKEN" \
  https://ctf2.dasctf.com/api/open/v1/user/agent/me/?limit=1

# 2) 赛事与 entered 状态（关注目标赛的 status / entered）
curl -s -H "Authorization: Bearer $CTF2_AGENT_TOKEN" \
  https://ctf2.dasctf.com/api/open/v1/user/agent/me/?limit=50 | python -m json.tool | head -40

# 3) 赛详情与阶段
curl -s -H "Authorization: Bearer $CTF2_AGENT_TOKEN" \
  "https://ctf2.dasctf.com/api/open/v1/user/agent/competitions/$CTF2_COMPETITION_ID/"
```
