# DASCTF 官方仿真平台 · 成功契约验证 runbook

> 🔒 **时间锁（2026-10-18 用户拍板）**：Agent Key 仅**决赛现场**发放，本流程冻结至 **2027-03-01**，
> 此前不要催办、不要提前联调。`scripts/verify_live_contract.py` 已内置同一把锁
> （`FREEZE_UNTIL`，冻结期内运行 rc=3 自动拒绝）。到期后按 P0→P2 执行。

> **承接**：`真机联调记录_20261005.md`（只读探测）已证明网络可达 / 端点路径正确 / 鉴权方式正确 /
> Token 被平台识别身份四项成立，但当时 Token 无权限（40403），成功响应结构未验证。
> 本 runbook 落地 10-05 记录 §四 的行动项 P1「拿到有效权限后验证成功契约」。
>
> **代码侧已备齐**：`internal/ctfplatform/dasctf.go` 的端点表 / 成功判据 / 靶机地址提取 /
> 附件下载（10-08 解存根）全部就位，本 runbook 不涉及改代码，只负责真机验证。

---

## P0 · 外部动作（决赛现场，拿到 Agent Key 后）

**拿到现场发放的 Agent Key 后，先确认它属本队本场次、比赛窗口期已开放**，再进 P1。
若仍 40403，按四种可能排查：
1. Agent 接入 Key 需在平台后台/赛事方开通后才生效；
2. agent 接口仅在比赛窗口期开放，非赛期一律 40403；
3. Token 属其他队伍/场次；
4. Token 已过期。

## P1 · 一键验证（拿到有效权限后）

```bash
# 凭证只从环境变量读，不落盘、不进命令历史明文
export DASCTF_BASE_URL=https://pro.dasctf.com
export DASCTF_TOKEN=<Agent Key>

# 只读契约（零副作用）：overview / 题目列表展平 / 题目详情 + 附件字段名
python scripts/verify_live_contract.py

# 含写入契约（起靶机→提交 flag→回收，有真实副作用）
python scripts/verify_live_contract.py --full
```

退出码语义：`0` = 全部通过（可参赛）；`1` = 有契约不一致（按输出逐项修 `dasctf.go`）或缺凭证；`2` = 全部 40403（权限仍未开通，回 P0）；`3` = 冻结期内（2027-03-01 前，见文首时间锁）。

## 逐项契约清单（脚本固化，真机逐项判 PASS/FAIL）

| # | 契约 | 判据 | 涉及代码 |
|---|---|---|---|
| 1 | overview 成功 | HTTP 200 且 `code=="00000"` | `codeIsSuccess` |
| 2 | 题目列表展平 | `data` 是平铺 list（若为 `{"corpus":[...]}` 嵌套需复核 `flattenChallenges`） | `flattenChallenges` |
| 3 | 题目详情 + 附件字段名 | `exerciseId` 数值型；附件字段命中 `attachment/attachments/file/url/downloadUrl/src/file_url` | `extractAttachmentURLs` |
| 4 | 起靶机 + 靶机地址 | `endpoints[].exposeIps[0]` 非空（"ip:port" 格式） | `extractAccess` |
| 5 | 提交判分通路 | 提交必错占位 flag，期望 `code=="00000"` 且 `isCorrect==false`（证明判分通路打通，而非误报满分） | `SubmitFlag` / `codeIsSuccess` |
| 6 | 回收靶机 | `code=="00000"` | `recover_env` |

## 失败处置

- **全部 40403**（rc=2）：权限问题，回 P0，不碰代码。
- **单项不一致**（rc=1）：代码契约与真机响应不符，按输出逐项修 `dasctf.go`，改完 `go test ./internal/ctfplatform/... -run 'TestRehearsal|TestLiveTarget|TestPlatformE2E'` 回归。
- **诚实边界**：本脚本的验证结果**只记录真机事实**，不得替代仿真测试或 golden 冻结作为代码回归依据。
