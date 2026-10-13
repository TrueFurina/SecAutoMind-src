# Key 轮换 Runbook（2026-10-13）

> **触发背景**：两把生产凭据属历史泄露项（P0-0），且 2026-10-13 盘点期间千问 key 在一次
> 工具输出中发生二次暴露。轮换完成前，**不要把本文件外传**（含生产机结构信息）。
>
> **适用范围**：生产机 `120.48.36.201`（root）+ 本机开发配置。
> **不适用范围**：公开仓库——已实证 `git grep` HEAD 无真实 key 入库（仅 ci.yml 的 8 字符前缀
> 与门禁测试构造值），无需 git 历史处理。

---

## 0. 结论（TL;DR）

| # | 动作 | 停机风险 | 执行人 |
|---|---|---|---|
| 1 | 千问 key：控制台建新 key → 改 unit env → 重启 → 验证 → 删旧 key | 秒级（重启） | 用户控制台 + 我改配置 |
| 2 | 飞书 app_secret：控制台重置 → 改 unit env + config.yaml 两处 → 重启 → 验证 | 约 1-2 分钟（重置即失效） | 用户控制台 + 我改配置 |
| 3 | 清理生产机 15 个 config.yaml.bak-*（10 个含旧千问 key、12 个含旧飞书 secret） | 无 | 我执行（mv 到 /tmp，24h 后删） |
| 4 | 清理生产机 1.8G 二进制残留（7 个 bak + 2 个 Windows PE 误传件） | 无 | 我执行（同上） |

**顺序铁律**：先建/重置新凭据 → 改配置 → 重启 → 验证 → **最后**才禁用旧凭据、清备份。
任何一步失败，旧凭据仍有效，可原地回滚。

---

## 1. 两把 key 的当前位置（2026-10-13 盘点实证）

| Key | 生产机位置 | 本机位置 | 备份残留 |
|---|---|---|---|
| 千问 `sk-ws-`（DashScope） | systemd unit `Environment=DASHSCOPE_API_KEY`（`/etc/systemd/system/secautomind.service`，共 5 行内联 Environment） | `config.yaml:132` qwen-max 段另有一把千问 key（**非 sk-ws- 格式**，需在控制台确认是否同账户） | 10 个 `config.yaml.bak-*` 含旧值明文 |
| 飞书 `app_secret` | unit `Environment=LARK_APP_SECRET` **+** `config.yaml:141` lark 段，**两处都是真值**（生效顺序未读码确认，稳妥做法两个都改） | `config.yaml:603` 为占位假值（lark enabled:false，不涉及） | 12 个 `config.yaml.bak-*` 含旧值明文 |

> ⚠️ 查生产机环境变量时，**任何 grep/sed 输出前必须先确认掩码规则覆盖 `-` 与 `.` 字符**
> （2026-10-13 事故：掩码字符类漏掉连字符，导致完整 key 进入输出）。安全做法：
> 只取计数或变量名，不取值——`grep -c '^DASHSCOPE' unit` 或 `grep -o '^[A-Z_]*=' unit`。

---

## 2. 轮换前检查（改任何东西之前）

```bash
# 2.1 确认服务与当前二进制（ExecStart 指向 secautomind-ai）
ssh root@120.48.36.201 "systemctl is-active secautomind && systemctl show secautomind -p ExecStart"

# 2.2 备份 unit 文件（轮换回滚点之一）
ssh root@120.48.36.201 "cp /etc/systemd/system/secautomind.service /root/secautomind.service.bak-$(date +%Y%m%d-%H%M%S)"

# 2.3 记录当前时间戳，供第 3/4 步日志窗口查询
date -u +"%Y-%m-%dT%H:%M:%SZ"
```

---

## 3. 千问（DashScope）key 轮换 —— 旧 key 最后才删

1. **控制台建新 key**：阿里云百炼控制台 → API-KEY 管理 → 创建新 key。
   **先不要动旧 key**（这是回滚保障）。
2. **改 unit**（我执行）：把 `Environment=DASHSCOPE_API_KEY=` 后面的值替换为新 key。
3. **本机同步**：若第 1 节确认 `config.yaml:132` 与泄露 key 同账户，一并替换（本地开发用）。
4. **重载并重启**（我执行）：
   ```bash
   ssh root@120.48.36.201 "systemctl daemon-reload && systemctl restart secautomind && sleep 3 && systemctl is-active secautomind"
   ```
5. **验证**（我执行）：
   ```bash
   # 5.1 日志无鉴权失败（窗口=第 2.3 步时间戳至今）
   ssh root@120.48.36.201 "journalctl -u secautomind --since '<时间戳>' | grep -iE '401|unauthorized|invalid.*key|apikey' | head -5"
   # 5.2 实拨一次：Web UI 发一条对话，或任一 IM 通道给机器人发消息，确认有正常回复
   ```
6. **控制台删除旧 key**（用户执行）。删完旧 key，生产机 bak 文件里的旧值同步失效。
7. **回滚**：若第 5 步验证失败且原因不明——把 unit 值改回旧 key（旧 key 在第 6 步前仍有效），
   `daemon-reload && restart`，再排查。

---

## 4. 飞书 app_secret 轮换 —— 有 1-2 分钟窗口

> 飞书重置 app_secret 后**旧值立即失效**，无法像千问那样新旧并行。窗口期机器人不可用，
> 建议低峰期执行；若控制台提示有并行期，以控制台为准。

1. **控制台重置**（用户执行）：飞书开放平台 → 你的应用 → 凭证与基础信息 → 重置 App Secret。
   新 secret 只完整显示一次，**先抄到本地记事本**（不要贴进任何聊天/文档/工单）。
2. **改两处配置**（我执行，都改成同一个新值，消除生效顺序歧义）：
   - unit `Environment=LARK_APP_SECRET=`
   - 生产机 `/opt/secautomind/config.yaml:141` lark 段 `app_secret:`
3. **重载并重启**（我执行）：同第 3 节第 4 步命令。
4. **验证**（我执行 + 用户配合）：
   ```bash
   ssh root@120.48.36.201 "journalctl -u secautomind --since '<时间戳>' | grep -iE 'lark|feishu|tenant_access_token|94003|94014' | head -5"
   ```
   用户在飞书里给机器人发一条消息，确认回包；再确认一条主动消息（告警类）可达。
5. **回滚**：旧 secret 已失效，**不存在回滚到旧值**。若新 secret 写错（漏字符），
   用记事本里的新 secret 重新写两处配置再重启；控制台无法再次查看同一 secret 时，
   只能再重置一次（旧窗口作废）。

---

## 5. 轮换后清理（生产机，我执行，mv 不直接删）

```bash
# 5.1 配置备份：15 个 config.yaml.bak-*（轮换后旧值已失效，但明文残留仍应清）
ssh root@120.48.36.201 "mkdir -p /tmp/secautomind-cleanup-20261013 && mv /opt/secautomind/config.yaml.bak-* /tmp/secautomind-cleanup-20261013/ && ls /tmp/secautomind-cleanup-20261013/ | wc -l"

# 5.2 二进制残留：7 个 secautomind-ai.bak-* + secautomind + secautomind.winpe-wrong（共 1.8G；
#     后两个 file 实测均为 Windows PE，ExecStart 不指向它们）
ssh root@120.48.36.201 "mv /opt/secautomind/secautomind-ai.bak-* /opt/secautomind/secautomind /opt/secautomind/secautomind.winpe-wrong /tmp/secautomind-cleanup-20261013/ && df -h /opt | tail -1"
```

**保留 24 小时**无异常后，由用户确认再 `rm -rf /tmp/secautomind-cleanup-20261013/`
（删除动作必须用户明确确认，我不自行删除）。

---

## 6. 顺带修（仓库侧，走 PR，不随轮换阻塞）

| 项 | 现状 | 建议 |
|---|---|---|
| `config.share.yaml:623` | lark 段 `app_secret: sk-xxxxxxx` 占位假值，与全文件 `${ENV}` 注入纪律不符，且形态像真 key 前缀 | 改 `${LARK_APP_SECRET}` |
| systemd unit | 5 行 `Environment=` 内联明文（unit 文件 root-only，但属敏感配置） | 迁 `EnvironmentFile=/etc/secautomind.env`（chmod 600），unit 只留路径 |

---

## 7. 验证清单（逐项打勾再收工）

- [ ] 百炼控制台旧 key 已删除，新 key 在用
- [ ] 生产日志无 401 / invalid key（千问通道）
- [ ] 飞书机器人消息回包正常；主动消息（告警）可达
- [ ] `systemctl show secautomind -p Environment` 确认两把新值生效（**输出前先掩码**）
- [ ] `/tmp/secautomind-cleanup-20261013/` 已建、生产机目录已清爽
- [ ] 24h 后用户确认删除 /tmp 暂存区
- [ ] 本机 `config.yaml:132` 若同账户已同步新 key

## 8. 一页纸应急卡

- **改完重启后服务起不来**：`journalctl -u secautomind -n 50 --no-pager` 看首条错误；
  配置写坏 → 用 `/root/secautomind.service.bak-*`（unit）或 `/opt/secautomind/config.yaml.backup`（配置）恢复。
- **机器人全通道沉默**：先 `systemctl is-active secautomind`，再查 `logs/secautomind.log` 尾部。
- **怀疑又有 key 进输出**：停止当前命令；对该 key 立即按本 runbook 第 3/4 节轮换；
  教训记账：掩码后必须回读输出确认无完整 token。
