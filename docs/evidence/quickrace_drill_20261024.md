# 1024 快闪赛赛前演练记录（2026-10-24）

> **口径**：本文所有数字均为 2026-10-24 本次实跑输出，未跑的项在 §6 明确写「未跑」。
> 不做推测，不把"看起来能跑"写成"已验证"。

## 0. 基线与边界

| 项 | 值 |
|---|---|
| HEAD | `d6d120e26e892e79bb7f34ffd849f05a6717112c` |
| 交付 exe | `installer/secautomind-ai.exe`，md5 `f14274208743d4d6f7779edca583ab98`，89.6 MB（89,617,920 B） |
| exe 内嵌构建 commit | `174c7a872d5f`（**落后于 HEAD**，见 §4） |
| 演练时段 | 2026-10-24 05:46 ~ 05:58（GMT+8） |
| 边界 | 本轮**未改** `internal/` `agents/` `cmd/`（T0 冻结纪律）；仅只读执行与文档记录 |

## 1. 交付包冒烟（五连中机器可判的部分）

在**空目录** `D:\tmp_smoke_1024` 启动绿色版，验证「拷到新机器能不能活」：

```bash
secautomind-ai.exe --http        # 空目录 → 自举生成 config.yaml
curl -o /dev/null -w '%{http_code}' http://127.0.0.1:18086/
```

| # | 项 | 实测 | 判定 |
|---|---|---|---|
| 1 | `GET /` | **200** | ✅ |
| 2 | 未登录访问受保护接口 `/api/config` | **401** | ✅ 鉴权生效 |
| 3 | `/api/setup/status` | **200**，`{"needs_setup":true}` | ✅ 首启向导可识别 |
| 4 | 首启凭据落盘 | `data/admin_initial_password.txt` 已生成，控制台一次性显示 | ✅ |
| 5 | 数据目录自建 | `agents/` `data/` `logs/` `config.yaml` 均在空目录内生成 | ✅ 无外部依赖 |
| 6 | 监听地址 | **`0.0.0.0:18086`**（netstat 实测） | ⚠️ 与材料宣称不符，见 §3 |

> 附带发现（**不是缺陷**，避免现场误判）：`/api/tools` 与 `/api/audit` 返回 **404**——这两个路径不存在，
> 不是"鉴权失效"。验证 401 必须用真实存在的受保护路径（如 `/api/config`）。

## 2. 演练测试（`./internal/ctfplatform/`）

### 2.1 默认档 `TestRehearsal`

```
PASS: TestRehearsalFinalsLoop (0.17s)
PASS: TestRehearsalSerialVsConcurrent (0.51s)
PASS: TestRehearsalInstanceChain (0.02s)
PASS: TestRehearsalAttachmentChain (0.01s)
PASS: TestRehearsalDetailEnrichment (0.00s)
PASS: TestRehearsalEnvRelease (12.35s)     # 靶机回收：accepted→destroy×1；对照 A/B 均 0
SKIP: TestRehearsalStress                 # 默认跳过，需 REHEARSAL_STRESS=1
SKIP: TestRehearsalConcurrencySweep       # 默认跳过，需 REHEARSAL_SWEEP=1
ok  secautomind-ai/internal/ctfplatform  13.534s
```

6 PASS / 2 SKIP（**默认档不覆盖压力与并发扫描**，故另跑，见下）。

### 2.2 限流注入 `REHEARSAL_STRESS=1`

```
压力演练：题数=20（可解 12）并发=4 求解耗时=60ms | 总耗时=222ms 吞吐=90.1 题/秒
         拉题 4 次（注入 429×2）提交 HTTP 12 次（注入 429×0）
--- PASS: TestRehearsalStress (0.22s)
```

**读法**：拉题侧注入了 2 次 429，仍完成 4 次拉题、12 次提交、12 道可解题全清 → 429 退避生效。

### 2.3 并发扫描 `REHEARSAL_SWEEP=1`

```
并发=1  总耗时=971ms  吞吐=12.4 题/秒  加速比=1.00x
并发=2  总耗时=486ms  吞吐=24.7 题/秒  加速比=2.00x
并发=4  总耗时=244ms  吞吐=49.2 题/秒  加速比=3.98x
并发=8  总耗时=163ms  吞吐=73.5 题/秒  加速比=5.95x
--- PASS: TestRehearsalConcurrencySweep (1.87s)
```

**读法**：并发 8 时加速比 5.95x（对 12 题规模已接近线性），未见锁竞争塌陷。

## 3. 两处实测偏差（T0 只记录，不改代码）

### D1 · 启动日志文案与事实不符
- 实测输出：`✔ 已创建 config.yaml（来自 config.example.yaml）`
- 实际来源：`internal/config/config.go:22` 是 `//go:embed default_config.yaml`，即自举模板是
  **`internal/config/default_config.yaml`**，不是 `config.example.yaml`。
- 文案位置：`internal/termout/startup.go:21`。

### D2 · 「安全默认」在交付二进制上不成立
| 位置 | `server.host` |
|---|---|
| `internal/config/default_config.yaml:16`（exe 自举模板，实际生效） | **`0.0.0.0`** |
| `internal/config/config.go:1993`（代码默认值） | **`0.0.0.0`** |
| `config.example.yaml:27`（仓库示例，材料引用的就是它） | `127.0.0.1` |

而对外材料称「部署即用、安全默认」「默认监听 127.0.0.1」：
- `docs/zh-CN/competition-2026/技术报告_SecAutoMind_202609.md:128`
- `docs/zh-CN/competition-2026/提交前硬门槛核查清单.md:25`

**影响**：空目录双击启动后，面板在**所有网卡**上监听 18086，局域网内可直达登录页。
材料引用的是示例文件，字面属实，但读者会理解为"交付包默认仅本机"。

**建议（T1 执行，不在本轮）**：`default_config.yaml` 与 `config.go:1993` 改为 `127.0.0.1`，
需要外联时用现存开关显式放开；文案改为 `default_config.yaml`；改后**必须重编 exe** 才生效。

## 4. 交付包自证（`build_installer.py --verify-only`）

```
[BLOCK] 交付二进制来源校验失败 2 处：
  · installer\secautomind-ai.exe：构建自 174c7a872d5f，当前 HEAD 是 d6d120e26e89 —— 产物落后于源码
  · SecAutoMind-Setup-1.7.28-x64.exe：内嵌 payload 构建自 174c7a872d5f（dirty=False），与 HEAD 不一致
RC=1
```

**范围核实**（`git diff --stat 174c7a8..HEAD -- '*.go' '*.js' '*.ts' '*.css' '*.html' '*.yaml' 'go.mod' 'go.sum'`）：
仅 `官网/index.html` 2 行（89.8→89.6 那处数字），**无产品源码变更** → 二进制能力等价，差异仅在 buildinfo 戳。

**但门禁按字面 BLOCK**，这点必须如实说，不能包装成"通过"。现场若被追问，两条路：
① 用 `build_on_server.sh` 以 HEAD 重编（本机内存不足时的既定做法）；② 直接说明"源码等价、戳落后"并给出上面的 diff 命令。

## 5. 最坏情况与 30 秒处置（按概率排序）

| 概率 | 故障 | 处置 |
|---|---|---|
| 高 | LLM 通道 4xx/超时 | 对话设置切 `aiChannelId`（qwen↔deepseek↔zhipu），切换约 2 秒生效；全挂 → 切离线录屏 |
| 高 | 端口 18086 被占 | 改 `config.yaml` 的 `server.port`（改配置即可，不必改码） |
| 中 | 评委质疑"监听 0.0.0.0" | 当场把 `server.host` 改 `127.0.0.1` 重启（配置层，30 秒内可做完） |
| 中 | 首启密码没记住 | `data/admin_initial_password.txt`（仅首次生成） |
| 低 | 杀软误杀 exe | 恢复隔离区 + 加白；备用 U 盘第二份 |
| 低 | SQLite busy | 只保留一个实例，重启 |

## 6. 未验证项（**必须保留，留空即不可信**）

- **真实平台拉题/提交**：未跑。需 1024 快闪赛凭证（`CTF2_COMPETITION_ID` + token），本地无。
- **LLM 通道实测**：未跑。需可用 API key；冒烟只验证了服务起得来，未验证对话有响应。
- **工具页 / 审计页 / HITL 审批页**：未跑。需登录后才有权限（本次只到 `needs_setup`）。
- **附件下载与靶机生命周期（起/取权/回收）真机链路**：未跑。`TestRehearsalEnvRelease` 是 httptest 桩，
  不等于真平台。
- **安装版 Setup 的安装流程**：未跑。只校验了内嵌 payload 的构建 commit。
- **TLS**：自举配置写 `tls_enabled: true` + `tls_auto_self_sign: true`，但实测 `http://` 直接 200、
  无 308 跳转 → TLS 未被实际启用（原因未查）。**演示按 HTTP 走，别承诺 HTTPS**。

## 7. 本轮结论

1. 绿色版**能在空目录自举启动并服务**（`/`=200、鉴权 401、向导 200），这是演示的生命线，已过。
2. 演练 8/8 全 PASS（默认 6 + 压力 1 + 并发 1），限流退避与并发扩展均有实测数据。
3. 两处偏差（D1 文案、D2 默认监听）**不影响今天能跑**，但会影响"安全默认"这句宣称的可信度；
   T0 不动代码，T1 修并重编。
4. 交付包自证 BLOCK 是**戳落后而非源码差异**，据实说明即可，别硬说通过。
