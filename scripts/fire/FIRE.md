# FIRE 运行手册：充值后受控 P0 跑批（batch2）

本手册固化「OpenRouter 充值 >0 后如何干净跑出真实解题数」的完整流程。
离线可验证项已全部验证通过，本手册仅描述充值后的执行步骤与关键纪律。

---

## 0. 前置状态（已在本地验证，无需重做）

| 离线可验证项 | 结论 |
|---|---|
| opt1 `ctf_crypto` 注入（**真实 Go 路径**：embed→写会话目录→python import 进 G） | ✅ 单测 `TestPySessionCtfCryptoInjected`（`f6caa94`），modinv/IDEA(`11fbed2b01986de5`)/Merkle 全调用成功 |
| 402/429 同通道退避重试 | ✅ 3 个单测全绿（`9bc7d52`） |
| `llmbench` 二进制可构建+启动 | ✅ 冒烟 `-h` 完整 flag 表、无 panic |
| opt2 原语库单测（IDEA/LCG/MHK/Merkle） | ✅ 26 passed（3 因本机缺 pycryptodome 跳，服务器有该依赖） |
| batch2 ids 规范化 + `split -l` 切块 | ✅ 逗号单行 23 id → 23 行 → 6 块(4,4,4,4,4,3) 总题数守恒 |
| 脚本 × 二进制 flag 兼容 | ✅ 6 个 flag 逐一比对 `cmd/llmbench/main.go` L328–341 全匹配 |
| 23/23 P0 id 与 `external_bench.json` 键匹配 | ✅ 100% 命中，无缺失 |
| linux 二进制预编译 | ✅ `.workbuddy/tmp/llmbench_linux`（ELF, 23.6MB）；可重编 |

**唯一硬阻塞**：OpenRouter `total_credits > 0`（7 通道全 0/不可达，含服务器 `/home/user/.openrouter_key`）。

---

## 1. 关键纪律与已修正的坑（务必先读，避免重蹈覆辙）

1. **`withp0` / `nop0` 现在就是同一份二进制复制**（P0 死锁修复 diff 已从源码丢失，grep 全仓无源码命中；续5 红线）。A/B 退化为同二进制自比，保留交错仅兼容历史命名。**不要**再去服务器找「P0 死锁修复」diff —— 确认不可重建。
2. **batch1（2026-11-12 05:xx）的 0/23 不是能力结果**：服务器当时 `.openrouter_key` 余额 =0，3 个 json 全是 `SKIPPED（LLM 不可用）`（withp0_1 跑5/skip18、withp0_2 跑3/skip20、nop0_1 跑1/skip22）。**opt1/opt2 原语库从未在真实额度下被测过**——本 batch2 才是第一次有效验证。
3. **模型 slug 必须是 `deepseek/deepseek-r1`**（OpenRouter 正确 slug）。代码默认值 `deepseek-reasoner` 与口语 `deepseek-reasoner` 在 OpenRouter 上**均无效**，会 model-not-found 崩。脚本已硬编码正确 slug。
4. **`RUNNER_LLM_NO_FALLBACK=1` 必须设**（评测红线，`llm_failover.go:336`）：只走主通道，禁止匿名/备用小模型降级冒充强模型名 → 否则假绿。与 `RUNNER_LLM_FALLBACK=true`（网关守卫放行所需，另一道独立闸门）并存不冲突。
5. **余额护栏**：脚本启动前查 `/credits`，`total_credits<=0` 直接拒跑（exit 2），不白烧等待。

---

## 2. 执行步骤（在本地 + 服务器各做一部分）

### 2.1 本地：构建 linux 二进制（如预编译产物已丢则重编）
```bash
# 在 Windows 本地仓库根
export PATH="/c/Users/Lenovo/sdk/go/bin:$PATH"
GOOS=linux GOARCH=amd64 CGO_ENABLED=0 \
  go build -o llmbench_linux ./cmd/llmbench
# 校验：head -c4 llmbench_linux 应为 7f 45 4c 46 (ELF)
```

### 2.2 传输到服务器，并复制成两个历史名字
```bash
# 从本地
scp llmbench_linux user@172.16.222.99:/home/user/SecAutoMind/
scp scripts/fire/batch2_openrouter.sh user@172.16.222.99:/home/user/SecAutoMind/

# 在服务器
cd /home/user/SecAutoMind
cp llmbench_linux llmbench_withp0
cp llmbench_linux llmbench_nop0
chmod +x llmbench_withp0 llmbench_nop0
```

### 2.3 冒烟测试（先小批，确认真打通 LLM，再放大）
```bash
# 在服务器，临时用 limit 冒烟（脚本本身按块跑，可用 sed 临时把 CHUNK 调小或单独探一题）
./llmbench_withp0 -real data/questions_external_bench/external_bench.json \
  -ids <(echo 某单一 P0 id) -att-root data/questions_external_bench/_attachments \
  -out smoke.json -with-skills -with-l2
# 检查 smoke.json：skipped=0 且确有 LLM 调用（非匿名小模型），才算真打通
```
> 若冒烟仍全 SKIP 或模型名异常，先查 `/home/user/.openrouter_key` 余额与 key 是否能调 `deepseek/deepseek-r1`，**不要**直接放大。

### 2.4 正式跑批
```bash
cd /home/user/SecAutoMind
nohup bash batch2_openrouter.sh > master.log 2>&1 &
# 监控：tail -f master.log；每块产出 batch2_{withp0,nop0}_{1..6}.json + .log
```

---

## 3. 跑后核对（用 `scripts/compare_runs_ab.py`）
- 汇总 `batch2_withp0_*.json` / `batch2_nop0_*.json` 的 `sha256_match` + `layer`。
- 只信 `sha256_match=True` 且执行期零外网（`CTF_AIRGAP=1` 已设）的题为有效纯 LLM 解出。
- 与 batch1 的「全 SKIP 无效跑」对比，本 batch2 才是首个有效基线。

---

## 4. 成本权衡（待你拍板）
`deepseek/deepseek-r1` 为溢价推理模型（~$1.85/M input），对 Google CTF 决赛级 crypto 远强于 V3-chat，但 23 题×多轮可能快速烧穿小额充值。若预算紧，改 `batch2_openrouter.sh` 第 21 行：
- `deepseek/deepseek-chat`（便宜但可能 0 解）
- `deepseek/deepseek-r1:free`（免费但强限流，可能反复 402）

默认保留 `r1`（契合「KPI=真实解题数」单一核心）。

---

## 5. 回归红线提醒
- **禁 `git add -A`**：只 stage 显式文件。
- 密钥不进模型上下文；env 明文凭证不 dump。
- 改分母/计数后必须重跑 `scripts/_kpi_canonical.py`（若引入新的解题统计）。
- 服务器 `/home/user/SecAutoMind` 非 git 仓；本地分支 `feat/private-pool-v1-20261107` 已推送远端（HEAD = `7e7dbc2`）。
