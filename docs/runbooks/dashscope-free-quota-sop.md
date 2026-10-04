# SOP：把阿里百炼（DashScope）当免费模型网关用

> 实测日期 2026-10-04。目标：**同一个百炼 key 下多个免费模型互为兜底，任一模型额度耗尽时自动切换**，
> 而不是"key 死��就换 key"。
>
> 适用：任何用百炼兼容模式（`https://dashscope.aliyuncs.com/compatible-mode/v1`）做 LLM 调用的项目。

---

## 0. 三条铁律（先记这个，能省掉 80% 的坑）

| # | 铁律 | 违反后果 |
|---|------|---------|
| 1 | **`403 Free quota exhausted` ≠ key 死了**，是**某一个模型**的免费额度耗尽 | 白白换 key、反而丢失网关下全部免费模型 |
| 2 | **改用哪个模型 ≠ 改 key**。key 不动，只改 `model` 字段 | 丢失全部兜底池 |
| 3 | **配了多个兜底模型 ≠ 会自动切换**。必须实测 failover 判据认不认这个错误 | 配了等于没配，额度耗尽照样硬挂 |

---

## 1. 认清百炼网关：免费额度是「按模型」计的

百炼（阿里云 Model Studio）一个 key 下挂着**几十个模型**（通义千问系列 + DeepSeek 系列 + Qwen 第三方蒸馏系列…），
**每个模型各有独立的免费额度**。控制台「模型列表 → 免费额度」列逐个模型显示 `免费额度 / 已消耗 / 剩余比例 / 到期时间`。

所以「免费额度用尽」的真实含义是：**你正在用的那个模型的 1M token 免费包烧完了**，
而同一个 key 下其它模型可能还是 100%。

**先查这张表再动手**。截至 2026-10-04 实测仍 100% 免费的一批（均已 curl 验证 200）：

| 模型 | 用途取向 | 实测 |
|------|---------|------|
| `deepseek-v3.1` | 通用主力，快、稳、便宜 | ✅ 200 |
| `deepseek-r1` | 推理型（适合解题/多步推导） | ✅ 200 |
| `deepseek-v3.2-exp` | 较新通用 | ✅ 200 |
| `deepseek-v4-pro` / `-v4-pro-0813` | 强通用 | ✅ 200 |
| `qwen3.8-max` | 千问自家旗舰 | ✅ 200 |
| `deepseek-r1-distill-qwen-32b/14b/7b` | 蒸馏小模型，省额度 | ✅ 200 |

> ⚠️ **这张表会过期**。百炼调整免费策略、或某模型额度烧完，上表立刻失真。
> **永远以「控制台截图」+「curl 探活」为准**，不要照抄本文档的模型清单。

---

## 2. 探活：确认模型 ID 与 key 有效（改任何配置前必做）

百炼兼容模式是 OpenAI 风格，单条 curl 即可确认「key × 模型」这个组合可用：

```bash
KEY="<你的百炼 API Key>"
curl -s -o /dev/null -w 'http=%{http_code}\n' --max-time 30 \
  -X POST https://dashscope.aliyuncs.com/compatible-mode/v1/chat/completions \
  -H "Authorization: Bearer $KEY" -H 'Content-Type: application/json' \
  -d '{"model":"deepseek-v3.1","messages":[{"role":"user","content":"say ok"}],"max_tokens":8}'
```

批量探活多个模型：

```bash
for M in deepseek-v3.1 deepseek-r1 qwen3.8-max deepseek-v3.2-exp; do
  code=$(curl -s -o /dev/null -w '%{http_code}' --max-time 30 \
    -X POST https://dashscope.aliyuncs.com/compatible-mode/v1/chat/completions \
    -H "Authorization: Bearer $KEY" -H 'Content-Type: application/json' \
    -d "{\"model\":\"$M\",\"messages\":[{\"role\":\"user\",\"content\":\"say ok\"}],\"max_tokens\":8}")
  echo "$M http=$code"
done
```

**200 = 可用**，可写进配置。

### 三种错误形态必须分清（这是 failover 判据的依据）

| HTTP | body 关键串 | 含义 | 该做什么 |
|------|-------------|------|---------|
| **403** | `Free quota exhausted` | **该模型**免费额度烧完 | ✅ **切换到同 key 其它模型** |
| 401 | `Incorrect API key provided` / `invalid_api_key` | key 错了/失效 | ❌ 别切模型，换 key |
| 404 | `does not exist or you do not have access to it` / `model_not_found` | 模型 ID 写错或无权限 | ❌ 改模型名 |

> 实测记录：`__no_such_model__` 返回 **404 + `model_not_found`**；
> 用错 key（抓到别的通道的 key）返回 **401 + `invalid_api_key`**。
> 这两种和配额耗尽的 403 **形态完全不同**，所以 failover 判据可以精确只捞「配额」这一类。

---

## 3. 配置形态：同 key 多通道，一个模型一通道

**核心思路**：不要在一个通道里堆模型，而是**同一 key 建多个通道、每个通道一个模型**，
这样兜底池天然形成，切换逻辑只需在「通道」层面做。

```yaml
ai:
  default_channel: deepseek        # 主通道（付费/自有 key，照常配）
  channels:
    # ── 主通道：自有付费 key，不受免费额度影响 ──
    deepseek:
      name: DeepSeek
      provider: openai_compatible
      api_key: ${DEEPSEEK_API_KEY}
      base_url: https://api.deepseek.com/v1
      model: deepseek-chat

    # ── 以下 4 个通道共用同一个百炼 key，互为兜底 ──
    qwen-max:                      # ⚠️ 通道名沿用历史命名即可，与 model 无关
      name: Qwen Max
      provider: openai_compatible
      api_key: ${DASHSCOPE_API_KEY}
      base_url: https://dashscope.aliyuncs.com/compatible-mode/v1
      model: deepseek-v3.1
      max_total_tokens: 120000
      max_completion_tokens: 32768
    dashscope-ds-r1:
      provider: openai_compatible
      api_key: ${DASHSCOPE_API_KEY}
      base_url: https://dashscope.aliyuncs.com/compatible-mode/v1
      model: deepseek-r1
      max_total_tokens: 120000
      max_completion_tokens: 32768
    dashscope-qwen38:
      provider: openai_compatible
      api_key: ${DASHSCOPE_API_KEY}
      base_url: https://dashscope.aliyuncs.com/compatible-mode/v1
      model: qwen3.8-max
      max_total_tokens: 120000
      max_completion_tokens: 32768
    dashscope-ds-v32:
      provider: openai_compatible
      api_key: ${DASHSCOPE_API_KEY}
      base_url: https://dashscope.aliyuncs.com/compatible-mode/v1
      model: deepseek-v3.2-exp
      max_total_tokens: 120000
      max_completion_tokens: 32768
```

**关键点**

- **通道 ID 是任意的**（`qwen-max` / `dashscope-ds-r1` …），代码若按名字取模型，改名会断链——改名前先 grep 谁引用它。
- **兜底顺序 = 通道遍历顺序**。主通道挂了才进兜底池，池内按配置顺序顺位切。
- **不要显式写 failover 列表**。本项目留空 `model_failover_channels` 才会走"自动列出所有已激活通道"的兜底；
  一旦显式写死，模型增减后新通道不会自动进池（`AutoFailoverChannelIDs` 被跳过）。
- **凭据用 `${ENV_VAR}` 注入**，别把真 key 落进版本库/交付包（公开仓库 = 永久泄漏，强推也删不掉历史）。

---

## 4. 🔴 关键：让「配额耗尽」能触发自动切换

**这是整套 SOP 里最容易漏、后果最严重的一步。**

多数 failover 实现把错误按 HTTP 状态码分类，`403` 默认被判为「致命、不重试」——
于是**配额一烧完就直接失败，兜底池形同虚设**。本项目实测就踩了这个坑：
`isRetryableHTTPStatus(403) = false` → 403 直接失败。

### 判据必须放在「状态码短路之前」

```go
func isEinoTransientRunError(err error) bool {
    // ... 取消/超时/超迭代上限等前置判据 ...

    // 🔴 配额耗尽判据：必须早于下面的状态码短路！
    // 错误文本常带 "status code: 403"，若先按状态码判会误当致命 4xx 而不切换。
    lower := strings.ToLower(err.Error())
    if strings.Contains(lower, "free quota") ||
       strings.Contains(lower, "quota exhausted") ||
       strings.Contains(lower, "免费额度") {
        return true
    }

    // ... 此后才是 408/409/425/429/5xx 等状态码判据 ...
}
```

### 🚨 三个反直觉的坑（全部实测踩过）

1. **把关键词加进 `transientMarkers` 列表 ≠ 生效。**
   该列表在**状态码短路之后**才查。`"status code: 403 ... Free quota exhausted"` 会被先按 403 判死，
   根本走不到列表。必须写成**短路前的独立判据**。
   （证据：同一批用例里，英文带 403 的那条 FAIL、不带状态码的中文那条 PASS。）

2. **配额判据要「窄」，别把真故障也重试。**
   只匹配配额字样，**不要**笼统放行所有 403——否则真正的密钥失效/权限不足也会被反复重试掩盖。
   必须加**反向用例**：`403 + invalid api key` 期望值必须是 `false`。

3. **`402` / `insufficient_quota`（OpenAI 侧同义形态）一起覆盖。**
   不同网关措辞不同，若代码里还有别家 provider，配额判据宜覆盖
   `free quota` / `quota exhausted` / `insufficient_quota` / `免费额度` / `额度已用尽`。

### 必须配反向用例（防回归）

```go
{"403 free quota exhausted", errors.New("status code: 403, status: 403 Forbidden, message: Free quota exhausted"), true},
{"403 free quota chinese", errors.New("免费额度用尽即停"), true},
{"403 auth not quota",    errors.New("status code: 403, status: 403 Forbidden, message: invalid api key"), false},  // 反向
{"401 wrong key",         errors.New("Incorrect API key provided"), false},                                     // 反向
```

### 变异自检（确认判据真的被测到了）

改坏判据（去掉配额分支）必须让测试变红。**若改坏仍绿 = 测试没碰到被测对象，零证明力。**

---

## 5. 验收清单

| # | 检查项 | 判据 |
|---|--------|------|
| 1 | 每个兜底模型 curl 探活 | 全部 `http=200` |
| 2 | 服务重启后正常拉起 | 无通道解析错误 |
| 3 | 主通道可用 | 一次真实请求成功 |
| 4 | 配额判据存在且在状态码短路前 | 代码 review + 单测 |
| 5 | 反向用例（401/403 鉴权失败）判致命 | 单测期望 `false` |
| 6 | 篡改判据后单测变红 | 变异自检 |
| 7 | 重启后日志无 `Free quota` 增长 | `grep -c "Free quota"` 不随时间涨 |
| 8 | 凭据未进版本库/交付包 | 双向扫描：`grep 文件` + `git diff --cached` |

**没有第 4/5/6 条，这次改动就只是「配了兜底池」而不是「真会自动切」**——配额耗尽时依旧硬挂。

---

## 6. 一句话总结

> 百炼的免费额度**按模型计**，所以正确姿势是：**key 不动、配多个模型通道、并且（最容易漏的）让 403 配额耗尽能触发 failover**。
> 少最后一步，前面全白配。

---

## 附：本项目实例（2026-10-04 收口）

- 线上 `ai.channels`：`deepseek`（自有 key，主）+ 4 通道共用 `${DASHSCOPE_API_KEY}` 兜底。
- 触发经过：QQ @ 报 `[NodeRunError] 403 Free quota exhausted` → 查明是 `qwen3-max` 单模型额度耗尽（key 本身活着）
  → 换 `deepseek-v3.1` 止血 → 再补代码让配额耗尽可切换 + 补 3 兜底通道做长期兜底。
- 验证：4 模型服务器 curl 全 200；重启后 `Free quota` 计数 0（末条为修复前那条）。
- 相关：`scripts/verify_demo_readiness.py`（演示就绪度闸门）、
  `internal/multiagent/eino_transient_retry.go`（配额判据）、`eino_transient_retry_test.go`（含反向用例）。
