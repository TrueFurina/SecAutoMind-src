# SOP：把阿里百炼（DashScope）当免费模型网关用

> 实测日期 2026-10-04。目标：**同一个百炼 key 下多个免费模型互为兜底，任一模型额度耗尽时自动切换**，
> 而不是"key 死��就换 key"。
>
> 适用：任何用百炼兼容模式（`https://dashscope.aliyuncs.com/compatible-mode/v1`）做 LLM 调用的项目。

---

## 0. 五条铁律（先记这个，能省掉 80% 的坑）

| # | 铁律 | 违反后果 |
|---|------|---------|
| 1 | **`403 Free quota exhausted` ≠ key 死了**，是**某一个模型**的免费额度耗尽 | 白白换 key、反而丢失网关下全部免费模型 |
| 2 | **改用哪个模型 ≠ 改 key**。key 不动，只改 `model` 字段 | 丢失全部兜底池 |
| 3 | **配了多个兜底模型 ≠ 会自动切换**。必须实测 failover 判据认不认这个错误 | 配了等于没配，额度耗尽照样硬挂 |
| 4 | **免费额度按周期重置**。实测：某模型 2 小时内从「耗尽 403」变回「100% 可用」 | 把「等重置」当「永久弃用」，白丢一个可用模型 |
| 5 | **探活必须看 body 有无 `error`，不能只看 HTTP 码** | 把 200 + `{"error":...}` 的模型误记为可用，配进兜底池后运行期才炸 |

> 铁律 4/5 均为 2026-10-04 实测打脸补记，非事后诸葛亮。

---

## 1. 认清百炼网关：免费额度是「按模型」计的

百炼（阿里云 Model Studio）一个 key 下挂着**几十个模型**（通义千问系列 + DeepSeek 系列 + Qwen 第三方蒸馏系列…），
**每个模型各有独立的免费额度**。控制台「模型列表 → 免费额度」列逐个模型显示 `免费额度 / 已消耗 / 剩余比例 / 到期时间`。

所以「免费额度用尽」的真实含义是：**你正在用的那个模型的 1M token 免费包烧完了**，
而同一个 key 下其它模型可能还是 100%。

**先查这张表再动手**。截至 2026-10-04 用真实 key 全量实测的分类结果（`chat/completions` 直连可用）：

### ✅ 可用于 chat（21 个实测通过）

| 家族 | 模型 | 用途取向 |
|------|------|---------|
| **DeepSeek** | `deepseek-v3` / `v3.1` / `v3.2-exp` | 通用主力，快稳便宜 |
| | `deepseek-v4-pro` / `v4-pro-0813` | 强通用（`max_tokens` 小会返回 `finish_reason:length`，属正常） |
| | `deepseek-r1` | 推理型，解题/多步推导 |
| | `deepseek-r1-distill-qwen-32b` / `14b` / `7b` | 蒸馏小模型，省额度 |
| **Qwen 旗舰** | `qwen3-max` / `qwen3-max-preview` | 千问旗舰 |
| | `qwen3.8-max` | 千问新一代旗舰 |
| | `qwen3.7-max` / `qwen3.7-max-preview` | 新旗舰 |
| | `qwen3.6-max-preview` | 上一代旗舰 |
| **Qwen 档位** | `qwen3.7-plus` / `qwen3.7-flash` / `qwen3.6-flash` / `qwen3.5-plus` / `qwen3.5-flash` | 通用中/快档 |
| | `qwen3.6-27b` / `qwen3.6-35b-a3b` | MoE 中量级 |
| **编程** | `qwen3-coder-plus` | 代码场景 |
| **Kimi** | `kimi-k2.7-code` / `kimi-k2.6` / `kimi-k2.5` | Moonshot 系列 |
| | `kimi-k2-thinking` / `Moonshot-Kimi-K2-Instruct` | 思考型 / 指令型 |
| **GLM** | `glm-5.2` / `glm-5.1` / `glm-5` / `glm-4.7` / `glm-4.6` | 智谱系列 |
| **其他** | `qwen3.5-ocr` / `qwen-mt-lite` | OCR / 翻译（见下方注意事项） |

### ❌ 不可用于 chat（实测报错，**别写进配置**）

| 模型 | 实测报错 | 原因 |
|------|---------|------|
| `glm-4.5` / `glm-4.5-air` | `This model only support stream mode, please enable stream` | **只支持流式**，非流式调用被拒 |
| `wanx2.1-*`（视频类） | `Unsupported model ... for OpenAI compatible` | 走视频生成端点，非 chat |
| `qwen-mt-*`（部分） | 视端点而定 | 翻译专用，chat 语义不对口 |

> 🔴 **`finish_reason: length` 不等于失败**。`deepseek-v4-pro` / `glm-5.2` / `qwen3.5-ocr` 等
> 在 `max_tokens` 很小时会返回 `length`（输出被截断）但**调用成功**。判成败要看有没有 `error` 字段，
> **不要**用关键字猜（见 §2.1）。

> ⚠️ **这张表会过期**。百炼调整免费策略、或某模型额度烧完，上表立刻失真。
> **永远以「控制台截图」+「curl 探活」为准**，不要照抄本文档的模型清单。

### 🔑 关键机制：免费额度**按周期重置**，不是烧完就永久没了

实测对照（同一模型、同一 key、相隔约 2 小时）：

| 时间点 | `qwen3-max` 状态 | 现象 |
|--------|------------------|------|
| 15:29 | **Free quota exhausted**（已消耗 1M） | Agent 报 403 |
| 18:4x | **100%，仅消耗 34 tokens** | curl 完全正常 |

**同一个模型、同一个 key，额度回来了。** 所以：

- **额度耗尽 ≠ 这个模型永久不可用** → 别急着把它从配置里删掉；
- **也别把"配额耗尽"当致命错误** → 隔一段时间它自己就恢复了（第 4 章的 failover 判据正是为此）；
- 排障时**先看控制台剩余比例**，再决定是"换模型"还是"等重置"。

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

批量探活多个模型（**判成败看 body 有无 `error` 字段，不要只看 HTTP 码**）：

```bash
for M in deepseek-v3.1 deepseek-r1 qwen3.8-max kimi-k2.7-code glm-5.2; do
  body=$(curl -s --max-time 40 -X POST \
    https://dashscope.aliyuncs.com/compatible-mode/v1/chat/completions \
    -H "Authorization: Bearer $KEY" -H 'Content-Type: application/json' \
    -d "{\"model\":\"$M\",\"messages\":[{\"role\":\"user\",\"content\":\"say ok\"}],\"max_tokens\":8}")
  if printf '%s' "$body" | grep -q '"error"'; then
    printf '%-24s FAIL  %s\n' "$M" "$(printf '%s' "$body" | grep -o '"message":"[^"]*"' | head -1)"
  else
    printf '%-24s USABLE\n' "$M"
  fi
done
```

### 🔴 §2.1 「有 HTTP 响应」≠「模型可用」

**这是本项目实测踩过的坑**：写探活脚本时按关键字分类（`model_not_found` / `invalid_api_key`），
结果把返回 `{"error":{"message":"This model only support stream mode..."}}` 的
`glm-4.5`、`glm-4.5-air` 和 `wanx2.1-t2v-turbo` **全部误判成 OK**——
它们确实回了 HTTP 200 + JSON，但 `error` 字段就在 body 里。

**正确判据只有一条：body 顶层有没有 `error`。**

| 现象 | 含义 |
|------|------|
| 有 `choices` 且无 `error` | ✅ 可用 |
| 有 `error` 字段 | ❌ 不可用（**即使 HTTP 是 200**） |
| `finish_reason: length` | ⚠️ 输出被截断，**但调用成功** |

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

**兜底池要跨家族**：不要把 4 个兜底全押在 DeepSeek 系。百炼按**模型**计费，
但**家族级限流/维护/策略收紧**是可能的——跨家族（DeepSeek / Qwen / Kimi / GLM 各取一两个）
才是真兜底。本项目现役 4 通道是 `deepseek-v3.1` + `deepseek-r1` + `qwen3.8-max` + `deepseek-v3.2-exp`，
**已横跨 DeepSeek 与 Qwen 两族**；若要更强可再加 `kimi-k2.7-code`、`glm-5.1`。

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

- 线上 `ai.channels`：`deepseek`（自有 key，主）+ **5 通道共用同一 `${DASHSCOPE_API_KEY}` 兜底**：
  `qwen-max`(deepseek-v3.1) / `dashscope-ds-r1`(deepseek-r1) / `dashscope-qwen38`(qwen3.8-max) /
  `dashscope-ds-v32`(deepseek-v3.2-exp) / `dashscope-kimi-k27code`(kimi-k2.7-code) / `dashscope-glm51`(glm-5.1)
  → **横跨 DeepSeek / Qwen / Kimi / GLM 四族**（同族全押不叫兜底）。
  兜底通道 ID 沿用 `dashscope-<族>-<模型>` 命名；`qwen-max` 因被代码按名取模型而保留历史名。
- 触发经过：QQ @ 报 `[NodeRunError] 403 Free quota exhausted` → 查明是 `qwen3-max` **单模型**额度耗尽
  （key 本身活着）→ 换 `deepseek-v3.1` 止血 → 补代码让配额耗尽可切换 + 扩兜底池做长期兜底。
- ⚠️ 约 2 小时后复查控制台：`qwen3-max` 已**回到 100%（仅耗 34 tokens）**→ 印证「额度按周期重置」（§1 铁律 4）。
- 验证：6 个兜底模型服务器直连全 `USABLE`（body 无 `error`）；`verify_demo_readiness.py` 6/6 🟢；
  重启后 `Free quota` 计数 0。
- 相关文件：`scripts/verify_demo_readiness.py`（演示就绪度闸门）、
  `internal/multiagent/eino_transient_retry.go`（配额判据）、`eino_transient_retry_test.go`（含反向用例）。
