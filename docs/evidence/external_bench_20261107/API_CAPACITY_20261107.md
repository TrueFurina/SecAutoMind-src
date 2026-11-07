# API 容量事实（2026-11-07 08:00–08:45）

这份文档记录一件比任何解题读数都重要的事：**充值 ≠ 可用**。
用户于 2026-11-07 早间给 DashScope 与 DeepSeek 充值，要求跑满 8 小时，
但夜间批次在 3 分钟内被接口层打回，整轮无任何能力读数。

## 1. 发生了什么

07:58 启动 8 通道批次（8 个 dashscope 模型 × 40 题），07:59–08:09 陆续返回：

| 通道 | 模型 | 结果 | 耗时 |
|---|---|---|---|
| qf | qwen3.8-flash | **39/40 题 403** | 616s |
| qf（第二轮） | qwen3.8-flash | **40/40 题 403** | 4s |
| mm | MiniMax-M2.5 | 8/8 题 403（A8 切片） | 1s |
| t24 | qwen3.8-2.4t-a95b | 8/8 题 403 | 1s |
| q37p | qwen3.7-plus | 8/8 题 403 | 1s |

错误原文：

```
HTTP 403 Forbidden: Free quota exhausted. To continue accessing the model on a paid
basis, please add funds or disable the "use free tier only" mode in the model page.
```

**关键在后半句**：账户有余额，但该模型仍处于「仅使用免费额度」模式，充值不会自动解除。
这是一个控制台开关，代码层无法绕过。

## 2. 为什么 07:55 的探针给出的是错答案

07:55 用 `probe_dashscope_models.py`（`max_tokens=64`）扫 10 个模型，报 **8/10 OK**，
其中包含 `qwen3.8-flash`。5 分钟后真实跑批对同一模型 39/40 全 403。

- 探针只验证「端点通不通」，不验证「这个模型还能不能承担真实负载」。
- 小请求可能吃到免费额度的残余，也可能命中与真实请求不同的配额路径。
- **结论：容量探针必须用真实请求规模（真附件、真轮次、真 max_tokens），
  否则它会给你一个「全部可用」的假信号。** 本仓库的 `probe_capacity.sh` 就是为此写的。

用 `max_tokens=512` + `--limit 1` 复测 qwen3.8-flash 与 MiniMax-M2.5，仍全 403
⇒ 排除「单请求规模超限」这一解释，确认是**按模型的额度锁**。

## 3. 实测可用性（真实请求，非小探针）

| 模型 | 状态 | 证据 |
|---|---|---|
| deepseek-v4-flash-0731 | ✅ 可用 | A8 切片 8 题：6 题真实作答、2 题接口失败，329k tokens |
| qwen3.5-35b-a3b | ✅ 可用 | 容量探针 2 题：30k prompt / 19k completion，8 次工具调用 |
| qwen3.8-27b | ⚠️ 可用但极慢 | 单题中位数 300s+，12 轮迭代下 8 题需 1 小时以上 |
| kimi-k3 | ⚠️ 可用但极慢 | 同上 |
| qwen3.8-flash | ❌ 403 额度锁 | 39/40 全 403，缩到 512 tokens 仍 403 |
| MiniMax-M2.5 | ❌ 403 额度锁 | 同上 |
| qwen3.8-2.4t-a95b | ❌ 403 额度锁 | 同上 |
| qwen3.7-plus | ❌ 403 额度锁 | 同上 |
| qwen3.8-max-0902 | ❌ 403 额度锁 | 07:55 探针即 403 |
| deepseek-v4.1-flash | ❌ 403 额度锁 | 07:55 探针即 403 |
| step-3.5-flash | ⚠️ API 通但无工具 | 100s 答完，`tool_calls=0`、`llm_rounds=[]`；该 provider 配置 `supports_tools=False` |

## 4. 需要的动作（只有账户持有人能做）

在阿里云百炼控制台的**模型页**，对仍要使用的每个模型关闭「仅使用免费额度」。
需要打开的至少包括：`qwen3.8-max-0902`、`deepseek-v4.1-flash`、`qwen3.8-flash`、
`MiniMax-M2.5`、`qwen3.8-2.4t-a95b`、`qwen3.7-plus`。

代码侧无需改动：`--provider dashscope` 已经指向同一个 OpenAI 兼容端点，
额度解除后同一批命令可以直接跑。

## 5. 这一轮为什么没有变成「假绿」

旧口径下，39/40 接口失败会被写成 `solved=0/40`，看上去等同于「模型能力为零」。
2026-11-07 早上新增的两道防线拦住了它：

1. **逐题 `api_error_rounds` / `api_error_first`**：失败原因随题入库，不再被 `except` 吞掉。
2. **整轮全失败的 ALERT**：`apierr == total` 时写 `alerts.log` 并在 master 台账里标 `ALERT`，
   明确写「本轮无能力读数」。

实测输出：

```
[08:09:06] ALERT qf_full16k_r2 全部 40 题接口失败/超时 -> 本轮无能力读数
[08:09:09] ALERT qf_pure16k 全部 40 题接口失败/超时 -> 本轮无能力读数
```

## 6. 顺带修掉的两个harness缺陷

| 缺陷 | 现象 | 修法 |
|---|---|---|
| 结果目录属主 | 批次以 root 建目录、以 `ctfsbx` 写结果 ⇒ `PermissionError`，任务静默 rc=1 | 建目录后 `chown ctfsbx:ctfsbx` |
| 探测脚本同理 | `capprobe/*.json` 全部写不进去 | 同上 |

这两条都是「跑批跑完了、但一个结果文件都没有」的形态，靠冒烟测试在 2 分钟内发现，
而不是等 8 小时后才发现。
