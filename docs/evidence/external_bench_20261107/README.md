# 外部真实赛题池（Google CTF 2021–2025）agentic 跑批

日期：2026-11-07
池：`data/questions_external_bench/external_bench.json`（40 题，crypto 26 / misc 14）
代码：`scripts/run_agentic_stepfun.py` + `scripts/ctf_stepfun_orchestrator.py`

---

## 0. 这一轮要回答什么

前 17 轮的读数（自造题 106/120 = 88.3%）有一个根本弱点：**题是我出的、参考解是我写的、
判分也是我写的**（F-16 自出卷自阅卷）。88.3% 只能读成「在这套自造题上的天花板」，
对真实 CTF 能力的外部效度约等于 0。

这一轮换成真赛题：Google CTF 2021–2025 的 crypto / misc 原题，答案哈希来自官方，
附件是赛事方发布的原始文件。要回答的是：

1. 同一套 agentic 代码、同一模型，在真赛题上能解出多少？
2. 解不出的题，是「不会」还是「环境不行 / 预算不够」？
3. 与自造题 88.3% 的差距有多大？差距从哪来？

---

## 1. 准入审计（跑之前做，不做事后剔除）

脚本：`scripts/audit_external_pool_readiness.py`（selftest 9/9，含变异验证）
结果：`pool_readiness.json`

| 项 | 数 | 说明 |
|---|---|---|
| 题数 | 40 | |
| 附件污染（读文件即得答案） | **0** | 池里有 `flag` / `flag.txt` 文件，但内容是**加密后的**，不是明文答案 |
| 硬不可用（必须执行沙箱给不了的运行时） | **3** | `abc-arm-and-amd`（原生二进制）、`segfault-labyrinth`（原生二进制）、`auxin2`（.rom 需模拟器） |
| 软受限（可绕过，仍计入能力） | 11 | sage 3 / go 3 / dart 1 / pyc 1 / zip 3 |
| **可计分分母** | **37** | 40 − 3 硬不可用 − 0 污染 |

题面自曝答案：**0 / 40**（`self_disclosure_in_statement` 机扫）。

结构分档（用于解释失败原因，不用于剔分母）：

| 档 | 数 | 含义 |
|---|---|---|
| A 静态数据完备 | 8 | 附件里有 output/cipher/pubkey 等，理论上不交互也能解 |
| B 需自建 oracle | 29 | 只有 chall.py / server.py，要自己实现协议或模拟 oracle |
| C 污染 | 0 | |
| D 硬不可用 | 3 | |

---

## 2. 隔离与命令绑定

🔴 本轮开始前 `iptables -S OUTPUT` 只剩 `-P OUTPUT ACCEPT`（上一次的规则已被
`/tmp/sbx_net.sh` 的 900s auto-teardown 拆除）。**不重施就等于没有隔离**，
所以本轮重新施加并重新生成证据。

规则（UID 995 = `ctfsbx`）：

```
-A OUTPUT -d 127.0.0.0/8 -o lo -m owner --uid-owner 995 -j ACCEPT
-A OUTPUT -d 14.103.2.83/32 -p tcp -m owner --uid-owner 995 -m tcp --dport 443 -j ACCEPT   # api.stepfun.com
-A OUTPUT -d 8.152.159.24/32 -p tcp -m owner --uid-owner 995 -m tcp --dport 443 -j ACCEPT  # dashscope.aliyuncs.com
-A OUTPUT -m owner --uid-owner 995 -j REJECT --reject-with icmp-port-unreachable
```

A/B 探针（`/tmp/probe_net.py`，同载荷不同 UID）：

| UID | api.stepfun.com | dashscope | example.com | 1.1.1.1 |
|---|---|---|---|---|
| 1000 (user) | OK | OK | OK | 不可达 |
| 995 (ctfsbx) | **OK** | **OK** | BLOCKED errno=101 | **BLOCKED errno=111** |

`REJECT` 而非 `DROP` 是刻意的：拒绝必须可判定（errno=111），
不允许退化成「看起来没连上」的不可判定状态。

证明文件：`isolation_proof.json`（`uid=995`，`command_sha256=a1af4ee7…`，
子进程形态 `[python, -I, -c]` 与 `run_python_tool()` 完全一致）。

---

## 3. 读数

<!-- 数据待填 -->

---

## 4. 未解分类

<!-- 数据待填 -->

---

## 5. 与自造池的对照

| 池 | 题源 | 分母 | agentic 解出率 |
|---|---|---|---|
| 私有池 v2 | 我造的（40 题） | 40 | 106/120 = 88.3%（三轮） |
| 外部池 external_bench | Google CTF 2021–2025 原题 | 37 | 见上 |

---

## 6. 作用域声明（必须与数字一起引用）

<!-- 数据待填 -->

---

## 7. 已知缺陷

<!-- 数据待填 -->
