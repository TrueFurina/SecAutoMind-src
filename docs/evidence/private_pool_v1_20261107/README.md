# 私有题池 v1 跑批实录（2026-11-07）

> 本目录是「自造私有题」这条线的全部证据。下面是可复核的事实，不含推断；
> 推断单独标了「推断」，不与事实混排。

## 一、口径

| 项 | 值 |
|---|---|
| 题池 | `data/ctf_benchmark/private_benchmark_v1.json`（10 题，sha256 `26dd0dee…`） |
| 题源 | 本项目原创（种子 sha256 派生 flag，明文不落盘），`source=self-authored / unreleased` |
| 私有性锚点 | `private_pool_registry.json`，R0–R6 全过，`anchored=True (10/10)` |
| 附件依赖 | 0（材料 100% 内嵌题面） |
| 路径 | `pure_llm`（模型无工具、无代码执行、无网络出口） |
| 模型 | stepfun `step-3.5-flash`，`temperature=0.2`（请求体硬编码，代码级可证） |
| 执行位置 | `172.16.222.99`（AGENTS.md 第零条：跑题只在服务器） |
| 入口 | `scripts/run_capability_eval.py --run`（前置守卫 + 结果级绑定 + 判分仲裁一体） |

## 二、三轮独立样本

三轮都是**全新调用**（每次 10 次 API 请求），不是同一次结果复用。

| 轮次 | 结果文件 | 命中 | 命中题 | 延迟合计 | 判分 |
|---|---|---|---|---|---|
| run_a | `run_a.result.json` | 3/10 | 01 xor、03 vigenere、07 licence | 220.7s | 服务器判分时 `anchored=False`（服务器当时无 git 历史）⇒ 不可归因 |
| run_b | `run_b.result.json` | 2/10 | 01 xor、07 licence | 232.6s | 缺泄漏集/训练白名单 ⇒ 不可归因 |
| **run_c** | `run_c.result.json` | **3/10** | 01 xor、04 lcg、07 licence | 231.6s | **可引用=True，rate=0.3** |

`run_c.verdict.json` 关键字段（机读）：

```
claimable              = true
capability_rate        = 0.3
claimable_denominator  = 10
effective_runs         = 10
attributable_runs      = 10
excluded_not_attributable = 0
verdicts               = {LLM_SOLVED: 3, CLEAN_FAIL: 7, NOT_ATTRIBUTABLE: 0}
blocking_reasons       = []
claim_scope            = capability_rate_candidate (anchored=True, private 10/10)
scoring_variant_gap    = false_negative_count 0
attachment_dependency  = attachment_dependent_count 0
```

`run_a.verdict_local_readjudge.json` 是 run_a 的**本机重判**（作用域已升到
`capability_rate_candidate`，但缺结果级绑定 ⇒ 全批 NOT_ATTRIBUTABLE）。
保留它只为记录「判分链路要求结果与本次跑批绑定」这一行为，**不能引用其数值**。

## 三、三轮交叉观察（事实）

| 题 | a | b | c | 说明 |
|---|---|---|---|---|
| 01 xor_single_byte | ✅ | ✅ | ✅ | 3/3 稳定 |
| 02 rsa_low_exponent_cube | ❌ | ❌ | ❌ | 0/3 |
| 03 vigenere_known_key | ✅ | ❌ | ❌ | 1/3 波动 |
| 04 lcg_predict_next | ❌ | ❌ | ✅ | 1/3 波动 |
| 05 weak_seed_prng | ❌ | ❌ | ❌ | 0/3 |
| 06 encoding_nest | ❌ | ❌ | ❌ | 0/3 |
| 07 licence_constraints | ✅ | ✅ | ✅ | 3/3 稳定 |
| 08 discrete_log_small | ❌ | ❌ | ❌ | 0/3 |
| 09 ctr_nonce_reuse | ❌ | ❌ | ❌ | 0/3 |
| 10 rsa_common_modulus | ❌ | ❌ | ❌ | 0/3 |

三轮样本合起来命中的题共 4 道（01/03/04/07），从未命中 6 道。
**同题在不同样本上命中不同（03、04）是「真推理而非模式匹配」的一个侧面证据**：
若模型记住了答案，不会时对时错。

## 四、失败模式（**推断**，未做机验）

命中集中在「无大整数运算」的题（XOR 枚举、约束求解、LCG 单步迭代），
失败集中在需要「精确大整数 / 批量运算」的题（RSA 立方根与共模、种子爆破 1e6 次、
离散对数 1e6 次、Base32/Base64 逐字符解码、43 字节 hex 异或）。

**这是推断，不是结论**：`raw_head` 只存 300 字符，没有完整推理全文，
无法区分「理解正确但算错」与「方法就错了」。要证实需要落全程 output。

已知含义（可直接用于产品判断）：`pure_llm` 路径下的分数**下限由算术规模决定**，
而不是由解题思路决定。若目标是测「思路」，题目必须低算术；若要测「端到端解题」，
必须走 agentic 路径给工具——那是另一条待证明的链路。

## 五、作用域声明（引用前必读）

1. **自造题**：只证明「链路可解 + 系统能解出结构完整的题」。**不能外推**为对
   未见过公开赛题的泛化能力，也不构成难度校准（难度是出题方设定的，非赛题分布抽样）。
2. **n=10**：样本量极小，一条题的翻转就是 10 个百分点。
3. **单模型单 provider**：stepfun `step-3.5-flash` 一个通道，无跨模型对照。
4. **`pure_llm` 无工具**：本读数**不**适用于 agentic 路径；那条路径的子进程隔离
   证据仍未闭环（第 13 轮撤回的跨层假绿）。
5. 三轮命中率 3/10、2/10、3/10，均值 2.67/10。**引用时应给三轮全貌**，
   不能只挑 run_c 的 0.3。

## 六、复现命令（服务器）

```bash
cd ~/sam
STEP_API_KEY=<key> STEP_BASE_URL=https://api.stepfun.com/v1 \
python3 scripts/run_capability_eval.py --run --mode pure_llm \
  --pool data/ctf_benchmark/private_benchmark_v1.json \
  --manifest data/ctf_benchmark/private_benchmark_v1.manifest.json \
  --prior-audit docs/evidence/private_pool_v1_20261107/pool_prior_audit.json \
  --result /tmp/r.result.json --out /tmp/r.verdict.json \
  -- python3 scripts/ctf_stepfun_orchestrator.py \
     --benchmark data/ctf_benchmark/private_benchmark_v1.json \
     --provider stepfun --concurrency 1 --timeout 150 --out /tmp/r.result.json
```

前置会逐项检查：池指纹 vs manifest、明文门禁覆盖且零违规、本批次零自曝、
命令池与 `--pool` 同指纹、temperature 代码级固定、未启用 agentic/artifact、
题池已入 git 历史。任一项 FAIL ⇒ 拒绝跑批（fail-closed）。
跑批后 `verify_run_result()` 再做三件事：rc=0 + 结果文件被本次重写 + 结果题 id
全在本批次池内；任一不成立即拒绝判分。

## 七、这一轮到底改变了什么

此前 14 轮的状态是：**零私有题 ⇒ 零能力证据 ⇒ 任何 0 分都不携带信息**。
现在这一格被填上了：

- 有 10 道题面可机验可解（`gen_private_pool_v1.py --verify` 10/10）、
  私有性有外部锚点（R0–R6）、材料零附件依赖的题；
- 有一份 `claimable=true`、`blocking_reasons=[]`、`NOT_ATTRIBUTABLE=0` 的跑批；
- 读数是 3/10，且给了三轮全貌，不是一声「0」。

这不代表能力很强。它代表**从今天起「解出多少」是一个可以被追问的数字**，
而不再是一个「无法测量」。

## 八、代码版本声明（必读，别让这一条变成隐患）

三轮跑批所用的 `scripts/ctf_stepfun_orchestrator.py` 是**工作树版本**，含一处
他人未提交的在途改动（`git status` 显示 `M`，7 行增 / 5 行删）。差异**仅在
`PROVIDERS["stepfun"]` 配置**：

| 项 | 已提交版本 | 跑批所用工作树版本 |
|---|---|---|
| `api_base` | `https://api.stepfun.com/step_plan/v1` | `https://api.stepfun.com/v1` |
| `key_env` | `STEPFUN_API_KEY` | `STEP_API_KEY` |
| `default_model` | `step-3.7-flash` | `step-3.5-flash` |

**`verify_flag()` 与判分相关代码零改动**（`git diff scripts/ctf_stepfun_orchestrator.py` 可复核）。
因此：

- 判分口径与本仓库提交版本一致，读数不受影响；
- 但「跑批实际用的代码」不等于 `4a6670b` 的代码。第三方要逐位复现，必须先取该 WIP
  （或等它入库），否则端点 / 模型名对不上，跑不出同一批请求。

未提交该 WIP 是刻意的：它属他人负责中的改动（记忆里连续三轮都记录了「未碰
`ctf_stepfun_orchestrator.py`」），本轮不越权代为提交。

---

# 九、agentic 对照（2026-11-07 追加）：3/10 是「算不动」，不是「想不出来」

## 9.1 这一节回答什么

第一节的 pure_llm 读数 3/10 有一个当时无法回答的问题：**失败的 7 道，是模型想不出思路，还是想得出但算不动？**

pure_llm 路径模型没有代码执行出口，所有算术必须在「心算」里完成。这恰好让
「思路」与「算术」两个变量绑死，无法分离。给工具、同池、同模型再跑一次，两个变量就分开了。

**结论先说**：pure_llm 的 3/10 由**算术规模**决定，不是由**解题思路**决定。
给工具后同一模型 10/10，且更快。

## 9.2 先把隔离做实（否则这个 10/10 一文不值）

第 13 轮撤回的跨层假绿：Go 探测二进制上的 seccomp 有效，被当成 agentic 跑批已隔离；
实际解题走 `subprocess.run([python,'-I','-c',code])`，是另一层，实测仍可出网。
`agentic_run_binding()` 因此要求第二条件——**本次跑批解题子进程内**的 IP 直连 A/B。

本次做法（不动任何他人 WIP 代码）：

| 层 | 手段 |
|---|---|
| 执行身份 | 专用系统 UID `ctfsbx(995)`；`run_python_tool` 的子进程继承该 UID |
| 网络 | `iptables -m owner --uid-owner 995 -j CTFSBX`；链内只放行 `127.0.0.0/8` 与 `api.stepfun.com:443`，其余 `REJECT --reject-with icmp-port-unreachable` |
| 证据 | `scripts/gen_agentic_isolation_proof.py` 用**与解题子进程相同的启动形态** `[python,'-I','-c',code]` 起子进程实测，失败即 RC=1 不产出证据 |
| 绑定 | proof 里写 `run_binding.command_sha256`，与本次跑批命令指纹逐字绑定 |

### A/B（同一台机、同一时刻、同一载荷、同一代码路径，只差 UID）

载荷复刻第 13 轮那个绕过：`importlib.import_module('so'+'cket')` + `getattr(m,'so'+'cket')`，
全代码不含 `socket` 连续字面量，因此 `_audit_code` 正则放行。走的是 agentic 唯一工具出口
`run_python_tool()`。

| 组 | UID | 直连 172.16.222.99:22 | 走 `run_python_tool`（同一载荷） |
|---|---|---|---|
| A 对照 | 1000 user | CONNECTED | **TOOL_CONNECTED**（第 13 轮假绿原样复现） |
| B 实验 | 995 ctfsbx | **BLOCKED errno=111** | **TOOL_BLOCKED errno=111** |

补充：`direct_public` 1.1.1.1:443 在 B 组同样 `BLOCKED errno=111`（改前该目的只能拿到
TimeoutError，不可判定）；AF_UNIX 收发正常（隔离没有过度到破坏工具链）。

### 本轮踩到并修掉的一个真盲点（值得记住）

第一版规则写 `-A CTFSBX -o lo -j ACCEPT`，实验组**仍然 CONNECTED**。
原因：Linux local route 让「连本机网卡 IP」也走 `lo`，按出口接口放行等于把直连本机放过去了。
改成 `-o lo -d 127.0.0.0/8` 后才成立。**隔离判据必须看 daddr，不能看 oiflag。**

## 9.3 五轮逐题对照（`Y`=判为解出，`.`=未解出）

| 题 ID | pure_a | pure_b | pure_c | ag_a | ag_b | 工具调用(a/b) |
|---|:--:|:--:|:--:|:--:|:--:|:--:|
| pp_v1_01_xor_single_byte | Y | Y | Y | Y | Y | 2/1 |
| pp_v1_02_rsa_low_exponent_cube | . | . | . | Y | Y | 2/2 |
| pp_v1_03_vigenere_known_key | Y | . | . | Y | Y | 2/1 |
| pp_v1_04_lcg_predict_next | . | . | Y | Y | Y | 1/1 |
| pp_v1_05_weak_seed_prng | . | . | . | Y | Y | 1/1 |
| pp_v1_06_encoding_nest | . | . | . | Y | Y | 3/4 |
| pp_v1_07_licence_constraints | Y | Y | Y | Y | Y | 1/1 |
| pp_v1_08_discrete_log_small | . | . | . | Y | Y | 1/2 |
| pp_v1_09_ctr_nonce_reuse | . | . | . | Y | Y | 1/1 |
| pp_v1_10_rsa_common_modulus | . | . | . | Y | Y | 1/1 |
| **合计** | **3** | **2** | **3** | **10** | **10** | 15/15 |
| 总延迟 | 220.7s | 232.6s | 231.6s | **69.0s** | **55.2s** | — |

## 9.4 三个可以直接读出的事实

1. **pure_llm 能稳定解出的只有 2 道**（01 单字节 XOR、07 八位约束求解），都是小整数算术。
   03 Vigenère、04 LCG 是碰运气（各 1/3），其余 6 道三轮全灭。
2. **agentic 两轮 10/10，且 02/05/06/08/09/10 是 pure_llm 三轮里一次都没解出过的题。**
   这 6 道共同点：需要大数模幂、立方根、离散对数枚举、多层解码——**思路不难，手算做不到**。
3. **agentic 比 pure_llm 快 3–4 倍**（55–69s vs 220–233s）。
   「给工具会更慢」这个常见担心在本池上被否证：省掉的是反复心算与自我纠错的 token 与轮次。

命中不是抄的，抽查两例（`agentic_run_a.result.json` 的模型输出）：

- `02`：`m = round(c ** (1/3))` → 打印 `m^3 == c: True` → `hex(m) = 6ef678253bf6b5c3a912`。用二分/浮点立方根求 m，再回代验证。
- `10`：扩展欧几里得求 `6*3 + (-1)*17 = 1` → `m = c1^6 * c2_inv mod n` → 验证 `m^3 mod n = c1` 且 `m^17 mod n = c2`。

15 次工具调用的 `allowed` 全为 true、`blocked` 全为 0，代码均为纯计算（XOR 求密钥字节、
`pow`/欧几里得/解码链），**没有一次尝试读文件或访问答案路径**。

## 9.5 判分口径（与 pure_llm 完全同一套，未放宽）

`agentic_run_a.verdict.json` / `agentic_run_b.verdict.json`：

```
claimable=true   capability_rate=1.0   claimable_denominator=10
effective_runs=10  attributable_runs=10  excluded_not_attributable=0
verdicts={LLM_SOLVED:10, CLEAN_FAIL:0, NOT_ATTRIBUTABLE:0}   blocking_reasons=[]
scoring_variant_gap.false_negative_count=0
attachment_dependency.attachment_dependent_count=0
claim_scope=capability_rate_candidate (private_proof_anchored=True, private_proven=10/10)
evidence.airgap_zero_egress_proven=true
evidence.airgap_scope_binding={proven:true, reason:"机制证据 + 本次跑批子进程隔离绑定均成立"}
```

另做了一次**与本仓判分函数无关的独立复算**：对 `got` 分别按原样、去 `flag{}` 壳两种形态
算 sha256 与池内 `flag_sha256` 比对，两轮共 20 个命中**全部一致**，无「判分称解出但复算不中」。

题面泄漏面也逐条查了：池文件出现 9 处 `flag{...}`，**全部是格式说明占位**
（如 ``flag{` + the lowercase hexadecimal representation of m + `}`），
按三种形态算 sha256 与真值比对，命中真答案 **0 条**。

## 9.6 作用域与局限（引用前必读）

- **n=10，单模型（step-3.5-flash），单 provider。** 两轮 agentic 样本，不是三轮；pure_llm 是三轮。
- 自造题不可外推为公开赛题泛化能力（同第一节第 5 条）。
- **agentic 10/10 不等于「系统能解 100% 的题」**，它证明的是：这批题在「思路可及 + 算术可用工具」
  两个条件同时满足时能全解；题池难度由出题方设定，不是赛题分布抽样。
- **隔离只对同 UID 成立**：跑批必须由 `ctfsbx` 执行，换 UID 规则不覆盖、证据失效须重生成。
- **`supports_tools` 是本题新增的一处配置显式打开**：WIP 的 `PROVIDERS["stepfun"]["supports_tools"]=False`
  是配置层一刀切，模型本身支持 function calling（一次带 tools 的请求实测返回
  `finish_reason=tool_calls, name=run_python, args={"code":"123 * 456"}`）。
  为不改他人 WIP，打开动作放在独立入口 `scripts/run_agentic_stepfun.py`，只改这一个布尔，
  其余全部透传，并在 stderr 落一行 `patched` 自证。**它不提供隔离**——隔离由外部 UID+iptables 保证，
  两者缺一不可。
- iptables 规则只匹配 `--uid-owner 995`，不触碰 `user`/sshd；装规则时挂 900s 自动拆除。

## 9.7 这一节到底改变了什么

上一节（第七节）写的是「从今天起『解出多少』是一个可以被追问的数字」。
本节把它推进一格：**追问「为什么只解出那么多」也有答案了。**

答案不是「模型不会这些密码学攻击」——三种 RPA/LCG/Vigenère 攻击它都写对了代码；
答案是**没有代码执行出口时，模型被自己的心算精度卡住**。这个结论直接影响工程决策：
agentic 才是该走的主路径，pure_llm 的低分不该被当成能力上限写进任何材料。
