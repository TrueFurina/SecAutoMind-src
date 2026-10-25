# scripts/ctf_sage — CTF 密码攻击模板库（求解器层）

> 定位：**求解器，不是提示器**。LLM/Agent 只负责从题面提取参数并填 JSON；
> 本库负责格构造、LLL、求根、解密，并对「前提不满足」诚实拒绝。
> 设计纪律与实证依据：`docs/zh-CN/competition-2026/求解能力深化计划_20261023.md`
> （结论：Go + 治理化调用数学求解器；模型提议、求解器处置、失败反馈进下一轮）。

## IO 契约（所有模板一致，见 common.py）

- 输入：JSON（stdin 或 `--params <file>`），字段见各模板 docstring。
- 输出：JSON（stdout）：
  `{"status": "solved" | "not_applicable" | "error", "flags": [...], "detail": "...", "engine": "..."}`
- `solved` = 攻击成功，`flags` 非空（调用方仍须自行校验 flag 真伪）；
  `not_applicable` = 攻击前提不满足并附原因（**AICrypto 实证头号失败模式是
  「套模式不检查前提」**——宁可拒绝，不许瞎跑产出垃圾）；
  `error` = 输入非法/内部错误。
- 禁网；纯 Python3 自包含（Fraction 精确算术 LLL），sympy 仅 t4/t5 用到；
  Sage 仅作可选加速（t1 有 `sage -c` 软探测路径，无 sage 自动回落纯 Python）。

## 模板清单

| 模板 | 攻击 | 构造权威来源 | 自测 | 已验证边界（2026-10-24 实测） |
|---|---|---|---|---|
| `t1_coppersmith.py` | Coppersmith 小根（单变量，mod N 或 mod N 的大因子） | 与 SageMath `small_roots` 源码逐行同构（m/t/ε/X 公式同构） | 7/7 | Sage docstring 513-bit RSA 实例（e=3、已知高 456 位）在规范参数 dim-9 由纯 Python LLL 恢复 K（服务器 82.9s，目标低于 det^(1/9) 23bit）；通用三次 ≤160bit；β=0.5；X>2^24 走 candidates 精确验证 |
| `t2_ecdsa_hnp.py` | ECDSA nonce 复用（精确代数）+ 偏差 nonce（HNP 格） | Kannan 嵌入（本库自推导 + 实证） | 4/4 + 8/9 参数回归 | 素数 n 下 8/9；唯一失败例 margin≤0 属数学不可行、门禁正确拒绝 |
| `t3_truncated_lfsr.py` | LFSR taps 恢复（full）+ 已知 taps 解状态（truncated） | GF(2) 线性代数 | 6/6 | 与 width 匹配的样本量即精确求解 |
| `t4_boneh_durfee.py` | Boneh-Durfee 小私钥指数（d < N^δ, δ≤0.292） | Herrmann–May PKC 2010 §3（unravelled linearization，论文原文 + mimoo 实现交叉对齐） | 6/6 | 128/192-bit、δ=0.24/0.25、m=3 恢复 d 并解密；δ 越界/小 e/d 不小/偶数 n 均正确拒绝 |
| `t5_dlp_bsgs_ph.py` | 离散对数：Pohlig-Hellman（光滑阶）+ BSGS（素数阶子群） | 标准算法 | 19/19 | 光滑阶直接解；非光滑阶 BSGS 在子群规模可负担时解；重复素因子（e≥2 数位剥离）与 order=3 小阶 BSGS 覆盖——2026-10-25 服务器冒烟抓出并修复两个真 bug（见「已知坑」） |
| `t6_hastad_broadcast.py` | Håstad 广播攻击（同 m 同 e、k≥e 个互质模数） | CRT + e 次整数根 | 4/4 | k≥e 且 m^e < N 时精确恢复；互质性/样本数前提不满足即拒绝 |

## 运行方式

```bash
# 单模板自测（合成参数造题 → 解题 → 断言；每个都应 <1min）
python t1_coppersmith.py --selftest

# 全库聚合自测（逐个跑 --selftest，落盘判 RC，防管道吞退出码）
python selftest_all.py                 # 本机 python
python selftest_all.py --python /path/to/python3   # 指定解释器（如服务器 venv）

# 能力边界验证（非自测：服务器专用约 2.5 分钟，本机约 9 分钟）
# 复现 Sage docstring 513-bit RSA 实例的 dim-9 恢复——README 核心声明的证据脚本
python validate_docstring_instance.py

# 求解（JSON 进，JSON 出）
echo '{"modulus": 10001, "poly": [-222, 5000, 10, 1]}' | python t1_coppersmith.py
python t4_boneh_durfee.py --params in.json
```

## 环境探测与 Agent 接入（P0-1，2026-10-25）

```bash
# 软探测：可选依赖 + 七模块可导入性，JSON 输出；退出码 0=就绪 / 1=有模板不可用 / 2=探测坏
python probe_env.py --pretty
```

- **降级链实测**：服务器（无 numpy/sage/gmpy2/flint/fpylll，有 sympy+pwntools）
  下 `probe_env.py` RC=0、7 模块全部可导入——纯 Python 自包含在降级环境成立。
- **L3 / Agent 接入**：`CTF-Agent_融合/ctf_agent/skills/ctf_sage_t{1..6}_*.py` 是
  六个薄适配层（零攻击逻辑，数学全在本库），经 runner 的 `execute_python` 工具调用：
  LLM 从题干提取数学参数走 `params` 字段（`internal/runnerl3` 的 RichSkillRunner
  可选接口；存量 flag 契约不受影响），适配层解析后调本库 solve 函数。
  治理提示（模板优先/禁网/flag 验证/前提检查）在 `internal/projectprompt/ctf_governance.go`。
- **注意**：适配层与实战引擎 `/e/Program/ctf-agent/skills/` 需保持一致（两处手工拷贝，
  无自动同步——新增/改动必须两边都放）。

## 能力边界（诚实声明，勿外推）

1. **纯 Python LLL 的规模墙**：dim≤~20 且条目 ~2^80 时秒级；dim-9/2171bit 需
   83s（服务器）～513s（本机，实测同格 6 倍差距——**重活一律上服务器**
   `user@172.16.222.99`，128 核/125G，见 AGENTS.md 第五条与项目记忆）。
   dim>20 交 sage/fpylll 路径，不假装能跑。
2. **t1 取根**：X ≤ 2^24 走 numpy 向量化扫描；更大 X 扫描不可行——
   调用方已知候选根时用 `candidates` 字段 O(1) 精确验证（判据
   `gcd(N, f(r)) ≥ N^beta` 本身不需要格）。
3. **t4 界**：Y 取 2√N+1 而非论文的 √N（根 y₀=−(p+q)/2 在 p≠q 时可达 ~1.4√N，
   用 √N 会破坏启发式——2026-10-23 实测踩过）；256-bit/m=3 已失败，需 m=4
   （纯 Python 数分钟）或 sage。
4. **LLL 实现可信度**：`common.lll_reduce` 为 Fraction 精确算术 + 增量 mu 更新，
   与 naive 版 60/60 逐字节一致；输出经 `is_lll_reduced` 断言规约条件、
   并在 2171-bit 条目上验证贴 Hermite 界（目标向量存在时低于 det^(1/9) 23bit）。
5. **环境差异与取根降级链**：本机有 numpy 无 sage/fpylll/gmpy2；服务器有 sympy/z3
   （2026-10-24 已按政策补装 numpy）。t1 取根按 `numpy 向量化(X≤2^24) → numpy
   浮点近似(X<2^50) → 纯 Python 暴力(X≤2^18) → candidates 精确验证 → sage`
   降级，任一环缺失不炸；`_roots_bruteforce` 保证无 numpy 环境（服务器）下
   自测与中小 X 场景仍可工作。

## 已知坑（都真踩过）

- **实验实例必须先验健全性**：2026-10-24 作废的全规模实验栽在构造
  `(x+M)^3−(C+M^3)`（M 含未知低位）——多项式根本不含目标根，「未恢复」
  不构成任何证据。正确构造 `f=(x+a)^e−C`（a=已知高位）落盘前必须断言
  `f(x₀) ≡ 0 mod N`。
- 🔴 **t5 两个真 bug（2026-10-25 服务器冒烟抓出，9/9 自测全漏——自测只证明
  覆盖到的路径）**：① PH 数位剥离的 BSGS 生成元必须用 `g^(order/q)`（阶 q），
  误用 `g^(order/pe)` 时 e=1 巧合相同故自测全过、e≥2 必挂；
  ② BSGS 巨步必须覆盖 `i ∈ [0, ceil(order/m)]`，`range(m+1)` 在
  `m(m+1) < order` 时漏解（最小反例 order=3：d=2 永远找不到）。
  修复后自测 19/19（重复素因子/多位剥离/order=3 小阶均已显式造例）。
  **教训：边界参数（小阶、重复素因子、e≥2）必须显式造回归例，不能只跑"典型"输入。**
- t4 的 y-shift 必须先在商环 `Z[u,x,y]/(xy+1−u)` 约化，否则引入单子集外项。
- t2 不能把 d 作格坐标（全尺寸，目标不再短）；t 不能并入基行（det 稀释）。
- sympy 的 `DomainMatrix.lll` 内部断言会崩（本格上），已弃用。
