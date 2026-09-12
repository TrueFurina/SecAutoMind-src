# 凭据泄露事故与门禁加固记录（2026-09-13）

> 本文记录一次**真实发生的交付安全事故**及其闭环，写作原则：不美化、不隐瞒、不删证据。
> 所有数字与结论均来自本机实测，命令与退出码随文给出。
> （承接 `evidence-championship-20260908.md` §P0-3「密钥门禁存在正则漏洞」与 `-20260909.md` §8）

---

## 1. 事故摘要

**一句话**：本项目真 key 的明文片段被打码后写进了 `docs/` 与门禁自测文件；其中 **2 份文档随交付包外发**、
**3 个提交已推送到公开仓库**，而密钥门禁全程报 `CLEAN`。

| 维度 | 事实 |
|---|---|
| 发现方式 | 交付包红线复验时，对全包做 `sk-` 形态扫描发现 |
| 受影响凭证 | 千问（DashScope）`sk-ws-` 通道 key；飞书 `app_secret` |
| 是否已外发 | **是** —— 交付包 `dist/SecAutoMind-v1.7.25-share.tar.gz`（09-12 版） |
| 是否已入库/推远端 | **是** —— 3 个提交均在 `main` 且为 HEAD 祖先 |
| 门禁当时结论 | `PASS`（**失效**） |

---

## 2. 泄露点清单与程度（脱敏后）

判定方法：取 `config.yaml` 中真值，与文件内串做**最长公共前缀**比对。

| # | 文件 | 行 | 与真值一致的前缀 | 是否入包 | 是否入库 |
|---|---|---|---|---|---|
| 1 | `scripts/secret_guard_test.py` | L33 | **56 字符**（千问 key） | ✅ | ✅ |
| 2 | `scripts/secret_guard_test.py` | L37 | **完整 32 字符**（飞书 app_secret） | ✅ | ✅ |
| 3 | `docs/质检报告_20260908_多透镜锐评.md` | L69 | **29 字符**（千问 key） | ✅ | ✅ |
| 4 | `docs/质检报告_20260908_多透镜锐评.md` | L70 | 8 字符（app_secret） | ✅ | ✅ |
| 5 | `docs/zh-CN/competition-2026/变动说明.md` | L505 | 15 字符（千问 key） | ✅ | ✅ |
| 6 | `docs/zh-CN/competition-2026/变动说明.md` | L502 / L504 | 8 字符 | ✅ | ✅ |
| 7 | `scripts/secret_guard.py`（docstring 举例） | L168 | 29 字符 | ✅ | ✅ |

> 第 7 条尤其讽刺：**门禁把自己的泄露样本当"示例"写进了自己的注释**。
> 第 1、2 条最严重：门禁自测文件里塞了两枚**真凭证**，理由是"反正是公开测试向量"。

---

## 3. 根因（两层，缺一不可）

### 3.1 判定层：`...` 被当作无条件「占位特征」

`secret_guard.py` 的占位符正则含 `\.\.\.`：

```python
PLACEHOLDER = re.compile(r"xxxx|XXXX|\bxxx\b|\.\.\.|\$\{|...")   # ← 问题所在
```

于是 `sk-ws-<真前缀>...` 这种**人工打码后的串**被判为"安全占位符"直接放行。
但打码串恰恰是「真 key 曾被写进文件」的**证据**，正确行为是报警而非豁免。

### 3.2 豁免层：`SELF_EXEMPT` 整体豁免了整个自测文件

```python
SELF_EXEMPT = {"scripts/secret_guard_test.py"}   # ← 被豁免的文件没人再看
```

豁免让两枚真凭证在门禁眼皮底下躺了 5 天。

### 3.3 制度层：门禁自测没进 CI

`ci.yml` 的 `secret-gate` 只跑 `secret_guard.py`，**没跑 `secret_guard_test.py`**。
违反 AGENTS.md 第四条「门禁自身必须有回归测试；没接 CI 的门禁等于没锁」。

---

## 4. 修复（三层加固 + 现场清理）

### 4.1 现场清理：8 处脱敏

全部替换为 `<redacted>` 或构造假值，**保留"此处曾泄露"的事实记录**（教育价值不删）。
落盘复核：全工作树残留真 key 指纹 **0**。

### 4.2 门禁本体加固

| 改动 | 说明 |
|---|---|
| `is_placeholder` 重写 | 省略号**不再**无条件豁免；核心形似凭证且 ≥12 字符 → 判为真实 |
| `SELF_EXEMPT` 语义变更 | 仍可标记豁免，但**不阻断**指纹反查 |
| **新增真 key 指纹反查** | 从 `config.yaml` / 环境变量读取本项目在用的真值，取前 12 字符当指纹；命中即 `BLOCK`，**不受任何豁免影响**。与正则形态无关 —— 带省略号、Base64、换行拆分都逃不掉 |
| 飞书规则阈值 `{24,}` → `{8,}` | 原阈值让"8 字符 + 省略号"的真打码片段逃逸；纯数字由 `is_placeholder` 兜住不误报 |

### 4.3 CI 接线（补制度缺口）

`secret-gate` job 现在跑三步：

```yaml
- run: python scripts/secret_guard.py                    # 门禁本体
- run: python scripts/secret_guard_test.py               # 门禁自测
- run: python scripts/secret_guard_mutation_check.py     # 变异验证（证明自测真能杀死退化）
```

新增 `scripts/secret_guard_mutation_check.py`：基线绿 → 注入旧行为 → 必须变红 → `finally` 恢复 → 复绿。

---

## 5. 验证证据（实测，含退出码）

### 5.1 门禁命中范围收敛

| 阶段 | `verdict` | `real` | 说明 |
|---|---|---|---|
| 修复前（本机实测） | — | 命中被 `...` 豁免，**报 PASS** | 失效 |
| 加固后、脱敏前 | `BLOCK` | **20**（其中指纹命中 **7**） | 精确覆盖全部 7 处泄露 |
| 加固后、脱敏后 | `BLOCK` | **5**（全在 `config.yaml`，指纹命中 2） | ✅ 仅剩工作树真 key（预期） |

> `config.yaml` 本就是真值所在（`.gitignore` 排除、不进包），报 `BLOCK` 是**正确行为**。

### 5.2 门禁自测

```
[PASS] 密钥门禁健康：9 类真实凭证全部可检出，9 类占位符全部正确豁免。   (RC=0)
```

新增 2 条 MUST_CATCH 用例，专门锁死本次两个盲区：
- 打码截断的凭证片段（省略号不得再豁免）
- `app_secret` 短打码片段（8 字符 + 省略号）

### 5.3 变异验证（证明测试**有效**，非仅"全绿"）

```
[1/4] 基线：RC=0 PASS
[2/4] 注入变异（省略号 -> 无条件豁免）：RC=1 FAIL(✅ 变异被捕获)
[3/4] 恢复原文件（finally 保证）
[4/4] 恢复后：RC=0 PASS
[PASS] 变异验证有效                                            (RC=0)
```

### 5.4 交付包复验

重打后对包内做独立扫描：禁区目录（`data/conversations`、`logs/`、`.workbuddy`、`.git`、`.env`…）全 0；
`config.yaml` 由 `config.share.yaml` 顶替（真值命中 0）；包内 exe 指纹与磁盘一致。

---

## 6. 未闭环项（需人工决策）

### 🔴 6.1 必须轮换凭证

真 key 片段**已推送到公开仓库且无法撤回**（3 个提交为 HEAD 祖先）。按行业规范，
**任何程度的泄露都应视为已泄露**。建议：

1. 千问（DashScope）控制台：吊销当前 `sk-ws-` key，新建一把；
2. 飞书开放平台：重置应用 `app_secret`；
3. 新值只经环境变量注入（本项目 env 优先级高于 yaml），不再落 `config.yaml`；
4. 轮换后跑 `python scripts/secret_guard.py` 确认 PASS。

### ⚠️ 6.2 git 历史处理（可选，高风险）

若坚持清理历史（`git filter-repo` / BFG），须知：
- 已推送的仓库历史**无法真正撤回**（可能已被 fork/缓存）；
- 本仓有 `git stash` 导致对象库损毁的血案前科，**动 `.git` 前必须整目录备份**；
- 清理后所有协作者需重新克隆。

**建议**：优先轮换（6.1），历史清理视对"公开仓库体面度"的要求再定。

---

## 7. 教训沉淀

1. **打码 ≠ 脱敏**。打码串（带 `...`）是泄露的**证据**，必须报警，绝不能被判为"安全"。
2. **豁免会腐化**。被 `SELF_EXEMPT` 豁免的文件没人再看 —— 豁免范围要尽可能小，且必须叠加强制校验（指纹反查）。
3. **"测试全绿"≠"测试有效"**。必须做变异验证：主动改回错误行为，确认测试会红。
4. **最强防线是"反查真值"**，不是"匹配形态"。正则永远有下一个洞；直接比对"是否含正在用的凭证片段"没有形态假设。
5. **门禁要进 CI，且门禁自己也要有 CI**。这是本项目**第二次**栽在同一件事上。

---

## 8. 后续加固：凭据改为纯环境变量注入（2026-09-13 同日）

§6.1 第 3 条「新值只经环境变量注入，不再落 `config.yaml`」已执行。**判据不是"看起来像"，
而是逐字节比对 + 持久化层级 + 加载链 + 端到端探针。**

### 8.1 env 现状核查（逐字节，非长度/前缀）

| 凭据 | 位置 | 环境变量 | 持久化层级 | 比对 |
|---|---|---|---|---|
| 千问 key（116 字符） | `config.yaml:137` | `DASHSCOPE_API_KEY` | User 级 | ✅ `sha256_16` 一致 |
| 飞书 `app_secret`（32 字符） | `config.yaml:614` | `FEISHU_APP_SECRET` | User + Machine 级 | ✅ `sha256_16` 一致 |

两把 key **本就在环境变量中且已持久化**，因此按「在就清理」处置。

### 8.2 清理动作

- `config.yaml:137` `api_key: sk-ws-…` → `api_key: ${DASHSCOPE_API_KEY}`（对齐 `config.share.yaml` 既有口径）
- `config.yaml:614` `app_secret: …` → `app_secret: ${FEISHU_APP_SECRET}`
- 仅替换「值」，保留缩进与注释；改前备份、**验证通过后回收备份**（含明文的 `.bak` 本身就是新的泄露面）。

### 8.3 验证结论（全部实测）

| 验证项 | 方法 | 结果 |
|---|---|---|
| 门禁转 PASS | `scripts/secret_guard.py` | **RC=1(BLOCK, real=5) → RC=0，真实凭证命中 0** |
| 门禁自测 | `scripts/secret_guard_test.py` | RC=0（9 检出 + 10 豁免） |
| 反向扫描 | 45 个敏感 env × 1470 个文本文件前缀搜索 | 无真 key 落盘（唯一命中 `TOKENROUTER_BASE_URL`，是 URL 非密钥） |
| 持久化 | `[Environment]::GetEnvironmentVariable(n,'User'/'Machine')` | config 引用的 8 个 `${VAR}` 全部 User 级持久化 |
| 加载链 | `grep` 调用点 | `config.go:1457 ExpandSecretEnv` → `1459 ResolveRobotSecretsFromEnv` → `ResolveAllAPIKeysFromEnv`（`envsecrets.go:301-318`） |
| 端到端 | 临时 Go 探针真实 `Load(config.yaml)`（跑完即删） | 8 通道全部解析成功，`qwen-max` key len=116、`lark.app_secret` len=32，**无 `${` 字面串残留** |
| config 包测试 | `go test ./internal/config/` | RC=0 |
| 交付包 | 包内 `config.yaml`（= share 版）本就走 env | 无需重打 |

### 8.4 边界声明（诚实项）

- 本次仅**消除工作树内的明文**。§6.1 的**轮换仍然必要** —— 两把 key 已推公开仓库，
  清理文件不等于失效凭证。
- 反向扫描的候选是「名字含 `KEY/SECRET/TOKEN/PASSWORD/CREDENTIAL` 的环境变量」；
  若某凭证从未被注入本机 env，此法覆盖不到该凭证（但也不存在"本机在用却不在 env"的落盘场景）。

