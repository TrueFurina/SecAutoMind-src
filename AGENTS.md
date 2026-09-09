# AGENTS.md — 本仓库的 AI 协作宪章

> 任何在本仓库工作的 AI agent（含并行会话、子代理、未来新会话）**必须先读本文件**。
> 本文件的每一条都由本项目的**真实事故**倒逼写成，不是通用套话。违反任意一条 = 本次工作作废。

---

## 第一条 · 诚实高于一切（最高优先级）

**AI 在本仓库最常见的失败模式不是"做不出来"，而是"做出来了但报告是假的"。**

### 1.1 禁止幻觉，禁止伪造证据
- 没跑过的命令，**不许说跑过**。没打开的文件，**不许描述它的内容**。
- 没验证的结论，必须显式写「**未验证 / 未能确认**」。这不会扣分，伪造才会。
- 引用行号前必须真的 `Read` 过那段代码。**编造行号是最恶劣的行为**——它看起来最像证据。
- 子代理/并行会话的结论**一律视为待验证的线索**，主 agent 必须亲自复核后才能写进报告。

### 1.2 失败必须报失败
- 命令返回非 0，就说非 0。**不许把 FAIL 说成"基本通过"**。
- **严禁用过滤命令掩盖失败**（本项目真实事故）：`go test ./... | grep -v "^ok"` 这类管道在缓冲/截断下会吞掉 FAIL 行，导致"看起来全绿"。
  正确做法：**把完整输出落盘再统计**，例如 `go test ./... > out.txt 2>&1; grep -c '^ok' out.txt; grep '^FAIL' out.txt`。
- 部分完成就说部分完成，不许用"收官/完成/全部搞定"概括未完成的工作。

### 1.3 区分「代码 bug」与「环境故障」（本项目 2026-09-09 实证）
- 环境故障（磁盘满、网络断、代理失效、工具链缺组件）导致的失败，**必须归因到环境**，不许算成代码缺陷。
- 反之，**不许拿环境当借口掩盖真 bug**。二者都不能偷懒：先排除环境干扰，再谈代码。
- 实证：C 盘仅剩 93M 时全库测试报 10 FAIL；把 `TMP/TEMP` 指到 D 盘后需重测才能定性。

### 1.4 度量工具本身也会骗人
- **引用任何工具给的数字之前，先验证一次**。实证：`gofmt -l` 报 281 个文件未格式化，
  `gofmt -w` 后 git 只记录 **52** 个有实质变化——其余 229 个是 CRLF/LF 行尾误报（Git Bash + autocrlf）。虚高 5 倍。
- 同理适用于 wc -l、cloc、测试计数等一切"看起来很客观"的数字。

### 1.5 不许注水，也不许为挑刺而挑刺
- 报告可以短，**不可以假**。凑数的"问题"和隐瞒的问题一样有害。
- 做得干净的部分要明确承认（例如"TODO/FIXME 真命中 0"），避免为了显得有产出而硬挑。

---

## 第二条 · 数字单一真值源

**所有对外的代码规模 / 能力数字，只能来自脚本实跑，禁止手写、禁止凭记忆、禁止"大概是"。**

```bash
python scripts/count_stats.py --json     # 唯一权威口径
python scripts/verify_evidence.py        # 证据/口径门禁
```

- 已作废旧口径（出现在材料里即为违规）：`662/242/123,149/153,987`、`677/250/125,954/158,247/166`、`151 求解器`、`140 工具`、`613 文件`。
- **140 是"三不管数字"的典型**：它既不等于 90（YAML 工具数）也不等于 142，凭空漂移却看起来像有依据。
  这类数字最危险。**宁可写"91 YAML + 52 内置 = 143 运行时"，也不要写一个没有分解式的整数。**
- 数字会实时过期：本项目出现过**三次**漂移全靠人肉发现。写死的数字在提交完成的下一秒就可能错。

---

## 第三条 · 改完必须验证（Edit 会假成功）

- 本项目已出现 **3 次** Edit 工具报成功但内容未落盘。**改完必须 `grep`/`Read` 复验。**
- Go 改完必须 `go build`；Python 改完必须实跑脚本并由退出码判定。
- 报告里写"已修复"之前，必须能给出**修复后的验证输出**。

---

## 第四条 · 门禁不是装饰品

- 写了一个门禁脚本，**必须把它接进 CI**。没接 CI 的门禁等于没锁（本项目实证：`secret_guard.py` 写好却没进 release 流程）。
- 门禁自身必须有回归测试。**失效的门禁比没有门禁更危险**——它会持续给出假的安全感。
  实证：旧打包前 grep 正则 `sk-[A-Za-z0-9]{16,}` 匹配不到 `sk-ws-H...`（第 4 位是连字符），
  一把真 key 从洞里漏过而门禁报 CLEAN。
- 现有门禁：`ci.yml` 三个 job（test / capability-gate / evidence-gate）+ `scripts/secret_guard.py` + `scripts/verify_evidence.py`。

---

## 第五条 · 本仓库已知环境坑（照抄即可，别再踩）

| 坑 | 正解 |
|---|---|
| `git push` 凭证 | `git -c credential.helper= -c credential.helper=manager push origin refs/heads/main:refs/heads/main` |
| `refs/tags/main` 歧义 | 必须写全 `refs/heads/main:refs/heads/main` |
| 远程跟踪引用被静默吞 | `.git/refs/remotes/**` 写入（**含 `git update-ref`**）在本环境 rc=0 但 ref 不变。判 ahead/behind 不可信本地引用，以 push 输出或 `git ls-remote` 为准。绕行：备份后整文件覆盖 `.git/packed-refs` |
| CGO 测试报 cgo.exe exit 2 | 先 `export PATH="/d/miniconda3_new/Library/mingw-w64/bin:$PATH"` |
| Go 工具链 | `.workbuddy/toolchain/go/bin/go.exe`；`GOPROXY=https://goproxy.cn,direct` |
| Python venv | `C:/Users/Lenovo/.workbuddy/binaries/python/envs/default/Scripts/python.exe` |
| C 盘空间告警 | `/tmp` 在 C 盘。空间紧张时 `export TMP=TEMP=TMPDIR=D:/tmp_gotest` 再跑测试 |
| `官网/` 被 `.gitignore:81` 排除 | 官网**从未进版本库**，改它只在磁盘/交付包生效，不随 git 分发 |

---

## 第六条 · 交付红线

- **打包前必跑** `python scripts/secret_guard.py`（exit 1 = 禁止打包）。它会扫**磁盘真实文件**，包括被 gitignore 却会进交付包的 `config.yaml`。
- 落盘必须内置打码；日志写 key 只用占位符。
- 用户原创项目**一律不要 LICENSE 文件**。

---

*本文件随事故更新。发现新的"AI 骗了自己"的案例，就补进第一条。*
