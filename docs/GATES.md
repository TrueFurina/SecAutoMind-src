# GATES · 门禁地图（自动派生，勿手改）

> **真源**：`.github/workflows/ci.yml`。本文件由 `scripts/gen_gates_map.py` 生成，
> 手改会在 `agent-docs-gate` 里被判红。改门禁 → 改 ci.yml 注释 → 重跑 `--write`。
>
> 每行的"守什么"取自该 job 上方的注释首句；**没有注释的 job 会显示为待补**——
> 那本身就是缺陷：一个说不出自己守什么的门禁，无法判断它是否失效。

共 **35** 个 job（其中 **30** 个带自测/变异验证）。

| job | 守什么 | 步骤数 | 变异/自测 |
|---|---|---|---|
| `test` | 主干测试门禁：go vet + `go test -race` 全量 + 构建，并前置 golden 冻结校验、 加密模板自测、HITL 边界检查 —— 它是唯一跑真实 Go 测试套件的 job， 其余 job 只跑各自… | 16 | 有 |
| `staticcheck-gate` | Go 全系静态检查门禁（2026-10-21 新增，通道见 E:\Program\实验服务器与全局配置.md §九） | 7 | 有 |
| `capability-gate` | 能力回归门禁：不依赖外部数据文件/在线靶场，纯 Go 内存级验证 | 2 | **无** |
| `evidence-gate` | 证据 / 口径一致性门禁：双语言机验证据包 + 单一真值源健康度 | 8 | 有 |
| `freeze-gate` | 决赛冻结纪律闸门（规划总纲 §4.3）：决赛前 14 天起拒绝"架构改动"的 PR | 5 | 有 |
| `binary-gate` | 交付二进制来源门禁（2026-10-18）：发出去的 exe 必须由当前 HEAD 构建 | 3 | 有 |
| `finals-rehearsal` | 决赛整链路演练（规划总纲 §2.1 的 e2e 要求，去掉"必须用官方平台"那部分） | 7 | 有 |
| `cross-bench-subset` | A→B 同卷立尺 · 有数据子集（12/88 题附件仍在）：从 test job 拆出的独立门禁 | 2 | **无** |
| `secret-gate` | 密钥门禁：防止真实凭证被提交进仓库 | 8 | 有 |
| `supply-chain-gate` | 材料口径门禁：docs/ PPT/ 官网 里的关键数字必须与 count_stats.py 真值一致 | 2 | 有 |
| `truth-source-gate` | 历史教训：材料数字漂移出现过三次，全靠人肉发现（工具数 90→91、求解器数 169→170 等） | 4 | 有 |
| `quant-gate` | 验收第 8 条：对外量化陈述 100% 可指回 —— 真跑命令复现，而非口头声明 | 6 | 有 |
| `caliber-gate` | 材料口径总闸（17 步）：材料数字 / 文档事实 / 范围豁免准入 / 工具与配方契约 / 错误投影 / 产物数字 / PPT 产物路径，逐个与单一真值源比对 | 17 | 有 |
| `cross-bench-manifest-gate` | cross-bench 产物清单一致性门禁（2026-10-16 实锤三条漂移后新增） | 4 | 有 |
| `web-parity-gate` | 前端资源副本一致性门禁：根 web/ 与 internal/app/web/ 是**两份物理副本**， 而 go:embed（internal/app/app_webfs.go，路径相对包目录）嵌入的是后者 | 2 | 有 |
| `css-shadow-gate` | CSS 影子块门禁（2026-10-19 新增） | 2 | 有 |
| `web-js-tests` | 前端运行时测试：`internal/app/web/static/js/*.test.cjs` 曾长期是**孤儿测试**—— ci.yml 全文没有 node --test，全靠人手跑，于是两条断言在实现重构后**静默腐… | 1 | **无** |
| `line-endings-gate` | 行尾门禁：脚本行尾此前是「各机器 core.autocrlf 说了算」的盲区（本仓无 .gitattributes） | 2 | 有 |
| `doc-port-gate` | 文档端口一致性门禁：docs/ 里的 curl / 浏览器地址 / nginx `proxy_pass` / docker `-p` 都是**可执行指令**，读者会直接复制；而交付包开箱的 config.yaml 端口是… | 2 | 有 |
| `docs-lint-gate` | 文档静态门禁：代码块围栏闭合 / 本地链接可达 / scripts 引用存在 / 英文文档有中文对应 | 2 | 有 |
| `agent-docs-gate` | 文档结构门禁（十一防线 P-01/P-02/P-03/P-09/P-10 的机验部分） | 2 | 有 |
| `mcp-servers-gate` | MCP 服务清单与契约一致性门禁 | 3 | 有 |
| `external-payload-gate` | 守的是「声明齐全 ≠ 实物存在」：external_westlake 基准 80/80 题标着 payload_status=verified_on_disk，但附件是导出方仓库相对路径、本仓库 0 题可解析； 同目录… | 2 | 有 |
| `plaintext-answer-gate` | 自产基准反注水：题干里不得直接写出答案 | 2 | 有 |
| `benchmark-validity-gate` | 真题基准可解性基线：A 层 ≤4 题、C 层占比 ≤71.0%（实测 70.9%） | 2 | 有 |
| `flag-eval-gate` | flag 评测口径门禁（2026-10-28 建立） | 3 | 有 |
| `flag-extract-contract-gate` | flag 提取跨语言单一真值源契约（2026-10-30 建立） | 2 | **无** |
| `session-gate` | 并发会话登记表门禁（2026-10-28 建立） | 2 | 有 |
| `benchmark-parity-gate` | 双语言基准 parity 门禁（静态集 55 题）：把「Python judge.py 镜像 == Go 生产路径」 这句**写在对外汇总里的宣称**真正接上线 | 2 | 有 |
| `suite-parity-gate` | 跨集 parity 门禁（台账驱动）—— 把【2】～【22】的「Python == Go」宣称按台账逐集接线 | 4 | 有 |
| `external-bench` | 外部真题对照尺（external-bench）—— 关闭「自产集高分 = 解题能力」的最后一个辩解出口 | 3 | 有 |
| `skill-exec-gate` | 解题 skill 可执行性门禁（2026-10-25）——堵死「skill 写在目录里但从未被调用」 | 9 | 有 |
| `answer-leak-gate` | 题库答案泄漏门禁（2026-10-28） 背景：real 4 道 / benchmark 15 道题干直接内嵌正确 flag，喂 description 等于喂答案； 门禁本体早已写好（scripts/check_ben… | 2 | 有 |
| `artifact-inject-gate` | 附件注入守卫：工件白名单模式只放开「相对文件名的 open()」，越界读取(绝对路径/..穿越/答案路径/列目录)必须被拦 | 1 | **无** |
| `ctf-agent-pytest-gate` | CTF-Agent 全量 pytest 门禁（2026-10-31 接入） | 5 | 有 |

## 已知盲区（人工维护，不由 ci.yml 派生）

> 这一节是唯一手写部分：**门禁守不到的地方**。新增门禁时如发现盲区，写在这里；
> 盲区被补上后，把该条删掉（不留"已修复"历史，历史在 git 里）。

- `check_material_numbers.py` 的覆盖数为 0 时才 fail-closed；**部分覆盖下降不报警**（例如材料从 docs/ 顶层挪进子目录而扫描 glob 未跟进）。
- 工具数存在两套口径（`tools_yaml` 文件计数 91 / `tools_declared` 真实工具 90）。2026-10-24 起由 `count_stats.py` 的不变量硬拦（91 == 90 + 1），但**材料仍可只写 91**而不解释 +1 是谁——文字层无法机验。
- `docs/` 顶层文档数量**只受"不得增加"约束**（见 `check_agent_docs.py` C5），存量 43 份尚未归档；历史快照与当前权威混在同一层，靠 `docs/INDEX.md` 标注区分。
- 门禁地图只证明"每个 job 有注释"，**不证明该 job 真能变红**；只有标"有"的 job 才做了变异验证，标"无"的 12 个 job 是否有效属未验证。
- 供应链门禁只保证 SBOM 与依赖树一致 + go.sum 覆盖，**不做 CVE 扫描**（离线无本地库，任何"漏洞数=0"都是假的）；`requirements.txt` 仍是 `>=` 浮动范围、无 lockfile，装到什么版本取决于当天 PyPI —— 这一条只有 G-02 的一半。
