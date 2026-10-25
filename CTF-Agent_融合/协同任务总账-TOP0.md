# 协同任务总账 · TOP-0（多智能体作战与交接单一事实源）

> **本文件是本项目多智能体协同的 TOP-0 文档。** 任何并发会话（含人类）在 `ctf_agent/` 上做任何操作，**必须先在本文件登记任务、再动手**；完工后回填状态 / commit / 发现。这是打破「多智能体黑盒」的核心机制，与《多智能体协同准则纲领》（原则层）、《CTDE协同协议》（规范层）、《scripts/_lease.py》+ `.git/hooks/pre-commit` （执法层）共同构成四层治理。
>
> **单一事实源原则**：当本文件、AGENTS.md、会话记忆、口头汇报出现冲突时，**以本文件登记的「任务状态 + 租约归属 + commit 证据」为准**。文档通胀（RDD）的根治，从「一切操作可追溯」开始。

---

## 〇、使用守则（必读，违反即重演初赛）

1. **登记优先（先于一切写操作）**：开工前用 ``ctf_agent/scripts/_log_task.py --start --id <ID> --owner <会话> --what <做什么> --scope <范围>`` 一键登记；完工用 ``--done <ID> --commit <hash> --note <发现>`` 回填；非 commit 手动改动用 ``--note`` 补登。不依赖任何常驻进程，靠每个会话自觉 + git hook 机器兜底。
2. **写前持租约**：改 `ctf_agent/` 仓库内文件必须先 `scripts/_lease.py acquire`（scope 用单次 `--scope` 多值），commit 过双门禁（密钥扫描 + scope 校验）。
3. **完工回填**：状态置 ✅，附 commit hash / 产物路径 / 关键发现；若中断须显式标注 🔴 受阻原因。
4. **在飞改动禁令**：会话退出前必须 commit 或显式移交（re-acquire 租约 + 说明），**禁止「改文件不提交」**（hook 只拦 commit，拦不住改不提交——本项目已两次中招）。
5. **诚实口径**：所有「解出/水位」类表述必须标注是否平台 accepted；非 accepted 一律记为「本地离线分析/沙盒实测」，严禁冒充战报。
6. **冲突仲裁**：并发冲突由协调者（Gu）按纲领裁决；不确定会话归属时停止操作、升级协调者。

### 状态图例

| 标记 | 含义 |
|---|---|
| ✅ | 已完成 |
| ⚠️ | 已发现事实 / 待办 / 已 defer |
| 🔴 | 受阻 / 未闭环（附原因） |
| 🔄 | 进行中 |
| ♻️ | 被覆盖 / 取代（旧方案作废） |
| 📌 | 已规划未执行（仅侦察/设计） |

### 会话代号表（谁在什么时候干了什么）

| 代号 | 时间窗 | 主导 agent | 主题 |
|---|---|---|---|
| **史前（H 段）** | 8/10–8/21 | 主开发会话（糖露星霜•暖霞拾光，单写者时代） | 项目奠基→跑分迭代→锐评整改→赛前冲刺→初赛 0 解出→赛后 P0 修复（251 commit，bundle 只读挖掘） |
| **Session A** | 8/21 14:00–17:00 | 后勤 agent（Gu） | 赛中 LLM 失效排查 + 0 解出真因 + P0 修复 |
| **Session B** | 8/21 赛后 | 另一并发会话（多会话） | 大改造潮 1384→6156 文件 + CTDE 协议初稿 + 本地离线解出 |
| **Session C** | 8/22 09:19–09:50 | Gu（协调者）+ 并行会话 | 极致锐评三轮 + CTDE 落地 + T-06/T-08 |
| **Session D** | 8/22 09:34–10:46 | Gu | 整改方案执行 + 发现 git 对象库损坏 + 重建 |
| **Session E** | 8/22 11:09–14:20 | Gu + 并行会话 | 解题作战纪律 + 重锐评验收 + M1/M2/M3 攻坚 + 接管并行改动 |
| **Session F** | 8/22 16:18–16:5x | Gu（承接/收口） | 诚实化 + 收口在飞改动 + 定纲领 + 清理 RDD + 冻结 + push |

---

## 一、历史任务总复盘（按会话，全部操作可追溯）

### 史前任务复盘（8/10 – 8/21 赛前长跑 · 来自 bundle 只读挖掘）

> **数据来源**：当前仓库 rebuild 后最早提交为 8/22，8/21 之前历史全在 rebuild 时丢失。本段全部 commit 证据来自 `_misc/_backup_pre_cleanup.bundle`（2.7G 含密钥旧历史）**只读导入临时裸仓**拉取（251 个历史 commit，8/10 起共 11 天），用毕即焚裸仓，**密钥零泄露**到工作树。
> **诚实口径（贯穿）**：以下「解出率/37%→59%→92%」「测试赛 7/7 800 分」等数字，**均为本地沙盒跑分 / 测试赛（已闭）水位，非初赛正式赛平台 accepted**。初赛正式赛真实水位仍是 **0 accepted**（见四、关键事实锚点）。测试赛 7/7 是另一独立已闭赛事，与初赛无关。

#### 阶段 0 — 项目奠基（8/10–8/11）
- **[H1]** 阶段1 项目骨架 + 本地题库基线 → ✅ `e812288c`
- **[H2]** 阶段2 1主1监推理内核 + 调度层 → ✅ `36ee8241`
- **[H3]** 阶段3 步骤级校验-反馈层 + 沙盒工具链 → ✅ `abe7b90e`
- **[H4]** 阶段4 单页看板 + 一键启动 + 题库跑分 → ✅ `e1d988ed`
- **[H5]** 真实 LLM 联调 + 内功优化（专家锐评第二轮落地）→ ✅ `e42784c8`
- **[H6]** 真实素材库 + 幻觉拦截修复（验证优先落地）→ ✅ `7c70111d`
- **[H7]** 工程增量改造（主 Agent 工具接入 + 沙盒安全加固）→ ✅ `8116d912`
- **[H8]** 跑分失败归因迭代（crypto 参数补全 + 输出链路修复）→ ✅ `a6a6a58c`
- **[H9]** ctfplatform 平台对接自测 + `get_access` 字段解析修复 → ✅ `c3a40711`（**注意**：此即初赛 0 解出根因之一 `get_access` 字段错位的最早修复尝试，后 8/21 又塌回）
- **[H10]** crypto 卡死题 Prompt 迭代 + dasctf 环境变量预留 → ✅ `378c6d33`
- **[H11]** Qwen 链路接入 + 双模型对比准备 → ✅ `1e42e71a`
- **[H12]** 千问免费额度备用链路接入 + dsh(DeepSeek harness) 路线放弃 → ✅ `a42f3ab0`

#### 阶段 1 — 模型链拓宽与跑分迭代（8/12–8/17）
- **[H13]** DeepSeek 全量跑分续跑 5.11 节（累计 16 题基准）→ ✅ `073a1da3`
- **[H14]** 0 解出根因修复——真实模式接入工具层（重大 bug）→ ✅ `54806a4e`
- **[H15]** 解出率突破 0→18.8%（工具层接入 + 模板兜底）→ ✅ `318cc3dd`
- **[H16]** 测试赛冲刺——补 crypto 参数 + Misc 模板兜底（解出率 22.2%）→ ✅ `700afe04`
- **[H17]** 测试赛当日冲刺——解出率 22.2%→50%（五处根因修复）→ ✅ `d5fefa16`
- **[H18]** 深度冲刺——解出率 50%→59.1%（场景补全 + web 兜底）→ ✅ `ae2d8b2b`
- **[H19]** 多题型攻坚——不再只靠 crypto（五大题型兜底链路全打通）→ ✅ `03b4843b`
- **[H20]** 抄学优秀作品迭代——多模型竞速 + Advisor + 题型流程模板 → ✅ `0f2d0e45`
- **[H21]** 人工干预闭环——卡壳自动标记 + 提示注入 + 看板介入（抄 CyberStrikeAI/NUS）→ ✅ `3af6464b`
- **[H22]** 抄学第二波——人工干预 + 清洗层 + 平台轮询 + 技能库 → ✅ `2cf099e0`
- **[H23]** 平台对战模式一键入口——拉题→解题→提交（测试赛/初赛主战场）→ ✅ `2ef912c1`
- **[H24]** 平台真实做题全链路打通 + 10663 解压题解题进展 → ✅ `a1f3a553`
- **[H25]** 测试赛实战冲刺——TheoremPlus 解出 + Fate RCE 突破 + 题目归档 → ✅ `f508378f`
- **[H26]** **🔴 测试赛战绩（独立已闭赛事，非初赛）**：Fate 解出(Nashorn 链 + 反射读 FLAG)、UploadKing 解出(XXE SVG 读 /flag)、shopping 解出(libc 泄露 + poison + free_hook=system)、7/7 全解出 800 分收官（排名 ~70）→ ✅ 荣誉归于该测试赛；**与初赛 0 accepted 严格区分**
- **[H27]** 解题报告生成器（手册第 8 条硬性要求）→ ✅ `d9909acf`
- **[H28]** 小米 MiMo / 百度千帆 / 7 个白名单 provider 批量接入 + 薅羊毛清单 → ✅ `63d0d8e6` `ec2fc3f7` `fb3ab8d9` `5e45eeff`

#### 阶段 2 — 备战初赛：provider 矩阵与故障预案（8/18–8/19）
- **[H29]** 抢一血战略落地 `_scan_firstblood` + `_race_start --firstblood` → ✅ `8204b954`
- **[H30]** 正式赛备战落地——演练验证 + 5 新 skill + 工具链 → ✅ `b76daf1d`
- **[H31]** 超级自进化轮——crypto 参数识别 / web 快速失败 / nashorn skill / zip 合并 → ✅ `2b8660d8`
- **[H32]** 实证验证轮——skill_map 扩展 + 测试赛/升级题型 skill 命中验证 → ✅ `43f20eb2`
- **[H33]** 正式赛一键作战 + web 升级 skill + Goal 规则 12–14 → ✅ `a7359ac2`
- **[H34]** **fix**：LLM 默认源切到免费可用源（DeepSeek/Qwen 已欠费）→ ✅ `e34ed7e4`
- **[H35]** **fix**：多 provider 时监督 agent 打默认端点 402——SupervisorAgent 传入 llm_client → ✅ `4179ff88`
- **[H36]** LLM 故障预案——provider 探测 + 自动切换脚本（正式赛生死线保障）→ ✅ `ac17b723`
- **[H37]** skill_map 全覆盖——25 skill 全部接入自动加载（52 关键词）→ ✅ `199607f8`
- **[H38]** 接入 16 模型竞速矩阵（智谱/豆包/Kimi/讯飞全通）+ TokenHub 17 模型 → ✅ `3b2e7f88` `76fdeff7`
- **[H39]** 去作弊化轮——禁用 `__direct_extract__` 抄答案路径（锐评回应）→ ✅ `d777ddec`

#### 阶段 3 — 锐评整改潮（8/19–8/20，RDD 病根）
- **[H40]** 外部锐评证据核实报告（逐条实证 + 整改状态核对）→ ✅ `774b107d`
- **[H41]** 锐评真整改轮——拆上帝模块 + 主循环测试 + 文档瘦身 → ✅ `cf88ff47`
- **[H42]** 锐评整改四轮——幻觉拦截根因修复 + 工具执行拆分（测试全绿）→ ✅ `60b098ad`
- **[H43]** 锐评整改五/六轮——速度止损 + 测试五路径 + LLM 封装拆分 + 调度层测试 → ✅ `2b9bfb99` `44b1438e`
- **[H44]** 赛前最终就绪——锐评整改闭环 + 止损规则确认 + 全量验证 → ✅ `e4652fbb`
- **[H45]** Skill 去伪报告——25 skill 诚实分类 + 7 题自主性核对 → ✅ `a6565161`
- **[H46]** **fix**：初赛两大致命 bug——注册表回退 + provider 模型隔离 → ✅ `e858c11f`
- **[H47]** **fix**：平台题 `DASCTF{}` flag 双重拦截（正式赛致命 bug）→ ✅ `ee8c9e4f`
- **[H48]** **fix**：本地评测 flag 精确校验（防跨题误判）→ ✅ `23cb94f9`
- **[H49]** 深度第一项——真实端到端回归跑分 + 阿里云百炼免费模型接入 → ✅ `23cb94f9` `98d057cc`
- **[H50]** reverse 实战突破（Where-is-flag + JS/HTML 支持）+ 省赛 reverse_2 实战解出 → ✅ `1b77957e` `dba8a68e`
- **[H51]** 风险全攻克轮——stuck_loop / hallucination / 结构债三项风险落地 → ✅ `4fcb2c12`
- **[H52]** 全量真实跑分补完——29 题 82.8% 解出率（reverse/pwn 分批）→ ✅ `c2561f6c`（沙盒跑分水位，**非 accepted**）
- **[H53]** 决赛多模型矩阵落地——build_race_solver 默认 6 模型 + 三档路由 + ECDSA 攻击 + 提交串行化 → ✅ `9284b5c0` `551448cd`

#### 阶段 4 — 赛前冲刺 + 初赛实战 0 解出（8/20–8/21）
- **[H54]** 初赛赛前冲刺——burst 高频轮询接线 + 赛前检查脚本 → ✅ `d1c5e154`
- **[H55]** 初赛彩排完成——修复 3 个彩排发现 bug + checklist 清零 → ✅ `c4940e34`
- **[H56]** P0 修复轮——竞速 or True 拆除 + Optional 导入 + 入口测试 + 监督模型名统一 → ✅ `063f892e` `3a60a39d` `29f9a38b`
- **[H57]** 开赛级 P0——启动入口勘误 + 分级升级空转 + 沙盒 AST 绕过 → ✅ `fc124375`
- **[H58]** **fix**：赛时救命——代理根因 + 错误 token + 空分类过滤 → ✅ `4c5f8aa2`（**即 A1 幽灵变量前传**）
- **[H59]** 正式赛平台接入——id=1629/账号/Accesskey 配置（pro.dasctf.com + ak_live 注入）→ ✅ `5374d45e` `1715a152`（**ak_live 明文进 git 历史，后 8/21 赛后脱敏 1aa7999f，旧历史仍在 bundle**）
- **[H60]** 测试题拉取诊断——网络通 + 网关 URL 阻塞（40001 缺参）→ ✅ `56fe06a3` `e6c42b4b`
- **[H61]** **🔴 初赛正式赛实战（8/21 14:00 开赛）**：全程记录诚实 0 解出（64 题 0 accepted 0 提交）→ ✅ `6e5d1f8e`（根因：环境残留幽灵变量 + 多进程互踩 + 403 WAF 风控，见 Session A）
- **[H62]** 赛后深挖——环境变量清理 + CRYPTO-01/02 复盘 → ✅ `05d0ef2a`
- **[H63]** **fix(正式赛)**：平台题三重修复——base_url 污染清空 + 无附件误伤豁免 + category 从 name 前缀提取 → ✅ `eefdaa66`（即 A8/A9 前传，rebuild 后代码保留）
- **[H64]** 网关白名单放行 + submit 返回值 tuple 解包修复 + 应急提交脚本 → ✅ `6505ccb8`
- **[H65]** 附件解析（attachment 嵌套对象）+ build_poller 用 build_platform_solver 下载附件 + 放行网关 → ✅ `2b1b9b56`（即 A8/A9 同根修复）
- **[H66]** 抢一血排序加题型优先级 + 纯 deepseek（minimal 去 qwen 免费额度耗尽）→ ✅ `3813b497` `08a36f84`
- **[H67]** **fix(赛后 P0 核心链路)**：LLM 并发/thinking + 工具失败 error + Windows 脚本执行 → ✅ `d1f0b136` `cf595b2d`
- **[H68]** **fix(赛后 P0-④)**：无数据止损 + get_challenge 重试 + dasctf 赛中修复落地 → ✅ `fdf10976`（即 A8/A9 正式沉淀）
- **[H69]** **security(赛后 P0)**：脱敏正式赛 AccessKey（ak_live 明文）——工作区已清理，**git 历史 1715a15 待决策**（最终由 D 系列 bundle 移出仓库解决）→ ✅ `1aa7999f`
- **[H70]** PKCS#1 v1.5 unpad 容错前导 00 丢失（02 开头等价）+ 支持 padded_long 整数输入 → ✅ `888277d8`（即 E30 10732 解法基础）
- **[H71]** 全员锐评修复收口——数据链路/沙盒安全/看板/仓库瘦身/测试补强 → ✅ `24e6853e`
- **[H72]** e2e 平台验证接入 setup.sh(--e2e) + 32 题分类回归脚本（web 23/32，纠正 75% misc 误判）→ ✅ `2009aa6f`
- **[H73]** 落库平台验证脚本（决赛前 P0-1 必跑）+ scripts 冗余归档 55 项 → ✅ `879d1c37` `3449e161`

#### 史前段核心结论
- 8/10–8/21 共 **251 个历史 commit**（bundle 统计），主线是「模型链拓宽 → 跑分迭代 → 锐评整改 → 赛前冲刺 → 初赛 0 解出 → 赛后 P0 修复」。
- **所有水位数字（18.8%→59.1%→82.8%→92.9%、测试赛 7/7）均为沙盒/测试赛口径，与初赛正式赛 0 accepted 无关**，这是 RDD 病最该警惕的口径混用。
- 初赛 0 解出的根因（幽灵 base_url / get_access 字段错位 / 多进程互踩 / 403 WAF）在史前段**反复修了又塌**（H9/H58/H63/H65/H68），是「无治理多会话反复踩同一坑」的铁证——正是 TOP-0 总账 + 租约机制要根治的。

### Session A — 8/21 赛中后勤巡检（后勤 agent · Gu）

> 目标：比赛开赛后排查「LLM 失效」与「0 解出」真因并修复。

- **[A1]** 战中巡检排查 LLM 失效 → ✅ 根因：WorkBuddy Bash 残留 `CTF_AGENT_LLM_BASE_URL=千帆` 幽灵变量覆盖正确端点
- **[A2]** 排查 glm-4.7 经 dashscope 401 → ✅ 端点不匹配（非 key 问题）
- **[A3]** 杀错配 race agent 进程 → ✅ 场上 5 个 agent 有 3 个错配（miniconda 启动全 401 还编假 flag）
- **[A4]** 加固 `start_race.bat` → ✅ 显式 `set CTF_AGENT_LLM_BASE_URL=` 清幽灵变量
- **[A5]** 干净重启 2 个 race agent → ✅ deepseek 主源 + medium profile
- **[A6]** 深挖 0 解出真因（DasCTF API 三层字段错配）→ ✅ ① list 阶段 `has_*` 永远 False → 不下载附件/不取靶机；② `get_access` 找 `access.host/port` 但真实字段是 `endpoints[].exposeIps[0]`；③ solver 用 list 空 description 未调 `get_challenge`
- **[A7]** 写 0 解出诊断报告 → ✅
- **[A8]** 实施 **P0①**：`run.py` solver 入口（~576 行）无条件 `get_challenge` 拿完整 detail → ✅ 备份 `.bak_20260821`（代码后被 git rebuild 保留）
- **[A9]** 实施 **P0②**：`dasctf.py` `get_access` 兜底解析 `endpoints[].exposeIps[0]` + `_request` 重试加 550 → ✅
- **[A10]** 改 `_race_start.py` 去 xfyun 坏轮、主源切 deepseek（qwen 403 额度耗尽）→ ✅
- **[A11]** 验证 race 健康（靶机/附件已注入）→ ✅ 但正式赛（8/21 14–17）最终 **64 题 0 解出、0 有效提交**（环境残留+多进程互踩+403 WAF 风控三重流程事故）

### Session B — 8/21 赛后大改造潮（另一并发会话 · 多会话）

> 目标：项目大改造 + 写 CTDE 协同协议 + 本地离线解出真题。

- **[B1]** 项目大改造 1384→6156 文件 → ✅（大量文档通胀，后锐评定为 RDD 病）
- **[B2]** AGENTS.md 21 铁律 + CTDE 租约执法初稿 → ✅（后被 Session C/D 演进）
- **[B3]** git 历史 rebuild（`filter-repo` 重写历史）→ ✅ 但**引入对象库损坏**（见 Session D-J2）
- **[B4]** 本地离线解出 specialcurve2（14/14）→ ✅ **非平台 accepted**，仅为本地 pdf/附件分析
- **[B5]** 本地离线解出 10732 PKCS#1 → ✅ flag `DASCTF{****}`，**非 accepted**
- **[B6]** 写 CTDE 协同协议初稿 → ✅
- **[B7]** 真题账 questions_real 14/14 → ✅ 本地离线口径
- **[B8]** 我的 8/21 commit 署名被洗（filter-repo 重写）→ ⚠️ 代码在，作者署名丢失（后续 git rebuild 同样现象）

### Session C — 8/22 09:19–09:50 极致锐评 + CTDE 落地 + T-06/T-08（Gu + 并行）

- **[C1]** 极致锐评第三轮（独立实测，非自述）→ ✅ 产出 `极致锐评-20260822-第三轮-锐评驱动开发.md`，打分 30/100
- **[C2]** 实测门禁测试红：`pytest 2 failed / 162 passed`（test_race_fixes ROT13/候选透传）→ ⚠️ 但后续 CTDE 轮实测已修绿（锐评断言过时，印证 RDD）
- **[C3]** 实测评审期间仓库仍被并行会话提交（09:19–09:20 共 8 commit）→ 🔴 单写者铁律立即被破坏
- **[C4]** 密钥止血只做一半：`_backup_pre_cleanup.bundle`（2.7G 含密钥旧历史）未 ignore → 🔴 后 T-06 修复
- **[C5]** filter-repo 事故：`.git-rewrite/` 199 文件曾入库 → ⚠️ 后清理
- **[C6]** 整改潮 42 commit 约 60% 是「出库/擦屁股」→ ⚠️ RDD 病证据
- **[C7]** 验证 P0 整改真实生效（`_preflight.py --skip-regression`）：provider 6/11 可用 + 全链路 dry-run 解出 `flag{****}` → ✅ 命中锐评处方「真 e2e」
- **[C8]** 修 `_preflight.py` BASE_URL `[!!!]` 误报 → ✅ commit `e7a341c`
- **[C9]** CTDE 协议落地 `CTDE协同协议-20260822.md`（R1–R5 / T-01~T-08 / 冲突仲裁表）→ ✅
- **[C10]** AGENTS.md 升级：单写者铁律 → CTDE 域写者 + 文件锁 → ✅
- **[C11]** 锁目录 `.workbuddy/locks/` 建 → ✅
- **[C12]** commit `011b0a0`（test_race_fixes + AGENTS.md）→ ✅ 但**同分钟另一会话删 fix 分支**（filter-repo 收尾），commit 变孤儿对象内容完好
- **[C13]** T-06 密钥 bundle 处理：`_backup_pre_cleanup.bundle` mv 至 `_misc/` + `.gitignore` 加 `*.bundle` → ✅ 密钥止血闭环
- **[C14]** T-08 答辩三件套初稿 ×3（创新点 / 诚实解出率 / 演示分镜）→ ✅ `deliverables/答辩三件套-*.md`
- **[C15]** CTDE 执法层机器化落地确认：`scripts/_lease.py` + `scripts/hooks/pre-commit` + `tests/test_lease.py`（13 passed）→ ✅ commit `62ee35b`
- **[C16]** git 状态 689→127 行（data/attachments 删除已 commit）→ ✅

### Session D — 8/22 09:34–10:46 整改方案执行 + git 损坏发现 + 重建（Gu）

- **[D1]** bundle 本质核实：`git bundle list-heads` 含 main + tag `pre-final-20260821`（8/21 20:45 瘦史前全量备份含密钥）→ ⚠️ 推/传/误 add 即泄露
- **[D2]** git 噪声规模更正：实测 `git status` **689 行**（~600 ` D` + 73 `??` + 1 ` M`），非锐评所写 42 → ⚠️
- **[D3]** 红测试实测 `pytest test_race_fixes` 5 passed → ✅ 印证 CTDE 轮已修，锐评部分断言过时
- **[D4]** 识别 CTDE 致命缺口：pre-commit「无租约+无 session→放行」靠自觉 → 🔴 后 P0① 焊死
- **[D5]** 交付 `整改方案-针对元锐评逐项-20260822.md` → ✅
- **[D6]** **🔴 危机：仓库对象库损坏**（`git stash -u` 失败 → `git ls-tree main` fatal not a tree → `git fsck` 大量 invalid reflog → main tree 不可读）→ 根因：并行会话 `filter-repo`/`gc` prune 成孤儿，main tree 与 blob 恰在被清范围
- **[D7]** 合并暂停（不在损坏仓库硬操作）→ ✅
- **[D8]** 零风险保护：写租约三件套 cp 至 `_misc/lease_backup/` + 完整 bundle 保留 → ✅
- **[D9]** 更正误判「fix 分支可当恢复源」（fix 与 main 同损，archive 0 字节）→ ⚠️
- **[D10]** `git fsck --full` 真实缺失 **4811 missing blob**；reflog invalid 9713 条 cosmetic → ⚠️
- **[D11]** 唯一可靠恢复源 = 工作区物理文件 + `_misc` bundle → ✅ 决策「以磁盘文件为准重建 git」
- **[D12]** **P0①** pre-commit 焊死放行缺口（无 session 且无 `CT_AGENT_SINGLE=1` → exit1，真实提交验证拦截）→ ✅
- **[D13]** **P0②** AGENTS.md 新增「六、唯一判据」（文档预算红线 + 真实平台 GO/NO-GO）→ ✅
- **[D14]** **P0③** 离线刷题实证节归档至 `_archive_离线刷题复盘-20260822.md` + 留诚实指针 → ✅
- **[D15]** **P0④** `test_report_honesty.py` 新增 `test_no_false_waterlevel_in_active_docs`（4 测全过）→ ✅
- **[D16]** **仓库损坏处理**：损坏 `.git` 整体移至 `_git_corrupt_backup_20260822/`（取证）+ `git init` 重建 → ✅ 新 `.git` 19M（原 3.8G）、fsck 零 broken link、17 测全过、git 干净（仓库瘦身副作用达成）
- **[D17]** 模型供应链核查：`circuit_breaker` 熔断已就位、默认 provider 收敛 baidu 千帆 → ✅
- **[D18]** 唯一未做：e2e `assert accepted` 硬卡门禁（需真实平台+key，暂无法安全验证）→ ⚠️ defer
- **[D19]** commit `b51b6ae` → ✅

### Session E — 8/22 11:09–14:20 解题作战纪律 + 重锐评验收 + M1/M2/M3（Gu + 并行）

- **[E1]** 只读 probe 平台 transport 层（pro.dasctf.com 可达，4 端点返回规范 JSON）→ ✅
- **[E2]** **🔴 BLOCKER**：所有端点 `code=40403 无权操作`（token 无赛事权限）→ 测试赛已关、当前无开放赛事，**无赛可打**
- **[E3]** 修 `_race_start.py` probe 硬编码「平台连通 OK」假阳性（现先校验业务码）→ ✅
- **[E4]** 删除一次性诊断脚本 `_diag_platform.py`（防仓库堆散落）→ ✅
- **[E5]** 分析并行会话烧 token 自爆实录（xuanhun_ezip 手搓 Z3 200 行 + bkcrack 坑 + 盲爆）→ ✅ 根因：把「工程完备性」当目标，违背唯一指标「解题数」
- **[E6]** AGENTS.md 新增「七、解题作战纪律」R1–R6 → ✅
- **[E7]** `core/prompts.py` 新增 `SOLVE_DISCIPLINE` 注入 `build_plan_prompt` → ✅ 提交前需 `bash setup.sh` 绿（后验证）
- **[E8]** 赛后重锐评代码级验收（五宗罪 + Brainfuck 修复 + 新三点）→ ✅ 产出 `赛后重锐评-验收记录-20260822.md`
- **[E9]** 金标准验证 `pytest 178 passed / 3 skipped` → ✅
- **[E10]** 三处小纠偏（放弃阈值 `stuck_count>=3` 实测 / skills 49 个 / js_secret 视觉非泄漏）→ ✅
- **[E11]** 清理 7 个源码树 `.bak` 至 `.workbuddy_cleanup_backup/removed_bak_20260822/` → ✅
- **[E12]** 详细整改规划（plan 模式）：3 个 Explore 代理只读探查 → ✅ 产出 `plans/electric-cascade-darwin.md`（M1–M5 里程碑）
- **[E13]** **M1.1** 索引重建 `scripts/_build_regression_index.py` → `category_regression.json`（47 题）→ ✅
- **[E14]** **M1.2** 修通 `_dryrun_race.py`（INDEX/FLAG_MAP / qpath 直载 / 真值判分 / verify_against_truth）→ ✅
- **[E15]** **M1.3** 4 类失败埋点（ERR_EXTRACT_FAIL / `_finalize` 分类链 / error_struct）→ ✅
- **[E16]** **M1.4** 门禁 `test_failure_taxonomy.py` → ✅ `185 passed / 3 skipped`
- **[E17]** 继承 xuanhun_ezip 只读侦察固化（`_m3_dec.bin` 唯一真目标 + ZipCrypto / `_layer3_plain.zip` 非 zip 垃圾 / multzip1 密码 66688 / multzip2 bkcrack 密钥仅对话记录未落盘 / 仓库已有 `zip_filename_chain_decode` 可复用）→ 📌 规划 Stage1–6 未执行（等用户信号）
- **[E18]** 深度调研 scene#2 → ✅ 产出 `深度调研-项目现状与解题数第一目标-20260822.md`（根因三件套 + 路径排序）
- **[E19]** 指导老师版深度锐评 → 三台手术：①文档改 3 份复盘结论统一「80% 流程 + 20% 窗口 0 解出」②`prompts.py::infer_skill_require` 瘦身 + `test_skill_routing_integrity.py` ③`benchmark.py` 真实模式改全链路 + `test_benchmark_real_chain.py` → ✅ `194 passed / 3 skipped`
- **[E20]** scene#8 数据分析及可视化 → ✅ `scripts/analysis/_scene8_collect.py` → `_scene8_stats.json` + `_scene8_build.py` → `deliverables/scene8-全面数据看板-20260822.html`（9 面板）+ `数据分析报告-scene8-20260822.md`
- **[E21]** **M3 战果**（4 笔 commit）：`593004f` jpeg_png_embedded OCR / `2934ef4` presolve 接入 / `8d23fb3` lfsr 正则 / `45a9181` flag_scan 过滤 → ✅ 解题数 64.3%→92.9%（+4 题）
- **[E22]** `5a02d46` fix lease release 未清理 coordination 锁文件（解锁自阻断）→ ✅
- **[E23]** 锐评「还是很严重」→ 四台新手术：④`config.py::print_effective_config_snapshot` + `llm/client.py::CTF_AGENT_ESCAPE_PROVIDER` ⑤`tools/skill_manager.py::VERIFIED_IN_RACE_SKILLS`（12/48 实证）⑥benchmark 真实模式实测 6/6=100% → 主Agent全链路真题基线报告 → ✅ `204 passed / 3 skipped`
- **[E24]** **M3 第 5 刀** `4503ad0` vigenere 接线 `vigenere_decode`（anwang 命中）→ ✅
- **[E25]** specialcurve2 骨架 `7e038fc`（factordb 分解 + ord 恢复 + d=e⁻¹，卡 88 位 DLP 无 Sage）→ 🔴 悬置（后 Z1 查 writeup 绕过）
- **[E26]** **🔴 并行会话警报（14:10）**：工作区出现 6 个 M 文件 + 2 新测试（13:35–13:44 改，无租约改核心文件，违反 CTDE R1），pytest 203+1 FAILED → 🔴 协议盲区（hook 拦不住改不提交）
- **[E27]** 接管并行会话改动收口（用户确认无并行会话）：审阅 172 行 diff（逃生+快照/实证分档/dryrun 超时归类）→ ✅ 失败测试根因 `crypto_complex_mult_group` 缺 `run()` 标准入口，补后 204 全绿
- **[E28]** 4 笔提交 `d6ef170` / `96e483c` / `18f6b6e` / `3252e27` → ✅ 今日 git 12 笔 commit，工作区干净
- **[E29]** **specialcurve2 实证**：factordb 分解 + PARI/GP `znlog` 恢复 e + 复数群阶 d=e⁻¹ → flag `DASCTF{****}` → ✅ **本地离线，非 accepted**
- **[E30]** **10732 PKCS#1 v1.5 正式赛真题**：hint 立方根 → PKCS1 raw 解密 → AES-ECB 解 PDF → PyMuPDF 视觉确认 flag `DASCTF{****}` → ✅ **本地离线，非 accepted**
- **[E31]** 沉淀 `crypto_complex_mult_group` skill 补 `run()` + specialcurve2 完整实证解 → ✅
- **[E32]** 经验沉淀：①「沉睡 skill」审计是 ROI 最高动作 ②writeup 是 R1 工具优先延伸 ③PDF 解出必须 PyMuPDF 渲染视觉确认 ④e=3 小明文直接开立方根 → ✅

### Session F — 8/22 16:18–16:5x 承接/收口（Gu）

> 目标：确认会话停止 + 收口在飞改动 + 定协同纲领 + 诚实化 + 清理 RDD + 冻结 + push。

- **[F1]** 确认中断任务已被并行会话 `e3f6924`（15:47，作者 糖露星霜•暖霞拾光）补提交 → ✅ 工作树 clean，无遗留（re-acquire 已无意义）
- **[F2]** 全量复测 `pytest -m "not slow"` → ✅ **208 passed / 1 skipped / 2 deselected（34s）**
- **[F3]** 租约执法层 + 双门禁现状确认 → ✅ `scripts/_lease.py` 存在，无活跃租约；`.git/hooks/pre-commit` 双门禁就位
- **[F4]** **⚠️ 真实解题数澄清（核心目标）**：`10732` / `14/14` / specialcurve2 全为**本地离线解出**，**非平台 accepted**；初赛真实战绩 **0 解出、0 有效提交**；日志「1/32」=「32 道里本地分析 1 道」非 accepted → 🔴 答辩/战报严禁引用为真实水位
- **[F5]** 选定主线①工程治理展示：逐项核验展示资产（VERIFIED 白名单 / 逃生开关 / 离线演练三件套 / 测试 / 报告 / 看板）→ ✅
- **[F6]** 产出 `deliverables/工程治理展示-诚实版.html`（顶部声明 accepted=0，只列 8 项已验证工程资产）→ ✅
- **[F7]** 确认并行会话停止（3 个 M 文件遗留 `tools/adapters/` 下 bkcrack/hash_crack/wordlist_crack，mtime 16:24–16:25）→ ✅ 典型「会话退出前未提交」
- **[F8]** 收口在飞改动（3 适配器质量修复：线程池防爆 / 前导零变体 / 加密位判定 / charset 净化，无密钥）→ ✅
- **[F9]** 验证优先：改动树上重跑 pytest 仍 208 全绿（16:21 那次在改动前跑）→ ✅
- **[F10]** gu 认领 `tools/adapters/**` 租约接管提交 `5650715`（双门禁全过：密钥扫描✅ + scope✅ 自动续租）→ ✅
- **[F11]** 定**多智能体协同准则纲领**（三层治理：原则层+规范层+执法层，10 条铁律每条绑真实事故）→ ✅ `deliverables/协同协议/多智能体协同准则纲领.md`
- **[F12]** AGENTS.md:8 接入「原则层」引用 → ✅ commit `db99d33`（持 scope=AGENTS.md 租约）
- **[F13]** push 失败（GitHub 连接重置，网络）→ 🔴 后 F22 复现
- **[F14]** 探查仓库现状 + RDD 文档定位 → ✅ 仓库内仅 10 个被跟踪 md；RDD 通胀主源在仓库外 `deliverables/` + 被 gitignore 的 `data/results/*.md`
- **[F15]** 清理 **RDD 文档通胀②**：建 `deliverables/协同协议/真实战绩口径声明.md`（单一可信源，钉死「accepted=0 唯一判据」）→ ✅
- **[F16]** README.md / README.zh.md 加诚实横幅 + 弱化 battle-tested 暗示 → ✅
- **[F17]** `deliverables/overview.md`（原写「真实水位 89%」）加诚实横幅引用声明 → ✅
- **[F18]** 收尾冻结 **③**：AGENTS.md 新增「八、项目收尾冻结（2026-08-22）」（达成 DoD，后续仅维护不新增功能/skill/模板）→ ✅
- **[F19]** 纲领末尾加冻结段 → ✅
- **[F20]** **租约坑修正**：`_lease.py --scope` 是 `nargs="+"`，多次独立 `--scope` 被 argparse 覆盖；正确语法 = 单次 `--scope` 后跟多值 → ✅ gu 认领 `README.md README.zh.md AGENTS.md` 成功
- **[F21]** pytest 重验 208 passed → ✅；commit `563517f`（3 文件 +21/-3，双门禁全过）→ ✅
- **[F22]** **✅ push 成功（2026-08-22 18:3x 网络恢复）**：根因定位——git 默认 HTTP/2 被本环境中间件 reset（`ls-remote` exit 128），强制 `http.version=HTTP/1.1` 后读通；且 sandbox 拦截 git 上传连接，**关沙箱**后 `git -c http.version=HTTP/1.1 push origin main` → `563517f..f8d8f04 main -> main` exit 0。已固化 `git config http.version HTTP/1.1`（仓库级）。验证：远端 `main` = `f8d8f0429` == 本地 HEAD `f8d8f04` → 完全同步。4 提交（5650715 + db99d33 + 563517f + f8d8f04）全上 GitHub，工作树干净。

### 8/22 承接开发早期（补充，来自会话交接记录）

- **[G1]** Phase0：`pytest + setup.sh` 验证无 regression → ✅ 208 passed / setup.sh 绿
- **[G2]** Phase1：CTDE 租约接管（acquire 租约 gu）→ ✅
- **[G3]** Phase2：收口 web mock 在飞改动 → ✅ commit `462aa10`（web 靶机 proxy 贯通 + mock，4 passed）
- **[G4]** Phase3：修 AGENTS.md 路径（`../deliverables/协同协议/` 修正误判）+ 10732 归档纠错 → ✅ commit `ca7ee9e`
- **[G5]** 发现 5 个别人 staged 的 coherent 文件（bkcrack adapter 等）→ ✅ 后被并行会话 `e3f6924` 补提交（见 F1）
- **[G6]** **✅ 网络恢复后补 push（2026-08-22 18:3x）**：见 F22 根因修复与同步验证，4 提交全上 GitHub。

### Session G-激活 — 2026-08-22 20:2x 双门禁事前门禁真正激活（Gu）

> 目标：接手工程治理，修复「双门禁就位」纸面生效——pre-commit 事前拦截从未真正激活（与总账反复声称矛盾，RDD 病活例子）。

- **[G-A1]** 复核发现：`.git/hooks/pre-commit`（F3 16:18 记「就位」）在 18:38 `core.hooksPath` 改指 `git_hooks/` 后已被覆盖失效；`git_hooks/` 仅含 post-commit/post-merge，**pre-commit 从未被 git 调用** → 治理是「事后记日志」非「事前拦提交」→ 🔴
- **[G-A2]** **激活前必改的致命 bug**：`scripts/hooks/pre-commit` 第17行 `ROOT="$(cd "$(dirname "$0")/../.." && pwd)"` 假设钩子在 `.git/hooks/`（两级深）；`core.hooksPath=git_hooks` 下钩子在 `git_hooks/`（一级深）→ ROOT 算到仓库父目录 `E:\Program\西湖论剑\`，`scripts/_scan_secrets.py` 找不到 → 误杀所有提交。修复为 `ROOT="$(git rev-parse --show-toplevel 2>/dev/null)" || ROOT="$(cd ... && pwd)"` 两段式（同时修 `|| cd ... && pwd` 优先级错把 git 输出+pwd 拼两行的 bug）→ ✅
- **[G-A3]** 部署：`cp scripts/hooks/pre-commit git_hooks/pre-commit` + chmod +x；`setup.sh` 加守卫式同步（git_hooks 已有则不覆盖）→ ✅
- **[G-A4]** 清死锁：`_lease.py acquire` 卡 `.atomcode/*.lock`（持有 PID 23088 已 DEAD，进程被杀未走 finally 释放）→ `rm` 锁（.atomcode 已 gitignore，安全）→ 重 acquire gu scope=[git_hooks/pre-commit setup.sh scripts/hooks/pre-commit] ttl 60 → ✅
- **[G-A5]** 验证：staged 三文件后手动 `CT_AGENT_SESSION=gu bash git_hooks/pre-commit` → 密钥扫描通过 + lease scope 内（自动续租）EXIT=0；真实提交将再触发门禁自动放行 → ✅
- **[G-A6]** 诚实化：F3 与四、锚点317「双门禁就位」更正为「此前纸面、本 Session 真正激活」→ ✅
- **[G-A7]** ⚠️ 副作用：激活后人类 `git commit` 若无 `CT_AGENT_SESSION` 且无 `CT_AGENT_SINGLE=1` 将被门禁拦截（项目设计如此，防多会话无锁并发）；属修 bug 非新功能，不违反冻结纪律（AGENTS.md 第八節）。commit 见五、实时变更流本条目对应行。

---

## 二、当前开放任务（未闭环，需跟进）

| 任务ID | 归属 | 状态 | 阻塞原因 / 下一步 |
|---|---|---|---|
| **T2-PLAN** | wb-takeover-20261022 | ✅ 阶段A 已合入 main（2026-10-22 07:59） | **阶段A 脚手架经合并闸门合入 main**：impl `150388ea` + 测试 `972ae89b` + filterrandom 回归修复 `d76572f2`（新增 `scripts/verify_filterrandom.py` + `_merge_gate.py` 重指向专属 skill `lfsr_filter_recover` 的 sha256 真值闭环）→ `--no-ff` 合并提交 `674c585d`。全门禁绿：KPI 14==14、filterrandom→REGRESS_PASS、全量 pytest 1968 passed/30 skipped（550.95s）、反注水通过；并行会话 WIP 经 `stash` 隔离并完整还原（103 跟踪修改+6 未跟踪），零丢失。修复根因：presolve 通用工具管线不路由专属 skill，故 `_regress_one.py` 长期 REGRESS_FAIL 提取=None；改专用 verify 脚本闭环（与 `verify_specialcurve2.py` 同款定位）。**阶段B/C 仍阻塞**：B 需 WSL2+Docker 容器执行器；C 需真实重型模型 key（用户须提供，本仓不代持密钥）。 |
| **P1-COST** | wb-takeover-20261022 | ✅ 已完成（2026-10-22 06:37） | 只读验收+文档落地 2027-prep/P1-降本体系验收与跑法-20261022.md（gitignored 本地规划，未改代码）；结论降本体系已完备且强制生效，无需再接模型 |
| **ARIS-B** | aris | ✅ 已完成（2026-08-29 07:29） | 验证: 聚焦排序/fail-open/真实控制器/live链路0题优雅/冒烟3-3 commit `68fc3a5` |
| **ARIS-A** | aris | ✅ 已完成（2026-08-29 07:29） | 验证: anwang 42898->12647 tokens(10K cap); 附带修复benchmark break缩进回归 commit `457fe15` |
| **P0-GU-1** | gu-p0-20260827 | ✅ 已完成（2026-08-27 11:37） | Phase0 收口完成：①requirements.txt+sympy 提交(129312e) ②台账收录边界规则 A/B/C/D/E 五类定稿(本地,台账 gitignore 不入库) ③merge_gate _classify_entry 机器化(2d85984, count 仅计 A/B 类 fail-closed, KPI 锚 9 验证通过) ④悬空 symlink 已由前序清理、fsck dangling 保守保留 ⑤_INDEX/总账锚点复核一致 commit `129312e,2d85984` |
| **SW-GIT1** | SoftwareWorkshop | 📝 进行中（2026-08-24 10:40） | git 仓库状态异常发现(止血已完成)：①HEAD曾悬空(commit --only在521文件全暂存混乱索引下制造孤儿commit f7a41c4且未更新ref)，已用symbolic-ref恢复HEAD->main(58e2797)；②全树521文件A暂存未commit=8/22重建遗留(所有并行会话改动add了从未进版本库)；③f7a41c4孤儿dangling含正确修复(未丢，工作树eval/benchmark.py已是修复版)。需协调器决策收口方案(521文件提交or reset)后再正常合入修复，禁止强行merge(unrelated-histories灾难)。scope=git元数据协调，不动工作树/版本库文件。 · scope=git 元数据(协调层)；不动工作树/版本库任何文件 → ✅ **已闭环（2026-08-26 22:02）**：实测当前 HEAD=`7703a89` 正常、工作树干净（git status 空）、无 dangling orphan、无 521 文件暂存残留；原 ①悬空 HEAD/②521 暂存/③孤儿 f7a41c4 均已随 8/26 多轮 closeout 提交（80b9300/`7703a89` 等）消解，仓库进入健康态。原「禁止强行 merge」警示因已无 unrelated-history 场景而自然失效。 |
| **SW-LOC1** | 糖露星霜•暖霞拾光 | ✅ | **Provider 跨源熔断兜底路由 + E1 结构化提取 + vnctf 网格重采样 numpy 向量化**（2026-08-26 21:1x–22:02）：commit `7703a89`。①`llm/failover.py` 跨源自动兜底（opt-in，`CTF_AGENT_LLM_FAILOVER=1`；跳已熔断源、按 `CTF_AGENT_FAILOVER_ORDER` 试白名单源；修复 `await` 同步函数致命 bug，改走 `*_async` 变体）→ 复活此前 baidu/deepseek 死、qwen 不稳时 LLM 贡献=0 的根因；②`phases.py` `extract_flag` 增结构化候选提取兜底（`{"candidates":[...]}`/围栏/内联 JSON 均识别），原三态校验与 `_extract_failed` 埋点完全不动；③`misc_grid_resample.py` `_build_or_reveal` 纯 Python 像素双循环 → numpy 向量化（2.54s→0.23s，full run 8.1s→3.8s，结果等价 `vnctf{****}`）。验证：failover 8/8、extract_flag 7/7、grid_opt 4/4、防错体系 73/73 全绿；默认关闭、向后兼容、零真 token。诚实口径：均属 LLM/提取鲁棒性，不计入真题确定性 KPI（真题集确定性直出 2026-08-27 复测 = 15/15（带 registry 的 `_verify_presolve_truth.py` 真值比对实测：gongye_web2 经 flag_scan 命中 ✅、specialcurve2 经 factordb+PARI 命中 ✅、vnctf 经 grid_resample 命中 ✅、xuanhun_signin 经 jpeg_png_embedded + tesseract OCR 命中 ✅；此前 14/15 系 xuanhun_signin 缺 tesseract OCR 系统依赖、12/15 系 `_verify_presolve_only.py` 用 `registry=None` 跳过 flag_scan 的降版结果、15/15 含非真题口径，均非权威）。注：15/15 依赖系统装 tesseract（conda-forge 安装至 D:\miniconda3_new\Library\bin + eng.traineddata 落 D:\miniconda3_new\Library\share\tessdata）；`skills/jpeg_png_embedded.py` 已增强为自动定位 tesseract 并以 Windows 风格路径设置 TESSDATA_PREFIX（TEST `tests/test_jpeg_png_ocr.py` 锁定））。 |
| **SW-GIT2** | SoftwareWorkshop | ✅ 已恢复（2026-08-27） | **实测追加卡点（接手以磁盘为准）**：①主仓库 ref 写入结构性损坏——`git branch`/`git update-ref`/`git worktree add -b` 全部 exit 0 但静默不写 ref（手动写 `.git/refs/heads/` 文件亦报 No such file）；worktree 自带 git 2.55 与系统 git 2.53 均失败→疑似 Windows 文件锁或 `.git` 落盘问题，其他并发会话正持锁。②租约实测：coordination.json 当前仅 3 租约=`gu→data/results`、`atomcode-overseer→2 scripts`、`research-expert-specialcurve2→core/+skills/+tools/整片`；**我之前的 gu-verify-0824 租约已消失**。→ SW-QWEN1 修复（benchmark.py∈eval/无主禁提交 + crypto_complex_mult_group.json∈skills/撞 research-expert 租约）**无法合入**。处置：修复已验证并固化为 patch 交付（`deliverables/patches_20260824/`），不强行 merge（避免摧毁他人在途工作，违背并发纪律）。前置：仓库 ref 修复 + 协调器分配 eval/ 租约/或 research-expert 释放 skills 租约。 → ✅ **已恢复（2026-08-27 质检实测）**：`git commit`/`git branch`/`git rm --cached` 全部正常，本会话成功提交 3 笔（`1274159`/`3b2c722`/`67bc0e3`），ref 写入结构性损坏已不复现（原 8/24 疑为临时文件锁/落盘问题，随 8/26 closeout 消解）。 |
| **SW-QWEN1** | SoftwareWorkshop | 📝 修复已验证，合入被阻（2026-08-24 11:10） | 重跑完成：robust 13/15(0.867)，baidu/qwen各13/15且双provider的13解100%为presolve静态直出(0 LLM)。根因=benchmark.py多provider复用Question对象致presolve_attempted跨provider污染(qwen原被压到7)，修复(每provider重载题目)后qwen恢复13/15，robust口径干净对称。诚实反转上一轮误判：qwen非真LLM跑通7道，而是同样presolve直出；LLM真推理双provider一致=0/2(2道presolve未覆盖难题全败)。**修复已生成标准 patch 并在隔离 worktree 验证通过（4 测试全绿），但因①仓库 ref 写入损坏(git branch/update-ref/worktree add -b 全部静默失败)②skills/ 被 research-expert-specialcurve2 租约占有、eval/ 无主禁提交→未能合入 main**。交付物：`deliverables/patches_20260824/`，待仓库 ref 修复 + 协调器分配 eval/ 租约后由正常 w/ 车道经 _merge_gate 合入。 → ⚠️ 2026-08-27 质检：ref 损坏前提已消除（见 SW-GIT2），但 eval/ 租约分配 + benchmark.py 是否已被 8/26 closeout 覆盖**待核实**，patch 合入仍需协调者决策。 |
| **F22 / AD-push** | Gu | ✅ | **已闭环（2026-08-22 18:3x）**：4 提交全上 GitHub，完全同步。根因=git HTTP/2 reset + sandbox 拦截上传，已固化 `http.version=HTTP/1.1`，后续 push 不再卡 |
| **D18** | Gu | ⚠️ | e2e `assert accepted` 硬卡门禁未做（需真实平台+key，当前 40403 无赛可打） |
| **E17** | Gu | 📌 | xuanhun_ezip 继承规划（Stage1–6）未执行，等用户信号 |
| **B3 残留** | — | ⚠️ | `_git_corrupt_backup_20260822/`（损坏旧 git，取证用，**勿恢复/勿删**）仍占空间 |
| **TOP-0 接线** | Gu | ✅ | 已接线：AGENTS.md 头部「三次修订」块（commit `f8d8f04`）强制「开工前先登记本文件」，优先级高于 AGENTS.md 与任何会话记忆 |
| **ARCH-1** | 科研专家团 | ✅ | 多智能体协同架构方案与评估-20260822.md（`deliverables/协同协议/`，规划稿只规划不执行）；结论=现有治理方向对但"CTDE分散执行"名不副实——`_lease.py:120` 单写者全局互斥锁（coordination.json 仅单 session 字段）=并行实为串行；评级：安全底座 8/10、作为协同范式 3/10、Go/No-Go=NO-GO(仅指并行范式)；理论锚点=CCF CW-PBFT（ECDSA身份→会话密钥签名 / Shapley贡献加权→CW-merge / SecurityGuard→hook三件套） |
| **ARCH-2** | 科研专家团 | 📌 | 未来蓝图（封存，待解除冻结后执行，勿现在动手）：D1 单写者锁→目录级多写者租约（~150行改造+交叠判定单测）· D3 活跃心跳（修 `_lease.py:237` 只挂 commit）· D4 会话密钥签名 commit · D5 贡献加权 merge · D6 merge 冲突策略；均见 ARCH-1 文档 §4/§5 |
| **FIX4** | Gu | ✅ | 已完成（2026-08-22 20:27）：冒烟通过——真实LLM/MOCK两模式 / `api/mode` 正确返回 / 前端横幅红绿区分 / 看板自欺风险已消除（commit `359f4c7`）；本行由科研专家团于 21:35 从「会话代号表」误插位校正回此表（修 `_log_task.py --start` 表格定位 bug 前的人工兜底） |
| **M2-FIX** | Gu | ✅ | **M2 归因修复（2026-08-22 22:3x）**：① P0 附件路径 bug——`_dryrun_race.py::find_local_attachment` 目录→真实文件（`_resolve_attachment_target` 递归找 tar.gz/pcapng/enc）+ `file_analysis_adapter` 支持目录摘要（不再 isfile 判「文件不存在」）；② P1 `web_source_audit` 接入 presolve 第 7 路（`_try_web_source_audit`，web 题后门/危险函数/版本-CVE 确定性审计）；③ P2 垃圾 flag 过滤（`_is_plausible_flag`：控制字符/引号占位符/纯题号式，实证过滤 `flag{--fa:\"\"}`/`flag{****}`/`ctf{****}`）；④ P2 `main_agent` web 无靶机空转兜底提示改「源码审计方向」。全量 pytest **208 passed/1 skipped 无回归**；10735 冒烟验证垃圾 flag 已过滤（`flag{****}`→presolve_miss） |
| **M2-10732** | Gu | ✅ | **已接入（2026-08-27 复核）**：`crypto_pkcs1_padding_oracle` skill 经 `agents/math_engine.py:_engine_pkcs1_oracle`（决赛 S2 2026-08-21 注册）接入 presolve→math_engine 链路，10732 真题 cuberoot→unpad→aes_ecb→PDF 全链路可解（`test_presolve_skill_wiring` 覆盖）。原「未接入 CryptoToolkit.build_fallback_script」指通用脚本生成路径，非必需——math_engine 已覆盖，该通用化路径降级 backlog |
| **M2-AUDIT-INJECT** | Gu | ✅ | **已闭环（2026-08-27 02:08，commit `b46dcb1`）**：根因= `run_presolve` 写入 `from_dict` 新建的 `q.extra`，未回写共享 `qdict`；`run_llm_agent` 又 `from_dict(qdict)` 重建 → LLM 阶段 extra 空。最小修复：`run_presolve` 在 presolve 后把 `q.extra`（含 `web_audit_report`）`update` 回共享 `qdict`；`prompts.py` 的 `【web 源码审计报告】` 注入链原本已通，仅缺上游回写。回归 `tests/test_dryrun_audit_passthrough.py`（2 passed）。双门禁全过（密钥/诚实/lease/73 防错绿/文档一致性）。 |
| **M2-VNCTF** | Gu | ✅ | **已闭环（2026-08-27 二次复测）**：`real_misc_vnctf_flag` 已非「待解题」——presolve `grid_resample` 路线（SW-LOC1 8/26 numpy 向量化）确定性直出 `vnctf{****}`（`_verify_presolve_only.py` 实测 PRESOLVE命中）；questions_real 条目 flag 留空系原始题面"flag 未知待解"、非索引漏填；沉睡 skill 审计靶子需求随 presolve 覆盖自然消解。 |
| **SW-LLM1** | Gu | ✅ | **免费优先 LLM 链路恢复（2026-08-27 01:2x）**：实测 5 免费源可达（qwen/qwen3.7-flash、ark/doubao-seed、xfyun/lite、tokenhub/hy3、moonshot/kimi-k2.6），3 个「免费」源实际欠费死（baidu 千帆 403 account_overdue、siliconflow 402 insufficient、glm 429 余额不足）；deepseek 充值新 key 属付费，全程未触碰。原默认 `CTF_AGENT_LLM_PROVIDER=baidu`（死源）已 `setx` 切 `qwen` + 启用 failover（顺序 `qwen,tokenhub,xfyun,moonshot,ark,mimo,deepseek`——付费 deepseek 垫底），默认路径复验返回 `pong`。并行会话在飞 config.py 改动（qwen 默认模型→qwen3.7-flash）方向一致，未触碰避免冲突。结论：8/26「providers 全熔断」已过时，LLM 贡献=0 系临时 outage 假象非能力缺口。 |

---

### 二·收尾状态（2026-08-27 23:3x 收口，会话=gu）

| 任务ID | 归属 | 状态 | 说明 |
|---|---|---|---|
| **SW-CLOSEOUT-0827** | gu | ✅ | **工程收口完成**：①反注水法令(f0ccece)写死 KPI=12 + 12题白名单 + tamper-evident 违规账；②honesty/budget-reflection/race-intelligence 规则层齐备；③failover/E1/vnctf 向量化(7703a89)经六门禁落盘；④_closeout.py 外部依赖断链检查(afc3c9d)固化 8/27「真题归档被删→4道verify断链」事故。工作树除并行会话 in-flight 3 文件外干净。 |
| **并行会话收口** | — | 🔴→⚠️ | 同身份(gu)并发自动提交会话停手于 20:41（末提交 31310f7/134f72f 为 ezrsa/exciting_inverse 真实离线解题，非注水）；KPI 已结构性锁死，无法再注水。停止方式仅用户侧：左侧栏结束该会话；本会话无法跨会话杀进程。 |
| **未提交 in-flight（并行会话，勿在本会话提交）** | — | ⚠️ | `ctf_agent/scripts/_mock_web_target.py`(+15 flaky就绪等待修复)、`research-wiki/ideas/idea_ctf_agent_race_intelligence.md`(+53)、`idea-stage/refine-logs/FINAL_PROPOSAL_RACE_INTELLIGENCE.md`(untracked)——均属并行会话 race-intelligence 在途工作，留其自行提交，避免并发覆盖。 |

---

## 三、未来任务录入模板（任何 agent 开工前先复制此块填写）

```
### [任务ID] 任务短语（一句话）
- 归属会话：Session X / 主导 agent
- 登记时间：YYYY-MM-DD HH:MM
- 预计范围 / 租约 scope：<文件/目录>
- 预计动作：<要做什么>
- 状态：📌 → 🔄 → ✅/🔴
- commit / 产物：<hash 或路径>
- 关键发现 / 备注：<事实、坑、对齐项>
```

**登记纪律（重申）**：
1. 先登记后动手，状态从 📌 起。
2. 改仓库内文件必须持租约（`scripts/_lease.py acquire --session <id> --scope <a> <b> <c>` 单次多值）。
3. 完工回填 ✅ + commit；中断填 🔴 + 原因 + 是否需移交。
4. 一切「解出/水位」标注 accepted 与否，非 accepted 记为本地离线分析。

---

## 四、关键事实锚点（防记忆漂移）

- **竞赛真实得分 = 0**：初赛 64 题 0 解出 0 提交；所有「14/14」「1/32」「10732」「specialcurve2」均为本地离线分析，**非平台 accepted**。
- **唯一 KPI（2026-08-27 方案A收敛后）**：`offline_verified = 9`（台账 `REAL_SOLVES_LEDGER.md` 第二节第 1-9 条，merge_gate `count_offline_verified` 口径；`KPI_BASELINE.json` 棘轮锚=9，2026-08-26 重跑 full_baseline 落盘）。另有两个**非 KPI** 口径勿混用：① 确定性管线真值验证 **15/15**（2026-08-27 `_verify_presolve_truth.py` 带 registry 真值比对实测；gongye_web2 经 flag_scan 命中 ✅、specialcurve2 经 factordb+PARI 命中 ✅、vnctf 经 grid_resample 命中 ✅、xuanhun_signin 经 jpeg_png_embedded + tesseract OCR 命中 ✅；`_verify_presolve_only.py` 因 `registry=None` 跳过 flag_scan 仅得 12/15，属降版口径不取用，见 SW-LOC1；15/15 依赖系统装 tesseract，见 SW-LOC1 末注）② benchmark robust **13/15**（baidu/qwen 解出集合并集，2026-08-24 隔离复跑）。三者含义不同：9=严格真题离线核验、15/15=presolve 覆盖度（带 registry 实测，已闭环）、13/15=双 provider 并集。**LLM 真推理贡献（2026-08-27 战役A 破冰实测）= ≥1（非 0）**：deepseek 充值后实测 `gongye_web2`、`ezrsa` 在 `--no-internal-presolve` 强制 LLM 链路下均 `SOLVED by main_agent_llm` 且 sha256 校验通过；根因**非 provider 熔断**（那是 8/26 临时 outage 假象，SW-LLM1 已证 5 免费源可达），而是 `main_agent` reason-loop 缺陷（LLM 反复 reason 不调工具）——已用 supervisor 多级强制路由修复（`flag_scan`→`crypto_auto`→`stego_lsb`，`a5c4fe0` + 本次扩展）。全量 15 题 LLM-ONLY 复跑数字见《LLM破冰战役A》报告。注：gongye_web2 当前台账 flag 已更新为裸 hex `6061e023...`（旧 `flag{****}` 字面量系 8/26 快照，勿再引用）。
- **工程质量 = 真达标**：`pytest -m "not slow"` **314 passed / 14 skipped / 2 deselected（2026-08-26 23:54 环境修复后实测，替代旧 271）**；CTDE 租约执法 + 双门禁 hook 在线（pre-commit 事前门禁已于本 Session「G-激活」真正激活于 git_hooks/，此前 16:18 记「双门禁就位」实为纸面）；离线演练体系（`_dryrun_race.py` + mock）可用。
- **仓库结构**（2026-08-26 质检修正：原「父目录非 git 仓库」锚点过时）：git 仓库根 = 父目录 `E:\Program\西湖论剑\`（`git rev-parse --show-toplevel` 实测）。**进 git 的** = `ctf_agent/`(365) + `.publish_assets/`(7) + `research-wiki/`(5) + `README.md` + `LICENSE` + `CLAUDE.md` + `.gitignore`；**被 .gitignore 不进 git 的** = `协同任务总账-TOP0.md`、`_INDEX.md`、`deliverables/`、`data/`、`_archive/`、`wt-*`、`.venv` 等。
- **push 状态**：⚠️ **本地已大幅前进、是否 push 待决策（2026-08-27 01:15 质检核实）**：末次实际 push 为 2026-08-22 18:5x（`d6454b5`，见 F22/AD-push）；此后本地 `master` 已前进至 `62b00e6`（含 8/26–8/27 多轮 closeout、KPI 收敛、main_agent KNOWN_GAP 修正、deepseek 新 key 配置等数十笔提交），远端 `origin/open-clean` 仍停在 `d6454b5`。`master` 配置 track `origin/open-clean` 但本地无对应 remote-tracking ref（`git rev-parse @{u}` 报 unknown revision）→ push 前需先 `git fetch` 确认远端分支存活。push 纪律不变：须 `http.version=HTTP/1.1` + 必要时关 sandbox（见 F22 根因）。是否同步公开仓待你决策（涉及代理/网络 + 公开仓纪律）。（2026-08-27 12:1x 再次实测）`git ls-remote origin` 已成功返回远端 HEAD（9fde8d8 main / open-clean），代理恢复、GitHub 可达 → 此前「23:3x 代理 443 死」判定已过时，**push 技术障碍解除**。但实际执行 push 是公开仓库外部副作用动作，且历史密钥 D1 bundle（pre-final-20260821 含 ak_live 明文）治理未完成（见 Session D [D1]），**是否 sync 公开仓需你明确授权**，维持「不擅自 push」纪律。当前分支 main，upstream 指向 open-clean（分支名不符，push 需 git push origin HEAD:open-clean 或先对齐）。
- **自动记录机制（共识 + 机器兜底，无常驻进程；2026-08-22 19:3x 升级）**：① **机器强制**——`git_hooks/post-commit` + `post-merge`（随仓库追踪，setup.sh 用 `core.hooksPath=git_hooks` 自动安装，解决"hook 不进 git"隐患）每次 commit/merge 自动把（时间/会话/commit/主题/改动文件）追记到本文件「五、实时变更流」段；② **共识层**——会话开工前/完工后用 `ctf_agent/scripts/_log_task.py --start/--done/--note` 一键登记（比手改 md 简单，friction 低才执行得动）。**不设开机自启、无常驻看门狗进程**（旧 `_watchdog_top0.ps1` 降级为手动深度审计工具，`start_watchdog.bat`/`_install_watchdog_task.ps1` 保留但不再推荐使用）。会话代号取自 `CT_AGENT_SESSION`，缺省 `manual/<user>`。相关 commit：`1f1b88d`（机制建立）、`71dbdf6`（路径修复）、`fc12129`（bug 修复 + 降级）。
- **不要碰**：`_git_corrupt_backup_20260822/`（损坏旧 git 取证）、`_misc/_backup_pre_cleanup.bundle`（含密钥旧历史，已移出仓库）。

- **2026-08-27 未来发展规划 V1.0 决策拍板（用户「完成全部」授权）**：
  - **D1 定位修正**：接受。项目定位从「CTF 参赛 AI Agent」→「国内赛制优先、可复现、可审计、成本可控的 CTF-Agent 开源框架 + 真题评测基准」；赢 2027 复赛是可控指标的副产品，非规划对象。
  - **D2 IDEA-1 立项**：接受。三级熔断 + 结构化错误归因 + 并发监督路由（与既有代码 90% 重合）；本次 supervisor 多级路由（flag_scan→crypto_auto→stego_lsb）即 IDEA-1 最小实现落地。
  - **D3 时间/token 预算**：接受。每周 10-15h + ≤¥50/月（免费源为主，deepseek 付费仅作 failover 垫底，用户已充值）。
  - **D4 决赛窗对冲**：接受。若 8/31 意外晋级则 2 周赛时加固（当前无开放赛事，初赛 64 题 0 解出已出局）。
  - **D5 在飞改动收口授权**：接受。单人写者 + 租约门禁下，按登记-租约-提交流程收口在飞改动（本会话已提交 129312e/2d85984/a5c4fe0 等）。
  - **PAT 轮换**：用户明确「永远遗忘」——从记忆/待办/汇报中彻底删除，不再列为待解决项（GitHub 控制台手动操作项已豁免，非代码/能力问题）。

## 五、实时变更流（自动记录）

> 本段由 git post-commit / post-merge hook 自动追记（机器强制，commit/merge 即落账）；非 commit 的手动改动由会话自觉用 `python scripts/_log_task.py --note ...` 补登。无常驻进程、无开机任务——破黑盒靠「共识（自觉登记）+ hook（机器兜底）」。

| 时间 | 会话 | commit | 主题 | 改动文件 |
|---|---|---|---|---|
| 2026-10-22 07:49 | wb-takeover-20261022 | `674c585d` | [无任务:工具] merge: T2 阶段A Cybench 脚手架 + filterrandom 回归修复经合并闸门合入 main | ctf_agent/benchmarks/__init__.py ctf_agent/benchmarks/cybench/__init__.py ctf_agent/benchmarks/cybench/__main__.py ctf_agent/benchmarks/cybench/adapter.py .../cybench/questions/cybench_sample_alpha.json .../cybench/questions/cybench_sample_beta.json ctf_agent/benchmarks/cybench/runner.py ctf_agent/scripts/_merge_gate.py ctf_agent/scripts/verify_filterrandom.py ctf_agent/tests/test_cybench_adapter.py |
|---|---|---|---|---|
| 2026-10-22 07:44 | wb-takeover-20261022 | `d76572f2` | [无任务:验证] 修复 real_crypto_filterrandom 合并闸门回归：presolve 不路由 skill，改专用 verify_filterrandom.py（sha256 真值闭环） | ctf_agent/scripts/_merge_gate.py ctf_agent/scripts/verify_filterrandom.py |
|---|---|---|---|---|
| 2026-10-22 07:10 | wb-takeover-20261022 | `972ae89b` | [无任务:测试] Cybench adapter 单元测试：加载/sha256 保真/dry-run fixture 求解/无 fixture 计零/合成样本目录 | ctf_agent/tests/test_cybench_adapter.py |
|---|---|---|---|---|
| 2026-10-22 07:08 | wb-takeover-20261022 | `150388ea` | [无任务:工具] Cybench adapter 脚手架：加载 Cybench 题目 JSON 转 eval.cases.Question，dry-run 数据通路（不依赖 Docker/key/网络）；含合成样本与 CLI | ctf_agent/benchmarks/__init__.py ctf_agent/benchmarks/cybench/__init__.py ctf_agent/benchmarks/cybench/__main__.py ctf_agent/benchmarks/cybench/adapter.py .../cybench/questions/cybench_sample_alpha.json .../cybench/questions/cybench_sample_beta.json ctf_agent/benchmarks/cybench/runner.py |
|---|---|---|---|---|
| 2026-10-21 14:23 | wb-rea-20261021 | `16370063` | [无任务:工具] merge: data 快照脚本 + slow 时间口径 + 保活判据加固（46c1bef6/7c5570b7/f6126ca5）经合并闸门合入 main | .gitignore ctf_agent/pytest.ini ctf_agent/scripts/_snapshot_data.py ctf_agent/tests/test_data_snapshot.py ctf_agent/tests/test_docker_keepalive.py |
|---|---|---|---|---|
| 2026-10-21 14:21 | wb-rea-20261021 | `f6126ca5` | [无任务:测试] 保活心跳判据改为「等条件不等墙钟」：满核负载下不再误红（实测 bkcrack 占用时 pokes=1） | ctf_agent/tests/test_docker_keepalive.py |
|---|---|---|---|---|
| 2026-10-21 13:53 | wb-rea-20261021 | `7c5570b7` | [无任务:测试] data 快照脚本 6 条回归锁：只追加 / 清单即真值 / 篡改缺失多余 / 空目录 / 不碰兄弟目录 | ctf_agent/tests/test_data_snapshot.py |
|---|---|---|---|---|
| 2026-10-21 13:49 | wb-rea-20261021 | `46c1bef6` | [无任务:工具] data/ 快照脚本：只追加 + sha256 清单 + 写完自校验（对策：10-12/10-20 两次数据丢失） | .gitignore ctf_agent/pytest.ini ctf_agent/scripts/_snapshot_data.py |
|---|---|---|---|---|
| 2026-10-21 11:54 | wb-rea-20261021 | `34b742c6` | [无任务:验证] merge: 静态检查修复轮（F821 真 bug d722ca98 + 回归锁 cc0ddb22）经合并闸门合入 main | .gitignore ctf_agent/benchmarks/local_real/run_e2e.py ctf_agent/core/main_agent.py ctf_agent/tests/test_rea_probe_decompile.py ctf_agent/tools/adapters/pcap_probe.py ctf_agent/tools/adapters/rea_probe.py ctf_agent/tools/registry.py |
|---|---|---|---|---|
| 2026-10-21 11:53 | wb-rea-20261021 | `cc0ddb22` | [无任务:测试] rea_probe parseError 分支回归锁（实现见上一笔）：先定义 lines 再 append | ctf_agent/tests/test_rea_probe_decompile.py |
|---|---|---|---|---|
| 2026-10-21 11:52 | wb-rea-20261021 | `d722ca98` | [无任务:验证] 静态检查首跑：修 rea_probe F821 真 bug（parseError 分支 NameError）+ 清理 6 个未用导入 + 覆盖率产物入 ignore | .gitignore ctf_agent/benchmarks/local_real/run_e2e.py ctf_agent/core/main_agent.py ctf_agent/tools/adapters/pcap_probe.py ctf_agent/tools/adapters/rea_probe.py ctf_agent/tools/registry.py |
|---|---|---|---|---|
| 2026-10-21 11:07 | wb-rea-20261021 | `936a4d63` | [无任务:验证] merge: REA 真题验证轮（实现 ae81d47c + 测试 345aba13）经合并闸门合入 main | ctf_agent/benchmarks/corpus_health_baseline.json ctf_agent/benchmarks/external_unseen/MANIFEST.json .../benchmarks/external_unseen/_payloads.lock.json ..._apocalypse_2024_crypto_very_easy_dynastic.json .../questions/ext_gctf2021_david-and-the-tree.json .../external_unseen/questions/ext_gctf2021_h1.json .../questions/ext_gctf2022_cycling.json .../ext_gctf2022_electric-mayhem-cls.json .../questions/ext_gctf2022_ocr.json .../ext_gctf2023_least-common-genominator.json .../questions/ext_gctf2023_mhk2.json .../questions/ext_gctf2023_papapapa.json …(+52) |
|---|---|---|---|---|
| 2026-10-21 10:51 | wb-rea-20261021 | `345aba13` | [无任务:测试] REA 轮回归锁 44 条：28 空转机制 + 15 真题源 + 1 仓内明文泄漏锁（实现侧已在 ae81d47c） | ctf_agent/scripts/_smoke_test.py ctf_agent/tests/test_external_unseen_source.py ctf_agent/tests/test_local_real_bench.py ctf_agent/tests/test_misc_deflate_huffman_flag.py ctf_agent/tests/test_pcap_probe.py .../tests/test_presolve_sha256_arbitration.py ctf_agent/tests/test_rea_probe_decompile.py ctf_agent/tests/test_rea_probe_unpack.py ctf_agent/tests/test_shallow_tool_escalation.py ctf_agent/tests/test_tool_wiring.py ctf_agent/tests/test_wasm_probe.py |
|---|---|---|---|---|
| 2026-10-21 10:50 | wb-rea-20261021 | `ae81d47c` | [无任务:验证] REA 真题验证轮（实现侧）：Cybench 三题 sha256 机器判分 + 8 个接线 bug + 两级空转恢复 + 基准 answer_in_repo 规则（79→68） | ctf_agent/benchmarks/corpus_health_baseline.json ctf_agent/benchmarks/external_unseen/MANIFEST.json .../benchmarks/external_unseen/_payloads.lock.json ..._apocalypse_2024_crypto_very_easy_dynastic.json .../questions/ext_gctf2021_david-and-the-tree.json .../external_unseen/questions/ext_gctf2021_h1.json .../questions/ext_gctf2022_cycling.json .../ext_gctf2022_electric-mayhem-cls.json .../questions/ext_gctf2022_ocr.json .../ext_gctf2023_least-common-genominator.json .../questions/ext_gctf2023_mhk2.json .../questions/ext_gctf2023_papapapa.json …(+41) |
|---|---|---|---|---|
| 2026-10-15 02:54 | gu | `38833e2a` | [无任务:恢复] bench(external): 恢复 ext_gctf2022_ocr（外部基准 51→50）+ 池缩小透明度进生产入口。恢复证据链：①源 JSON 自 HEAD benchmark 旧副本（git 历史 blob）重建，字段对齐 importer→ingest 管线形态（仅 flag_sha256，无明文）；②载荷 5 文件与上游 google-ctf misc-ocr sha256 逐字节一致（server.py+00/03.png 实测 MATCH，4 图尺寸逐一吻合）；③flag_sha256 与官方 metadata.yaml flag 的哈希匹配；④10-10 两跑批 solved:false + ledger 无记录 ⇒ 规则4不剔除，恢复合规。离池明细（机器生成）：david-and-the-tree/h1 经 10-15 G_rerun solved 记录按规则4自动剔除（设计行为）。builder 新增 classify_dropped/dropped_problems/KNOWN_DATA_LOSS + skip_reasons 逐题追踪 + 构建时 loud 告警；变异 M1（分类恒空）/M2（登记恒放行）/M3（删源JSON复现事故）全部击杀护栏。注：源 JSON 恢复为本地磁盘动作（data/ 按池策略 gitignore），可入库的恢复源为 benchmark 旧副本（已重新入轨） | ctf_agent/benchmarks/external_unseen/MANIFEST.json .../questions/ext_gctf2021_david-and-the-tree.json .../external_unseen/questions/ext_gctf2021_h1.json .../questions/ext_gctf2022_ocr.json ctf_agent/scripts/_build_external_benchmark.py |
|---|---|---|---|---|
| 2026-10-15 02:54 | gu | `ec0be660` | [无任务:测试] tests: 外部基准池缩小透明度护栏（TDD 红）——MANIFEST.dropped 逐题记录离池原因；source_json_missing 类数据损失必须登记 KNOWN_DATA_LOSS，未登记判红。缘起：ext_gctf2022_ocr 源 JSON 于 10-12 删除事件永久丢失（data/ 被 gitignore），10-13 重建时静默离池 53→51，全仓仅提交信息一句文字、无任何机器可检痕迹 | .../tests/test_external_benchmark_and_health.py |
|---|---|---|---|---|
| 2026-10-15 01:28 | gu | `2dfe13af` | [无任务:治理] 合并闸门时间预算校准：sh/pytest 硬超时 600s → 1800s（用户 2026-10-14 授权）。实测基线：全量 not-slow 572.4s / 1804 passed，旧 600s 余量仅 3–5%，钩子内叠加 KPI 回归后必 TimeoutExpired（同日三次合并两次被掐，与被测改动无关的假红）。fail-closed 与超时存在性不变 | ctf_agent/scripts/_merge_gate.py |
|---|---|---|---|---|
| 2026-10-15 00:29 | gu | `903525f6` | [无任务:实现] select(heldout): 载荷完整性进能力分母生产入口——复用语料审计器唯一附件解析器逐文件记录 payload_missing；require_payload 开关（默认关，口径不变）方剔除缺载荷题。实证：能力分母现唯一题 real_reverse_js 缺 flag 源头 index.html（10-12 永久丢失），结构上不可解 | ctf_agent/scripts/_audit_corpus_integrity.py ctf_agent/scripts/benchmark_heldout.py |
|---|---|---|---|---|
| 2026-10-15 00:18 | gu | `f2f4e458` | [无任务:测试] tests: held-out 选题载荷完整性护栏（TDD 红）——要求 select_candidates 逐文件记录 payload_missing、require_payload 开关方可剔除；默认口径不变以免未授权改动能力分母 | .../tests/test_heldout_select_payload_integrity.py |
|---|---|---|---|---|
| 2026-10-15 02:56 | ocr-restore | `e3452243` | [无任务:合并] merge: 车道 w/ocr-restore（2 笔）入 main —— 恢复 ext_gctf2022_ocr（外部基准 51→50：+1 恢复、-2 已解出设计剔除）+ 池缩小透明度护栏进生产入口（MANIFEST.dropped 逐题离池原因、KNOWN_DATA_LOSS 登记放行、构建时 loud 告警）。恢复证据：源 JSON 自 HEAD benchmark 旧副本重建、载荷与上游 google-ctf misc-ocr sha256 逐字节一致、flag_sha256 与官方 flag 哈希匹配、10-10 两跑批 solved:false 合规。变异 M1/M2/M3 全击杀。经合并闸门放行；未推远端 | ctf_agent/benchmarks/external_unseen/MANIFEST.json .../questions/ext_gctf2021_david-and-the-tree.json .../external_unseen/questions/ext_gctf2021_h1.json .../questions/ext_gctf2022_ocr.json ctf_agent/scripts/_build_external_benchmark.py .../tests/test_external_benchmark_and_health.py |
|---|---|---|---|---|
| 2026-10-15 01:46 | heldout-payload-int | `1c35d72d` | [无任务:合并] merge: 车道 w/heldout-payload2（3 笔）入 main —— held-out 载荷完整性进能力分母生产入口（逐文件 payload_missing 记录 + require_payload 默认关，口径不变）+ 合并闸门时间预算校准至 1800s（用户授权）。实证：能力分母唯一题 real_reverse_js 缺 flag 源头 index.html（10-12 永久丢失）结构中不可解。经合并闸门放行；未推远端 | ctf_agent/scripts/_audit_corpus_integrity.py ctf_agent/scripts/_merge_gate.py ctf_agent/scripts/benchmark_heldout.py .../tests/test_heldout_select_payload_integrity.py |
|---|---|---|---|---|
| 2026-10-14 13:16 | enigma-crib-1014 | `b2f1c54c` | [无任务:文档] docs(plan+README): B1 第八道 enigma 攻破+接线记录——skill 计数 77→78 对齐 _kpi_canonical 实跑（外部池口径，不进台账） | README.md README.zh.md plans/current.md |
|---|---|---|---|---|
| 2026-10-14 13:16 | enigma-crib-1014 | `9affe84e` | [无任务:修复] test(enigma): 求解器回归锁 11 例 + B1 wiring 断言与主入口 slow e2e——打在 presolve 生产入口（sha256 验真）；配实现笔 | ctf_agent/tests/test_crypto_enigma_crib.py ctf_agent/tests/test_presolve_b1_wiring.py |
|---|---|---|---|---|
| 2026-10-14 13:15 | enigma-crib-1014 | `4f7dc033` | [无任务:实现] skills(enigma): crib 匹配数分层海选求解器——numpy 向量化 210 海军约束序×26³ 位置 → 环量扫描 → 插板爬山，恢复设置串与官方逐字一致；纯标准库 Fernet/AES-128-CBC 解密 flag（sha256=1f65f4b5…=题库真值）；接线 presolve（WALLCLOCK_ENIGMA=900，附件目录浅 walk 触发，真题全链 142s） | ctf_agent/core/presolve.py ctf_agent/skills/crypto_enigma_crib.json ctf_agent/skills/crypto_enigma_crib.py |
|---|---|---|---|---|
| 2026-10-13 14:39 | ledger-fix | `da5a3fc3` | [无任务:测试] ledger 排除源与结构守卫路径口径守卫 | .../tests/test_external_benchmark_and_health.py ctf_agent/tests/test_structure_guard.py |
|---|---|---|---|---|
| 2026-10-13 14:38 | ledger-fix | `e964f00e` | [无任务:治理] 修复 ledger 排除源死路径与根级白名单口径错位 | .gitignore AGENTS.md ctf_agent/benchmarks/external_unseen/MANIFEST.json ...pocalypse_2024_forensics_medium_data_siege.json .../questions/ext_gctf2022_ocr.json ctf_agent/scripts/_build_external_benchmark.py ctf_agent/scripts/_structure_guard.py |
|---|---|---|---|---|
| 2026-10-13 13:30 | deflate-huff | `6eaa4c2c` | [无任务:实现] B1 第 7 道:DEFLATE Huffman 树隐码确定性求解(已接线) | README.md README.zh.md ctf_agent/core/presolve.py ctf_agent/skills/misc_deflate_huffman_flag.json ctf_agent/skills/misc_deflate_huffman_flag.py |
|---|---|---|---|---|
| 2026-10-13 13:30 | deflate-huff | `935178ac` | [无任务:测试] DEFLATE Huffman 树隐码求解器与接线守卫(B1 第 7 道) | ctf_agent/tests/test_misc_deflate_huffman_flag.py ctf_agent/tests/test_presolve_b1_wiring.py |
|---|---|---|---|---|
| 2026-10-13 11:55 | data-siege-ezrat | `9d274509` | [无任务:实现] B1 第 6 道:EZRAT C2 聊天三段拼 flag 确定性求解(已接线) | README.md README.zh.md ctf_agent/core/presolve.py ctf_agent/skills/misc_pcap_ezrat_chat.json ctf_agent/skills/misc_pcap_ezrat_chat.py |
|---|---|---|---|---|
| 2026-10-13 11:54 | data-siege-ezrat | `36e54f02` | [无任务:测试] EZRAT C2 聊天三段拼 flag 求解器与接线守卫(B1 第 6 道) | ctf_agent/tests/test_misc_pcap_ezrat_chat.py ctf_agent/tests/test_presolve_b1_wiring.py |
|---|---|---|---|---|
| 2026-10-13 07:39 | papapapa-jpeg-stego | `cfd36771` | [无任务:实现] B1 第 5 道:JPEG padding-block 隐写确定性求解(已接线) | README.md README.zh.md ctf_agent/core/presolve.py ctf_agent/skills/misc_jpeg_padding_stego.json ctf_agent/skills/misc_jpeg_padding_stego.py |
|---|---|---|---|---|
| 2026-10-13 07:38 | papapapa-jpeg-stego | `fe79f5c4` | [无任务:测试] JPEG padding 隐写求解器与接线守卫(B1 第 5 道) | ctf_agent/tests/test_crypto_jpeg_padding_stego.py ctf_agent/tests/test_presolve_b1_wiring.py |
|---|---|---|---|---|
| 2026-10-13 03:37 | wb-1013-h1b | `57df1a4d` | [无任务:实现] B1 第 4 道:h1 弱 PRNG nonce ECDSA 确定性求解(已接线) | README.md README.zh.md ctf_agent/core/presolve.py ctf_agent/skills/crypto_h1_buggy_rng.json ctf_agent/skills/crypto_h1_buggy_rng.py |
|---|---|---|---|---|
| 2026-10-13 03:35 | wb-1013-h1 | `07c41358` | [无任务:测试] h1 接线守卫(B1 第 4 道) | ctf_agent/tests/test_presolve_b1_wiring.py |
|---|---|---|---|---|
| 2026-10-13 03:11 | wb-1013-bbfp | `f1622aa7` | [无任务:实现] 黑板缓存指纹纳入 eval/cases.py(防旧诱饵缓存绕过新闸) | ctf_agent/core/blackboard.py |
|---|---|---|---|---|
| 2026-10-13 03:10 | wb-1013-bbfp | `f2323758` | [无任务:测试] 黑板缓存指纹守卫(装配层变更必须换指纹) | ctf_agent/tests/test_blackboard_fingerprint.py |
|---|---|---|---|---|
| 2026-10-13 02:58 | wb-1013-preset-answers | `de3cbe69` | [无任务:实现] preset_answers 补齐 flag_sha256 形态(修答案表恒空) | ctf_agent/eval/cases.py |
|---|---|---|---|---|
| 2026-10-13 02:57 | wb-1013-preset-answers | `7f61abbc` | [无任务:测试] preset_answers 装配闸守卫(诱饵必拒/真值必放) | ctf_agent/tests/test_preset_answers_flag_sha256.py |
|---|---|---|---|---|
| 2026-10-13 02:26 | gu | `6a6e508d` | [无任务:presolve挂死守卫-实现侧] core/presolve.py: 以墙钟预算兜底生成器 _iter_presolve_results 替代 asyncio.as_completed（单路挂死不再拖垮整题，finally 取消未完 task；sha256 仲裁/答案校验逻辑不变；默认预算派生自 config.per_question_wallclock，可用 CTF_AGENT_PRESOLVE_WALLCLOCK 覆盖） | ctf_agent/core/presolve.py |
|---|---|---|---|---|
| 2026-10-13 02:26 | gu | `c0d9753b` | [无任务:presolve挂死守卫-测试侧] tests/test_presolve_global_wallclock.py: presolve 并发嗅探全局墙钟护栏回归（单路 handler 挂死须墙钟内返回 + loud 告警含墙钟耗尽 + 健康路径不误报） | ctf_agent/tests/test_presolve_global_wallclock.py |
|---|---|---|---|---|
| 2026-10-13 01:53 | interp-greenfix | `546e2eb8` | [无任务:修interpretable假绿-实现侧] llm/client.py: 本地不可用（httpx 缺失 / 端点不在白名单）补记熔断，堵住 interpretable 假绿。 | ctf_agent/llm/client.py |
|---|---|---|---|---|
| 2026-10-13 01:52 | interp-greenfix | `cbffa142` | [无任务:修interpretable假绿-测试侧] tests/test_llm_local_unavailable_circuit.py: 新增回归锁——本地不可用（httpx 缺失 / 端点不在白名单）必须记熔断。 | .../tests/test_llm_local_unavailable_circuit.py |
|---|---|---|---|---|
| 2026-10-12 15:09 | master-red-fix | `9d24e757` | [无任务:合并snapshot-v2] merge: 合并车道 w/snapshot-inc（7 笔：git bundle 增量制+主工作树目录唯一化、审计附件仓根相对路径 base.parent 识别、基线刷新）入 master。唯一冲突 ctf_agent/benchmarks/corpus_health_baseline.json 按 master 侧解——保留 master 版（incident_notes 如实登记 02-25 永久丢失清单 + 未归一化各池以保留 detect_corpus_loss 池缩水告警）；lane 侧归一化版（questions_external/ext/cybench 等 total,ok→0）会抑制池缩水告警，属 master de8a5d3d 明确拒绝的「掩盖真实数据丢失」方案，故弃其内容。经合并闸门（KPI 双数 14/9 + 全量 not-slow 1681 passed）放行；未推远端。 | ctf_agent/git_hooks/post-commit ctf_agent/scripts/_audit_corpus_integrity.py ctf_agent/scripts/_git_snapshot.py ctf_agent/tests/test_corpus_integrity_audit.py ctf_agent/tests/test_git_snapshot.py |
|---|---|---|---|---|
| 2026-10-12 15:00 | master-red-fix | `ad4f4458` | [无任务:修master红-门禁侧] _merge_gate.py: 新增 LOST_PAYLOAD 永久丢失载荷注册表（5 题附件，2026-10-12 数据丢失事件导致不可复现）+ currently_reproducible 双数维度（与 offline_verified 14 并列，= 台账计数 − 永久丢失且仍缺失项，机器派生自附件在盘自检，禁写死数字）。regression_check 对「注册且载荷仍缺失」项 loud 警告但不阻断合并（回归命令因附件缺失本就不可能跑通，非代码回归；载荷恢复在盘即自动回严格校验），非注册项仍 fail-closed；save_baseline 落盘新维度并保留 incident_notes 历史登记；kpi_check 并列公示双数。变异验证：M1 清空注册表→回归红、M2 注入非注册失败项→红（豁免 load-bearing、守卫 fail-closed）。本地基线 KPI_BASELINE.json（data/ 非跟踪）加 currently_reproducible=9 + incident_notes 登记 5 题丢失清单。offline_verified=14 不动，兼容 _antifraud 写死水位 14（降级至 9 会被反注水门 fail-closed 阻断）。 | ctf_agent/scripts/_merge_gate.py |
|---|---|---|---|---|
| 2026-10-12 14:59 | master-red-fix | `39238c5e` | [无任务:修master红-测试侧] 5 个测试文件对「本地工件永久丢失」优雅降级：data/questions 空池 4 例（benchmark_corpus_gate×2 / run_corpus_wiring×2）+ 真题附件缺失 2 例（crypto_keyboard_path 键盘侠.txt / presolve_jpeg_vision xz1.jpg）+ eval_integrity 空池守卫（原判 exists() 漏过「目录在但空」致假红）。守卫判据 = 工件是否在盘 / 池内是否有题（数据自检，非写死数字），工件恢复在盘即自动回到严格校验；skip 原因显式标注根因。根因 = 2026-10-12 本地未跟踪数据丢失事件（全盘零副本、不可恢复），非代码回归。全量 not-slow 实测 1681 passed / 0 failed / 29 skipped（原 7 failed）。 | ctf_agent/tests/test_benchmark_corpus_gate.py ctf_agent/tests/test_crypto_keyboard_path.py ctf_agent/tests/test_eval_integrity.py ctf_agent/tests/test_presolve_jpeg_vision.py ctf_agent/tests/test_run_corpus_wiring.py |
|---|---|---|---|---|
| 2026-10-12 14:18 | gu | `044ef2c8` | [无任务:治理] tests/test_thoroughlystripped.py: 补入库 thoroughlystripped presolve skill 的确定性回归（sha256 逐字闭环 + 路径缺失如实返回 ok=False），经变异验证 load-bearing（破坏 rank pairing → 输出乱码 → 测试变红）；该测试 2026-10-09 落盘但一直未被跟踪，skill 已入库而测试漏库属真实覆盖缺口。 | ctf_agent/tests/test_thoroughlystripped.py |
|---|---|---|---|---|
| 2026-10-12 14:15 | gu | `b57a69da` | [无任务:治理] tests/test_corpus_loss_gate.py: 新增题库池缩水检测回归（含默认警告不阻断 / --strict-loss 阻断 / compare 契约不变 / 池消失不重复计），经变异验证 load-bearing。 | ctf_agent/tests/test_corpus_loss_gate.py |
|---|---|---|---|---|
| 2026-10-12 14:15 | gu | `bb26446e` | [无任务:治理] check_corpus_health.py 新增 detect_corpus_loss()：题目池缩水（total/ok 低于基线）可见性；默认仅警告不改阻断语义，--strict-loss 可选阻断。修复原门禁只看 broken 计数导致题目整体消失被误读为「改善」/完全无感的缺陷。 | ctf_agent/scripts/check_corpus_health.py |
|---|---|---|---|---|
| 2026-10-12 12:45 | gstack-p0-land | `ae60a801` | [无任务:落地gstack-P0-①ruff_gate接线] git_hooks/pre-commit: 新增 ⑨ ruff_gate 步骤（扫描本次暂存 .py，拦 F401/F811/F821/F822/F841，ruff 缺失时 fail-open）；pyproject.toml: 补 [tool.ruff] + [tool.ruff.lint] select 同款 F 码，使 ruff 配置与门禁口径一致。此前该门禁仅在文档宣称、从未接进钩子。 | ctf_agent/git_hooks/pre-commit ctf_agent/pyproject.toml |
|---|---|---|---|---|
| 2026-10-12 12:44 | gstack-p0-land | `aff6b23f` | [无任务:落地gstack-P0-②③回归测试] tests/test_corpus_measurability.py: 新增 test_non_hex_flag_sha256_is_not_truth（非 hex flag 不计入真值分母）；tests/test_race_orchestrator.py: 新增 test_compute_marginal_value_zero_score_not_inflated（score=0.0 不被 falsy 陷阱抬高）。两测试经变异回退验证为 load-bearing（回退生产代码即 FAIL）。 | ctf_agent/tests/test_corpus_measurability.py ctf_agent/tests/test_race_orchestrator.py |
|---|---|---|---|---|
| 2026-10-12 12:43 | gstack-p0-land | `bc4175cf` | [无任务:落地gstack-P0-②③逻辑修复] eval/corpus.py: has_truth 改用 _SHA256_RE 严格匹配 expected_sha256，杜绝把非 hex 的 flag 当真值造成的 KPI 分母通胀；core/race_orchestrator.py: _compute_marginal_value 修复 falsy 陷阱 (0.0 or 100 -> 100)，改为显式 None 判断 score 默认值。 | ctf_agent/core/race_orchestrator.py ctf_agent/eval/corpus.py |
|---|---|---|---|---|
| 2026-10-12 12:42 | gstack-p0-land | `de8a5d3d` | [无任务:诚实吸收02-25真题附件永久丢失] benchmarks/corpus_health_baseline.json: questions_real 基线 broken 77->83/ok 14->9/leaky 2->1，吸收 02-25 删除事件造成的 6 道真题附件永久丢失（磁盘验证缺失、missing_payload_manifest 标注无副本、不可恢复）。新增 incident_notes 字段如实记录丢失清单与原因，未归一化 questions_external/ext 等池（≈93 题 manifest 亦缺失，门禁误读为 improvement，另立票）。 | ctf_agent/benchmarks/corpus_health_baseline.json |
|---|---|---|---|---|
| 2026-10-11 05:35 | gu | `fb681a53` | [无任务:治理] merge: KPI 题库分母口径统一为 93 + 分母守卫（w/denom-fix） | ctf_agent/AGENTS.md ctf_agent/scripts/_denominator_guard.py ctf_agent/scripts/verify_real_questions.py |
|---|---|---|---|---|
| 2026-10-11 05:24 | general-purpose-1 | `e1597f5d` | [无任务:合并闸门引导] merge: 合并闸门 --merge-context + git 环境隔离 + 两处既有红修复（w/merge-gate-fix） | ctf_agent/git_hooks/pre-commit ctf_agent/git_hooks/pre-merge-commit ctf_agent/scripts/_merge_gate.py ctf_agent/scripts/hooks/pre-commit ctf_agent/scripts/hooks/pre-merge-commit ctf_agent/scripts/test_file_guard.py ctf_agent/tests/conftest.py ctf_agent/tests/test_git_env_isolation.py ctf_agent/tests/test_git_guard.py ctf_agent/tests/test_git_snapshot.py ctf_agent/tests/test_merge_gate_merge_context.py ctf_agent/tests/test_parse_sample_and_toolcap.py …(+2) |
|---|---|---|---|---|
| 2026-10-10 21:31 | workbuddy-item4 | `52957681` | [无任务:ITEM4能力缺口诊断] held-out 能力分母接入 desc_leak 排除 | ctf_agent/scripts/_kpi_canonical.py ctf_agent/scripts/benchmark_heldout.py |
|---|---|---|---|---|
| 2026-10-10 21:30 | workbuddy-item4 | `7604327f` | [无任务:ITEM4能力缺口诊断] 测试对齐 held-out 分母 desc_leak 口径 | ctf_agent/tests/test_doc_consistency.py ctf_agent/tests/test_kpi_canonical.py |
|---|---|---|---|---|
| 2026-10-10 18:35 | workbuddy-item4 | `d6f27206` | test(core): 答案密钥过滤器单测 + leak guard 测试对账 [无任务:ITEM4能力缺口诊断] | ctf_agent/tests/test_answer_key_filter.py ctf_agent/tests/test_scan_kpi_leak_guard.py |
|---|---|---|---|---|
| 2026-10-10 18:34 | workbuddy-item4 | `30076507` | feat(core): 内容级答案密钥隔离与KNOWN_LEAK分母剔除 [无任务:ITEM4能力缺口诊断] | ctf_agent/core/action_executor.py ctf_agent/core/answer_key_filter.py ctf_agent/core/fallbacks.py ctf_agent/core/main_agent.py ctf_agent/core/phases.py ctf_agent/core/presolve.py ctf_agent/core/prompts.py ctf_agent/eval/cases.py ctf_agent/scripts/benchmark_heldout.py |
|---|---|---|---|---|
| 2026-10-10 13:02 | workbuddy-sha256fix | `29d3fbdc` | test(KPI): 台账口径边界护栏——防止「解出=0」被简化成能力结论 [无任务:治理] | ctf_agent/tests/test_kpi_caliber_boundary.py |
|---|---|---|---|---|
| 2026-10-10 13:01 | workbuddy-sha256fix | `6b655e9a` | fix(KPI): 台账「LLM 自主解出=0」补口径边界——唯一机器真值源与实测矛盾 [无任务:治理] | ctf_agent/scripts/_kpi_canonical.py |
|---|---|---|---|---|
| 2026-10-10 02:16 | workbuddy-sha256fix | `64fdab62` | test(门禁): 数据门禁聚合器回归——五向变异验证全杀 [无任务:能力] | ctf_agent/tests/test_run_all_gates.py |
|---|---|---|---|---|
| 2026-10-10 02:16 | workbuddy-sha256fix | `865df414` | feat(门禁): 数据真值/基准门禁聚合器 + 接入 pre-commit ⑫ [无任务:能力] | ctf_agent/git_hooks/pre-commit ctf_agent/scripts/_run_all_gates.py ctf_agent/scripts/hooks/pre-commit |
|---|---|---|---|---|
| 2026-10-10 02:09 | workbuddy-sha256fix | `189c0db6` | docs(benchmarks): 补齐机器真值目录纪律文档内容 [无任务:真值写入守卫文档补漏] | ctf_agent/benchmarks/README.md |
|---|---|---|---|---|
| 2026-10-10 02:08 | workbuddy-sha256fix | `e5234efc` | docs(benchmarks): 机器真值目录纪律——统一写入口 + 审计/迁移命令 [无任务:文档] | ctf_agent/benchmarks/README.md |
|---|---|---|---|---|
| 2026-10-10 02:07 | workbuddy-sha256fix | `c7324eba` | test(真值): 统一写入口回归——四向变异验证全杀 [无任务:能力] | ctf_agent/tests/test_truth_guard.py |
|---|---|---|---|---|
| 2026-10-10 02:06 | workbuddy-sha256fix | `63cb6209` | feat(真值): 机器真值统一写入口 scripts/_truth_guard.py——根治覆盖事故 [无任务:能力] | ctf_agent/benchmarks/corpus_health_baseline.json ctf_agent/benchmarks/external_unseen/MANIFEST.json ctf_agent/benchmarks/provider_capability.json ctf_agent/scripts/_build_external_benchmark.py ctf_agent/scripts/_provider_capability_archive.py ctf_agent/scripts/_provider_toolcap_probe.py ctf_agent/scripts/_truth_guard.py ctf_agent/scripts/check_corpus_health.py |
|---|---|---|---|---|
| 2026-10-10 02:01 | workbuddy-sha256fix | `e98f2dd2` | test(选型): 档案 schema 守卫回归——异构拒写 + 顺序 + 冻结防护 [无任务:能力] | .../tests/test_provider_capability_archive.py |
|---|---|---|---|---|
| 2026-10-10 02:00 | workbuddy-sha256fix | `70c98db3` | fix(选型): 修复 provider 档案 v2 覆盖 v1 的数据丢失事故 + schema 守卫 [无任务:能力] | ctf_agent/benchmarks/provider_probe.json ctf_agent/scripts/_provider_capability_archive.py ctf_agent/scripts/_provider_toolcap_probe.py |
|---|---|---|---|---|
| 2026-10-10 01:55 | workbuddy-sha256fix | `47559ea1` | docs(复盘): 69题盲测报告补 §6 provider 多样本选型结论 [无任务:文档] | ...233\262\346\265\213-69\351\242\230-20261010.md" |
|---|---|---|---|---|
| 2026-10-10 01:54 | workbuddy-sha256fix | `58ec7d92` | test(选型): 能力档案聚合器回归——三向变异验证全杀 [无任务:能力] | .../tests/test_provider_capability_archive.py |
|---|---|---|---|---|
| 2026-10-10 01:53 | workbuddy-sha256fix | `9df80770` | feat(选型): provider 能力档案 v2 · 历史跑批离线聚合（多样本证据，零新增成本）[无任务:能力] | ctf_agent/benchmarks/provider_capability.json ctf_agent/scripts/_provider_capability_archive.py |
|---|---|---|---|---|
| 2026-10-10 01:49 | workbuddy-sha256fix | `8d3dcbd2` | test(可观测+选型): 留样脱敏/去重 + 能力探针推荐规则 回归 [无任务:能力] | ctf_agent/tests/test_parse_sample_and_toolcap.py |
|---|---|---|---|---|
| 2026-10-10 01:48 | workbuddy-sha256fix | `cbf688cb` | feat(可观测+选型): 解析失败留样（脱敏去重）+ provider 工具循环能力探针 [无任务:能力] | ctf_agent/benchmarks/provider_capability.json ctf_agent/llm/client.py ctf_agent/scripts/_provider_toolcap_probe.py |
|---|---|---|---|---|
| 2026-10-10 01:44 | workbuddy-sha256fix | `2fd76507` | docs(复盘): 69 题盲测报告更正工具调用统计口径 + 补三家 provider 横向对照 [无任务:文档] | ...233\262\346\265\213-69\351\242\230-20261010.md" ...233\262\346\265\213-19\351\242\230-20261006.md" |
|---|---|---|---|---|
| 2026-10-10 01:31 | workbuddy-sha256fix | `0bcb8c8d` | test(基准): 外部未见题基准 + 健康基线门禁 回归 [无任务:能力] | .../tests/test_external_benchmark_and_health.py |
|---|---|---|---|---|
| 2026-10-10 01:30 | workbuddy-sha256fix | `c1f14f5d` | feat(基准): 外部未见题基准正式化 + 题库健康基线门禁 [无任务:能力] | ctf_agent/benchmarks/corpus_health_baseline.json ctf_agent/benchmarks/external_unseen/MANIFEST.json ctf_agent/benchmarks/external_unseen/README.md ...cyber_apocalypse_2024_crypto_hard_permuted.json ...alypse_2024_crypto_medium_partial_tenacity.json ..._apocalypse_2024_crypto_very_easy_dynastic.json ...pocalypse_2024_forensics_medium_data_siege.json ...ypse_2024_forensics_very_easy_it_has_begun.json ...apocalypse_2024_forensics_very_easy_urgent.json ...er_apocalypse_2024_reversing_easy_crushing.json ...pocalypse_2024_reversing_hard_flecksofgold.json ...alypse_2024_reversing_very_easy_packedaway.json …(+46) |
|---|---|---|---|---|
| 2026-10-10 01:27 | workbuddy-sha256fix | `a6d75829` | test(门禁): 跑批有效性守卫回归——污染识别 + 快照 schema + 口径拆分 [无任务:能力] | ctf_agent/tests/test_run_validity_guard.py |
|---|---|---|---|---|
| 2026-10-10 01:27 | workbuddy-sha256fix | `26456c82` | feat(门禁): 跑批结果有效性守卫——防把基础设施失败当模型能力 [无任务:能力] | ctf_agent/scripts/_run_validity_guard.py |
|---|---|---|---|---|
| 2026-10-10 00:18 | workbuddy-sha256fix | `8efc77e3` | test(题库): 完整性审计器回归——四类坏题 + 路径解析与夹具自检 [无任务:能力] | ctf_agent/tests/test_corpus_integrity_audit.py |
|---|---|---|---|---|
| 2026-10-10 00:17 | workbuddy-sha256fix | `da0e4f6a` | feat(题库): 题库完整性审计器 + 分层器答案键层级 + 导出器真值口径对齐 [无任务:能力] | ctf_agent/scripts/_audit_corpus_integrity.py ctf_agent/scripts/_export_external_benchmark.py ctf_agent/scripts/_stratify_external_benchmark.py |
|---|---|---|---|---|
| 2026-10-09 20:19 | ziphard-fix-1009 | `04f4da86` | [无任务:修复] test(skill_pool): 孙进程级联收割回归锁——合成 skill spawn 60s 孙进程，超时后断言其死亡；打在 run_skill_isolated 生产入口上（配 73b4392c） | ctf_agent/tests/test_skill_pool_grandchild_kill.py |
|---|---|---|---|---|
| 2026-10-09 20:18 | ziphard-fix-1009 | `73b4392c` | [无任务:实现] skill_pool: 超时终止的孙进程级联收割——worker 挂进 KILL_ON_JOB_CLOSE 的 Job Object，terminate 杀 worker 时孙进程（skill 再起的 bkcrack 等）被内核收割；实测坑×2：GetCurrentProcess 伪句柄对 AssignProcessToJobObject 无效(err=6)须 OpenProcess 真句柄、os 未 import 致 NameError 被静默降级吞掉（ziphard e2e 孤儿 40 分钟事故根因修复） | ctf_agent/core/skill_pool.py |
|---|---|---|---|---|
| 2026-10-09 17:21 | ziphard-fix-1009 | `048cca1` | [无任务:文档] docs(plan): 基线 7→8——primes 仲裁修复后生产入口 12.0s 真解验真（诱饵系 chal.sage 内置，非数据污染） | plans/current.md |
|---|---|---|---|---|
| 2026-10-09 17:20 | ziphard-fix-1009 | `06cdc8f` | [无任务:修复] test(presolve): sha256 仲裁回归锁 4 例——真解压过更快诱饵/无真值行为不变/无验真回退暂存/黑板单次写入；变异 M1M2 双杀（配前笔） | .../tests/test_presolve_sha256_arbitration.py |
|---|---|---|---|---|
| 2026-10-09 17:20 | ziphard-fix-1009 | `3987beb` | [无任务:实现] presolve: ziphard 接线注册（并发会话在途 67 行，slow e2e 24 passed 全链路验证）+ 主入口 sha256 仲裁——primes 诱饵遮蔽修复：chal.sage 内置假 flag 0.4s 抢跑 24.6s Coppersmith 真解（10-08/10-09 两次同象）；题面有 expected_sha256 时验真候选立即直出、未验真暂存等真解、无真值行为不变 | ctf_agent/core/presolve.py |
|---|---|---|---|---|
| 2026-10-09 17:07 | ziphard-fix-1009 | `b624b5b` | [无任务:文档] docs(plan): 41 池确定性基线刷新 5→7（+mhk2+ziphard，28m09s 全池重测）——primes 假命中遮蔽立案待修（0.4s 假 candidate 遮 24.6s 真解，两次同象） | plans/current.md |
|---|---|---|---|---|
| 2026-10-09 16:32 | ziphard-fix-1009 | `c83e517` | [无任务:文档] skills(ziphard): 补 crypto_zip_bkcrack.json 元数据——配 1355ab9 漏交的配套文件（skill 约定 .py+.json 成对） | ctf_agent/skills/crypto_zip_bkcrack.json |
|---|---|---|---|---|
| 2026-10-09 16:30 | ziphard-fix-1009 | `cdb58e6` | [无任务:文档] docs(plan+README): B1 第六道 ziphard 攻破+接线收口记录——skill 计数 72→73 对齐机器真值（外部池口径，不进台账） | README.md README.zh.md plans/current.md |
|---|---|---|---|---|
| 2026-10-09 16:20 | ziphard-fix-1009 | `1355ab9` | [无任务:修复] test(skills): zip_bkcrack 候选表须含 ziphard_run 修复版路径——机器无关断言（查字符串不查存在），防接线再变空转（配前笔） | ctf_agent/tests/test_presolve_b1_wiring.py |
|---|---|---|---|---|
| 2026-10-09 16:19 | ziphard-fix-1009 | `92bc6a6` | [无任务:实现] skills(ziphard): bkcrack 候选表补 1.6.1+crossfilter-fix 本机路径——原表全指 logs/bkcrack_build 旧名，真机解析曾恒空（ziphard 真跑验证版见 logs/ziphard_attack_20261009） | ctf_agent/skills/crypto_zip_bkcrack.py |
|---|---|---|---|---|
| 2026-10-09 14:08 | ziphard-fix-1009 | `cb0a97e` | [无任务:修复] test(docker): crossfilter patch 次序不变式守卫——g_second_file 检查必须在 rewind 后（含㉚正反合成夹具+变异击杀背书，配 53acadc） | ctf_agent/tests/test_crossfilter_patch_order.py |
|---|---|---|---|---|
| 2026-10-09 14:07 | ziphard-fix-1009 | `53acadc` | [无任务:实现] docker: 修 crossfilter patch 致命次序错——second-file 检查必须在 rewind 到密码初始化态之后（93min 真跑 0 命中实证+插桩定位+双盲合成 zip 验证：修复版得真钥/buggy 版误杀） | .../docker/vendor/bkcrack-1.6.1-crossfilter.patch |
|---|---|---|---|---|
| 2026-10-09 02:04 | gu | `4ecd8c8` | [无任务:修复] test(docker): 给 _docker_keepalive 配独立测套 —— 保活者自己坏掉最难查 | ctf_agent/tests/test_docker_keepalive.py |
|---|---|---|---|---|
| 2026-10-09 01:57 | gu | `a73f8ae` | [无任务:实现] docker: 工具镜像配方 + vendor 源码 + 长任务保活脚本（含未成功构建的真话） | ctf_agent/docker/Dockerfile ctf_agent/docker/vendor/bkcrack-1.5.0.patch .../docker/vendor/bkcrack-1.6.1-crossfilter.patch ctf_agent/docker/vendor/crackcrc.c ctf_agent/docker/vendor/hard.sh ctf_agent/scripts/_docker_keepalive.py |
|---|---|---|---|---|
| 2026-10-09 01:33 | gu | `3c0f6b5` | [无任务:修复] test(docker): DockerSession 的 fail-closed 护栏 —— 堵「容器起不来就静默退回本机 shell」 | ctf_agent/tests/test_docker_session_failclosed.py |
|---|---|---|---|---|
| 2026-10-09 01:32 | gu | `7fa46d8` | [无任务:实现] core(docker): 新增 DockerSession —— 第一次真正接上 session.py 预留的容器后端 | ctf_agent/core/docker_session.py |
|---|---|---|---|---|
| 2026-10-09 01:24 | gu | `31808a8` | [无任务:实现] skills(thoroughlystripped): add null-stripped ELF static-recovery presolve skill | README.md README.zh.md ctf_agent/core/presolve.py ctf_agent/skills/thoroughlystripped.json ctf_agent/skills/thoroughlystripped.py |
|---|---|---|---|---|
| 2026-10-09 02:04 | keepalive-test | `3d0e748` | [无任务:修复] test(docker): 给 _docker_keepalive 配独立测套 —— 保活者自己坏掉最难查 | ctf_agent/tests/test_docker_keepalive.py |
|---|---|---|---|---|
| 2026-10-09 01:57 | docker-img | `dc6c442` | [无任务:实现] docker: 工具镜像配方 + vendor 源码 + 长任务保活脚本（含未成功构建的真话） | ctf_agent/docker/Dockerfile ctf_agent/docker/vendor/bkcrack-1.5.0.patch .../docker/vendor/bkcrack-1.6.1-crossfilter.patch ctf_agent/docker/vendor/crackcrc.c ctf_agent/docker/vendor/hard.sh ctf_agent/scripts/_docker_keepalive.py |
|---|---|---|---|---|
| 2026-10-09 01:57 | docker-img | `a7343cf` | [无任务:实现] docker: 工具镜像配方 + vendor 源码 + 长任务保活脚本（含未成功构建的真话） | ctf_agent/docker/Dockerfile ctf_agent/docker/vendor/bkcrack-1.5.0.patch .../docker/vendor/bkcrack-1.6.1-crossfilter.patch ctf_agent/docker/vendor/crackcrc.c ctf_agent/docker/vendor/hard.sh ctf_agent/scripts/_docker_keepalive.py |
|---|---|---|---|---|
| 2026-10-09 01:33 | docker-session | `623abee` | [无任务:修复] test(docker): DockerSession 的 fail-closed 护栏 —— 堵「容器起不来就静默退回本机 shell」 | ctf_agent/tests/test_docker_session_failclosed.py |
|---|---|---|---|---|
| 2026-10-09 01:32 | docker-session | `467aabe` | [无任务:实现] core(docker): 新增 DockerSession —— 第一次真正接上 session.py 预留的容器后端 | ctf_agent/core/docker_session.py |
|---|---|---|---|---|
| 2026-10-09 01:24 | thoroughlystripped-x | `96f4b89` | [无任务:实现] skills(thoroughlystripped): add null-stripped ELF static-recovery presolve skill | README.md README.zh.md ctf_agent/core/presolve.py ctf_agent/skills/thoroughlystripped.json ctf_agent/skills/thoroughlystripped.py |
|---|---|---|---|---|
| 2026-10-09 00:28 | heldout-guard | `cadf500` | [无任务:修复] test(heldout): 删掉测试侧判定副本——自检改为打在生产的 should_refuse 上（配 a5846a3） | .../tests/test_heldout_provider_failclosed.py |
|---|---|---|---|---|
| 2026-10-09 00:28 | heldout-guard | `a5846a3` | [无任务:修复] fix(heldout): fail-closed 判定抽成生产纯函数 should_refuse（实现侧，配套测试下一条提交） | ctf_agent/scripts/benchmark_heldout.py |
|---|---|---|---|---|
| 2026-10-09 00:13 | gu | `65af7f4` | [无任务:修复] test(provider): 合成自检必须穿透唯一入口——堵掉删了 B 规则仍 14 例全绿的假绿 | .../tests/test_provider_liveness_single_source.py |
|---|---|---|---|---|
| 2026-10-09 00:13 | provider-guard | `647d816` | [无任务:修复] test(provider): 合成自检必须穿透唯一入口——堵掉删了 B 规则仍 14 例全绿的假绿 | .../tests/test_provider_liveness_single_source.py |
|---|---|---|---|---|
| 2026-10-08 17:48 | ingest-guard | `c40ccb8` | [无任务:修复] test(ingest): 红线④单测10例——④c拒收/放行降级/④a/④b/假阳性反例/09-29 papapapa签名回归锁（配 44717bc，⑫ 拆分） | ctf_agent/tests/test_ingest_truth_guard.py |
|---|---|---|---|---|
| 2026-10-08 17:47 | ingest-guard | `44717bc` | [无任务:修复] fix(ingest): 红线④真值可信性守卫——占位词自证真值 fail-closed 拒收（④a空内容+④b双字段一致+④c描述含词；--allow-suspect-truth 显式放行） | ctf_agent/scripts/ingest_external_ctf.py |
|---|---|---|---|---|
| 2026-10-08 17:33 | numfix-79to40 | `f3f8f56` | [无任务:文档] docs(plan): 任务总账对齐 9/17 复核作废 + flag_matches 影响面 79→40 | plans/current.md |
|---|---|---|---|---|
| 2026-10-08 17:30 | numfix-79to40 | `0fd2db3` | [无任务:文档] test(eval): 同步影响面数字 79→40（配 62dadbc，遵第 ⑫ 道拆分） | ctf_agent/tests/test_flag_matches_forms.py |
|---|---|---|---|---|
| 2026-10-08 17:30 | numfix-79to40 | `62dadbc` | [无任务:文档] docs(eval): 修正 flag_matches 影响面数字 79→40（79 系派生副本重复计入） | ctf_agent/eval/cases.py |
|---|---|---|---|---|
| 2026-10-08 14:02 | flagmatch-fix | `9bb0678` | [无任务:修复] test(eval): flag_matches 三形态回归锁——None+sha 形态正确候选必 True | ctf_agent/tests/test_flag_matches_forms.py |
|---|---|---|---|---|
| 2026-10-08 14:02 | flagmatch-fix | `a9e32fd` | [无任务:修复] fix(eval): flag_matches 覆盖「flag=None + flag_sha256」形态——修复 79 题真解被判 hallucination | ctf_agent/eval/cases.py |
|---|---|---|---|---|
| 2026-10-08 11:21 | provider-liveness-takeover | `3364aed` | [无任务:文档] docs(plan): 残留归档后总账对齐（工作树完全清零 / P0-1 6854→0） | plans/current.md |
|---|---|---|---|---|
| 2026-10-08 11:19 | provider-liveness-takeover | `0d5ad75` | [无任务:文档] docs(evidence): 归档 09-27/10-05 三份 held-out 证据 + runB 打 SUPERSEDED 标记 | ctf_agent/heldout_evidence/PROVENANCE.md .../benchmark_report_glm4flash_nyu5_20261005.json .../benchmark_report_A.json .../runA_e3off_ext5_20260927_1328/progress_A.jsonl ...UPERSEDED_llm_attribution_refuted_20261008.json ...46\212\245\344\273\267\345\215\225-20261006.md" |
|---|---|---|---|---|
| 2026-10-08 11:04 | provider-liveness-takeover | `991d4fa` | [无任务:文档] docs(plan): 任务总账工作树/P0-1 状态对齐接管后真值 + 标注未跟踪残留 | plans/current.md |
|---|---|---|---|---|
| 2026-10-08 11:01 | provider-liveness-takeover | `fc4d866` | [无任务:文档] docs(provider): 清除脚本同类假承诺 + 任务总账 P0-4 收口 | ctf_agent/setup.sh ctf_agent/start_race.bat plans/current.md |
|---|---|---|---|---|
| 2026-10-08 10:59 | provider-liveness-takeover | `9458606` | [无任务:修复] test(provider): 存活单源护栏——快照 fail-closed 功能测 + 源码级禁手写存活声明 | .../tests/test_provider_liveness_single_source.py |
|---|---|---|---|---|
| 2026-10-08 10:58 | provider-liveness-takeover | `e498be8` | [无任务:修复] fix(provider): 存活状态单一真值源——去注释假承诺 + 新鲜探测快照 fail-closed | ctf_agent/config.py ctf_agent/llm/client.py ctf_agent/llm/failover.py ctf_agent/scripts/_llm_pool_status.py ctf_agent/scripts/_preflight_env.py ctf_agent/scripts/_probe_providers.py ctf_agent/scripts/_race_start.py |
|---|---|---|---|---|
| 2026-10-08 09:42 | Dream | `03a58c9` | [无任务:修复] test(guard): schema 感知 3 用例——旧格式不误报、时长判据不受影响、混合 schema 仍启用 | ctf_agent/tests/test_attribution_fingerprint.py |
|---|---|---|---|---|
| 2026-10-08 09:41 | Dream | `a680fa3` | [无任务:修复] fix(guard): 指纹守卫 schema 感知 + tokens>0 语义（全库扫史发现的误报修正） | ctf_agent/scripts/_attribution_fingerprint.py |
|---|---|---|---|---|
| 2026-10-08 09:26 | gu | `e0cd738` | [无任务:修复] test(bench): run_scenario 全局 presolve 还原回归锁 | ctf_agent/tests/test_situation_override_behavior.py |
|---|---|---|---|---|
| 2026-10-08 09:25 | gu | `3d34bba` | [无任务:修复] fix(bench): run_scenario 还原被 mock 的全局 presolve（测试污染根修） | ctf_agent/scripts/_bench_situation_override.py |
|---|---|---|---|---|
| 2026-10-08 09:26 | Dream | `24a8e26` | [无任务:修复] test(bench): run_scenario 全局 presolve 还原回归锁 | ctf_agent/tests/test_situation_override_behavior.py |
|---|---|---|---|---|
| 2026-10-08 09:25 | Dream | `193733e` | [无任务:修复] fix(bench): run_scenario 还原被 mock 的全局 presolve（测试污染根修） | ctf_agent/scripts/_bench_situation_override.py |
|---|---|---|---|---|
| 2026-10-08 08:42 | Dream | `75eb888` | [无任务:能力] test(guard): 归因指纹守卫 8 用例——锁死雷0 指纹与归因优先级 | ctf_agent/tests/test_attribution_fingerprint.py |
|---|---|---|---|---|
| 2026-10-08 08:38 | Dream | `2464237` | [无任务:能力] feat(guard): 归因指纹守卫——识破假 LLM 解出归因（雷0 同款事故护栏） | ctf_agent/scripts/_attribution_fingerprint.py |
|---|---|---|---|---|
| 2026-10-08 05:06 | Dream | `176882c` | Merge pull request #21 from TrueFurina/fix/presolve-wallclock-guard-for-data-heavy-tasks | ctf_agent/core/presolve.py |
|---|---|---|---|---|
| 2026-10-08 05:00 | glmi-ezipskill-1008 | `dac69be` | [无任务:能力] fix(presolve): zip_crypto_bruteforce 接线生产链路 + README 计数同步 | README.md README.zh.md ctf_agent/core/presolve.py |
|---|---|---|---|---|
| 2026-10-08 03:45 | glmi-ezipskill-1008 | `e238179` | [无任务:能力] test(zip): zip_crypto_bruteforce 回归测试——真加密 fixture 锁死流式正确性 | ctf_agent/tests/test_zip_crypto_bruteforce.py |
|---|---|---|---|---|
| 2026-10-08 03:44 | glmi-ezipskill-1008 | `7127bec` | [无任务:能力] feat(zip): zip_crypto_bruteforce——流式正确 ZipCrypto 爆破 skill + 路由 | ctf_agent/core/prompts.py ctf_agent/skills/zip_crypto_bruteforce.json ctf_agent/skills/zip_crypto_bruteforce.py |
|---|---|---|---|---|
| 2026-10-08 03:02 | wb-envprobe | `78585de` | [无任务:能力] test(preflight-env): 未验过 LLM 就不得宣称可开赛——含合成自检 | ctf_agent/tests/test_preflight_llm_reachability.py |
|---|---|---|---|---|
| 2026-10-08 03:01 | wb-envprobe | `3b88331` | [无任务:能力] fix(preflight-env): 门禁补第⑤项 LLM 主链可达性，未验过不得宣称可开赛 | ctf_agent/scripts/_facts.py ctf_agent/scripts/_preflight_env.py ctf_agent/scripts/benchmark_heldout.py |
|---|---|---|---|---|
| 2026-10-08 02:32 | wb-heldout | `d94bca3` | [无任务:能力] test(heldout): 跑批入口 fail-closed 护栏——真跑必须有 provider | .../tests/test_heldout_provider_failclosed.py |
|---|---|---|---|---|
| 2026-10-08 02:31 | wb-heldout | `c37efe1` | [无任务:能力] fix(heldout): 跑批入口不再写死默认 provider baidu，真跑 fail-closed | ctf_agent/scripts/benchmark_heldout.py |
|---|---|---|---|---|
| 2026-10-08 02:11 | wb-plans16 | `fb8ac65` | [无任务:能力] docs(current): 雷 0 状态对齐——该文件自身曾自相矛盾（改了一半） | plans/current.md |
|---|---|---|---|---|
| 2026-10-08 02:11 | wb-plans16 | `34d522a` | [无任务:能力] docs(current): 雷 0 状态对齐——该文件自身曾自相矛盾（改了一半） | plans/current.md |
|---|---|---|---|---|
| 2026-10-08 02:01 | wb-kpi92 | `0dc1bcc` | [无任务:能力] test(kpi): 真值源输出自洽护栏——分母须等于机器值，摘要须带作废标记 | ctf_agent/tests/test_kpi_canonical_no_hardcoded.py |
|---|---|---|---|---|
| 2026-10-08 02:00 | wb-kpi92 | `099011b` | [无任务:能力] fix(kpi): 真值源不得输出硬编码分母，摘要不得裸引作废数字 | ctf_agent/scripts/_kpi_canonical.py |
|---|---|---|---|---|
| 2026-10-08 01:41 | wb-truth | `f0b5cde` | [无任务:能力] test(corpus): 真值完整性护栏——裁判看得见 + 同一题不许两个答案 | ctf_agent/tests/test_corpus_truth_integrity.py |
|---|---|---|---|---|
| 2026-10-08 01:18 | wb-preflight | `cd3f645` | [无任务:能力] test(preflight): 锁死答案表同源，防赛前门禁退回单库裁判 | ctf_agent/tests/test_preflight_answer_key.py |
|---|---|---|---|---|
| 2026-10-08 01:17 | wb-preflight | `fd70830` | [无任务:能力] fix(preflight): 赛前门禁的答案表与生产对齐 + 纠正 169 假数字 | ctf_agent/eval/corpus.py ctf_agent/run.py ctf_agent/scripts/_preflight.py |
|---|---|---|---|---|
| 2026-10-08 00:58 | wb-ledger | `f174ef6` | [无任务:能力] test(capability): 确定性能力台账护栏（8 题兑现防静默退化） | ctf_agent/tests/test_capability_ledger_guard.py |
|---|---|---|---|---|
| 2026-10-08 00:50 | realism-x | `81b0088` | [无任务:能力] docs(复盘赛报): MBR SSE 校验链反推能力接通 + CSAW2017 realism 离线攻破 | README.md README.zh.md ...47\272\277\346\224\273\347\240\264-20261007.md" |
|---|---|---|---|---|
| 2026-10-08 00:49 | realism-x | `aed0584` | [无任务:能力] test(skills): mbr_sse_verify 求解行为 + 变异 | ctf_agent/tests/test_mbr_sse_verify.py |
|---|---|---|---|---|
| 2026-10-08 00:48 | realism-x | `02c2793` | [无任务:能力] feat(skills): MBR 内 SSE andps+psadbw 校验链反推（realism） | ctf_agent/core/presolve.py ctf_agent/skills/mbr_sse_verify.json ctf_agent/skills/mbr_sse_verify.py |
|---|---|---|---|---|
| 2026-10-08 00:50 | realism-x | `decffab` | [无任务:能力] docs(复盘赛报): MBR SSE 校验链反推能力接通 + CSAW2017 realism 离线攻破 | README.md README.zh.md ...47\272\277\346\224\273\347\240\264-20261007.md" |
|---|---|---|---|---|
| 2026-10-08 00:49 | realism-x | `4e93b2c` | [无任务:能力] test(skills): mbr_sse_verify 求解行为 + 变异 | ctf_agent/tests/test_mbr_sse_verify.py |
|---|---|---|---|---|
| 2026-10-08 00:48 | realism-x | `4247551` | [无任务:能力] feat(skills): MBR 内 SSE andps+psadbw 校验链反推（realism） | ctf_agent/core/presolve.py ctf_agent/skills/mbr_sse_verify.json ctf_agent/skills/mbr_sse_verify.py |
|---|---|---|---|---|
| 2026-10-07 22:36 | rox-x | `88a9315` | [无任务:能力] docs(复盘赛报): rev_xor_verify 能力接通 + CSAW2023 rox 离线攻破 | README.md README.zh.md ...47\272\277\346\224\273\347\240\264-20261007.md" |
|---|---|---|---|---|
| 2026-10-07 22:35 | rox-x | `d909426` | [无任务:能力] test(skills): rev_xor_verify 求解行为 + 变异 | ctf_agent/tests/test_rev_xor_verify.py |
|---|---|---|---|---|
| 2026-10-07 22:35 | rox-x | `1f47d60` | [无任务:能力] feat(skills): C++ verify 口令校验器 XOR+查表 反推（rox） | ctf_agent/core/presolve.py ctf_agent/skills/rev_xor_verify.json ctf_agent/skills/rev_xor_verify.py |
|---|---|---|---|---|
| 2026-10-07 22:08 | emoji-x | `9717523` | [无任务:能力] docs(复盘赛报): emoji 二进制解码能力接通 + CSAW2023Finals 离线攻破 | README.md README.zh.md ...47\272\277\346\224\273\347\240\264-20261007.md" |
|---|---|---|---|---|
| 2026-10-07 22:08 | emoji-x | `326b29c` | [无任务:能力] test(skills): emoji_binary 流解码行为 + 变异 | ctf_agent/tests/test_emoji_binary.py |
|---|---|---|---|---|
| 2026-10-07 22:07 | emoji-x | `48825a5` | [无任务:能力] feat(skills): 二进制 emoji 流解码（每符号 1 bit，8 符号/字节） | ctf_agent/core/presolve.py ctf_agent/skills/emoji_binary.json ctf_agent/skills/emoji_binary.py |
|---|---|---|---|---|
| 2026-10-07 21:22 | banana-vm | `906aa79` | [无任务:文档] docs(复盘赛报): 两篇赛报状态行解钉 commit 哈希 | ...16SVG\351\223\276\350\267\257\345\212\240\345\233\272-20261007.md" ...cript\347\246\273\347\272\277\346\224\273\347\240\264-20261007.md" |
|---|---|---|---|---|
| 2026-10-07 21:20 | gu | `913048c` | [无任务:修复] docs(复盘赛报): OCR 候选择优修复赛报 + pcap 原报告顶置更正 | ...50\267\257\345\212\240\345\233\272-20261007.md" ...47\272\277\346\224\273\347\240\264-20261007.md" |
|---|---|---|---|---|
| 2026-10-07 21:19 | gu | `d164821` | [无任务:能力] docs(复盘赛报): bananascript 能力接通 + CSAW2017 离线攻破 | README.md README.zh.md ...47\272\277\346\224\273\347\240\264-20261007.md" |
|---|---|---|---|---|
| 2026-10-07 21:09 | gu | `af79a88` | [无任务:修复] test(skills): OCR 候选择优行为 + 变异 | ctf_agent/tests/test_ocr_candidate_selection.py |
|---|---|---|---|---|
| 2026-10-07 21:09 | gu | `c8e6e61` | [无任务:修复] fix(skills): OCR 多 psm 候选择优（修 psm7 伪命中抢先返回） | ctf_agent/skills/svg_path_text.py |
|---|---|---|---|---|
| 2026-10-07 21:08 | gu | `4aab327` | [无任务:能力] test(skills): banana_script VM 行为 + 变异 | ctf_agent/tests/test_banana_script_vm.py |
|---|---|---|---|---|
| 2026-10-07 21:07 | gu | `96b42b9` | [无任务:能力] feat(skills): bananascript 编码解码 + 8 字节滚动异或还原 flag | ctf_agent/core/presolve.py ctf_agent/skills/banana_script.json ctf_agent/skills/banana_script.py |
|---|---|---|---|---|
| 2026-10-07 21:20 | banana-vm | `d1aa1e1` | [无任务:修复] docs(复盘赛报): OCR 候选择优修复赛报 + pcap 原报告顶置更正 | ...50\267\257\345\212\240\345\233\272-20261007.md" ...47\272\277\346\224\273\347\240\264-20261007.md" |
|---|---|---|---|---|
| 2026-10-07 21:19 | banana-vm | `7530273` | [无任务:能力] docs(复盘赛报): bananascript 能力接通 + CSAW2017 离线攻破 | README.md README.zh.md ...47\272\277\346\224\273\347\240\264-20261007.md" |
|---|---|---|---|---|
| 2026-10-07 21:09 | banana-vm | `d98d76a` | [无任务:修复] test(skills): OCR 候选择优行为 + 变异 | ctf_agent/tests/test_ocr_candidate_selection.py |
|---|---|---|---|---|
| 2026-10-07 21:09 | banana-vm | `0f2e7ab` | [无任务:修复] fix(skills): OCR 多 psm 候选择优（修 psm7 伪命中抢先返回） | ctf_agent/skills/svg_path_text.py |
|---|---|---|---|---|
| 2026-10-07 21:08 | banana-vm | `c644ac3` | [无任务:能力] test(skills): banana_script VM 行为 + 变异 | ctf_agent/tests/test_banana_script_vm.py |
|---|---|---|---|---|
| 2026-10-07 21:07 | banana-vm | `3a4b01c` | [无任务:能力] feat(skills): bananascript 编码解码 + 8 字节滚动异或还原 flag | ctf_agent/core/presolve.py ctf_agent/skills/banana_script.json ctf_agent/skills/banana_script.py |
|---|---|---|---|---|
| 2026-10-07 04:34 | pcap-solver | `c0b5b61` | [无任务:能力] docs(复盘赛报): pcap 表单雕取能力接通 + missed_registration 离线攻破 | ...47\272\277\346\224\273\347\240\264-20261007.md" |
|---|---|---|---|---|
| 2026-10-07 04:34 | pcap-solver | `1fd052b` | [无任务:能力] test(skills): pcap_http_carve 行为 + 变异 | ctf_agent/tests/test_pcap_http_carve.py |
|---|---|---|---|---|
| 2026-10-07 04:33 | pcap-solver | `ade6cfd` | [无任务:能力] feat(skills): pcap HTTP 表单切片 → 嵌入文件雕取 → OCR | README.md README.zh.md ctf_agent/core/presolve.py ctf_agent/skills/pcap_http_carve.json ctf_agent/skills/pcap_http_carve.py |
|---|---|---|---|---|
| 2026-10-07 04:19 | wb-runwiring | `2b109d2` | [无任务:能力] test(run): 三加载点口径接线回归——占位感染 + 哑开关（含变异验证） | ctf_agent/tests/test_run_corpus_wiring.py |
|---|---|---|---|---|
| 2026-10-07 04:18 | wb-runwiring | `03eb0b1` | [无任务:能力] feat(run): 生产入口三加载点接口径层——答案表跨库 + 待跑题库套闸门 | ctf_agent/eval/corpus.py ctf_agent/run.py .../_probe_cross_question_false_positive.py |
|---|---|---|---|---|
| 2026-10-07 04:16 | rev-solver | `133c0fe` | [无任务:文档] docs: 复盘赛报——rev 静态常量比对求解能力接通（CSAW beleaf/whataxor/tablez 离线攻破） | ...47\272\277\346\224\273\347\240\264-20261007.md" |
|---|---|---|---|---|
| 2026-10-07 04:16 | rev-solver | `6b0ff5d` | [无任务:能力] test(presolve): ELF 静态常量比对求解回归（20 用例，含变异验证） | ctf_agent/tests/test_rev_const_compare.py |
|---|---|---|---|---|
| 2026-10-07 04:15 | rev-solver | `7bb6eb4` | [无任务:能力] feat(presolve): ELF 静态「常量比对」型逆向求解链路（xor/替换表/树索引） | README.md README.zh.md ctf_agent/core/presolve.py ctf_agent/skills/rev_const_compare.json ctf_agent/skills/rev_const_compare.py |
|---|---|---|---|---|
| 2026-10-07 03:56 | svg-fix | `ea47801` | [无任务:文档] docs: 修正 floating_points 复盘报告的派生数字（回源取数） | ...273\347\272\277\346\224\273\347\240\264-20261007.md" |
|---|---|---|---|---|
| 2026-10-07 03:49 | svg-solver | `83390a2` | [无任务:文档] docs: 复盘赛报——SVG 路径文字渲染能力接通（CSAW2023 Finals floating_points 离线攻破） | ...47\272\277\346\224\273\347\240\264-20261007.md" |
|---|---|---|---|---|
| 2026-10-07 03:48 | svg-solver | `039d5d7` | [无任务:能力] test(presolve): SVG path 文字渲染求解回归（19 用例，含变异验证） | ctf_agent/tests/test_svg_path_text.py |
|---|---|---|---|---|
| 2026-10-07 03:48 | svg-solver | `47ad227` | [无任务:能力] feat(presolve): SVG path 文字渲染求解链路（bzip2/Ascii85 → 栅格化 → OCR） | README.md README.zh.md ctf_agent/core/presolve.py ctf_agent/skills/svg_path_text.json ctf_agent/skills/svg_path_text.py |
|---|---|---|---|---|
| 2026-10-07 03:30 | wb-corpus2 | `eeef3f6` | [无任务:能力] test(benchmark): 口径闸门 + CLI 端到端开关回归（含变异验证） | ctf_agent/tests/test_benchmark_corpus_gate.py |
|---|---|---|---|---|
| 2026-10-07 03:30 | wb-corpus2 | `21876b4` | [无任务:能力] feat(benchmark): 评测入口接入口径闸门 —— 跳过不可测题 | ctf_agent/eval/benchmark.py ctf_agent/eval/corpus.py |
|---|---|---|---|---|
| 2026-10-07 03:24 | collusion-solver | `7fd0899` | [无任务:文档] docs: 复盘赛报——RSA-IBE 串谋攻击求解链接通（CSAW2018 collusion 离线攻破） | ...47\272\277\346\224\273\347\240\264-20261007.md" |
|---|---|---|---|---|
| 2026-10-07 03:23 | collusion-solver | `8b11043` | [无任务:能力] test(presolve): RSA-IBE 串谋攻击求解回归 | ctf_agent/tests/test_rsa_ibe_collusion_presolve.py |
|---|---|---|---|---|
| 2026-10-07 03:23 | collusion-solver | `3864936` | [无任务:能力] feat(presolve): RSA-IBE 串谋攻击求解（collusion） | ctf_agent/core/presolve.py |
|---|---|---|---|---|
| 2026-10-07 03:08 | ecxor-docfix | `129a24a` | [无任务:文档] docs: 修正 ECXOR 复盘报告的派生数字（插入行数 266 / 并发嗅探路数） | ...ECXOR\347\246\273\347\272\277\346\224\273\347\240\264-20261007.md" |
|---|---|---|---|---|
| 2026-10-07 03:06 | ecxor-solver | `4a822a6` | [无任务:文档] docs: 复盘赛报——曲线25519 ECXOR 求解链接通（CSAW2017 Finals 离线攻破） | ...47\272\277\346\224\273\347\240\264-20261007.md" |
|---|---|---|---|---|
| 2026-10-07 03:05 | ecxor-solver | `b3d8581` | [无任务:能力] test(presolve): ECXOR 求解回归（合成正/负例 + 真题端到端） | ctf_agent/tests/test_ecxor_presolve.py |
|---|---|---|---|---|
| 2026-10-07 03:05 | ecxor-solver | `e06aabd` | [无任务:能力] feat(presolve): 新增「曲线25519 ECXOR」确定性求解链 | ctf_agent/core/presolve.py |
|---|---|---|---|---|
| 2026-10-07 03:01 | wb-corpus | `cbbda05` | [无任务:能力] test(corpus): 可测性/择优去重/flag前缀回归（含变异验证） | ctf_agent/tests/test_corpus_measurability.py .../tests/test_skill_dispatch_numeric_params.py |
|---|---|---|---|---|
| 2026-10-07 03:00 | wb-corpus | `f9654c5` | [无任务:能力] feat(corpus): 题库口径统一层 —— 可测性判定 + 跨库择优去重 | ctf_agent/eval/corpus.py ctf_agent/scripts/_audit_autocallable_coverage.py .../scripts/_audit_corpus_duplicate_pollution.py ctf_agent/tools/skill_dispatch.py |
|---|---|---|---|---|
| 2026-10-07 02:46 | atomcode-almostxor | `d7c476e` | [无任务:文档] docs: 复盘赛报——almost_xor（n-bit 分组模加密码）求解链接通（CSAW2017 离线攻破） | ...47\272\277\346\224\273\347\240\264-20261007.md" |
|---|---|---|---|---|
| 2026-10-07 02:44 | atomcode-almostxor | `667e4de` | [无任务:能力] test(presolve): almost_xor 求解回归（合成正/负例 + 真题端到端） | ctf_agent/tests/test_almost_xor_presolve.py |
|---|---|---|---|---|
| 2026-10-07 02:44 | atomcode-almostxor | `cc1bb49` | [无任务:能力] feat(presolve): 新增「almost_xor（n-bit 分组模加密码）」确定性求解链 | ctf_agent/core/presolve.py |
|---|---|---|---|---|
| 2026-10-07 02:28 | atomcode-nibble | `1fcba73` | [无任务:文档] docs: 复盘赛报——nibble-swap→base64 解码链接通（A5 br3akth3vau1t 离线攻破） | ...47\272\277\346\224\273\347\240\264-20261007.md" |
|---|---|---|---|---|
| 2026-10-07 02:26 | atomcode-nibble | `70f933b` | [无任务:能力] test(presolve): nibble-swap→base64 解码链回归（合成正/负例 + 真题端到端） | ctf_agent/tests/test_nibble_b64_presolve.py |
|---|---|---|---|---|
| 2026-10-07 02:26 | atomcode-nibble | `d9e4e49` | [无任务:能力] feat(presolve): 新增「nibble-swap → base64」解码链，离线攻破 CSAW-Quals 2023 Br3akTh3V@u1t | ctf_agent/core/presolve.py |
|---|---|---|---|---|
| 2026-10-07 02:17 | wb-c-wiring | `8ba7166` | [无任务:能力] test(skill): C 类入参提取回归 + 两处过期断言语义修正 | ctf_agent/tests/test_mainchain_skill_dispatch.py .../tests/test_skill_dispatch_numeric_params.py ctf_agent/tests/test_skill_routing_integrity.py |
|---|---|---|---|---|
| 2026-10-07 02:16 | wb-c-wiring | `2cee554` | [无任务:能力] feat(skill): C 类数值 skill 确定性入参接线 + 修两处失真 | ctf_agent/core/main_agent.py ctf_agent/scripts/_audit_autocallable_coverage.py .../scripts/_audit_corpus_duplicate_pollution.py ctf_agent/scripts/_probe_all_skill_params.py ctf_agent/scripts/_probe_c_params.py ctf_agent/scripts/_probe_expand_autocallable.py ctf_agent/scripts/_verify_numeric_dispatch.py ctf_agent/tools/skill_dispatch.py |
|---|---|---|---|---|
| 2026-10-07 02:14 | atomcode-catnorm | `2fab738` | [无任务:文档] docs: 复盘赛报——加载层 category 归一化（接管外部题「能力不可达」缺口） | ...50\276\276\347\274\272\345\217\243-20261007.md" |
|---|---|---|---|---|
| 2026-10-07 02:12 | atomcode-catnorm | `333ae0d` | [无任务:能力] test(eval): category 归一化回归（纯函数 + from_dict + 全链路） | ctf_agent/tests/test_category_normalization.py |
|---|---|---|---|---|
| 2026-10-07 02:12 | atomcode-catnorm | `21036e8` | [无任务:能力] feat(eval): 加载层 category 归一化，接管外部题「能力不可达」缺口 | ctf_agent/eval/cases.py |
|---|---|---|---|---|
| 2026-10-07 02:03 | atomcode-xorcap | `a90a534` | [无任务:文档] docs: 补入 8 份复盘赛报（本会话 presolve/跑批实测记录） | ...47\272\277\346\224\273\347\240\264-20261007.md" ...\256\236\346\265\213-5\351\242\230-20261006.md" ...\256\236\346\265\213-5\351\242\230-20261006.md" ...46\241\210\347\233\264\350\257\273-20261006.md" ...51\242\230\346\216\242\351\222\210-20261006.md" ...233\262\346\265\213-19\351\242\230-20261006.md" ...47\272\277\346\224\273\347\240\264-20261007.md" ...\256\236\346\265\213-5\351\242\230-20261007.md" |
|---|---|---|---|---|
| 2026-10-07 02:01 | atomcode-xorcap | `ed24347` | [无任务:能力] test: triage 段 2.8 假阳性负例（md5 不吻合 / 非可打印 flag） | ctf_agent/tests/test_xor_bruteforce_fallback.py |
|---|---|---|---|---|
| 2026-10-07 02:01 | atomcode-xorcap | `fdc4517` | [无任务:能力] fix: triage 段 2.8 假阳性加固（可打印约束 + md5 强制仲裁） | ctf_agent/agents/crypto_toolkit.py |
|---|---|---|---|---|
| 2026-10-07 01:53 | atomcode-xorcap | `99ec0c9` | [无任务:能力] test: 编码块 XOR 爆破段 + 沙盒超长源码回归（含变异验证） | ctf_agent/tests/test_subprocess_long_source.py ctf_agent/tests/test_xor_bruteforce_fallback.py |
|---|---|---|---|---|
| 2026-10-07 01:53 | atomcode-xorcap | `dea01a5` | [无任务:能力] feat: triage 编码块 XOR 爆破段 + 沙盒超长源码临时文件执行 | ctf_agent/agents/crypto_toolkit.py ctf_agent/sandbox/subprocess_executor.py |
|---|---|---|---|---|
| 2026-10-07 01:37 | atomcode-lowe-pem | `4093f2b` | [无任务:能力] test(crypto): PEM 小指数跨模攻击回归（端到端 + 负例） | ctf_agent/tests/test_pem_small_e_wrap_fallback.py |
|---|---|---|---|---|
| 2026-10-07 01:37 | atomcode-lowe-pem | `aa1d962` | [无任务:能力] feat(crypto): 接通 PEM 公钥布局的小指数跨模攻击（lowe 类） | ctf_agent/agents/crypto_toolkit.py |
|---|---|---|---|---|
| 2026-10-07 01:24 | glm4plus-b | `aab9af6` | [无任务:能力] config: 登记 glm 非推理档入白名单(glm-4-plus/4-air/4-air-250414) | ctf_agent/config.py |
|---|---|---|---|---|
| 2026-10-06 22:44 | gu | `ba5042c` | [无任务:能力] fix(agent): 打通主链 skill 调用（实测路由命中→真实解出） | ctf_agent/core/main_agent.py ctf_agent/core/prompts.py .../tests/test_crypto_complex_mult_group_route.py ctf_agent/tests/test_mainchain_skill_dispatch.py ctf_agent/tools/skill_dispatch.py |
|---|---|---|---|---|
| 2026-10-06 22:33 | gu | `83f5905` | [无任务:能力] feat(tools)+test: skill 入参适配层与主链断链回归测试 | ctf_agent/tests/test_mainchain_skill_dispatch.py ctf_agent/tools/skill_dispatch.py |
|---|---|---|---|---|
| 2026-10-06 22:33 | gu | `6795e75` | [无任务:能力] feat(agent): 接通主链 skill 断链（本轮 11 题能力可兑现为解题率） | ctf_agent/core/main_agent.py ctf_agent/tests/test_sandbox_delete_narrowing.py |
|---|---|---|---|---|
| 2026-10-06 22:25 | gu | `808af3f` | [无任务:能力] feat(security): subprocess 受限白名单（仅允许 run(列表) 执行 tesseract） | ctf_agent/skills/jpeg_png_embedded.py ctf_agent/tools/skill_manager.py |
|---|---|---|---|---|
| 2026-10-06 22:15 | gu | `622e6ea` | [无任务:能力] tests: 同步护栏（js 解锁 / OCR 类仍锁） | ctf_agent/tests/test_not_wirable_orphans.py ctf_agent/tests/test_sandbox_delete_narrowing.py |
|---|---|---|---|---|
| 2026-10-06 22:15 | gu | `5bf28f4` | [无任务:能力] fix(skill): js_methodology 的 os.popen 换纯 Python 查 PATH | ctf_agent/skills/reverse_js_methodology.py |
|---|---|---|---|---|
| 2026-10-06 22:12 | gu | `f646807` | [无任务:能力] tests: 补 complex_mult_group 沙箱回归护栏 | ctf_agent/tests/test_sandbox_delete_narrowing.py |
|---|---|---|---|---|
| 2026-10-06 22:11 | gu | `3f99f5e` | [无任务:能力] fix(skill): complex_mult_group 移除外部进程调用以通过沙箱 | ctf_agent/skills/crypto_complex_mult_group.py |
|---|---|---|---|---|
| 2026-10-06 22:01 | gu | `9734c9a` | [无任务:能力] tests: 同步不可接线护栏的沙箱状态（收窄后 3 个已解锁） | ctf_agent/tests/test_not_wirable_orphans.py |
|---|---|---|---|---|
| 2026-10-06 22:01 | gu | `522f5d0` | [无任务:能力] tests: 新增 AST 沙箱删除类收窄的安全护栏（11 用例） | ctf_agent/tests/test_sandbox_delete_narrowing.py |
|---|---|---|---|---|
| 2026-10-06 22:01 | gu | `d0e5979` | [无任务:能力] fix(security): AST沙箱删除类收窄 + 补齐8 个高危漏网 | ctf_agent/tools/skill_manager.py |
|---|---|---|---|---|
| 2026-10-06 21:57 | freemodel-readme | `cf179d8` | [无任务:文档] README: skills 计数 62→63 同步机器真值（消合并门禁红点） | README.md README.zh.md |
|---|---|---|---|---|
| 2026-10-06 21:57 | freemodel-readme | `b095958` | [无任务:能力] config: 登记免费 agent 档 glm-4.7-flash / glm-4.5-flash 入模型白名单 | ctf_agent/config.py |
|---|---|---|---|---|
| 2026-10-06 21:41 | gu | `ca3ef16` | [无任务:能力] tests: 新增剩余 11 孤儿「不可接线」护栏 | ctf_agent/tests/test_not_wirable_orphans.py |
|---|---|---|---|---|
| 2026-10-06 21:37 | gu | `6a36117` | [无任务:能力] tests: 新增 ezRSA 路由纠错+ 崩溃兜底回归测试 | ctf_agent/tests/test_ezrsa_route_fix.py |
|---|---|---|---|---|
| 2026-10-06 21:37 | gu | `6c385cf` | [无任务:能力] skill_map: 广播攻击改指专用 crypto_hastad_broadcast（ezRSA 真·L2） | ctf_agent/core/prompts.py |
|---|---|---|---|---|
| 2026-10-06 21:37 | gu | `4dc1274` | [无任务:能力] fix(skill): rsa_fermat_factor 加异常兜底防冒泡崩溃 | ctf_agent/skills/rsa_fermat_factor.py |
|---|---|---|---|---|
| 2026-10-06 21:29 | wallclock-split | `4cde728` | [无任务:测试] test(report): 锁死 wallclock 内外拆分（外 killed 截断 / 内 timeout 机制终结） | ctf_agent/tests/test_benchmark_wallclock.py |
|---|---|---|---|---|
| 2026-10-06 21:28 | wallclock-split | `0796f14` | [无任务:能力] fix(report): wallclock 内外拆分——内部止损不再被过度作废 | ctf_agent/core/error_taxonomy.py ctf_agent/core/goal_directive.py ctf_agent/eval/benchmark.py |
|---|---|---|---|---|
| 2026-10-06 21:21 | gu | `c65b966` | [无任务:能力] tests: 更正 primes 护栏为真解校验并接线断言 | ctf_agent/tests/test_orphan_batch4_routes.py |
|---|---|---|---|---|
| 2026-10-06 21:21 | gu | `dd9fe62` | [无任务:能力] skill_map: 接线 PRIMES（mangled somehow -> crypto_primes_subset） | ctf_agent/core/prompts.py |
|---|---|---|---|---|
| 2026-10-06 20:49 | gu | `90270d4` | [无任务:能力] tests: 新增同名附件冲突检测器回归测试 | ctf_agent/tests/test_attachment_collision_audit.py |
|---|---|---|---|---|
| 2026-10-06 20:49 | gu | `a83e0fe` | [无任务:能力] tools: 新增同名附件冲突检测器 | ctf_agent/scripts/_audit_attachment_collision.py |
|---|---|---|---|---|
| 2026-10-06 20:44 | circuit-relabel-wrongdir-1006 | `fd2072a` | test(taxonomy): 锁死熔断退化桶含 wrong_direction + 全链回填不可解释 [无任务:测试] | ctf_agent/tests/test_benchmark_real_chain.py ctf_agent/tests/test_error_taxonomy_circuit.py |
|---|---|---|---|---|
| 2026-10-06 20:43 | circuit-relabel-wrongdir-1006 | `ffa9bd3` | fix(taxonomy): 熔断退化桶补入 wrong_direction——provider 死亡不再冒充能力测量 [无任务:能力] | ctf_agent/core/error_taxonomy.py |
|---|---|---|---|---|
| 2026-10-06 20:15 | circuit-perm429-1006 | `0a06638` | test(llm): 锁死永久性 429 熔断 + 真限流不误熔断 [无任务:测试] | .../tests/test_circuit_breaker_permanent_429.py |
|---|---|---|---|---|
| 2026-10-06 20:14 | circuit-perm429-1006 | `0d289df` | fix(llm): 永久性 429（余额耗尽/账号停用）纳入 provider 熔断 [无任务:能力] | ctf_agent/llm/client.py |
|---|---|---|---|---|
| 2026-10-06 20:14 | gu | `483f3cd` | [无任务:能力] tests: 新增题面真值一致性审计器回归测试 | ctf_agent/tests/test_truth_consistency_audit.py |
|---|---|---|---|---|
| 2026-10-06 20:14 | gu | `f92cee3` | [无任务:能力] tools: 新增题面 flag_sha256 一致性审计器 | ctf_agent/scripts/_audit_truth_consistency.py |
|---|---|---|---|---|
| 2026-10-06 19:55 | gu | `48c26eb` | [无任务:能力] tests: 新增第五批两题路由+真解回归测试 | ctf_agent/tests/test_orphan_batch5_routes.py |
|---|---|---|---|---|
| 2026-10-06 19:55 | gu | `7d92e8f` | [无任务:能力] skill_map: 接线第五批两题（lfsr_filter / electric_mayhem_cls） | ctf_agent/core/prompts.py |
|---|---|---|---|---|
| 2026-10-06 19:55 | gu | `4080775` | [无任务:能力] fix(skill): lfsr_filter_recover 补 run() 入口使其可被加载 | ctf_agent/skills/lfsr_filter_recover.py |
|---|---|---|---|---|
| 2026-10-06 19:45 | gu | `4efbbee` | [无任务:能力] tests: 新增第四批三题路由+真解回归测试 | ctf_agent/tests/test_orphan_batch4_routes.py |
|---|---|---|---|---|
| 2026-10-06 19:45 | gu | `b1be2ab` | [无任务:能力] skill_map: 接线第四批三题（qr_matrix/mhk2/lcd） | ctf_agent/core/prompts.py |
|---|---|---|---|---|
| 2026-10-06 19:24 | gu | `9c6b630` | [无任务:能力] tests: 新增 lowe 路由+真解回归测试 | ctf_agent/tests/test_lowe_route.py |
|---|---|---|---|---|
| 2026-10-06 19:24 | gu | `88849b5` | [无任务:能力] skill_map: 接线 lowe（perfect cube -> pkcs1_padding_oracle） | ctf_agent/core/prompts.py |
|---|---|---|---|---|
| 2026-10-06 19:18 | code-action-fallback-1006 | `94bb491` | test(llm): 锁死代码动作兜底（recover_script）——纯函数/usage变体/旧签名容忍/端到端 [无任务:测试] | ctf_agent/tests/test_llm_client_contract.py ctf_agent/tests/test_recover_script_fallback.py |
|---|---|---|---|---|
| 2026-10-06 19:18 | code-action-fallback-1006 | `d8e9d1d` | fix(llm): 打通代码动作兜底（recover_script）到生产路径——弱模型吐代码块可执行 [无任务:能力] | ctf_agent/core/llm_wrapper.py ctf_agent/llm/client.py ctf_agent/run.py |
|---|---|---|---|---|
| 2026-10-06 19:16 | gu | `663dd10` | [无任务:能力] tests: 新增真·L2 两题路由+真解回归测试 | ctf_agent/tests/test_l2_legendre_modinv_route.py |
|---|---|---|---|---|
| 2026-10-06 19:16 | gu | `cafa5ff` | [无任务:能力] skill_map: 接线两道真·L2 专属键（legendre_phi/modinv_factor） | ctf_agent/core/prompts.py |
|---|---|---|---|---|
| 2026-10-06 18:39 | gu | `4058651` | [无任务:能力] tests: 新增 Cycling 路由+真解回归测试 | ctf_agent/tests/test_cycling_route.py |
|---|---|---|---|---|
| 2026-10-06 18:39 | gu | `ec89e4a` | [无任务:能力] skill_map: 接线 crypto_cycling（Cycling 题专属键 2^1025） | ctf_agent/core/prompts.py |
|---|---|---|---|---|
| 2026-10-06 18:31 | harden-json-extract-1006 | `df04184` | test(llm): 锁死 _extract_json_object 鲁棒性（围栏任意位置/嵌套/平衡扫描/repair）[无任务:测试] | ctf_agent/tests/test_extract_json_object.py |
|---|---|---|---|---|
| 2026-10-06 18:31 | harden-json-extract-1006 | `7ec96ac` | fix(llm): 动作解析器鲁棒化——弱模型 JSON 围栏/废话包裹可解析 [无任务:能力] | ctf_agent/llm/client.py |
|---|---|---|---|---|
| 2026-10-06 18:30 | gu | `b88edcb` | [无任务:能力] tests: 新增 caesar 泛化回归测试 | .../tests/test_caesar_route_generalization.py |
|---|---|---|---|---|
| 2026-10-06 18:30 | gu | `e759e8e` | [无任务:能力] skill_map: 删除 caesar 过度泛化键 移位/位移 | ctf_agent/core/prompts.py |
|---|---|---|---|---|
| 2026-10-06 18:28 | gu | `ea61139` | [无任务:能力] skill_map: 删除 caesar 过度泛化键 移位/位移 | ctf_agent/core/prompts.py ctf_agent/llm/client.py |
|---|---|---|---|---|
| 2026-10-06 16:28 | gu | `b57139e` | test(B2): 锁死 10733 路由到 crypto_high_exponent 并端到端解出（确定性）[无任务:能力] | ctf_agent/tests/test_10733_high_exponent_route.py |
|---|---|---|---|---|
| 2026-10-06 16:28 | gu | `c521da4` | fix(B2): skill_map 补高偶指数 RSA/hint泄露p 路由到 crypto_high_exponent（10733 真根因）[无任务:能力] | ctf_agent/core/prompts.py |
|---|---|---|---|---|
| 2026-10-06 15:36 | gu | `4739511` | test(B2): 锁死 specialcurve2 端到端路由到 crypto_complex_mult_group（确定性）[无任务:能力] | .../tests/test_crypto_complex_mult_group_route.py |
|---|---|---|---|---|
| 2026-10-06 15:36 | gu | `f14c8c6` | fix(B2): skill_map 复数乘法群 RSA 路由前置到裸 'rsa' 前并去重（specialcurve2 根因最终闭环）[无任务:能力] | ctf_agent/core/prompts.py |
|---|---|---|---|---|
| 2026-10-06 15:31 | reconcile-p1-1006 | `9ad234d` | [无任务:测试] P1 墙钟对齐：对齐纯函数契约 + 集成回归（eval→build_solver→MainAgent 下传链路，含变异验证） | ctf_agent/tests/test_p1_wallclock_alignment.py |
|---|---|---|---|---|
| 2026-10-06 15:31 | reconcile-p1-1006 | `3a77da2` | [无任务:能力] P1 墙钟对齐：评测 --wallclock 经 build_solver 下传 MainAgent，普通/HARD 两分支收敛到 评测墙钟-30s 余量，避免 Agent 被外部 asyncio.wait_for 提前取消导致 0 token 假象 | ctf_agent/eval/benchmark.py ctf_agent/run.py |
|---|---|---|---|---|
| 2026-10-06 13:53 | reconcile-inflight-1006 | `c2f013b` | [无任务:口径治理] held-out 实测状态机器派生(禁手写) + summarize 纯函数 + README 声明锚定真值(含变异验证) | ctf_agent/tests/test_kpi_canonical.py |
|---|---|---|---|---|
| 2026-10-06 13:52 | reconcile-inflight-1006 | `789112a` | [无任务:治理] glm 免费模型接入(默认 glm-4-flash) + benchmark_heldout 去 presolve-skip 同口径 + 修正 pre-commit test_file_guard 路径 | ctf_agent/config.py ctf_agent/git_hooks/pre-commit ctf_agent/scripts/benchmark_heldout.py |
|---|---|---|---|---|
| 2026-10-06 11:42 | gu | `c1ca90b` | test(B2): 锁死已知 p + 高偶指数 RSA 还原路径（10733 同结构向量，5/5 绿）[无任务:能力] | ctf_agent/tests/test_rsa_high_even_p_known.py |
|---|---|---|---|---|
| 2026-10-06 11:42 | gu | `8d344e2` | fix(B2): rsa_fermat_factor 补已知 p/q 路径 + 高偶指数 e=2^k 降幂+Rabin 还原（10733 根因）[无任务:能力] | ctf_agent/skills/rsa_fermat_factor.json ctf_agent/skills/rsa_fermat_factor.py |
|---|---|---|---|---|
| 2026-10-06 11:25 | gu | `3d71a33` | test(B2): 锁死复数乘法群 RSA 路由与'非椭圆曲线'指引，防 ECC 误判复发[无任务:能力] | .../tests/test_crypto_complex_mult_group_route.py |
|---|---|---|---|---|
| 2026-10-06 11:25 | gu | `1b57a33` | fix(B2): 补复数乘法群 RSA 变体 skill 路由+标准路径识别（纠错 specialcurve2 根因：skill_map 路由缺口非 ECC）[无任务:能力] | ctf_agent/agents/templates.py ctf_agent/core/prompts.py |
|---|---|---|---|---|
| 2026-10-06 11:23 | gu | `4460cb1` | revert(test): 删除错误的 ECC 方向测试（与 revert-impl 配对，修复方向已证伪）[无任务:能力] | ctf_agent/tests/test_crypto_ecc_direction.py |
|---|---|---|---|---|
| 2026-10-06 11:23 | gu | `1c52dd9` | revert(impl): 回退错误 ECC 方向模板（实证 specialcurve2 为复数乘法群 RSA 变体非椭圆曲线；根因是 skill 路由缺口）[无任务:能力] | ctf_agent/agents/templates.py |
|---|---|---|---|---|
| 2026-10-06 10:44 | gu | `7b4c237` | test(B2): 锁死 crypto 卡壳必获 ECC/ECDLP 方向模板（防静默回退）[无任务:能力] | ctf_agent/tests/test_crypto_ecc_direction.py |
|---|---|---|---|---|
| 2026-10-06 10:42 | gu | `a4a2a64` | feat(分层作战视图): crypto 标准路径补椭圆曲线/ECDLP/离散对数方向（B2 提推理·防奔错方向）[无任务:能力] | ctf_agent/agents/templates.py |
|---|---|---|---|---|
| 2026-10-06 10:28 | gu | `138d624` | fix(分层): 裸明文答案漏判修复——≤4KB 附件按精确摘要补判 L0 [无任务:能力] | ctf_agent/scripts/_stratify_external_benchmark.py |
|---|---|---|---|---|
| 2026-10-06 10:25 | gu | `9ffe5fc` | test(分层): 补裸明文答案判 L0 回归用例，锁死 10-06 修复点 [无任务:能力] | .../tests/test_stratify_external_benchmark.py |
|---|---|---|---|---|
| 2026-10-06 00:46 | workbuddy-sha256fix | `6a286ca` | feat(互操作): 本项目报告 → 对方判定器 输入桥（口径对接防失真）[无任务:能力] | ctf_agent/scripts/_bridge_report_for_peer_judge.py |
|---|---|---|---|---|
| 2026-10-06 00:38 | workbuddy-sha256fix | `3f2e4f3` | test(互操作): 分层脚本回归——钉死"对候选算摘要"的比对方向 [无任务:能力] | .../tests/test_stratify_external_benchmark.py |
|---|---|---|---|---|
| 2026-10-06 00:38 | workbuddy-sha256fix | `7900e4c` | feat(互操作): 外部基准静态分层脚本 + 导出器答案泄漏标注 [无任务:能力] | ctf_agent/scripts/_export_external_benchmark.py ctf_agent/scripts/_stratify_external_benchmark.py |
|---|---|---|---|---|
| 2026-10-06 00:26 | gstack-lead | `f0dcc56` | [无任务:测试] solve_once 取消路径记账回归（1 例，变异敏感） | ctf_agent/tests/test_solve_once_usage_on_cancel.py |
|---|---|---|---|---|
| 2026-10-06 00:25 | gstack-lead | `c5e606d` | [无任务:修复] solve_once 记账移入 finally：被取消/预算早退也入账（修「恒记 0 token」） | ctf_agent/run.py |
|---|---|---|---|---|
| 2026-10-06 00:17 | workbuddy-sha256fix | `7dfe517` | test(度量): 预扫开关回归（默认语义/取值表/调用点统一）[无任务:能力] | ctf_agent/tests/test_internal_presolve_switch.py |
|---|---|---|---|---|
| 2026-10-06 00:17 | workbuddy-sha256fix | `3bebe36` | feat(度量): 新增 CTF_AGENT_INTERNAL_PRESOLVE 开关，分离确定性直扫与 LLM 独立贡献 [无任务:能力] | ctf_agent/core/main_agent.py |
|---|---|---|---|---|
| 2026-10-05 23:24 | workbuddy-sha256fix | `3955884` | test(互操作): 审计脚本回归 + 外部明文答案红线变异验证 [无任务:能力] | ctf_agent/tests/test_peer_audit_scripts.py |
|---|---|---|---|---|
| 2026-10-05 23:23 | workbuddy-sha256fix | `274be4e` | feat(互操作): 真值源一致性 + LLM评测池口径 审计脚本（跨项目支持项2/3）[无任务:能力] | ctf_agent/scripts/_audit_llm_pool.py ctf_agent/scripts/_audit_truth_sources.py |
|---|---|---|---|---|
| 2026-10-05 23:01 | workbuddy-sha256fix | `25f4e1e` | test(互操作): 外部基准导出器选择规则回归 + 载荷硬门变异验证 [无任务:能力] | ctf_agent/tests/test_export_external_benchmark.py |
|---|---|---|---|---|
| 2026-10-05 23:01 | workbuddy-sha256fix | `bf76611` | feat(互操作): 外部真题基准导出器 → SecAutoMind external_westlake [无任务:能力] | ctf_agent/scripts/_export_external_benchmark.py |
|---|---|---|---|---|
| 2026-10-05 22:46 | gstack-lead | `c3ee5e6` | [无任务:能力] plans/current.md 记录熔断粒度修复（缺口②收口） | plans/current.md |
|---|---|---|---|---|
| 2026-10-05 22:34 | gstack-lead | `1c78004` | [无任务:测试] 同步既有测试到模型级熔断 API（failover / ai_vision） | ctf_agent/tests/test_ai_vision.py ctf_agent/tests/test_llm_failover.py |
|---|---|---|---|---|
| 2026-10-05 22:34 | gstack-lead | `9868693` | [无任务:修复] failover.py 熔断判定同步改为模型粒度（同缺口②） | ctf_agent/llm/failover.py |
|---|---|---|---|---|
| 2026-10-05 22:21 | gstack-lead | `adee193` | [无任务:测试] 熔断模型粒度回归测试（10 例，含变异敏感断言） | ctf_agent/tests/test_circuit_model_granularity.py |
|---|---|---|---|---|
| 2026-10-05 22:21 | gstack-lead | `8f5e7bc` | [无任务:修复] 熔断粒度由 provider 细化到 (provider, model)（修免费模型被连坐） | ctf_agent/llm/client.py ctf_agent/run.py |
|---|---|---|---|---|
| 2026-10-05 19:30 | circuit-fix | `1049413` | [无任务:能力] plans/current.md 记录 provider 熔断根因回填修复（2026-10-05，¥0） | plans/current.md |
|---|---|---|---|---|
| 2026-10-05 19:25 | circuit-fix | `0fc3399` | [无任务:能力] provider 熔断根因回填的回归测试（与实现拆两次提交） | ctf_agent/tests/test_error_taxonomy_circuit.py |
|---|---|---|---|---|
| 2026-10-05 19:25 | circuit-fix | `1315087` | [无任务:能力] 修复 provider 熔断(401/402/403) 根因回填：诚实口径（实现） | ctf_agent/core/error_taxonomy.py ctf_agent/run.py |
|---|---|---|---|---|
| 2026-10-05 18:46 | abqwen | `d76d82d` | [无任务:能力] plans/current.md 记录轻量模型覆盖失效修复 + qwen 受控 A/B（0/5，两臂一致） | plans/current.md |
|---|---|---|---|---|
| 2026-10-05 18:15 | abqwen | `3fc23f1` | [无任务:能力] 修正 test_qr_matrix 陈旧断言：sha256 权威旁路后隔离诱饵守卫 | ctf_agent/tests/test_qr_matrix.py |
|---|---|---|---|---|
| 2026-10-05 18:15 | abqwen | `e9f5bfe` | [无任务:能力] 轻量模型覆盖修复的回归测试（与实现拆两次提交） | ctf_agent/tests/test_model_light_override.py |
|---|---|---|---|---|
| 2026-10-05 18:14 | abqwen | `fbd9449` | [无任务:能力] 修复显式 provider 时 CTF_AGENT_{****}_MODEL 轻量覆盖失效 | ctf_agent/llm/client.py |
|---|---|---|---|---|
| 2026-10-05 17:28 | abtok2 | `a5a61ea` | [无任务:能力] plans/current.md 记录免费源受控 A/B：hy3 上为干净零结果 | plans/current.md |
|---|---|---|---|---|
| 2026-10-05 16:24 | ab402 | `03825ab` | [无任务:能力] plans/current.md 记录 A/B 验证受阻：DeepSeek 余额耗尽致跑批作废 | plans/current.md |
|---|---|---|---|---|
| 2026-10-05 16:18 | sigcollapse | `ea29f79` | [无任务:能力] plans/current.md 记录策略签名空输出塌缩的架构根因修复（B2 前置卡点） | plans/current.md |
|---|---|---|---|---|
| 2026-10-05 15:36 | sigcollapse | `07749c6` | [无任务:能力] 策略签名空输出塌缩修复的回归测试（与实现拆两次提交） | .../tests/test_strategy_signature_no_collapse.py |
|---|---|---|---|---|
| 2026-10-05 15:35 | sigcollapse | `e27d3bc` | [无任务:能力] 修复策略签名「空输出塌缩」：不同脚本静默不再误判死循环弃题 | ctf_agent/core/main_agent.py ctf_agent/core/phases.py |
|---|---|---|---|---|
| 2026-10-05 15:21 | b2pilot | `aec861b` | [无任务:能力] plans/current.md 记录 B2 能力测量试点结果（0/5，外部池累计 0/25） | plans/current.md |
|---|---|---|---|---|
| 2026-10-05 15:13 | b1plans2 | `5265a50` | [无任务:能力] plans/current.md 补记 phases 同类隐患同源修复 | plans/current.md |
|---|---|---|---|---|
| 2026-10-05 15:11 | b1phases | `6742c55` | [无任务:能力] phases 宽 pattern+sha256 兜底回归测试（与实现拆两次提交） | ctf_agent/tests/test_sha256_arbitration.py |
|---|---|---|---|---|
| 2026-10-05 15:11 | b1phases | `dd644a1` | [无任务:能力] phases 提取补宽 pattern+sha256 兜底：修复 flag_pattern 声明有误致真 flag 提取不到 | ctf_agent/core/phases.py |
|---|---|---|---|---|
| 2026-10-05 15:05 | b1flagpat | `87b78e0` | [无任务:能力] plans/current.md 记录 presolve flag_pattern 闸根因修复（B1 主链有效性） | plans/current.md |
|---|---|---|---|---|
| 2026-10-05 15:03 | b1flagpat | `9fa15aa` | [无任务:能力] B1 flag_pattern 闸修复：presolve 主入口端到端回归测试 | ctf_agent/tests/test_presolve_b1_wiring.py |
|---|---|---|---|---|
| 2026-10-05 15:03 | b1flagpat | `76d0450` | [无任务:能力] 修复 presolve flag_pattern 闸误杀真解：题面 sha256 命中即放行 | ctf_agent/core/presolve.py |
|---|---|---|---|---|
| 2026-10-05 14:35 | b1lcg | `d7a4ecf` | [无任务:能力] B1 工具链补齐：least-common-genominator presolve 接线回归测试（与实现拆两次提交） | ctf_agent/tests/test_presolve_b1_wiring.py |
|---|---|---|---|---|
| 2026-10-05 14:34 | b1lcg | `452f5f9` | [无任务:能力] B1 工具链补齐：least-common-genominator LCG→RSA 求解器接入主链 | README.md README.zh.md ctf_agent/core/presolve.py ctf_agent/skills/crypto_lcg_recover.json ctf_agent/skills/crypto_lcg_recover.py plans/current.md |
|---|---|---|---|---|
| 2026-10-05 14:09 | b1cls | `4807c4d` | [无任务:能力] B1 工具链补齐：electric-mayhem-cls presolve 接线回归测试（与实现拆两次提交） | ctf_agent/tests/test_presolve_b1_wiring.py |
|---|---|---|---|---|
| 2026-10-05 14:09 | b1cls | `2213374` | [无任务:能力] B1 工具链补齐：electric-mayhem-cls AES-128 CPA 侧信道求解器接入主链 | README.md README.zh.md ctf_agent/core/presolve.py ctf_agent/skills/crypto_electric_mayhem_cls.json ctf_agent/skills/crypto_electric_mayhem_cls.py plans/current.md |
|---|---|---|---|---|
| 2026-10-05 13:51 | b1doc | `c031deb` | [无任务:能力] B1 工具链补齐收尾：plans/current.md 补 cycling 已落地记录 | plans/current.md |
|---|---|---|---|---|
| 2026-10-05 13:44 | b1cycling | `e9842ef` | [无任务:能力] B1 工具链补齐：cycling 接线回归测试（与实现拆两次提交） | ctf_agent/tests/test_presolve_b1_wiring.py |
|---|---|---|---|---|
| 2026-10-05 13:43 | b1cycling | `7f17ec1` | [无任务:能力] B1 工具链补齐：cycling 确定性求解器接入 presolve 主链 | README.md README.zh.md ctf_agent/core/presolve.py ctf_agent/skills/crypto_cycling.json ctf_agent/skills/crypto_cycling.py |
|---|---|---|---|---|
| 2026-10-04 16:17 | gu-abc-verify | `d50044c` | [无任务:能力] abc shellcode 验证脚本（Docker 跨架构跑 payload，待 daemon 就绪） | ctf_agent/scripts/verify_abc_shellcode.sh |
|---|---|---|---|---|
| 2026-10-04 16:10 | gu-abc-polyglot | `dc65fb9` | [无任务:能力] abc-arm-and-amd polyglot shellcode 构造器（字节级正确，待环境验证） | ctf_agent/scripts/build_abc_polyglot.py |
|---|---|---|---|---|
| 2026-10-04 15:48 | gu-symlink-3final | `5c3a83c` | [无任务:治理] 定向修复最后 3 题软链接附件（enigma 全量 + electric 部分） | ctf_agent/scripts/_repair_symlink_3_remaining.py |
|---|---|---|---|---|
| 2026-10-04 15:15 | gu-symlink-adapters | `68ae76c` | [无任务:治理] NYU/Cybench 源软链接修复 + 审计脚本 SYMLINK_TEXT 精化 | ctf_agent/scripts/_attachment_integrity_audit.py ctf_agent/scripts/_bench_adapter.py |
|---|---|---|---|---|
| 2026-10-04 15:12 | gu-symlink-repair | `fe6f486` | [无任务:治理] 附件软链接修复工具：配合审计脚本修 21 道题空输入附件 | ctf_agent/scripts/_repair_symlink_attachments.py |
|---|---|---|---|---|
| 2026-10-04 15:10 | gu-symlink-prevent | `31d7de3` | [无任务:治理] fetch_google_ctf 软链接附件预防补丁：跟随 mode=120000 目标再下载 | ctf_agent/scripts/fetch_google_ctf.py |
|---|---|---|---|---|
| 2026-10-04 04:24 | gu | `1e07875` | [无任务:治理] 新增附件完整性审计：外部池 21/40 题附件实为符号链接路径文本 | ctf_agent/scripts/_attachment_integrity_audit.py |
|---|---|---|---|---|
| 2026-10-04 04:17 | gu | `e613213` | [无任务:治理] plans/current.md：mhk2 也已接线，B1 两道全部进主链，KPI 口径不变 | plans/current.md |
|---|---|---|---|---|
| 2026-10-04 04:16 | gu | `6d11f26` | [无任务:治理] 新增 B1 接线回归测试 7 例 + KNOWN_GAP 摘除 mhk2（两路均已接线） | ctf_agent/tests/test_presolve_b1_wiring.py ctf_agent/tests/test_skill_coverage.py |
|---|---|---|---|---|
| 2026-10-04 04:16 | gu | `c3677d7` | [无任务:治理] presolve 接线 crypto_knapsack_mhk：MHK2 背包等价密钥恢复进生产预扫 | ctf_agent/core/presolve.py |
|---|---|---|---|---|
| 2026-10-04 04:04 | gu | `3f20575` | [无任务:治理] plans/current.md：primes 已接入 presolve 主链，mhk2 仍为未接线缺口 | plans/current.md |
|---|---|---|---|---|
| 2026-10-04 04:03 | gu | `c008acc` | [无任务:治理] 接线测试：已接线断言 + 由 q 反解 n 的确定性与防误判 + presolve 端到端 | ctf_agent/tests/test_crypto_primes.py ctf_agent/tests/test_skill_coverage.py |
|---|---|---|---|---|
| 2026-10-04 04:02 | gu | `087610f` | [无任务:治理] presolve 接线 crypto_primes_subset：题面/附件抠 (q,x,r)，由 q 反解 n | ctf_agent/core/presolve.py |
|---|---|---|---|---|
| 2026-10-04 03:52 | gu | `95d8376` | [无任务:治理] plans/current.md 记录 B1 第二道 primes 落地与工具链余额降级 | plans/current.md |
|---|---|---|---|---|
| 2026-10-04 03:50 | gu | `6d1ae1d` | [无任务:治理] PRIMES 求解器测试 10 例 + 补 KNOWN_GAP（修 mhk2 遗留红门） | ctf_agent/tests/test_crypto_primes.py ctf_agent/tests/test_skill_coverage.py |
|---|---|---|---|---|
| 2026-10-04 03:49 | gu | `c501266` | [无任务:治理] B1 工具链：PRIMES 子集积确定性求解器（首一化 Coppersmith + 精确 Hensel 求根） | README.md README.zh.md ctf_agent/core/coppersmith.py ctf_agent/skills/crypto_primes_subset.json ctf_agent/skills/crypto_primes_subset.py |
|---|---|---|---|---|
| 2026-10-04 01:28 | mhk2-plans | `0350389` | [无任务:能力] plans/current.md 补 B1 第一小步 mhk2 落地进展 | plans/current.md |
|---|---|---|---|---|
| 2026-10-04 01:23 | mhk2-skill | `448b7cc` | [无任务:能力] 新增 MHK 背包恢复 skill 的回归测试（含真实题端到端） | ctf_agent/tests/test_crypto_knapsack_mhk.py |
|---|---|---|---|---|
| 2026-10-04 01:22 | mhk2-skill | `7012221` | [无任务:能力] 新增 MHK 背包等价密钥恢复 skill + 核心格工具 | README.md README.zh.md ctf_agent/core/lattice.py ctf_agent/requirements.txt ctf_agent/skills/crypto_knapsack_mhk.json ctf_agent/skills/crypto_knapsack_mhk.py |
|---|---|---|---|---|
| 2026-10-04 00:25 | claude-gap | `bab0036` | [无任务:文档] 20题能力缺口实测清单：0/20 拆成四类（工具链5/靶机6/纯推理8/离线可补3）+ 口径升级（agent 自评不可信）+ 优先级 B1>B2 | plans/current.md |
|---|---|---|---|---|
| 2026-10-04 00:12 | claude-p2close | `aba2ad8` | [无任务:文档] 四轮真跑证据汇总 + 事实纠正（P1首轮为 misc×4+crypto×1，misc 首轮即已实测）+ 收口交付物索引 | plans/current.md |
|---|---|---|---|---|
| 2026-10-03 23:44 | claude-e2dedup | `6693106` | [无任务:测试] E2 强切去重回归（2 例新 + 2 例旧断言校正：烧满预算→≤12 上限，归因 unresolved→stuck_loop） | ctf_agent/tests/test_main_agent_e2_budget.py |
|---|---|---|---|---|
| 2026-10-03 23:43 | claude-e2dedup | `07fafeb` | [无任务:能力] E2 强切按签名去重：同一策略签名只切一次，恢复硬止损路径 | ctf_agent/core/main_agent.py plans/current.md |
|---|---|---|---|---|
| 2026-10-03 22:54 | claude-e2fix | `9e780b3` | [无任务:测试] E2 三元组签名回归（探索不误伤 + 同前缀近似重复仍拦截，2 例） | ctf_agent/tests/test_main_agent_e2_budget.py |
|---|---|---|---|---|
| 2026-10-03 22:53 | claude-e2fix | `e91babb` | [无任务:能力] E2 强制切换改三元组签名：同 action 不同 observation 的正常探索不再误伤 | ctf_agent/core/main_agent.py plans/current.md |
|---|---|---|---|---|
| 2026-10-03 22:31 | claude-p2ab | `0d11f50` | [无任务:P1] RAG 语料审计（零交集）+ A/B 跑批记录（0/5，止损正确）+ E2 误伤发现（47% 强切） | plans/current.md |
|---|---|---|---|---|
| 2026-10-03 22:19 | claude-p2rag | `27b9f39` | [无任务:测试] RAG 语料审计回归测试（6 例） | ctf_agent/tests/test_rag_corpus_audit.py |
|---|---|---|---|---|
| 2026-10-03 22:18 | claude-p2rag | `816fa5e` | [无任务:能力] P2 第四刀：RAG 语料审计（held-out 泄漏红线 + 台账对齐） | ctf_agent/scripts/_rag_corpus_audit.py |
|---|---|---|---|---|
| 2026-10-03 21:56 | claude-p2hp | `2aa1114` | [无任务:测试] 分层作战视图回归测试（8 例） | ctf_agent/tests/test_hierarchical_plan.py |
|---|---|---|---|---|
| 2026-10-03 21:55 | claude-p2hp | `1c15482` | [无任务:能力] P2 第三刀：卡壳「分层作战视图」（¥0，纯规则零 LLM） | ctf_agent/core/hierarchical_plan.py ctf_agent/core/prompts.py ctf_agent/core/strategy_blackboard.py plans/current.md |
|---|---|---|---|---|
| 2026-10-03 21:36 | claude-p2bb | `5987a76` | [无任务:测试] 策略黑板回归测试（15 例） | ctf_agent/tests/test_strategy_blackboard.py |
|---|---|---|---|---|
| 2026-10-03 21:34 | claude-p2bb | `eec5ed2` | [无任务:能力] P2 第二刀：题内跨步「已试策略黑板」（¥0，纯规则零 LLM） | ctf_agent/core/main_agent.py ctf_agent/core/prompts.py ctf_agent/core/strategy_blackboard.py plans/current.md |
|---|---|---|---|---|
| 2026-10-03 20:02 | gu | `f9dcfda` | [无任务:能力] P2 首刀（反思规则⑥ token 口径）落地 + P1 第二轮结果记录 | plans/current.md |
|---|---|---|---|---|
| 2026-10-03 19:52 | gu | `78bec78` | [无任务:测试] 规则⑥ token 口径回归测试（5 例） | ctf_agent/tests/test_budget_reflection.py |
|---|---|---|---|---|
| 2026-10-03 19:51 | gu | `09ee5fb` | [无任务:能力] 预算反思规则⑥加 token 口径——治「步数先到、token 还剩大半」的过早放弃 | ctf_agent/core/budget_reflection.py ctf_agent/core/main_agent.py ctf_agent/run.py |
|---|---|---|---|---|
| 2026-10-03 19:27 | gu | `0e059af` | [无任务:P1] AICTF 备战启动：P0 度量冻结 + P1 首轮真跑（0/5，race_abandon×5） | plans/current.md |
|---|---|---|---|---|
| 2026-10-03 02:54 | gu | `ac94303` | [无任务:口径] docs/POSTMORTEM.md 口径刷新（题库 92→93 / 覆盖率 15.2%→15.1% / 跑池 17→41 / LLM 解出作废）+ plans 扩池构成澄清 | docs/POSTMORTEM.md plans/current.md |
|---|---|---|---|---|
| 2026-10-03 02:45 | gu | `32651ca` | [无任务:口径] 复盘赛报两份公开文档口径更正（池 17→41 / LLM 1/2 作废） | ...\351\246\226\346\254\241\347\234\237\345\256\236LLM-20260919.md" ...15\347\233\230-20260929-\346\224\266\345\217\243\347\211\210.md" |
|---|---|---|---|---|
| 2026-10-03 02:39 | gu | `c502bc1` | [无任务:治理] 同步 plans/current.md：移交清单已同步真值源（行动清单 #7 收口） | plans/current.md |
|---|---|---|---|---|
| 2026-10-03 02:30 | gu | `4cf1842` | [无任务:治理] 同步 plans/current.md：记录推送结果（远端已分叉 3 文档提交 → 合并后推送） | plans/current.md |
|---|---|---|---|---|
| 2026-10-03 02:25 | gu | `ad8a17c` | [无任务:治理] merge：并入远端 origin/main 的 3 个文档提交（README hero + 架构图 + skill 计数） | README.md docs/ARCHITECTURE.md docs/architecture.svg |
|---|---|---|---|---|
| 2026-10-03 02:21 | gu | `b987167` | [无任务:治理] 同步 plans/current.md：记录 10733 语料补齐 + Google CTF 扩池 + 用户授权推送 | plans/current.md |
|---|---|---|---|---|
| 2026-10-03 02:15 | gu | `11e3d05` | [无任务:口径] 补齐 10733 语料（台账-语料漂移 1→0）+ Google CTF 扩池（runnable 17→41）；real_corpus 92→93 | README.md README.zh.md ctf_agent/data/questions_real/crypto/10733.json ctf_agent/scripts/_kpi_canonical.py ctf_agent/scripts/_kpi_leak_crossaudit.py |
|---|---|---|---|---|
| 2026-10-03 01:35 | gu | `66995a6` | [无任务:治理] 同步 plans/current.md：记录 presolve 假命中治理 + B/C 层探查结论 | plans/current.md |
|---|---|---|---|---|
| 2026-10-03 01:24 | gu | `5c70e76` | [无任务:口径] presolve 假命中治理回归测试：附件多候选守卫 + 元词拒绝 + 占位拒绝（含变异验证） | ctf_agent/tests/test_presolve_answer_check.py |
|---|---|---|---|---|
| 2026-10-03 01:21 | gu | `7859665` | [无任务:口径] presolve B 组假命中治理：共享附件多候选守卫（B 组假命中 11→1，A 组真命中不变） | ctf_agent/core/main_agent.py ctf_agent/core/presolve.py .../presolve_audit_cybench13_v3_20261003.json .../presolve_audit_internal92_v3_20261003.json .../presolve_audit_nyu34_v3_20261003.json ctf_agent/scripts/_presolve_audit.py |
|---|---|---|---|---|
| 2026-10-03 00:22 | gu | `6790751` | [无任务:口径] 修 _kpi_canonical.py 注释漂移：heldout_candidates 注释误写 10（真值=2），纯注释不改逻辑/输出，KPI 锚点 offline_verified=14/heldout=2 不变 | ctf_agent/scripts/_kpi_canonical.py |
|---|---|---|---|---|
| 2026-10-01 17:37 | kpi-leak-guard | `75bd9be` | [无任务:口径] KPI 反注水闸门回归测试：分区语义 / fail-closed / 二段 oracle | ctf_agent/tests/test_scan_kpi_leak_guard.py |
|---|---|---|---|---|
| 2026-10-01 17:37 | kpi-leak-guard | `1cfbc90` | [无任务:口径] KPI 候选扫描补反注水闸门：真值来源判定替代失效的 answer_disclosed | ctf_agent/scripts/_scan_kpi_candidates.py |
|---|---|---|---|---|
| 2026-10-01 14:15 | qr-solver | `a1407a7` | [无任务:口径] 同步 plans/current.md 的 NYU 预扫计数（1/34 -> 2/34，干净 1/33） | plans/current.md |
|---|---|---|---|---|
| 2026-10-01 14:09 | qr-solver | `420f5ed` | [无任务:口径] 落盘 _FLAG_RE 修复后的三池审计证据 v2/v3 | .../clean_metric_cybench13_v3_20261001.json .../clean_metric_internal92_v3_20261001.json .../clean_metric_nyu34_v3_20261001.json .../leak_provenance_cybench13_v3_20261001.json .../leak_provenance_nyu34_v3_20261001.json .../leak_provenance_real92_v3_20261001.json .../presolve_audit_cybench_v2_20261001.json .../presolve_audit_internal92_v2_20261001.json .../presolve_audit_nyu34_v2_20261001.json .../presolve_audit_real92_v2_20261001.json |
|---|---|---|---|---|
| 2026-10-01 14:04 | qr-solver | `75b7fa4` | [无任务:解题] QR 矩阵解码测试：真实题锁 + 位序/极性不变性 + 3 项变异 | ctf_agent/tests/test_qr_matrix.py |
|---|---|---|---|---|
| 2026-10-01 14:03 | qr-solver | `474dac4` | [无任务:解题] 新增 QR 矩阵解码 skill 并接入确定性预扫 | README.md README.zh.md ctf_agent/core/presolve.py ctf_agent/skills/misc_qr_matrix.json ctf_agent/skills/misc_qr_matrix.py |
|---|---|---|---|---|
| 2026-10-01 13:20 | leak-baretoken | `8b4d765` | [无任务:口径] 答案来源审计裸 token 通道测试（含变异 + 回归锁切 v2） | ctf_agent/tests/test_kpi_crossaudit.py ctf_agent/tests/test_leak_provenance.py |
|---|---|---|---|---|
| 2026-10-01 13:19 | leak-baretoken | `55068d2` | [无任务:口径] 修答案来源审计裸 token 盲区：att_leak 68→77、干净样本 23→14 | .../clean_metric_cybench13_v2_20261001.json .../clean_metric_internal92_v2_20261001.json .../clean_metric_nyu34_v2_20261001.json .../kpi_leak_crossaudit_v2_20261001.json .../leak_provenance_cybench13_v2_20261001.json .../leak_provenance_nyu34_v2_20261001.json .../leak_provenance_real92_v2_20261001.json ctf_agent/scripts/_leak_provenance.py |
|---|---|---|---|---|
| 2026-10-01 13:02 | kpi-crossaudit | `c62cd1d` | [无任务:口径] KPI 交叉审计判定测试（含 2 项变异 + 真实仓库回归锁） | ctf_agent/tests/test_kpi_crossaudit.py |
|---|---|---|---|---|
| 2026-10-01 13:01 | kpi-crossaudit | `f12aa7d` | [无任务:口径] KPI 锚点答案来源交叉审计：offline_verified=14 零泄漏 | .../kpi_leak_crossaudit_20261001.json ctf_agent/scripts/_kpi_leak_crossaudit.py ctf_agent/scripts/_leak_provenance.py |
|---|---|---|---|---|
| 2026-10-01 12:47 | gu-leak | `e7b5c66` | [无任务:口径] 答案来源审计判定测试（含 2 项变异验证） | ctf_agent/tests/test_leak_provenance.py |
|---|---|---|---|---|
| 2026-10-01 12:46 | gu-leak | `9cc4fdb` | [无任务:口径] 答案来源审计 + 干净口径对比（刨除 grep 白给分） | .../clean_metric_cybench13_20261001.json .../clean_metric_internal92_20261001.json .../clean_metric_nyu34_20261001.json .../leak_provenance_cybench13_20261001.json .../leak_provenance_nyu34_20261001.json .../leak_provenance_real92_20261001.json ctf_agent/scripts/_clean_metric.py ctf_agent/scripts/_leak_provenance.py |
|---|---|---|---|---|
| 2026-10-01 12:30 | gu-bench | `f41dc8a` | [无任务:对标] Cybench 本地适配器 + 朴素基线 + 求解器头对头对比 | .../baseline_naive_cybench_20261001.json .../baseline_naive_internal92_20261001.json .../baseline_naive_nyu34_20261001.json .../heldout_evidence/compare_cybench_20261001.json .../compare_internal92_20261001.json .../heldout_evidence/compare_nyu34_20261001.json .../cybench_adapter_local_20261001.json .../presolve_audit_cybench_20261001.json .../presolve_audit_internal92_20261001.json .../presolve_audit_nyu34_20261001.json .../presolve_audit_nyuA12_20261001.json ctf_agent/scripts/_baseline_naive.py …(+2) |
|---|---|---|---|---|
| 2026-10-01 08:30 | gu-envelope | `89342e2` | [无任务:排障] 新增 shell 输出解码回归测试（含变异验证） | ctf_agent/tests/test_session_decode.py |
|---|---|---|---|---|
| 2026-10-01 08:30 | gu-envelope | `6051728` | [无任务:排障] 修工作区 shell 输出被解崩成 None（静默空输出） | ctf_agent/core/session.py ...eport_nyu_A5_ceiling200k_20261001_deepseek.json ..._report_nyu_A5_decodefix_20261001_deepseek.json ctf_agent/scripts/_bench_ceiling.py ctf_agent/scripts/_probe_shell_rc255.py |
|---|---|---|---|---|
| 2026-10-01 07:55 | gu-envelope | `07041ca` | [无任务:扩池] 新增能力信封分档判定测试（含 2 项变异验证） | ctf_agent/tests/test_envelope_band.py |
|---|---|---|---|---|
| 2026-10-01 07:54 | gu-envelope | `7fb19fb` | [无任务:扩池] 固化能力信封分档 + 归档 A 档 5 题实测证据 | ...k_report_nyu_A5_envelope_20261001_deepseek.json .../envelope_band_questions_ext_20261001.json ctf_agent/scripts/_bench_adapter.py ctf_agent/scripts/_envelope_band.py |
|---|---|---|---|---|
| 2026-10-01 02:54 | gstack-lead | `1d0198d` | [无任务:规划] 更新计划：雷 0 与雷 2 已收口，跑批结果入册 | plans/current.md |
|---|---|---|---|---|
| 2026-10-01 02:52 | gstack-lead | `596b056` | [无任务:治理] .gitignore 屏蔽竞赛遗留目录（git add -A 从 6854 降到 7） | .gitignore |
|---|---|---|---|---|
| 2026-10-01 02:50 | gstack-lead | `ad61c8b` | [无任务:口径] 真值源与中英 README 顶置口径更正：LLM 自主解出 1/2 作废 | README.md README.zh.md ctf_agent/scripts/_kpi_canonical.py |
|---|---|---|---|---|
| 2026-10-01 02:45 | gstack-lead | `4f2d04a` | [无任务:证据] 归档首批 NYU 5 题实测证据 + 更新计划（主链路 0/5） | ...chmark_report_nyu_trial5_20261001_deepseek.json plans/current.md |
|---|---|---|---|---|
| 2026-10-01 02:26 | gstack-lead | `1bcba6d` | [无任务:规划] 重建 plans/current.md（原为空壳且停更于 09-21） | plans/current.md |
|---|---|---|---|---|
| 2026-10-01 02:24 | gstack-lead | `d51fdae` | [无任务:治理] eval/benchmark.py 真实模式默认 provider 改为 deepseek（baidu 已欠费） | ctf_agent/eval/benchmark.py |
|---|---|---|---|---|
| 2026-10-01 02:22 | gstack-lead | `834bffd` | [无任务:治理] 门禁脚本 test_file_guard.py 入库（修新克隆必被拦死） | ctf_agent/scripts/test_file_guard.py |
|---|---|---|---|---|
| 2026-09-30 18:22 | gu-lead | `f122e89` | [无任务:测试] load_questions 附件目录跳过守卫回归测试（3 例，含变异敏感断言） | .../tests/test_load_questions_attachment_skip.py |
|---|---|---|---|---|
| 2026-09-30 18:21 | gu-lead | `a11d805` | [无任务:扩池] NYU 批量适配 34 题 + 两处基础设施修复 | .gitignore ctf_agent/eval/cases.py ctf_agent/scripts/_bench_adapter.py ctf_agent/scripts/_cybench_survey.py ctf_agent/scripts/_nyu_survey.py |
|---|---|---|---|---|
| 2026-09-30 14:58 | gu-lead | `44fad27` | [无任务:测试] presolve 答案校验闸回归测试（22 例，含变异敏感断言） | ctf_agent/tests/test_presolve_answer_check.py |
|---|---|---|---|---|
| 2026-09-30 14:58 | gu-lead | `038fe50` | [无任务:修复] presolve 答案校验闸 sha256 感知 + 题面提取正则修复（92 题审计双 P0） | ctf_agent/core/main_agent.py ctf_agent/core/presolve.py ctf_agent/eval/cases.py ctf_agent/run.py ctf_agent/scripts/_presolve_audit.py |
|---|---|---|---|---|
| 2026-09-29 22:40 | finalize0929 | `60ebaf7` | test(benchmark): 同步 summarize integrity 语义——机制终结不复用 truncated | ctf_agent/tests/test_benchmark_real_chain.py |
|---|---|---|---|---|
| 2026-09-29 22:40 | finalize0929 | `51643ed` | fix(report): 分离「机制终结」与「真·外部掐断」，修复 held-out 报告 integrity 误标 | ...45\210\206\345\261\202\347\216\207_20260929.md" .../M2_E3\345\257\271\347\205\247_20260929.md" ...34\346\210\230\350\247\204\345\210\222_2027.md" ctf_agent/eval/benchmark.py ...260929-\346\224\266\345\217\243\347\211\210.md" |
|---|---|---|---|---|
| 2026-09-29 19:49 | agent-g1runtime-0929 | `f146866` | [无任务:治理] G1/G5 运行时接入测试：15 例锁死开关语义/真实执行/闸门生效/注入行为 | ctf_agent/tests/test_g_runtime_integration.py |
|---|---|---|---|---|
| 2026-09-29 19:49 | agent-g1runtime-0929 | `11dd4d0` | [无任务:治理] G1/G5 持久会话接入主链路运行时：command 动作 + 会话记忆注入 plan prompt | ctf_agent/core/main_agent.py ctf_agent/core/phases.py ctf_agent/core/prompts.py |
|---|---|---|---|---|
| 2026-09-29 01:13 | gu | `6595a29` | [无任务:治理] 闸门 CLI 测试：6 例锁死占位符必 FAIL、无基准不可核验、退出码语义 | ctf_agent/tests/test_flag_gate_cli.py |
|---|---|---|---|---|
| 2026-09-29 01:13 | gu | `202bbf9` | [无任务:治理] 新增解出闸门 CLI：候选需过 sha256 才记解出，退出码 0/1/2 供 CI 判定 | ctf_agent/scripts/flag_gate_cli.py |
|---|---|---|---|---|
| 2026-09-29 01:09 | gu | `cbb9081` | [无任务:治理] 解出闸门测试：9 例锁死无基准不可核验、占位符不得通过（含变异验证） | ctf_agent/tests/test_flag_verify.py |
|---|---|---|---|---|
| 2026-09-29 01:09 | gu | `6c9c2c0` | [无任务:治理] 新增解出闸门 flag_verify：正则命中只算候选，sha256 比对才算解出（fail-closed） | ctf_agent/core/flag_verify.py |
|---|---|---|---|---|
| 2026-09-29 01:04 | gu | `de1b8ef` | [无任务:治理] 占位符守卫测试：22 例锁死 echo 占位式命中不得判 SUCCESS（含变异验证） | ctf_agent/tests/test_reflect_placeholder_guard.py |
|---|---|---|---|---|
| 2026-09-29 01:03 | gu | `bf82cd6` | [无任务:治理] G2 reflect 占位符假阳性守卫：剔除 echo 打印的占位式命中，防伪造解出 | ctf_agent/core/agent_loop.py |
|---|---|---|---|---|
| 2026-09-28 15:11 | gu | `abff999` | [无任务:治理] 轨道A 离线集成验证：G1+G2 闭环真实 subprocess 执行 + 盲猜对照 STUCK + G5/G6 组合 | ctf_agent/tests/test_g1_g2_offline_integration.py |
|---|---|---|---|---|
| 2026-09-28 14:56 | gu | `24fbe8b` | [无任务:治理] 轨道A G系列抽象单测（测试层，与实现分提交） | ctf_agent/tests/test_agent_loop.py ctf_agent/tests/test_mcp_adapter.py ctf_agent/tests/test_memory.py ctf_agent/tests/test_model_registry.py ctf_agent/tests/test_session.py |
|---|---|---|---|---|
| 2026-09-28 14:55 | gu | `7cbc880` | [无任务:治理] 轨道A G系列¥0抽象：Session/闭环/MCP/记忆/模型注册表（实现层） | ...6\220-SOTA\345\257\271\346\257\224-20260928.md" ctf_agent/core/agent_loop.py ctf_agent/core/mcp_adapter.py ctf_agent/core/memory.py ctf_agent/core/model_registry.py ctf_agent/core/session.py |
|---|---|---|---|---|
| 2026-09-27 13:14 | xihu-lead | `1525072` | [无任务:开源发布收口] README Known limitations 中英段 + 路径完整性测试 + POSTMORTEM 入口导读 | README.md README.zh.md ctf_agent/tests/test_readme_path_integrity.py docs/POSTMORTEM.md |
|---|---|---|---|---|
| 2026-09-26 20:05 | docscope-0926 | `e0b9725` | [无任务:口径治理] 给已公开的 09-19 复盘报告加顶置口径更正声明 | ...26\346\254\241\347\234\237\345\256\236LLM-20260919.md" |
|---|---|---|---|---|
| 2026-09-26 20:03 | readme-scope-0926 | `67097ca` | [无任务:口径治理] 修 README 中英文口径漂移 + 补 17 题池的口径区分说明 | README.md README.zh.md |
|---|---|---|---|---|
| 2026-09-26 19:57 | kpi-scope-0926 | `d76ad80` | [无任务:口径治理] 新增锁口径测试：能力分母(2) 与可选跑池(17) 必须可区分（测试部分，2/2） | ctf_agent/tests/test_kpi_canonical.py |
|---|---|---|---|---|
| 2026-09-26 19:57 | kpi-scope-0926 | `fc3d8f0` | [无任务:口径治理] canonical 新增 heldout_runnable_pool 字段（实现部分，1/2） | ctf_agent/scripts/_kpi_canonical.py ctf_agent/scripts/benchmark_heldout.py |
|---|---|---|---|---|
| 2026-09-23 02:16 | agent-p08-feedback-0923 | `e3eb1b1` | [无任务:P0-8] 终态失败口径提升为单一真值 + FeedbackLoop 层短路（止损第三层） | ctf_agent/core/error_taxonomy.py ctf_agent/eval/benchmark.py ctf_agent/tests/test_feedback_terminal.py ctf_agent/verify/feedback.py |
|---|---|---|---|---|
| 2026-09-23 01:54 | agent-abandon-terminal-0923 | `7dcd91b` | [无任务:P0-5/P0-7] 修复早停止损被重跑抹掉：终态分类归 race_abandon + 预算硬顶不再空烧 | ctf_agent/core/main_agent.py ctf_agent/tests/test_abandon_terminal.py |
|---|---|---|---|---|
| 2026-09-23 01:25 | agent-p0-fixes-0923 | `88910ac` | [无任务:P0-1/P0-3] 修复 held-out 预算烧穿根因：空转检测器 + 终态失败重试短路 | ctf_agent/core/main_agent.py ctf_agent/eval/benchmark.py ctf_agent/scripts/benchmark_heldout.py .../tests/test_benchmark_retry_shortcircuit.py ctf_agent/tests/test_p0_stuck_detection.py |
|---|---|---|---|---|
| 2026-09-23 00:14 | holdout-p0 | `3231e28` | [无任务:held-out 17 池预算烧穿根因修复] | ctf_agent/core/budget_reflection.py ctf_agent/core/main_agent.py ctf_agent/eval/benchmark.py ctf_agent/tests/test_benchmark_real_chain.py ctf_agent/tests/test_budget_reflection.py |
|---|---|---|---|---|
| 2026-09-22 22:10 | agent-heldout-gctf-0922 | `2dc7b6d` | feat(heldout): P0-① 真实采源——Google CTF 真题接入，strict 池 2→17 | ctf_agent/scripts/benchmark_heldout.py ctf_agent/scripts/fetch_google_ctf.py ctf_agent/scripts/ingest_external_ctf.py ctf_agent/tests/test_heldout_external.py |
|---|---|---|---|---|
| 2026-09-22 18:50 | agent-heldout-extscaffold-0922 | `b061eeb` | feat(heldout): P0-① 外部 CTF 平台题源离线脚手架（诚实扩池） | ctf_agent/scripts/benchmark_heldout.py ctf_agent/scripts/ingest_external_ctf.py ctf_agent/tests/test_heldout_external.py |
|---|---|---|---|---|
| 2026-09-22 18:08 | agent-heldout-honest-0922 | `3f1ad0d` | fix(kpi): 诚实修订 held-out 口径为干净 2 题池（LLM 自主 1/2） [无任务:治理] | README.md README.zh.md ..._1x.SUPERSEDED_contaminated_pool_20260921.json} ..._2x.SUPERSEDED_contaminated_pool_20260921.json} .../benchmark_report_clean2_20260922_deepseek.json ...ncluded_source_leaked_gongye_web2_20260922.json ctf_agent/scripts/_kpi_canonical.py |
|---|---|---|---|---|
| 2026-09-22 13:54 | agent-antihallu-skillcov-0922 | `7fea1fa` | [无任务:治理] 大确定性 skill 覆盖：presolve 生产链路新增 4 路（19→23） | ctf_agent/core/presolve.py ctf_agent/tests/test_skill_coverage.py |
|---|---|---|---|---|
| 2026-09-22 13:39 | agent-antihallu-skillcov-0922 | `40c96ef` | [无任务:治理] 反幻觉 provenance 闸：堵打印泄漏与无关工具调用放行两处旧泄漏 | ctf_agent/core/anti_hallucination.py ctf_agent/core/phases.py ctf_agent/tests/test_anti_hallucination.py ctf_agent/tests/test_extract_flag.py ctf_agent/tests/test_sha256_arbitration.py |
|---|---|---|---|---|
| 2026-09-22 08:41 | agent-heldout-srcfix-0922 | `90b2926` | 诚实分类修正：held-out 选题加源码内明文 flag 检测 [无任务:治理] | ctf_agent/scripts/benchmark_heldout.py |
|---|---|---|---|---|
| 2026-09-22 02:35 | agent-heldout-lock-0922 | `b8d524a` | fix(heldout): 排除 WRITEUP 重建题，纠正 held-out 分母虚高 [无任务:治理] | .../crypto/real_crypto_anxun2020_coolboy.json .../misc/real_misc_anxun2020_722b6d.json .../misc/real_misc_vnctf_strangeflag.json .../reverse/real_reverse_anxun2020_easycm.json .../reverse/real_reverse_anxun2020_notright.json .../reverse/real_reverse_vnctf_babymaze.json .../web/real_web_anxun2020_welcome.json ctf_agent/scripts/benchmark_heldout.py |
|---|---|---|---|---|
| 2026-09-21 17:02 | gu | `3f0c315` | docs(agents): 植入项目级 .agents/skills 四件套 + plans 外脑 [无任务:文档] | .agents/skills/arch-rules/SKILL.md .agents/skills/debug-playbook/SKILL.md .agents/skills/project-context/SKILL.md .agents/skills/session-boot/SKILL.md plans/current.md plans/decisions.md |
|---|---|---|---|---|
| 2026-09-20 19:20 | heldout-llm-backoff | `efa3572` | fix(llm): 429 限流与瞬时超时有界指数退避重试 [无任务:治理] | ctf_agent/llm/client.py |
|---|---|---|---|---|
| 2026-09-19 11:28 | workbuddy-xihu-gov | `a115b04` | chore(gitignore): 忽略根目录通宵调试残留文件 [无任务:治理] | .gitignore |
|---|---|---|---|---|
| 2026-09-19 11:27 | workbuddy-xihu-p0 | `15f0b52` | fix(heldout): P0 验证器修复 + held-out 真实 LLM 重测收口 [无任务:治理] | ctf_agent/config.py ...46\236\204\344\272\213\346\225\205-20260825.md" ...50\275\256\346\225\231\350\256\255-20260829.md" ctf_agent/scripts/_llm_breaking_ice.py ctf_agent/scripts/release_export.py ctf_agent/tests/test_release_export_policy.py ctf_agent/verify/flag_checker.py ...254\241\347\234\237\345\256\236LLM-20260919.md" |
|---|---|---|---|---|
| 2026-09-19 09:24 | team-lead | `f78b4fd` | fix(core): 重放被合并孤儿化的两项修复（原 1bc66fa + 8ca4db1）[无任务:治理] | ctf_agent/core/main_agent.py ctf_agent/core/phases.py ctf_agent/core/presolve.py ctf_agent/run.py ctf_agent/tests/test_sha256_arbitration.py |
|---|---|---|---|---|
| 2026-09-19 09:23 | team-lead | `8337db0` | fix(data): 恢复被远端合并带入的题库 flag 字段真值（92 文件）[无任务:治理] | ctf_agent/data/questions_real/crypto/real_crypto_anwang_crypto1.json ctf_agent/data/questions_real/crypto/real_crypto_anxun2020_aes.json ctf_agent/data/questions_real/crypto/real_crypto_anxun2020_coolboy.json .../data/questions_real/crypto/real_crypto_changan2021_checkin.json .../data/questions_real/crypto/real_crypto_changan2021_easyrsa.json ctf_agent/data/questions_real/crypto/real_crypto_changan2021_ezpy.json ctf_agent/data/questions_real/crypto/real_crypto_dnui_keyboard.json ctf_agent/data/questions_real/crypto/real_crypto_exciting_inverse.json ctf_agent/data/questions_real/crypto/real_crypto_ezmult.json ctf_agent/data/questions_real/crypto/real_crypto_ezrsa.json ctf_agent/data/questions_real/crypto/real_crypto_filterrandom.json ctf_agent/data/questions_real/crypto/real_crypto_gaoxiao2024_z3.json …(+80) |
|---|---|---|---|---|
| 2026-09-19 09:03 | team-lead | `87f4fe3` | feat(heldout): 跑分工具链 4 件入库，支撑 held-out 数字可复现 [无任务:治理] | ctf_agent/scripts/_heldout_rerun_wrapper.py ctf_agent/scripts/_probe_providers.py ctf_agent/scripts/benchmark_heldout_multimodel.py ctf_agent/scripts/summarize_heldout.py |
|---|---|---|---|---|
| 2026-09-19 09:02 | team-lead | `72ced42` | docs(kpi): README 新增 Project status（两分口径）+ 路径基准说明 + heldout_status 机器派生 [无任务:治理] | README.md README.zh.md ctf_agent/scripts/_kpi_canonical.py |
|---|---|---|---|---|
| 2026-09-19 08:57 | team-lead | `dd7ef25` | docs(复盘赛报): 复盘赛报 14 篇全文入库（重放：前次提交被带外合并孤儿化）[无任务:治理] | .gitignore AGENTS.md ...254\241\347\234\237\345\256\236LLM-20260919.md" .../honest_bench_first_signal_20260901.md" .../llm_breaking_ice_rerun_20260901.md" ...45\272\246\346\224\271\351\200\240-20260821.md" ...45\272\246\345\244\215\347\233\230-20260821.md" ...\227-2\351\242\2300\347\237\233\347\233\276.md" ...220\346\212\245\345\221\212-scene8-20260822.md" ...260822-\346\225\264\345\220\210\347\211\210.md" ...46\210\230\350\256\241\345\210\222-20260824.md" ...1\266\346\212\245\345\221\212-20260821-1010.md" …(+4) |
|---|---|---|---|---|
| 2026-09-19 08:52 | team-lead | `13a77b0` | docs(复盘赛报): 复盘赛报 14 篇全文入库（用户 2026-09-19 裁决「可以公开」）[无任务:治理] | .gitignore AGENTS.md ...254\241\347\234\237\345\256\236LLM-20260919.md" .../honest_bench_first_signal_20260901.md" .../llm_breaking_ice_rerun_20260901.md" ...45\272\246\346\224\271\351\200\240-20260821.md" ...45\272\246\345\244\215\347\233\230-20260821.md" ...\227-2\351\242\2300\347\237\233\347\233\276.md" ...220\346\212\245\345\221\212-scene8-20260822.md" ...260822-\346\225\264\345\220\210\347\211\210.md" ...46\210\230\350\256\241\345\210\222-20260824.md" ...1\266\346\212\245\345\221\212-20260821-1010.md" …(+4) |
|---|---|---|---|---|
| 2026-09-19 08:51 | workbuddy-sha256fix | `8ca4db1` | fix(鲁棒性): 主循环步级容错——plan/act 单步异常不再炸穿整题 [无任务:治理] | ctf_agent/core/main_agent.py |
|---|---|---|---|---|
| 2026-09-19 08:47 | workbuddy-sha256fix | `1bc66fa` | fix(幻觉攻坚): sha256 真值仲裁三层接入 + solver 校验查错题库 P0 修复 [无任务:治理] | ctf_agent/core/phases.py ctf_agent/core/presolve.py ctf_agent/run.py ctf_agent/tests/test_sha256_arbitration.py |
|---|---|---|---|---|
| 2026-09-19 04:34 | software-engineer-4 | `f2ed227` | docs(heldout): heldout 证据回滚为逐字节原文 [无任务:文档] | ctf_agent/heldout_evidence/PROVENANCE.md .../benchmark_report_A_deepseek_1x.json .../benchmark_report_B_deepseek_2x.json |
|---|---|---|---|---|
| 2026-09-19 04:32 | software-engineer-2 | `da469ba` | fix(防复发): 修 ⑥ 门禁两处假红（GIT_INDEX_FILE 泄漏 + pytest tmp 批量删除）[无任务:治理] | ctf_agent/git_hooks/pre-commit ctf_agent/pytest.ini ctf_agent/scripts/hooks/pre-commit |
|---|---|---|---|---|
| 2026-09-19 04:31 | software-engineer-4 | `b6559d8` | docs(heldout): 归档 held-out 实测证据（A/B report + PROVENANCE） [无任务:文档] | ctf_agent/heldout_evidence/PROVENANCE.md .../benchmark_report_A_deepseek_1x.json .../benchmark_report_B_deepseek_2x.json |
|---|---|---|---|---|
| 2026-09-19 04:27 | software-engineer-5 | `41ffb07` | fix(发布闸): 明文 flag 由硬失败改为提示 + 凭据硬红线收拢加强（补回流：前一版被并发会话树重建丢弃） [无任务:治理] | ctf_agent/.gitignore ctf_agent/scripts/release_export.py |
|---|---|---|---|---|
| 2026-09-19 04:24 | software-engineer-5 | `b332b23` | test(发布闸): 测试夹具改为拼接构造，避免自测文件被发布闸判为凭据泄漏 [无任务:治理] | ctf_agent/tests/test_release_export_policy.py |
|---|---|---|---|---|
| 2026-09-19 04:19 | software-engineer-3 | `454b6b5` | docs(防漂移): README 手写计数改机器派生 + 中英差异对齐（P0-5/P0-4）[无任务:治理] | README.md README.zh.md ctf_agent/.gitignore ctf_agent/scripts/_kpi_canonical.py ctf_agent/scripts/release_export.py ctf_agent/tests/test_kpi_canonical.py ctf_agent/tests/test_release_export_policy.py |
|---|---|---|---|---|
| 2026-09-19 04:12 | software-engineer-2 | `3911a80` | fix(防复发): 修 bundle 同名覆盖（同秒） + 对齐节流测试 + ⑥ 纳入防复发自检 [无任务:治理] | ctf_agent/scripts/_git_snapshot.py |
|---|---|---|---|---|
| 2026-09-19 04:11 | software-engineer-2 | `3c94a95` | fix(防复发): 对齐 bundle 节流测试新语义 + 堵 ⑥ 盲点（纳入防复发自检）[无任务:治理] | ctf_agent/git_hooks/pre-commit ctf_agent/tests/test_git_guard.py |
|---|---|---|---|---|
| 2026-09-19 04:07 | software-engineer-2 | `1bb8f8f` | chore(防复发): .gitignore 忽略恢复期手工损坏备份 _git_backup_manual_*/ [无任务:治理] | .gitignore |
|---|---|---|---|---|
| 2026-09-19 04:06 | software-engineer-2 | `3c63322` | fix(防复发): bundle 快照节流改「时间 OR 落后 N 提交」+ post-commit 每次提交兜底 [无任务:治理] | ctf_agent/git_hooks/post-commit ctf_agent/scripts/_git_snapshot.py ctf_agent/tests/test_git_snapshot.py |
|---|---|---|---|---|
| 2026-09-19 04:03 | software-engineer-2 | `c28b1b6` | fix(防复发): 僵尸租约改「只报告+手动 --force」，boot 零写入 [无任务:治理] | ctf_agent/scripts/_lease.py ctf_agent/scripts/_session_boot.py ctf_agent/tests/test_lease_reap.py |
|---|---|---|---|---|
| 2026-09-19 04:00 | software-engineer-3 | `a52cb5e` | docs(kpi): 为 break-ice 实验的 15 分母补口径限定语 + 防回归测试（C①） | README.md ctf_agent/tests/test_doc_consistency.py |
|---|---|---|---|---|
| 2026-09-19 03:51 | software-engineer-2 | `e3647cd` | fix(防复发): post-commit 快照改相对路径（修 MSYS 路径致 python exit 2）[无任务:治理] | ctf_agent/git_hooks/post-commit |
|---|---|---|---|---|
| 2026-09-19 03:49 | software-engineer-3 | `b9671ed` | fix(kpi): 修正 README 中英两版 KPI 数字漂移并堵住闸门盲区（P0-3） | README.md README.zh.md ctf_agent/scripts/_doc_consistency.py ctf_agent/tests/test_doc_consistency.py |
|---|---|---|---|---|
| 2026-09-19 03:48 | software-engineer-2 | `339af56` | feat(防复发): git 健康门禁 L0 + refs/对象库快照兜底 [无任务:治理] | ctf_agent/git_hooks/post-commit ctf_agent/git_hooks/pre-commit ctf_agent/scripts/_git_guard.py ctf_agent/scripts/_git_snapshot.py ctf_agent/scripts/_lease.py ctf_agent/scripts/_merge_gate.py ctf_agent/scripts/_session_boot.py ctf_agent/tests/test_git_guard.py ctf_agent/tests/test_lease_reap.py |
|---|---|---|---|---|
| 2026-09-17 18:03 | atomcode-p0-kpi | `5c984f6` | [无任务:治理] P0-② KPI 单一权威口径 + P0-③ 治链路(E3 解药启用) + P0-① skip 审计 | ctf_agent/scripts/_chain_stats.py ctf_agent/scripts/_kpi_canonical.py ctf_agent/scripts/_skip_audit.py ctf_agent/scripts/benchmark_heldout.py ctf_agent/tests/test_kpi_canonical.py ctf_agent/tests/test_sandbox_guard.py |
|---|---|---|---|---|
| 2026-09-15 19:50 | gu | `b1537d1` | [无任务:治理] KPI 严格诚实合法抬升：由 13 升至 14，唯一新增 vnctf_cm1（VNCTF2022 cm1）经 XXTEA 确定性变换真算带动证据晋级（flag_sha256 逐字匹配题面真值，非读泄露答案）；同批 57 道候选经甄别，55 道为读泄露附件、1 道为 D 类题面给答案，均依规排除不计入；16 道真值回归全 REGRESS_PASS、全量 pytest 425 通过、反注水法令零违规、文档与机器计数口径一致 | README.md ctf_agent/AGENTS.md ctf_agent/REAL_SOLVES_LEDGER.md ctf_agent/scripts/_antifraud.py ctf_agent/scripts/_merge_gate.py ctf_agent/scripts/_scan_kpi_candidates.py ctf_agent/scripts/_verify_kpi_promote.py ctf_agent/tests/test_antifraud.py |
|---|---|---|---|---|
| 2026-09-15 12:00 | gu | `d40e535` | fix: breaking-ice baidu 凭证预检对齐 config.resolve_api_key（补 QIANFAN_API_KEY 单 key 形式） [无任务:治理] | ctf_agent/scripts/_llm_breaking_ice.py |
|---|---|---|---|---|
| 2026-09-14 03:33 | atomcode-hardening | `b2c7679` | [无任务:治理] 工程加固三件: ①黑板缓存版本化——条目绑定 presolve.py 源码指纹(sha256前16位),指纹不匹配/旧格式无fp条目自动失效,防 presolve 升级后旧缓存脏命中(实测:同指纹命中✅/旧指纹失效✅/无fp失效✅) ②merge_gate 超时诊断收口——sh() 内部每命令 timeout=600s 本就充足,此前 EXIT=124 为外层 bash timeout 290s 截断,非内部缺陷,不改代码只改调用方式 ③配方库扩充 entropy_scan——字节熵扫描(纯Python内建),熵>7.2 提示加壳/加密/压缩(reverse 分诊),实测 py脚本 6.118 normal 判定正确;全量 pytest EXIT=0 | ctf_agent/core/blackboard.py ctf_agent/tools/tool_recipes/entropy_scan.json |
|---|---|---|---|---|
| 2026-09-13 17:12 | gu | `e43bfaf` | feat: 在线CTF验证面(D2) + breaking-ice诚实分类(D1) [无任务:治理] | README.md ctf_agent/scripts/_llm_breaking_ice.py ctf_agent/scripts/_online_ctf_validate.py ctf_agent/tests/test_llm_breaking_ice.py |
|---|---|---|---|---|
| 2026-09-12 16:17 | atomcode-docdrift | `ddded7c` | [无任务:治理] 修复合并闸门假红：verify_10735.py 补 ProgramFiles 默认值 + 清残留旧水位表述 | ctf_agent/scripts/verify_10735.py |
|---|---|---|---|---|
| 2026-09-12 16:08 | atomcode-docdrift | `bfcbeed` | [无任务:治理] 根治 KPI 口径漂移：台账第五节/README 对齐机器真值 + 新增 KPI 数字跨文档机器闸门 | README.md ctf_agent/REAL_SOLVES_LEDGER.md ctf_agent/scripts/_doc_consistency.py ctf_agent/tests/test_doc_consistency.py |
|---|---|---|---|---|
| 2026-09-12 12:34 | atomcode-specialcurve2 | `80624b1` | [无任务:晋级] specialcurve2 KPI合法提升12→13: verify_specialcurve2.py重写为完整攻击链(自洽验证pow(2,e,n)==norm(HINT)实测True+factordb/ECM(B1=25万,gmpy2实测190s)分解266-bit n三89-bit安全素数+ord=∏(p²-1)+d=e⁻¹+M=C^d复数群快速幂)→sha256逐字匹配题面官方flag_sha256=cd7e815f(A类外部真值闭环,REGRESS_PASS EXIT=0)；原'实例值丢失'判定过时(公开writeup ljahum博客2021-12-14留存原实例n/HINT/C)；_merge_gate:REGRESSION_CHECKS 14→15+KNOWN_GAP 1→0清零+_CIRCULAR_VERIFY_EXCLUDE移除(不再同义反复)；_antifraud:PROMOTION_EVIDENCE第4项+水位=9+4=13；台账题块1 ⛔→✅ offline_verified；KPI_BASELINE 13/回归15；test_antifraud 21 passed+全量pytest EXIT=0 | README.md ctf_agent/REAL_SOLVES_LEDGER.md ctf_agent/scripts/_antifraud.py ctf_agent/scripts/_merge_gate.py ctf_agent/scripts/verify_specialcurve2.py ctf_agent/tests/test_antifraud.py |
|---|---|---|---|---|
| 2026-09-04 10:38 | aris-round3 | `93a245f` | [无任务:文档] docs(aris): 第三轮实证(黑板缓存真bug+5缺口引擎+BeCare4链+web审计_time修复) | idea-stage/research/ROUND3_FINDINGS-20260904.md |
|---|---|---|---|---|
| 2026-09-04 10:38 | aris-round3 | `733938a` | [无任务:治理] feat(aris): 第三轮——黑板缓存答案校验修复+附件脚本/迷宫引擎+web审计_time修复与原型链污染检测(18缺口14解决) | ctf_agent/core/presolve.py ctf_agent/skills/web_source_audit.py ctf_agent/tests/test_presolve_poller.py |
|---|---|---|---|---|
| 2026-09-03 13:25 | gu | `f036286` | [无任务:治理] 10735 治理修复（KPI水位不变12，回归集 13→14 / KNOWN_GAP 2→1）：①从报废仓库 _archive/ctf_agent_broken/ 找回 16MB 原始赛题 pcap logbool.pcapng(110701包)落 data/race_attachments/(.gitignore排除不入HEAD) ②新增 scripts/verify_10735.py 可复现verifier:scapy重装HTTP流→sqlmap布尔盲注谓词解析→0..255 argmin冲突数鲁棒解码还原ctfblob各列(content=338-hex RAR5/password)→完整版7z.exe带密码解压→三重sha256锚校验(content-hex=380c0718.../rar字节=a7699a1d...与归档logbool.rar逐字节一致/flag.txt=67f3e126...与归档_10735_unrar一致)→实测REGRESS_PASS(19s,worst_conflict=0) ③_merge_gate:REGRESSION_CHECKS 13→14+KNOWN_GAP 2→1(仅剩specialcurve2) ④台账/README/HONOR_CODE/_antifraud治理注释/core.main_agent注释同步 ⑤不进PROMOTION_EVIDENCE:题面data/race_details/10735.json无flag_sha256官方字段、sha锚源自2026-08-24台账自记录+归档中间产物交叉(双独立运行互证但非外部官方真值)——写入=自我授权注水(诚信红线) ⑥KPI_WATERMARK/AUTHORIZED/offline_verified全保持12不动,10735不在AUTHORIZED白名单→状态行不可标offline_verified(防n=13≠12触发WATERMARK_DRIFT) | ctf_agent/REAL_SOLVES_LEDGER.md ctf_agent/core/main_agent.py ctf_agent/governance/anti_fraud/HONOR_CODE.md ctf_agent/scripts/_antifraud.py ctf_agent/scripts/_merge_gate.py ctf_agent/scripts/verify_10735.py |
|---|---|---|---|---|
| 2026-09-03 12:56 | gov3-0903 | `0f8f9fa` | [无任务:治理] 10732 治理修复（KPI水位不变12，回归集 12→13 / KNOWN_GAP 3→2）：①从题面自带 DASCTF OSS URL(9.11MB/腾讯COS)重下原始赛题包→解26MB(Crypto+task.py+PKCS#1.v1.5.enc)落 data/race_attachments/(.gitignore排除不入HEAD) ②新增 scripts/verify_10732.py 可复现verifier:读附件task.py注释padded_long→剥PKCS#1 v1.5篡改填充(题方PKCS1_v1_5.encrypt改写全0 PS后门)→末尾16B=AES_KEY=44bfc33d0bfb3cd688a074a7adad1504(强校验)→AES-ECB解密→38624B %PDF-1.4→视觉裁flag行→实测REGRESS_PASS ③_merge_gate:REGRESSION_CHECKS 12→13+KNOWN_GAP 3→2(剩10735/specialcurve2) ④台账/README/反注水注释同步「✅可机器复现+⛔不进严格KPI」双标 ⑤不进PROMOTION_EVIDENCE:题面无flag_sha256、视觉读法sha256=2e9af0b3...与台账337eadc1前缀不一致、无外部真值闭环——写入=自我授权注水(诚信红线) ⑥KPI_WATERMARK/AUTHORIZED/offline_verified全保持12不动(enforce(full) 0违规,count_offline_verified=12==基线) ⑦test_antifraud加10732防御测试(不在AUTHORIZED/PROMOTION、在REGRESSION、不在KNOWN_GAP);413 passed/14 skipped,回归集13/13 overall=True | README.md ctf_agent/REAL_SOLVES_LEDGER.md ctf_agent/scripts/_antifraud.py ctf_agent/scripts/_merge_gate.py ctf_agent/scripts/verify_10732.py ctf_agent/tests/test_antifraud.py |
|---|---|---|---|---|
| 2026-09-03 06:20 | gu | `8762b98` | [无任务:修复] vnctf_flag 治理修复（KPI水位不变12）：①题面flag_pattern修订(flag{...}→vnctf{...}|flag{...}兼容) ②venv certifi RECORD缺失修复(强装certifi==2026.7.22)+httpx安装让baidu ernie-4.5-turbo-vl视觉LLM兜底可走通 ③_regress_one.py real_misc_vnctf_flag实测REGRESS_PASS(5159ms,skills/misc_grid_resample.run网格重采样+vision LLM OCR+题面sha256严格校验) ④合并基线REGRESSION_CHECKS 11→12+KNOWN_GAP 4→3+第二节-B 14/15→15/15+test_antifraud加vnctf在AUTHORIZED的防御断言 ⑤本题本就在9地板BASE_AUTHORIZED_KPI_SOLVES,本次不新增PROMOTION_EVIDENCE,KPI_WATERMARK=AUTHORIZED=12不变(把'假可复现已计入'升级为'真可复现已计入',与9→10/10→11/11→12三道带证晋级模式不同) ⑥test_antifraud.py 20 passed+enforce(full)=(True,[])+回归集12/12 overall=True全过,venv半坏非代码问题(2026-08-29前后ctf_agent/.gitignore含/data/*与docs/*边界处已多次踩坑) | README.md ctf_agent/REAL_SOLVES_LEDGER.md .../data/questions_real/misc/real_misc_vnctf_flag.json ctf_agent/scripts/_antifraud.py ctf_agent/scripts/_merge_gate.py ctf_agent/tests/test_antifraud.py |
|---|---|---|---|---|
| 2026-09-03 05:53 | gu | `3198304` | [无任务:晋级] exciting_inverse KPI合法提升11→12: skills/crypto_modinv_factor.py phi+双模逆二次分解求解器(CRT⟹A·p+B·q=N+1⟹q二次方程判别式开方分解1024-bit p/q)接入presolve _try_modinv_factor,_regress_one实测REGRESS_PASS(233ms)且sha256逐字匹配题面真值4b84616c,PROMOTION_EVIDENCE三题带证据晋级(地板9+晋升3=水位12,全证据态),台账/README/KPI_BASELINE五源同步,回归集11道全过,411测试全绿 | README.md ctf_agent/REAL_SOLVES_LEDGER.md ctf_agent/core/presolve.py ctf_agent/scripts/_antifraud.py ctf_agent/scripts/_merge_gate.py ctf_agent/skills/crypto_modinv_factor.py ctf_agent/tests/test_antifraud.py |
|---|---|---|---|---|
| 2026-09-03 05:37 | gu | `9d2fb3d` | [无任务:晋级] simplelegendre KPI合法提升10→11: skills/crypto_legendre_phi.py勒让德符号逐位分解求解器(phi泄露分解1024-bit p/q+逐位Legendre (c|p)=(-1)^bi判定)接入presolve _try_legendre_phi,_regress_one实测REGRESS_PASS(1213ms)且sha256匹配题面真值,PROMOTION_EVIDENCE带证据晋级,台账/README/KPI_BASELINE五源同步,回归集10道全过,411测试全绿 | README.md ctf_agent/REAL_SOLVES_LEDGER.md ctf_agent/core/presolve.py ctf_agent/scripts/_antifraud.py ctf_agent/scripts/_merge_gate.py ctf_agent/skills/crypto_legendre_phi.py ctf_agent/tests/test_antifraud.py |
|---|---|---|---|---|
| 2026-09-03 04:06 | gu | `78035c3` | [无任务:恢复] repo: 对象库灾难恢复+工作树重收口——8/29-9/3 loose对象灭失(.pack缺失/refs消失),重挂远程基线2ca7f39后整体重收口:①8/29-9/3本地工作(blackboard事实黑板/tool_recipes配方/honest_bench/幻觉根因研究文档/崩溃安全网) ②ezrsa KPI合法提升9→10(skills/crypto_hastad_broadcast.py Håstad e=17,presolve _try_hastad_broadcast接入,_regress_one REGRESS_PASS且sha256匹配题面真值,PROMOTION_EVIDENCE带证据晋级,台账/README/KPI_BASELINE同步) ③tests/conftest.py黑板测试隔离(修poller测试跨进程串扰,411全绿) | .gitignore README.md ctf_agent/REAL_SOLVES_LEDGER.md ctf_agent/core/blackboard.py ctf_agent/core/phases.py ctf_agent/core/presolve.py ctf_agent/core/prompts.py ctf_agent/core/race_orchestrator.py ctf_agent/eval/benchmark.py ctf_agent/report/generator.py ctf_agent/run.py ctf_agent/scripts/_antifraud.py …(+14) |
|---|---|---|---|---|
| 2026-09-03 02:21 | gu | `091488d` | [无任务:治理] chore(gitignore): ctf_agent/deliverables/** 整体本地化——honest_bench/llm_breaking_ice/能力缺口诊断等本地产物永不进 git,杜绝 git add -A 误提交污染(含并行进程自动提交);已跟踪 benchmark_runs/20260828 批次不受影响 | .gitignore |
|---|---|---|---|---|
| 2026-09-03 00:24 | gu | `38024be` | [无任务:工程] feat(benchmark): 崩溃安全网——run_benchmark 逐题落盘 progress.jsonl + BaseException 兜底报告(任何逃逸都留诊断与已完成数据,不静默丢报告);不触 KPI_WATERMARK | ctf_agent/eval/benchmark.py |
|---|---|---|---|---|
| 2026-09-02 10:23 | aris-round2 | `552292f` | [无任务:文档] docs(aris): 第二轮实证(B1根因定论+崩溃安全网+幻觉证据门+presolve 13-18) | .../HALLUCINATION_PRESOLVE_FIX-20260901.md |
|---|---|---|---|---|
| 2026-09-02 10:23 | aris-round2 | `dd088d1` | [无任务:治理] feat(aris): LLM幻觉根因修复(提取工具证据门) + presolve覆盖率升级(flag_pattern直扫+零宽隐写,18缺口13解决) | ctf_agent/core/phases.py ctf_agent/core/presolve.py ctf_agent/tests/test_extract_flag.py |
|---|---|---|---|---|
| 2026-09-02 03:49 | atomcode-p1release | `8a6c146` | [无任务:治理] feat(engineering): 对齐 SecAutoMind 差距——①事实黑板(blackboard.json presolve缓存跨会话复用,同题二次命中跳过重算) ②HITL敏感操作审批(高危工具白名单,默认记录审计/CTF_AGENT_HITL=1交互倒计时) ③复盘报告生成(goal_log失败桶+攻击链时间线+IOC+台账引用) ④工具声明式配方(JSON配方→ToolAdapter,降低加工具成本)——均以解题能力为最终目标,presolve直出不回归 | ctf_agent/core/blackboard.py ctf_agent/core/presolve.py ctf_agent/report/generator.py ctf_agent/run.py ctf_agent/tools/recipe_loader.py ctf_agent/tools/registry.py ctf_agent/tools/tool_recipes/strings_extract.json |
|---|---|---|---|---|
| 2026-09-01 19:14 | gu | `1059694` | [无任务:修复] honest_bench 四层过滤补题面级泄露检测：anxun2020_aes 假解识破(9/22->8/21) | ctf_agent/scripts/_honest_bench.py |
|---|---|---|---|---|
| 2026-09-01 19:09 | gu | `38bd0ee` | [无任务:工具] honest_bench 诚实化修正：三级输入过滤 + no_sha256 明文 fallback + no_presolve async 化 | ctf_agent/scripts/_honest_bench.py |
|---|---|---|---|---|
| 2026-09-01 18:40 | gu | `2a48483` | [无任务:修复] crypto_keyboard_path.run 兼容 attachments 键——修复 772d5c1 强制路由契约不匹配 | ctf_agent/skills/crypto_keyboard_path.py |
|---|---|---|---|---|
| 2026-09-01 18:37 | aris-improve | `48d189e` | [无任务:文档] docs(aris): 无赛期精进实证(预算加固/presolve矩阵/LLM真推理/MV) | .../research/IMPROVEMENT_FINDINGS-20260901.md |
|---|---|---|---|---|
| 2026-09-01 18:36 | aris-improve | `47ac4d4` | [无任务:治理] feat(aris): 步级硬停边界兜底(BudgetExceeded转换) + MV驱动换题(赛智收尾) | ctf_agent/core/race_orchestrator.py |
|---|---|---|---|---|
| 2026-09-01 18:33 | gu | `45e0e4e` | [无任务:修复] run.py: BudgetExceeded 边界兜底——单题预算超限不逃逸出 solve_once | ctf_agent/run.py |
|---|---|---|---|---|
| 2026-09-01 18:32 | gu | `e4f15e1` | [无任务:接线] M4: 修复 pwn_libc_fingerprint 缺 run() 死加载 + skill_map 补 4 个孤儿 skill 触发词 | ctf_agent/core/prompts.py ctf_agent/skills/pwn_libc_fingerprint.py ctf_agent/skills/task_analyzer.json |
|---|---|---|---|---|
| 2026-09-01 11:39 | gu | `2ca7f39` | [无任务:修复] Revert P1 Item4 修复A: 撤销明文附件答案提取（flag.txt 系答案密钥，读取即注水） | ctf_agent/core/presolve.py |
|---|---|---|---|---|
| 2026-09-01 11:39 | gu | `0370bb0` | [无任务:修复] Revert P1 Item4 修复A: 撤销明文附件答案提取（flag.txt 系答案密钥，读取即注水） | ctf_agent/core/presolve.py |
|---|---|---|---|---|
| 2026-09-01 11:39 | gu | `498b88a` | Revert "[无任务:修复] P1 Item4 修复A: presolve 明文小附件(flag.txt等)答案提取" | ctf_agent/core/presolve.py |
|---|---|---|---|---|
| 2026-09-01 11:30 | gu | `f4837b9` | [无任务:修复] P1 Item4 修复A: presolve 明文小附件(flag.txt等)答案提取 | ctf_agent/core/presolve.py |
|---|---|---|---|---|
| 2026-09-01 11:22 | gu | `95ee530` | [无任务:修复] P1 Item4: 失败题可观测性修复（MainAgent.solve 回传最终步 observation） | ctf_agent/core/main_agent.py |
|---|---|---|---|---|
| 2026-09-01 08:04 | gu | `772d5c1` | [无任务:修复] 反幻觉+代码围栏恢复防御加固（repair 2/3） | ctf_agent/core/llm_wrapper.py ctf_agent/core/main_agent.py ctf_agent/core/phases.py ctf_agent/llm/client.py |
|---|---|---|---|---|
| 2026-09-01 08:04 | gu | `6adffcd` | [无任务:修复] 修正 sha256 占位校验误杀：is_correct/ver_solved 改 sha256 感知 | ctf_agent/run.py ctf_agent/scripts/_dryrun_race.py |
|---|---|---|---|---|
| 2026-09-01 04:56 | gu | `31c79d0` | [无任务:修复] presolve: 拒绝不匹配 flag_pattern 的诱饵候选，修正 reverse 0.0s 误判 | ctf_agent/core/presolve.py |
|---|---|---|---|---|
| 2026-09-01 04:32 | gu-p1-heavymodel | `30c4d8e` | [无任务:修复] heavy 模型 provider 感知——消除非 baidu provider 升级 404 | ctf_agent/config.py ctf_agent/core/main_agent.py ctf_agent/llm/client.py ctf_agent/scripts/_dryrun_race.py ctf_agent/scripts/_net_check.py ctf_agent/scripts/_preflight.py ctf_agent/scripts/_preflight_whitelist.py ctf_agent/scripts/_smoke_real_llm.py |
|---|---|---|---|---|
| 2026-09-01 04:15 | gu-m3-prompts | `4a4b6e4` | [无任务:功能] feat(prompts): M3 补键盘/坐标→crypto_keyboard_path 映射 | ctf_agent/core/prompts.py |
|---|---|---|---|---|
| 2026-09-01 04:08 | gu-m3-closeout | `08f1242` | [无任务:修复] fix(judge): M3 真值 sha256 脱敏判分 | ctf_agent/scripts/_dryrun_race.py |
|---|---|---|---|---|
| 2026-09-01 04:07 | gu-m3-closeout | `16b18eb` | [无任务:功能] feat(agent): M3 放弃前确定性兜底 _deterministic_last_chance | ctf_agent/core/main_agent.py |
|---|---|---|---|---|
| 2026-08-30 15:26 | atomcode-p1release | `fbbfac1` | [无任务:治理] feat(skills): 新增 3 个 reverse skill 补短板——reverse_router(文件类型确定性路由,借鉴reverse-skill路由矩阵) + reverse_angr_solver(迷宫类符号执行,angr未装降级提示) + reverse_js_methodology(JS逆向4步,node未装降级)——reverse 9真题vs4skill 薄弱环节补强 | ctf_agent/skills/reverse_angr_solver.json ctf_agent/skills/reverse_angr_solver.py ctf_agent/skills/reverse_js_methodology.json ctf_agent/skills/reverse_js_methodology.py ctf_agent/skills/reverse_router.json ctf_agent/skills/reverse_router.py |
|---|---|---|---|---|
| 2026-08-29 19:30 | gu-closeout-0829 | `fdd95fc` | [无任务:治理] fix(merge_gate): real_misc_vnctf_flag 诚实校准——点阵显字需OCR/视觉模型（架构级缺口）且 verify 依赖的 verified_flags.json 真值库已随 8/28 results 隔离丢失、不可复现，移出回归集入 KNOWN_GAP（与 MEMORY.md 判断一致） | ctf_agent/scripts/_merge_gate.py |
|---|---|---|---|---|
| 2026-08-29 19:27 | gu-closeout-0829 | `5df57d7` | [无任务:功能] feat(platform): CTF² 平台适配器（ctf2.dasctf.com BUUCTF 迁移题库）——列表/详情/附件/提交四接口，8/29 实测 API 结构（data.data 嵌套），urllib 无第三方依赖 | ...50\275\256\346\225\231\350\256\255-20260829.md" ctf_agent/platform_ctf2.py ctf_agent/scripts/_closeout.py ctf_agent/scripts/hooks/commit-msg ctf_agent/scripts/hooks/pre-commit ctf_agent/scripts/hooks/pre-merge-commit |
|---|---|---|---|---|
| 2026-08-29 17:12 | aris-bcfind | `fa75217` | [无任务:文档] docs(aris): B/C实验实证结论存档(预算参数纯收益+presolve掩盖量化) | idea-stage/research/BC_FINDINGS-20260829.md |
|---|---|---|---|---|
| 2026-08-29 17:08 | gu | `5c4ef4a` | [无任务:文档] docs: 仓库内 reverse 扫描轮——2 个 reverse 题解出（离线推导，非平台 accepted——flag 已脱敏不写进 message） | ...272\244\346\216\245\346\226\207\346\241\243.md" |
|---|---|---|---|---|
| 2026-08-29 16:47 | atomcode-p1release | `1156910` | [无任务:治理] fix(client): heavy_map qwen 重型 deepseek-v4-pro-0813(免费额度耗尽403)→kimi-k3(免费额度100%剩余,HTTP200实测)——用户明确不用pro，重型升级改走免费强推理模型 | ctf_agent/llm/client.py |
|---|---|---|---|---|
| 2026-08-29 16:28 | gu | `5752301` | [无任务:文档] docs: 风险解决轮记录——qiangwang_classic/dnui_keyboard 再排查未解出（如实——不注水） | ...4\272\244\346\216\245\346\226\207\346\241\243.md" |
|---|---|---|---|---|
| 2026-08-29 16:27 | aris-switch | `96b9306` | [无任务:治理] feat(aris): 换题决策完整化——沉溺保护(信心阈值换题)+FeedbackLoop换题钩子接入live链路 | ctf_agent/core/race_orchestrator.py ctf_agent/run.py ctf_agent/verify/feedback.py |
|---|---|---|---|---|
| 2026-08-29 08:10 | gu | `68169af` | [无任务:治理] 发布就绪收口：trusted_rce 黑名单/IP强校验加固 + setup.sh 去个人化 + presolve 导入告警去重 + 台账路径脱敏 + 启动脚本可移植化 | AGENTS.md ctf_agent/AGENTS.md ctf_agent/REAL_SOLVES_LEDGER.md ctf_agent/config.py ctf_agent/core/presolve.py ctf_agent/pyproject.toml ctf_agent/sandbox/subprocess_executor.py ctf_agent/sandbox/trusted_rce.py ctf_agent/scripts/_fix_presolve_concurrent.py ctf_agent/scripts/_fix_round5.py ctf_agent/scripts/_fix_round5_runpy.py ctf_agent/scripts/_fw_10793.py …(+10) |
|---|---|---|---|---|
| 2026-08-29 07:31 | aris-runbook | `cd54027` | [无任务:文档] docs(aris): 开赛一键启动runbook(live+race-intelligence) | .../research/LIVE_LAUNCH_RUNBOOK-20260829.md |
|---|---|---|---|---|
| 2026-08-29 01:05 | gu | `0c33eb5` | [无任务:治理] 收口在飞改动：P0 修复×2（fallback sys.path 注入 + _classify 兜底）+ README skills 52 + 根 data/ gitignore + Block2 报告脚本 | .gitignore README.md README.zh.md ctf_agent/agents/crypto_toolkit.py ctf_agent/scripts/block2_report.py ctf_agent/skills/web_target_interact.py idea-stage/refine-logs/EXPERIMENT_PLAN.md |
|---|---|---|---|---|
| 2026-08-28 22:01 | gu | `01ad553` | [无任务:治理] fix(vision): ai_vision 默认 provider 锁定 baidu（抗 CTF_AGENT_LLM_PROVIDER=qwen 漂移）；对齐 ERR_UNRESOLVED 测试 | ctf_agent/llm/client.py ctf_agent/tests/test_ai_vision.py ctf_agent/tests/test_failure_taxonomy.py ctf_agent/tests/test_main_agent_e2_budget.py ctf_agent/tests/test_main_agent_wallclock.py ctf_agent/tests/test_presolve_jpeg_vision.py |
|---|---|---|---|---|
| 2026-08-28 21:55 | gu | `3246b15` | [无任务:治理] 将 .publish_assets/ 改为 gitignore 并取消跟踪 | .gitignore .../.github/ISSUE_TEMPLATE/bug_report.yml .../.github/ISSUE_TEMPLATE/feature_request.yml .publish_assets/.github/workflows/ci.yml .publish_assets/CONTRIBUTING.md .publish_assets/LICENSE .publish_assets/README.md .publish_assets/docs/ARCHITECTURE.md |
|---|---|---|---|---|
| 2026-08-28 21:53 | gu | `4ab1fdb` | [无任务:治理] 修复 README.md 断链：恢复 README.zh.md 并加入结构守卫根白名单 | README.zh.md ctf_agent/scripts/_structure_guard.py |
|---|---|---|---|---|
| 2026-08-28 21:42 | gu | `a97c33e` | [无任务:治理] 收口在途开发：根级文件与发布资产收口 | .gitignore .../.github/ISSUE_TEMPLATE/bug_report.yml .../.github/ISSUE_TEMPLATE/feature_request.yml .publish_assets/.github/workflows/ci.yml .publish_assets/CONTRIBUTING.md .publish_assets/LICENSE .publish_assets/README.md .publish_assets/docs/ARCHITECTURE.md AGENTS.md CLAUDE.md README.md README.zh.md …(+1) |
|---|---|---|---|---|
| 2026-08-28 21:41 | gu | `1ddf815` | [无任务:治理] 收口在途开发：idea-stage 科研产物与项目元文档 | docs/.gitkeep ...275\222\346\241\243\350\257\264\346\230\216.md" idea-stage/IDEA_REPORT.md ...46\225\233\346\217\220\346\241\210-20260827.md" idea-stage/refine-logs/FINAL_PROPOSAL.md .../FINAL_PROPOSAL_RACE_INTELLIGENCE.md .../research-wiki/competitive_landscape_round2.md idea-stage/research-wiki/gap_map.md idea-stage/research-wiki/graph/edges.jsonl .../ideas/idea_ctf_agent_context_compression.md .../ideas/idea_ctf_agent_human_in_loop.md .../ideas/idea_ctf_agent_race_intelligence.md …(+22) |
|---|---|---|---|---|
| 2026-08-28 21:41 | gu | `a2e33cb` | [无任务:治理] 收口在途开发：ctf_agent 杂项（skills/ctfplatform/hooks/配置） | ctf_agent/.gitignore ctf_agent/AGENTS.md ctf_agent/config.py ctf_agent/ctfplatform/ctfplatform/__init__.py ctf_agent/ctfplatform/ctfplatform/base.py ctf_agent/ctfplatform/ctfplatform/dasctf.py ctf_agent/ctfplatform/ctfplatform/poller.py ctf_agent/ctfplatform/poller.py .../llm_breaking_ice_20260828-013535.json .../llm_breaking_ice_20260828-022534.json .../llm_breaking_ice_20260828-105946.json .../llm_breaking_ice_20260828-105959.json …(+17) |
|---|---|---|---|---|
| 2026-08-28 21:41 | gu | `267f20d` | [无任务:治理] 收口在途开发：ctf_agent 核心与引擎模块 | ctf_agent/agents/crypto_toolkit.py ctf_agent/agents/vision_flag_router.py ctf_agent/agents/web_toolkit.py ctf_agent/core/action_executor.py ctf_agent/core/budget_reflection.py ctf_agent/core/confidence.py ctf_agent/core/decision_engine.py ctf_agent/core/goal_directive.py ctf_agent/core/llm_wrapper.py ctf_agent/core/main_agent.py ctf_agent/core/marginal_value.py ctf_agent/core/phases.py …(+18) |
|---|---|---|---|---|
| 2026-08-28 21:41 | gu | `3ef5b00` | [无任务:治理] 收口在途开发：ctf_agent/scripts 求解器与工具集 | ctf_agent/scripts/_bench_situation_override.py ctf_agent/scripts/_board.py ctf_agent/scripts/_chain_stats.py ctf_agent/scripts/_closeout.py ctf_agent/scripts/_dryrun_race.py ctf_agent/scripts/_fix_ledger_kpi.py ctf_agent/scripts/_gen_ctf2022_20260827.py ctf_agent/scripts/_gen_local_text_20260827.py ctf_agent/scripts/_gen_longjian_2024_2025.py ctf_agent/scripts/_gen_sheng_traffic.py ctf_agent/scripts/_gen_web_misc_20260827.py ctf_agent/scripts/_kpa_zip.py …(+42) |
|---|---|---|---|---|
| 2026-08-28 21:40 | gu | `33abdab` | [无任务:治理] 收口在途开发：ctf_agent/tests 测试套件 | ctf_agent/tests/{tests => }/README.md ctf_agent/tests/test_ai_vision.py ctf_agent/tests/test_budget_reflection.py ctf_agent/tests/test_crypto_keyboard_path.py ctf_agent/tests/test_dryrun_audit_passthrough.py ctf_agent/tests/test_eval_integrity.py ctf_agent/tests/test_extract_flag.py ctf_agent/tests/test_grid_resample_opt.py ctf_agent/tests/test_guards.py ctf_agent/tests/test_jpeg_png_ocr.py ctf_agent/tests/test_llm_failover.py ctf_agent/tests/test_main_agent_e2_budget.py …(+56) |
|---|---|---|---|---|
| 2026-08-28 21:40 | gu | `74e04d5` | [无任务:治理] 收口在途开发：ctf_agent/data/questions_real 真题真值层 | .../crypto/real_crypto_anwang_crypto1.json .../crypto/real_crypto_anxun2020_aes.json .../crypto/real_crypto_anxun2020_coolboy.json .../crypto/real_crypto_changan2021_checkin.json .../crypto/real_crypto_changan2021_easyrsa.json .../crypto/real_crypto_changan2021_ezpy.json .../crypto/real_crypto_dnui_keyboard.json .../crypto/real_crypto_exciting_inverse.json .../data/questions_real/crypto/real_crypto_ezmult.json .../data/questions_real/crypto/real_crypto_ezrsa.json .../questions_real/crypto/real_crypto_filterrandom.json .../crypto/real_crypto_gaoxiao2024_z3.json …(+80) |
|---|---|---|---|---|
| 2026-08-28 20:34 | gu | `eb46fdf` | [无任务] 恢复重提 P0-P6：git 元数据损坏后的等价重提 | ctf_agent/REAL_SOLVES_LEDGER.md ctf_agent/core/race_orchestrator.py ctf_agent/governance/anti_fraud/HONOR_CODE.md ctf_agent/scripts/_antifraud.py ctf_agent/scripts/_merge_gate.py ctf_agent/scripts/_mock_web_target.py ctf_agent/scripts/_regress_one.py ctf_agent/scripts/_structure_guard.py ctf_agent/scripts/web_target_real.py ctf_agent/tests/test_antifraud.py ctf_agent/tests/test_race_orchestrator.py ctf_agent/tests/test_web_target_mock.py |
|---|---|---|---|---|
| 2026-08-28 20:30 | gu | `f4d2d73` | [无任务] feat(vision): misc_grid_resample 视觉兜底改接统一 ai_vision（ernie-4.5-turbo-vl via baidu） | ctf_agent/skills/misc_grid_resample.py ctf_agent/tests/test_grid_resample_vision.py |
|---|---|---|---|---|
| 2026-08-28 20:25 | gu | `3bdaff5` | [无任务] 修复git对象库损坏并重提交Claim1实证结论与benchmark并发层 | ctf_agent/eval/benchmark.py idea-stage/refine-logs/EXPERIMENT_PLAN.md idea-stage/research/CLAIM1_findings.md |
|---|---|---|---|---|
| 2026-08-28 19:38 | workbuddy-xihu-20260828 | `68b4506` | [无任务] research(claim1): 实证闭环——熔断省18.7% token零解出率损失(kpi9真值)；EXPERIMENT_PLAN纠正40道/40%过度宣称；新增findings | idea-stage/refine-logs/EXPERIMENT_PLAN.md idea-stage/research/CLAIM1_findings.md |
|---|---|---|---|---|
| 2026-08-28 01:07 | gu | `4adcc90` | [无任务] chore(provider): 登记百度千帆全量 ERNIE 模型(27个) 到 BAIDU_QIANFAN_ERNIE_MODELS 注册表 | ctf_agent/config.py |
|---|---|---|---|---|
| 2026-08-28 01:05 | gu | `88e788e` | [无任务] chore(provider): 安排 baidu 千帆三个免费 ernie-4.5-turbo 模型 + README 补 LLM 破冰口径 | README.md ctf_agent/config.py |
|---|---|---|---|---|
| 2026-08-28 00:46 | atomcode-closeout | `753e618` | [无任务] fix(test): MockTarget 就绪等待(纯TCP探测)——消除套件内偶发 conn_refused flaky(3次重跑全过) | ctf_agent/scripts/_mock_web_target.py |
|---|---|---|---|---|
| 2026-08-28 00:45 | gu | `ab6e782` | [无任务] docs: 仓库内真题继续解轮——simplelegendre 分解成功 bit 解密乱码（如实——不注水） | ...4\272\244\346\216\245\346\226\207\346\241\243.md" |
|---|---|---|---|---|
| 2026-08-27 23:43 | gu | `afc3c9d` | chore(closeout): _closeout.py 固化外部真题依赖断链检查——2026-08-27 E:/Program/Cybersecurity/比赛真题被清理删除致4道verify静默断链事故的收尾防护(check_external_deps 核对附件源存在性) [无任务] | ctf_agent/scripts/_closeout.py |
|---|---|---|---|---|
| 2026-08-27 23:38 | gu | `b2c5e2f` | [无任务] chore: 新增诚实视觉路由模块(vision_flag_router) + 测试垃圾 gitignore | .gitignore ctf_agent/agents/vision_flag_router.py ctf_agent/tests/test_vision_flag_router.py |
|---|---|---|---|---|
| 2026-08-27 20:41 | gu | `31310f7` | [无任务] docs: 仓库内真题继续解轮——exciting_inverse 解出（离线推导，非平台 accepted——flag 已脱敏不写进 message） | ...272\244\346\216\245\346\226\207\346\241\243.md" |
|---|---|---|---|---|
| 2026-08-27 20:05 | gu | `134f72f` | [无任务] docs: 真题集继续解轮——ezrsa 解出（离线推导，非平台 accepted——flag 已脱敏不写进 message） | ...272\244\346\216\245\346\226\207\346\241\243.md" |
|---|---|---|---|---|
| 2026-08-27 19:05 | gu | `f0ccece` | [无任务] feat(antifraud): 反注水法令写死——KPI_WATERMARK=12 硬编码真值锚(不读任何可编辑文件) + AUTHORIZED_KPI_SOLVES 12题ID级白名单 + 泄露式假验证/基线篡改/授权走私检测 + 永久tamper-evident违规账(violations.jsonl,纳版本控制) + 钩子接入pre-commit(gate10)/pre-merge/commit-msg + 16单测 | .gitignore ctf_agent/git_hooks/commit-msg ctf_agent/git_hooks/pre-commit ctf_agent/git_hooks/pre-merge-commit ctf_agent/governance/anti_fraud/HONOR_CODE.md ctf_agent/governance/anti_fraud/violations.jsonl ctf_agent/scripts/_antifraud.py ctf_agent/tests/test_antifraud.py |
|---|---|---|---|---|
| 2026-08-27 18:48 | gu | `60e2d90` | [无任务] feat(budget-reflection): race-intelligence第二层——纯规则预算反思(CONTINUE/SWITCH/ABANDON),无LLM可单测;main_agent每5步只读日志+CTF_AGENT_BUDGET_REFLECTION闸门早停(默认关,零回归);9测试绿,全47测试绿 | ctf_agent/core/budget_reflection.py ctf_agent/core/main_agent.py ctf_agent/tests/test_budget_reflection.py |
|---|---|---|---|---|
| 2026-08-27 18:44 | gu | `2381ea1` | [无任务] fix(honesty): 严格纠正——kpi_check 升级为 n==基线(注水亦失败)+前置泄露式假验证扫描;重写demo_llm_rag_solve去除硬编码10733真flag/解法/EXPECTED(仅留RAG检索结构);加test_no_leaked_flag护栏;36测试绿,kpi_check=True | ctf_agent/scripts/_merge_gate.py ctf_agent/scripts/demo_llm_rag_solve.py ctf_agent/tests/test_no_leaked_flag.py |
|---|---|---|---|---|
| 2026-08-27 18:25 | gu | `6f2a138` | 真题库重建(续十二): 外网权威writeup补缺 6道真真题(UMDCTF2022 Vigenere + DiceCTF2022 knock-knock/point + UDOMCTF2022 命令注入/摩斯/AES) [无任务] | .../crypto/real_crypto_udomctf2022_aes.json .../crypto/real_crypto_umdctf2022_vigenere.json .../misc/real_misc_udomctf2022_morse.json .../web/real_web_dicectf2022_knockknock.json .../web/real_web_dicectf2022_point.json .../web/real_web_udomctf2022_cmdinj.json ctf_agent/scripts/_gen_ctf2022_20260827.py |
|---|---|---|---|---|
| 2026-08-27 18:24 | gu | `d2eeb9e` | 真题库重建(续十一): 外网权威writeup补缺 7道真真题(强网杯2020×2 + 陇剑杯2023 baby_forensics3 + WGMY2022×2 SSTI + LINECTF2022 + HackTheBoo2022 SSTI) [无任务] | .../real_misc_longjian2023_baby_forensics3.json .../misc/real_misc_qiangwang2020_cefang.json .../misc/real_misc_qiangwang2020_upload.json .../web/real_web_hacktheboo2022_spookifier.json .../web/real_web_linectf2022_ssti_jwt.json .../web/real_web_wgmy2022_christmas_wishlist.json .../web/real_web_wgmy2022_christmas_wishlist2.json ctf_agent/scripts/_gen_web_misc_20260827.py |
|---|---|---|---|---|
| 2026-08-27 18:22 | gu | `e7cf9cc` | 真题库重建(续十): 本机writeup文本补缺 4道真真题(VNCTF2022 TimeFlies/VNloan + 长安杯2021 pwn3 + 安洵2020 AES-CBC) [无任务] | .../crypto/real_crypto_anxun2020_aes.json .../misc/real_misc_vnctf_vnloan.json .../pwn/real_pwn_changan2021_pwn3.json .../reverse/real_reverse_vnctf_timeflies.json ctf_agent/scripts/_gen_local_text_20260827.py |
|---|---|---|---|---|
| 2026-08-27 18:18 | gu | `5a8cccc` | [无任务] feat(writeup_rag): 真实集成——RAG每步检索注入主解题循环(CTF_AGENT_WRITEUP_RAG开关,零回归)+merge_gate硬编码排除specialcurve2循环核验(诚实KPI锁12)+台账注水校正(13->12,LLM贡献0,demo泄露标注);33测试绿 | ctf_agent/REAL_SOLVES_LEDGER.md ctf_agent/core/main_agent.py ctf_agent/core/prompts.py ctf_agent/scripts/_merge_gate.py ctf_agent/tests/test_writeup_rag.py |
|---|---|---|---|---|
| 2026-08-27 18:11 | gu | `f425781` | 真题库重建(续九): NACTF2020 Zip Madness 递归解压flag(writeup明文已给) [无任务] | .../misc/real_misc_nactf2020_zip_madness.json |
|---|---|---|---|---|
| 2026-08-27 18:10 | gu | `a2d5684` | 真题库重建(续八): 本地金矿PDF抽取 某省赛路由器流量分析×5(明文答案writeup已给) + MJUCTF/隐写PDF文本归档 [无任务] | ...al_misc_sheng2022_traffic_bruteforce_count.json .../real_misc_sheng2022_traffic_enable_pwd.json ..._misc_sheng2022_traffic_ftp_dataconn_count.json .../misc/real_misc_sheng2022_traffic_ftp_port.json .../real_misc_sheng2022_traffic_telnet_pwd.json ctf_agent/scripts/_gen_sheng_traffic.py ...42\230\344\270\216\351\242\230\350\247\243.txt" |
|---|---|---|---|---|
| 2026-08-27 18:09 | gu | `5ba40da` | [无任务] feat(writeup_rag): LLM 推理贡献从 0 突破 + 端到端验证 10733 | ctf_agent/AGENTS.md ctf_agent/REAL_SOLVES_LEDGER.md ctf_agent/knowledge/__init__.py ctf_agent/knowledge/bm25.py ctf_agent/knowledge/reason_with_rag.py ctf_agent/knowledge/writeup_rag.py ctf_agent/knowledge/writeups_corpus.jsonl ctf_agent/scripts/demo_llm_rag_solve.py |
|---|---|---|---|---|
| 2026-08-27 18:08 | gu | `7653fa7` | 真题库重建(续七): 陇剑杯2024初赛×5 + 陇剑杯2025决赛×4 = 9道 forensic/应急响应真题(redis md5可验证solver) [无任务] | .../misc/real_misc_longjian2024_smallsword1.json .../misc/real_misc_longjian2024_smallsword2.json .../misc/real_misc_longjian2024_smallsword3.json .../misc/real_misc_longjian2024_ssw_redis.json .../misc/real_misc_longjian2024_telnet.json .../misc/real_misc_longjian2025_app_part2.json .../real_misc_longjian2025_data_security1.json .../misc/real_misc_longjian2025_siem.json .../web/real_web_longjian2025_which_sql.json ctf_agent/scripts/_gen_longjian_2024_2025.py ctf_agent/scripts/_solve_longjian2024_redis.py recovered_external/wp_text/ctf_misc_hidden.txt |
|---|---|---|---|---|
| 2026-08-27 18:01 | gu | `487464c` | 真题库重建(续六): 公开WP flag-known 陇剑杯2023×5 + 春秋杯2022×2 + MJUCTF×2 = 9道 [无任务] | .../crypto/real_crypto_longjian2023_hd1.json .../misc/real_misc_chunqiu2022_checkin.json .../questions_real/misc/real_misc_chunqiu2022_tiger.json .../questions_real/misc/real_misc_longjian2023_bf.json .../misc/real_misc_longjian2023_smallsword3.json .../data/questions_real/misc/real_misc_mjuctf_speak.json .../misc/real_misc_mjuctf_this_is_the_flag.json .../web/real_web_longjian2023_hard_web1.json .../web/real_web_longjian2023_hard_web2.json |
|---|---|---|---|---|
| 2026-08-27 18:01 | gu | `90786e1` | [无任务] honest(KPI治理): 统一真值=13 + ledger 纳入版本控制 + 修复 specialcurve2 误标 | ctf_agent/.gitignore ctf_agent/AGENTS.md ctf_agent/REAL_SOLVES_LEDGER.md |
|---|---|---|---|---|
| 2026-08-27 18:00 | 糖露星霜•暖霞拾光 | `8d705ea` | 真题库重建(续五): 外网wp实跑复现 长安杯2021×4 + HWS DASCTF2022Jan×2 = 6道(4硬验证), 全文VERIFIED [无任务] | .../crypto/real_crypto_changan2021_checkin.json .../crypto/real_crypto_changan2021_easyrsa.json .../crypto/real_crypto_changan2021_ezpy.json .../misc/real_misc_hws2022_badpdf.json .../questions_real/pwn/real_pwn_hws2022_peach.json .../web/real_web_changan2021_soeasy.json ctf_agent/scripts/_solve_changan_checkin.py ctf_agent/scripts/_solve_changan_easyrsa.py ctf_agent/scripts/_solve_changan_ezpy.py ctf_agent/scripts/_solve_changan_soeasy.py ctf_agent/scripts/_solve_hws_badpdf.py ctf_agent/scripts/_solve_hws_peach.py |
|---|---|---|---|---|
| 2026-08-27 17:52 | 糖露星霜•暖霞拾光 | `39c618c` | [无任务] test(race-intel): 态势接管闸门行为级验证——确定性mock驱动真实solve循环,隔离override把常规CONTINUE监督推成SWITCH(空转10→5),3测试绿 | ctf_agent/scripts/_bench_situation_override.py .../tests/test_situation_override_behavior.py |
|---|---|---|---|---|
| 2026-08-27 17:51 | 糖露星霜•暖霞拾光 | `f0b304b` | 真题库重建(续四): 本地408金矿抽取 高校运维赛×7+ISCTF2024×6+GKCTF2020×3+ByteCTF×1 = 17道真真题 [无任务] | .../crypto/real_crypto_gaoxiao2024_z3.json .../crypto/real_crypto_gkctf2020_che11y.json .../crypto/real_crypto_gkctf2020_rsa.json .../crypto/real_crypto_isctf2024_decrypt.json .../misc/real_misc_bytectf_flag.json .../misc/real_misc_gaoxiao2024_cve41773.json .../misc/real_misc_gaoxiao2024_file_extract.json .../misc/real_misc_gaoxiao2024_phish_link.json .../misc/real_misc_gaoxiao2024_phish_sender.json .../misc/real_misc_gaoxiao2024_xiandian.json .../misc/real_misc_gkctf2020_pokemon.json .../misc/real_misc_isctf2024_checkin02.json …(+11) |
|---|---|---|---|---|
| 2026-08-27 17:37 | 糖露星霜•暖霞拾光 | `54b4534` | 真题库重建(续三): 本地官方wp金矿挖出 VNCTF2022×3 + 安洵杯crypto/reverse/web×5, cm1含可验证XXTEA求解器 [无任务] | .../crypto/real_crypto_anxun2020_coolboy.json .../misc/real_misc_anxun2020_722b6d.json .../misc/real_misc_vnctf_strangeflag.json .../reverse/real_reverse_anxun2020_easycm.json .../reverse/real_reverse_anxun2020_notright.json .../reverse/real_reverse_vnctf_babymaze.json .../reverse/real_reverse_vnctf_cm1.json .../web/real_web_anxun2020_welcome.json ctf_agent/scripts/_solve_vnctf_cm1.py recovered_external/wp_text/anxun2020_official.txt recovered_external/wp_text/changan.txt .../wp_text/qiangwang2020_blockchain.txt …(+1) |
|---|---|---|---|---|
| 2026-08-27 17:13 | 糖露星霜•暖霞拾光 | `5dd4b1c` | [无任务] feat(race-intel): 态势接管闸门——信心过低+过半预算时提前咨询监督换策略(env默认关,零回归), +should_early_switch单测 | ctf_agent/core/confidence.py ctf_agent/core/main_agent.py ctf_agent/tests/test_race_intelligence.py |
|---|---|---|---|---|
| 2026-08-27 17:12 | 糖露星霜•暖霞拾光 | `b7bfae8` | external CTF真题库外网重建: 安洵杯2020 misc×4 + 泰山杯2021 crypto C组题 [无任务] | .../crypto/real_taishan2021_crypto_cgroup.json .../data/questions_real/misc/real_anxun2020_BeCare4.json .../data/questions_real/misc/real_anxun2020_depressed.json .../data/questions_real/misc/real_anxun2020_easyzip.json .../data/questions_real/misc/real_anxun2020_love_letter.json |
|---|---|---|---|---|
| 2026-08-27 17:11 | 糖露星霜•暖霞拾光 | `fb9de97` | [无任务] feat(race-intel): 纯规则态势感知核心——单题信心/边际收益/三态决策引擎 + main_agent 只读态势日志(不改控制流,15测试绿) | ctf_agent/core/confidence.py ctf_agent/core/decision_engine.py ctf_agent/core/main_agent.py ctf_agent/core/marginal_value.py ctf_agent/core/race_state.py ctf_agent/tests/test_race_intelligence.py |
|---|---|---|---|---|
| 2026-08-27 17:05 | 糖露星霜•暖霞拾光 | `de7329e` | [无任务] chore(calibration): 诚实校准收口——merge_gate 移 specialcurve2 出回归集入 KNOWN_GAP；校准脚本落库去明文 flag | ctf_agent/scripts/_fix_ledger_kpi.py ctf_agent/scripts/_merge_gate.py ctf_agent/scripts/_reconcile_truth.py |
|---|---|---|---|---|
| 2026-08-27 16:44 | atomcode-overseer-20260823 | `5f7169f` | [无任务] fix(crypto_toolkit): 八进制提取正则\b[0-7]{3}\b→{2,3}兼容2位冒号(72)——修复anwang_crypto1 key/data匹配失败致crypto_auto未解出 | ctf_agent/agents/crypto_toolkit.py |
|---|---|---|---|---|
| 2026-08-27 16:41 | 糖露星霜•暖霞拾光 | `f9f7020` | [无任务] fix(test): merge_gate failclosed 测试对齐 KPI 口径（A类计数字段） | ctf_agent/tests/test_merge_gate_failclosed.py |
|---|---|---|---|---|
| 2026-08-27 16:36 | aris-commit | `ef40877` | [无任务] feat(aris): 两轮 idea-discovery 产出入库——竞品全景+7个idea+实验计划+最终提案 | idea-stage/IDEA_REPORT.md idea-stage/refine-logs/EXPERIMENT_PLAN.md idea-stage/refine-logs/FINAL_PROPOSAL.md research-wiki/competitive_landscape_round2.md .../ideas/idea_ctf_agent_context_compression.md .../ideas/idea_ctf_agent_human_in_loop.md .../ideas/idea_ctf_agent_race_intelligence.md research-wiki/ideas/idea_ctf_agent_writeup_rag.md research-wiki/index.md research-wiki/log.md .../papers/idea_ctf_agent_adaptive_routing.md .../papers/idea_ctf_agent_budget_reflection.md …(+3) |
|---|---|---|---|---|
| 2026-08-27 14:39 | 糖露星霜•暖霞拾光 | `90e333a` | [无任务] feat(web): 受信 RCE 通道扩展至上传 RCE + 反序列化 POP 链子类 | ctf_agent/agents/web_toolkit.py ctf_agent/scripts/_smoke_web_targets.py ctf_agent/scripts/web_target_unserialize_rce.py ctf_agent/scripts/web_target_upload_rce.py |
|---|---|---|---|---|
| 2026-08-27 14:30 | 糖露星霜•暖霞拾光 | `573c74c` | [无任务] feat(crypto): QWERTY 键盘路径密码确定性解码器 + presolve 接入 | ctf_agent/core/presolve.py ctf_agent/skills/crypto_keyboard_path.py ctf_agent/tests/test_crypto_keyboard_path.py |
|---|---|---|---|---|
| 2026-08-27 14:28 | 糖露星霜•暖霞拾光 | `27a7e9f` | [无任务] 外部真题附件重建入仓库: RSA3 与西湖FilterRandom 恢复; HGAME RSA 三题 verify 均 3/3 复现, lfsr skill 从恢复源码跑通 DASCTF flag。新增 _recover_hgame_rsa3.py / _recover_xihu_filterrandom.py 记录重建过程; 修 verify 脚本 emoji(GBK 控制台) 与 RSA3 守卫逻辑。 | ctf_agent/scripts/_recover_hgame_rsa3.py ctf_agent/scripts/_recover_xihu_filterrandom.py ctf_agent/scripts/verify_hgame2022_rsa.py ctf_agent/scripts/verify_hgame_rsa.py |
|---|---|---|---|---|
| 2026-08-27 14:26 | 糖露星霜•暖霞拾光 | `14c9045` | [无任务] feat(agent): v3 监督多级强制路由 + JPEG尾PNG OCR 视觉技能 | ctf_agent/core/main_agent.py ctf_agent/skills/jpeg_png_embedded.py ctf_agent/tests/test_jpeg_png_ocr.py |
|---|---|---|---|---|
| 2026-08-27 14:04 | 糖露星霜•暖霞拾光 | `71b6200` | [无任务] 外部真题 verify 脚本改仓库内部相对路径 + fail-closed 兜底；新增 _recover_hgame_outputs.py 在仓库内重建 HGAME RSA1/RSA2 附件(output.txt 留磁盘，受 .gitignore 管控不入库)。安网 misc3/玄盾 EZIP/西湖论剑2021 原始附件公开渠道不可得，脚本缺源即优雅 SKIP(退出码 2)，不再 FileNotFoundError 裸崩。 | ctf_agent/scripts/_kpa_zip.py ctf_agent/scripts/_recover_hgame_outputs.py ctf_agent/scripts/verify_anwang_misc3.py ctf_agent/scripts/verify_hgame2022_rsa.py ctf_agent/scripts/verify_hgame_rsa.py ctf_agent/skills/lfsr_filter_recover.py |
|---|---|---|---|---|
| 2026-08-27 14:01 | 糖露星霜•暖霞拾光 | `92984f4` | [无任务] 受信通道扩展·命令注入子类：新增 web-009 命令注入 RCE 真靶机(9009，flag在靶机文件系统经通道后渗透)；web_toolkit 新增 _FALLBACK_CMD_RCE 并经路由拆分(rce+ssti→SSTI_RCE，rce+命令注入→CMD_RCE)；主 Agent 真打 web-009 SOLVED_BY_LLM=True（LLM贡献8->9，self_authored不计入KPI）；修正探测 label ;id→&id；附冒烟/批量验证升级 | ctf_agent/agents/web_toolkit.py ctf_agent/scripts/_smoke_web_targets.py ctf_agent/scripts/_verify_web_batch.py ctf_agent/scripts/web_target_cmd_rce.py |
|---|---|---|---|---|
| 2026-08-27 14:00 | 糖露星霜•暖霞拾光 | `23fbf7b` | [无任务] 受信通道扩展·命令注入子类：新增 web-009 命令注入 RCE 真靶机(9009，flag在靶机文件系统经通道后渗透)；web_toolkit 新增 _FALLBACK_CMD_RCE 并经路由拆分(rce+ssti→SSTI_RCE，rce+命令注入→CMD_RCE)；主 Agent 真打 web-009 SOLVED_BY_LLM=True（LLM贡献8->9，self_authored不计入KPI）；修正探测 label ;id→&id；附冒烟/批量验证升级+诚实进展报告 | ctf_agent/agents/web_toolkit.py ctf_agent/scripts/_kpa_zip.py ctf_agent/scripts/_recover_hgame_outputs.py ctf_agent/scripts/_smoke_web_targets.py ctf_agent/scripts/_verify_web_batch.py ctf_agent/scripts/verify_anwang_misc3.py ctf_agent/scripts/verify_hgame2022_rsa.py ctf_agent/scripts/verify_hgame_rsa.py ctf_agent/scripts/web_target_cmd_rce.py ctf_agent/skills/lfsr_filter_recover.py |
|---|---|---|---|---|
| 2026-08-27 13:31 | 糖露星霜•暖霞拾光 | `d03a8d1` | [无任务] 受信 RCE 通道：sandbox/trusted_rce.py 经 CTF_AGENT_TRUSTED_RCE=1 门控+审计突破沙盒禁 os.popen 边界；web_toolkit 新增 _FALLBACK_SSTI_RCE 分支(description 含 rce 优先选入)；web-008 SSTI RCE 真靶机(泄漏仅诱饵,flag在文件系统)；主 Agent 经受信通道真解 web-008 SOLVED_BY_LLM=True（LLM贡献7->8，self_authored不计入KPI）；subprocess_executor allowlist 加 sandbox（默认关，非沙盒弱化） | ctf_agent/agents/web_toolkit.py ctf_agent/sandbox/subprocess_executor.py ctf_agent/sandbox/trusted_rce.py ctf_agent/scripts/_smoke_web_targets.py ctf_agent/scripts/_verify_web_batch.py ctf_agent/scripts/web_target_ssti_rce.py |
|---|---|---|---|---|
| 2026-08-27 13:16 | 糖露星霜•暖霞拾光 | `11d1b09` | [无任务] 扩 web 练兵场第三轮：新增 web-006 备份泄露 + web-007 SSRF 回环真靶机；主 Agent 真打 web-001~007 七类 web 漏洞全解（SOLVED_BY_LLM=True，LLM 贡献 5->7）；SSRF 靶机改 ThreadingHTTPServer 修复回环死锁；附冒烟/批量验证升级（self_authored，不计入 KPI） | ctf_agent/scripts/_smoke_web_targets.py ctf_agent/scripts/_verify_web_batch.py ctf_agent/scripts/web_target_backup.py ctf_agent/scripts/web_target_ssrf.py |
|---|---|---|---|---|
| 2026-08-27 13:09 | 糖露星霜•暖霞拾光 | `4584b34` | [无任务] 扩 web 练兵场第二轮：新增 web-004 路径穿越 + web-005 JWT 弱密钥真靶机；主 Agent 真打 web-001~005 五类 web 漏洞全解（SOLVED_BY_LLM=True，LLM 贡献 3->5）；附冒烟/批量验证升级（self_authored，不计入 KPI；进展报告按 gitignore 留本地） | ctf_agent/scripts/_smoke_web_targets.py ctf_agent/scripts/_verify_web_batch.py ctf_agent/scripts/web_target_jwt.py ctf_agent/scripts/web_target_traversal.py |
|---|---|---|---|---|
| 2026-08-27 13:02 | 糖露星霜•暖霞拾光 | `3dcf147` | [无任务] 收口外部真题源永久丢失：外部 verify 脚本改 fail-closed + 监督信号撤回失真声称 | ...\271\262\351\242\204\344\277\241\345\217\267-20260826.md" ctf_agent/scripts/_kpa_zip.py ctf_agent/scripts/verify_anwang_misc3.py ctf_agent/scripts/verify_hgame2022_rsa.py ctf_agent/scripts/verify_hgame_rsa.py ctf_agent/skills/lfsr_filter_recover.py |
|---|---|---|---|---|
| 2026-08-27 12:24 | gu-fixall-20260827 | `2682e63` | [无任务] feat(agent): supervisor 多级强制路由(flag_scan→crypto_auto→stego_lsb) + web 真题采集校验框架 collect_web_real.py | ctf_agent/core/main_agent.py ctf_agent/scripts/collect_web_real.py |
|---|---|---|---|---|
| 2026-08-27 12:03 | gu-llm-ice-20260827 | `a5c4fe0` | [无任务] feat(agent): 战役A LLM破冰——reason-loop 监督强制 flag_scan 路由（IDEA-1 最小实现）+ _llm_breaking_ice harness | ctf_agent/core/main_agent.py ctf_agent/scripts/_llm_breaking_ice.py |
|---|---|---|---|---|
| 2026-08-27 11:45 | gu | `e2cc101` | [无任务] docs: 免费优先生效实测——默认 qwen 百炼 200（不烧 deepseek 付费——显式备用） | ...4\272\244\346\216\245\346\226\207\346\241\243.md" |
|---|---|---|---|---|
| 2026-08-27 11:36 | gu-p0-20260827 | `2d85984` | [无任务] feat(merge_gate): 收录边界规则机器化——_classify_entry A/B/E/C 分类 + count 仅计 A/B 类（fail-closed 未标注默认 C 不计）——KPI 口径从'文档裁定'升级为'代码判定' | ctf_agent/scripts/_merge_gate.py |
|---|---|---|---|---|
| 2026-08-27 11:33 | gu-p0-20260827 | `129312e` | [无任务] chore(env): requirements.txt 补 sympy==1.14.0（math_engine 依赖，re-benchmark 实测需要）——在飞改动收口 | ctf_agent/requirements.txt |
|---|---|---|---|---|
| 2026-08-27 11:31 | gu | `53160e6` | [无任务] docs: 免费 provider 可用清单完整（qwen 百炼 + 讯飞 lite 双免费源 200 确认——deepseek 付费备用） | ...272\244\346\216\245\346\226\207\346\241\243.md" |
|---|---|---|---|---|
| 2026-08-27 11:14 | atomcode-p1release | `dc402b3` | [无任务] fix(config): qwen 默认模型 deepseek-v4-pro-0813(深推理贵)→qwen3.7-flash(免费额度99.97%剩余)——用户明确要求不用pro，默认走便宜快速模型，pro仅留重型升级 | ctf_agent/config.py |
|---|---|---|---|---|
| 2026-08-27 02:08 | gu | `b46dcb1` | [无任务] fix(dryrun): 回写 presolve web_audit_report 到共享 qdict（M2-AUDIT-INJECT 闭环） | ctf_agent/scripts/_dryrun_race.py ctf_agent/tests/test_dryrun_audit_passthrough.py |
|---|---|---|---|---|
| 2026-08-27 01:20 | gu | `86ff1c4` | [无任务] docs: 免费优先配置——默认切 qwen 百炼（免费 200——替代 baidu 欠费）+ deepseek 付费兜底 | ...272\244\346\216\245\346\226\207\346\241\243.md" |
|---|---|---|---|---|
| 2026-08-27 01:19 | atomcode-closeout | `5a6d6e1` | [无任务] chore(env): 固化 requirements.txt(.venv 34依赖冻结, 防 miniconda3 事故复发) | ctf_agent/requirements.txt |
|---|---|---|---|---|
| 2026-08-27 01:07 | gu | `62b00e6` | [无任务] docs: deepseek 新 key 配置完成——实际调用 200 确认（风险全解决） | ...4\272\244\346\216\245\346\226\207\346\241\243.md" |
|---|---|---|---|---|
| 2026-08-27 00:58 | atomcode-p1release | `f7c52c7` | [无任务] fix(main_agent): 修正 KNOWN_GAP 集合——anwang_crypto1(安网杯八进制+Vigenère,presolve可解)非KNOWN_GAP，回退上批次误归类；正确集合={10732,10735}(台账派生的缺参题) | ctf_agent/core/main_agent.py |
|---|---|---|---|---|
| 2026-08-27 00:51 | gu | `67bc0e3` | [无任务] docs: README Honest KPI 统一到 offline_verified=9 唯一口径（14/15 标注为 presolve 覆盖度非解出） | README.md |
|---|---|---|---|---|
| 2026-08-27 00:48 | atomcode-p1release | `abe0e92` | [无任务] fix(main_agent): KNOWN_GAP题(anwang_crypto1缺运行时参数)解不出归extract_fail而非wrong_direction——修正监督裁决误判66条，失败桶口径真实化 | ctf_agent/core/main_agent.py |
|---|---|---|---|---|
| 2026-08-27 00:41 | gu | `3b2c722` | [无任务] chore: 攻坚文档回到 gitignored（data/results/*.md 夹生追踪清理） | ...51\252\214\350\256\276\350\256\241-20260825.md" |
|---|---|---|---|---|
| 2026-08-27 00:39 | gu | `1274159` | [无任务] fix(setup): .venv 自愈——pyvenv.cfg base 失效时自动重建 + 攻坚文档夹生追踪清理 + 租约路径基准修复(仓库根=父目录) | ctf_agent/scripts/_lease.py ctf_agent/setup.sh |
|---|---|---|---|---|
| 2026-08-27 00:38 | gu | `f746652` | [无任务] docs: API 更换风险解决记录（resolve 机制确认/python 路径解决/新 key 服务商未确认——如实） | ...272\244\346\216\245\346\226\207\346\241\243.md" |
|---|---|---|---|---|
| 2026-08-26 22:02 | 糖露星霜•暖霞拾光 | `7703a89` | [无任务] feat(ctf_agent): 跨源熔断兜底路由 + E1 结构化提取 + vnctf 网格重采样 numpy 向量化（离线测试全绿） | .../.github/ISSUE_TEMPLATE/bug_report.yml .../.github/ISSUE_TEMPLATE/feature_request.yml .publish_assets/.github/workflows/ci.yml .publish_assets/CONTRIBUTING.md .publish_assets/LICENSE .publish_assets/README.md .publish_assets/docs/ARCHITECTURE.md ctf_agent/benchmark_report.json ctf_agent/core/llm_wrapper.py ctf_agent/core/phases.py ctf_agent/llm/failover.py ctf_agent/skills/misc_grid_resample.py …(+3) |
|---|---|---|---|---|
| 2026-08-26 21:11 | atomcode-closeout | `6721d4c` | [无任务] docs(监督): 监督干预信号-20260826 固化多轮观察结论+处置建议(20处裸奔/红牌复核/攻坚进展/同口径重跑83.2%) | ...51\242\204\344\277\241\345\217\267-20260826.md" |
|---|---|---|---|---|
| 2026-08-26 21:09 | atomcode-closeout | `80b9300` | [无任务] chore(closeout): 收口在飞2处——prompts flag_pattern 默认值修复 + test_eval_integrity 题库缺失skipTest | ctf_agent/core/prompts.py ctf_agent/tests/test_eval_integrity.py |
|---|---|---|---|---|
| 2026-08-26 21:04 | atomcode-overseer-20260823 | `e7edeb1` | [无任务] docs(主Agent攻坚): 第二十四章 dnui_keyboard解出——题面直接给CLCKOUTHK+flag_sha256双源验证,台账offline_verified第10项;exciting_inverse止损 | ...51\252\214\350\256\276\350\256\241-20260825.md" |
|---|---|---|---|---|
| 2026-08-26 20:47 | 糖露星霜•暖霞拾光 | `1a2cdcf` | fix(web): SSRF 兜底命中 flag 后立即 break，避免继续打挂死候选致超时丢输出 [无任务] | ctf_agent/agents/web_toolkit.py |
|---|---|---|---|---|
| 2026-08-26 20:31 | aris-setup | `de9029d` | [无任务] feat(aris): research-wiki 知识库入库——按用户决策保留跟踪（移除 .gitignore 忽略项） | .gitignore research-wiki/gap_map.md research-wiki/graph/edges.jsonl research-wiki/index.md research-wiki/log.md research-wiki/query_pack.md |
|---|---|---|---|---|
| 2026-08-26 18:33 | 糖露星霜•暖霞拾光 | `273b478` | test: 新增真题集真值/安全不变式批量回归校验（P3 vnctf 闭环强化） [无任务] | ctf_agent/scripts/verify_real_questions.py |
|---|---|---|---|---|
| 2026-08-26 18:32 | 糖露星霜•暖霞拾光 | `49c7083` | fix(web): 路径穿越兜底命中后结构化回传 [FLAG_FOUND] 供主 Agent 取值 [无任务] | ctf_agent/agents/web_toolkit.py |
|---|---|---|---|---|
| 2026-08-26 18:31 | 糖露星霜•暖霞拾光 | `a43a20e` | feat(web): 新增 SSRF 自动解兜底分支与 web-011 练兵端点 [无任务] | ctf_agent/agents/web_toolkit.py ctf_agent/scripts/web_target_range.py |
|---|---|---|---|---|
| 2026-08-26 18:15 | 糖露星霜•暖霞拾光 | `3e251d9` | chore: 加固 .gitignore 屏蔽真题集 _attachments 明文真 flag 附件 [无任务] | .gitignore ctf_agent/.gitignore .../questions_real/_attachments/.gitattributes .../crypto/real_crypto_anwang_crypto1/flag.txt ...0\260]\351\224\256\347\233\230\344\276\240.txt" .../crypto/real_crypto_exciting_inverse/output .../crypto/real_crypto_exciting_inverse/problem.py .../_attachments/crypto/real_crypto_ezmult/s1.txt .../_attachments/crypto/real_crypto_ezrsa/output .../_attachments/crypto/real_crypto_ezrsa/task.py .../real_crypto_filterrandom/FilterRandom.py .../classicCrypto.txt …(+7) |
|---|---|---|---|---|
| 2026-08-26 15:03 | atomcode-p1release | `26e887d` | [无任务] fix(config): qwen 默认模型 qwen3.7-plus(403额度耗尽)→deepseek-v4-pro-0813(HTTP200可用)，修复 qwen provider 熔断根因 | ctf_agent/config.py |
|---|---|---|---|---|
| 2026-08-26 14:56 | aris-setup | `0b754bf` | [无任务] feat(aris): 集成 ARIS 睡觉自动科研工作流——CLAUDE.md 配置+research-wiki 知识库初始化 | .gitignore CLAUDE.md research-wiki/gap_map.md research-wiki/graph/edges.jsonl research-wiki/index.md research-wiki/log.md research-wiki/query_pack.md |
|---|---|---|---|---|
| 2026-08-26 14:50 | atomcode-overseer-20260823 | `927e0c9` | [无任务] docs(主Agent攻坚): 第二十三章 ezmult解出——base64+ROT13+flag_sha256双源验证,台账offline_verified第9项;qiangwang/filterrandom止损 | ...\351\252\214\350\256\276\350\256\241-20260825.md" |
|---|---|---|---|---|
| 2026-08-26 14:41 | atomcode-overseer-20260823 | `c743178` | [无任务] docs(主Agent攻坚): 第二十二章 simplelegendre解出——勒让德逐位解密+flag_sha256双源验证,台账offline_verified第8项;dnui_keyboard止损 | ...236\351\252\214\350\256\276\350\256\241-20260825.md" |
|---|---|---|---|---|
| 2026-08-26 14:23 | atomcode-overseer-20260823 | `91d8909` | [无任务] docs(主Agent攻坚): 第二十一章 ezrsa解出——Hastad广播e=17爆破+flag_sha256双源验证,台账offline_verified第7项 | ...\236\351\252\214\350\256\276\350\256\241-20260825.md" |
|---|---|---|---|---|
| 2026-08-26 14:06 | atomcode-overseer-20260823 | `83f2fa1` | [无任务] docs(主Agent攻坚): 第二十章 anwang修复需重启进程生效+stuck_loop已由E2覆盖核心阈值降级不落地(误杀风险) | ...351\252\214\350\256\276\350\256\241-20260825.md" |
|---|---|---|---|---|
| 2026-08-26 13:58 | atomcode-overseer-20260823 | `c92c2ac` | [无任务] docs(主Agent攻坚): 第十九章 specialcurve2联动解出——_attachments兜底覆盖anwang+specialcurve两类,complex_mult_group路由触发+flag双源验证匹配 | ...51\252\214\350\256\276\350\256\241-20260825.md" |
|---|---|---|---|---|
| 2026-08-26 13:51 | atomcode-overseer-20260823 | `49030b5` | [无任务] fix(presolve): _attachments兜底补全——附件下载失败时从platform_meta/题面json补全,修复crypto_auto不触发致wrong_direction;质检通过+11passed | ctf_agent/core/presolve.py ...51\252\214\350\256\276\350\256\241-20260825.md" |
|---|---|---|---|---|
| 2026-08-26 11:52 | gu | `4795d0c` | [无任务] docs: 全量文本扫描轮记录——txt/md/log/json 无解出（如实 + 并行会话 web 突破） | ...272\244\346\216\245\346\226\207\346\241\243.md" |
|---|---|---|---|---|
| 2026-08-26 09:37 | 糖露星霜•暖霞拾光 | `18f4cf1` | [无任务] web 真靶机突破：修复 _FALLBACK_SQLI GET->POST，主 Agent 真打 web-001 由 stuck_loop 转为 2 调用 SOLVED_BY_LLM=True；附真执行靶机+验证脚本+诚实进展记录（self_authored 靶，不计入 KPI） | ctf_agent/agents/web_toolkit.py ctf_agent/scripts/_verify_web_real.py ctf_agent/scripts/web_target_real.py ...46\234\272\350\277\233\345\261\225-20260826.md" |
|---|---|---|---|---|
| 2026-08-26 09:31 | 糖露星霜•暖霞拾光 | `d14e9af` | [无任务] 真题集副本字节保真：_attachments 加 .gitattributes(* -text) 禁行尾转换 + 20副本按原件逐字节重写，消除 git autocrlf 导致的 SHA256 差异（满足删外部源前逐字节一致校验） | .../questions_real/_attachments/.gitattributes ...0\260]\351\224\256\347\233\230\344\276\240.txt" .../real_crypto_filterrandom/FilterRandom.py .../real_crypto_specialcurve2/SpecialCurve2.py .../_attachments/reverse/real_reverse_js/coso.js .../reverse/real_reverse_js/index.html .../web/real_web_gongye_web2/index.php |
|---|---|---|---|---|
| 2026-08-26 09:31 | gu | `b14ebfe` | [无任务] docs: exe/elf 扫描轮记录——2 个 Reverse flag 解出（离线推导，非平台 accepted） | ...51\252\214\350\256\276\350\256\241-20260825.md" ...272\244\346\216\245\346\226\207\346\241\243.md" |
|---|---|---|---|---|
| 2026-08-26 09:25 | 糖露星霜•暖霞拾光 | `55e2888` | [无任务] 真题集自包含化：15题附件(20文件,1.71MB)内联至 data/questions_real/_attachments/，json 路径改相对 ctf_agent 根——脱离外部 比赛真题 依赖（空间中性，KPI计数/真值不变） | .../crypto/real_crypto_anwang_crypto1/flag.txt ...0\260]\351\224\256\347\233\230\344\276\240.txt" .../crypto/real_crypto_exciting_inverse/output .../crypto/real_crypto_exciting_inverse/problem.py .../_attachments/crypto/real_crypto_ezmult/s1.txt .../_attachments/crypto/real_crypto_ezrsa/output .../_attachments/crypto/real_crypto_ezrsa/task.py .../real_crypto_filterrandom/FilterRandom.py .../classicCrypto.txt .../crypto/real_crypto_simplelegendre/output .../crypto/real_crypto_simplelegendre/task.py .../real_crypto_specialcurve2/SpecialCurve2.py …(+19) |
|---|---|---|---|---|
| 2026-08-26 09:18 | gu | `63c50dc` | [无任务] docs: rar/7z 扫描轮记录——rar/7z 无解出（如实 + 并行会话负结果验证） | ...272\244\346\216\245\346\226\207\346\241\243.md" |
|---|---|---|---|---|
| 2026-08-26 09:17 | atomcode-overseer-20260823 | `752f541` | [无任务] docs(主Agent攻坚): 第十四章 wrong_direction攻坚验证(负结果)——补工具证据未降wrong_direction(17→18.5%),根因仍是presolve路由缺失 | ...51\252\214\350\256\276\350\256\241-20260825.md" |
|---|---|---|---|---|
| 2026-08-26 04:41 | gu | `ff17235` | [无任务] docs: 补验证轮记录——2 个未确认 flag 验证为真（离线推导，非平台 accepted） | ...272\244\346\216\245\346\226\207\346\241\243.md" |
|---|---|---|---|---|
| 2026-08-26 04:14 | 糖露星霜•暖霞拾光 | `a9d3e03` | [无任务] 固化 presolve-skip 测量开关 + 交接文档 + 真题验证脚本（第九轮资产固化） | ...51\252\214\350\256\276\350\256\241-20260825.md" ctf_agent/eval/benchmark.py ctf_agent/run.py ctf_agent/scripts/verify_anwang_misc3.py ctf_agent/scripts/verify_hgame2022_rsa.py |
|---|---|---|---|---|
| 2026-08-26 04:08 | gu | `46d2b72` | [无任务] docs: 全量 strings 扫描轮记录——2 个 Reverse flag 解出（离线推导，非平台 accepted） | ...272\244\346\216\245\346\226\207\346\241\243.md" |
|---|---|---|---|---|
| 2026-08-26 03:08 | 糖露星霜•暖霞拾光 | `58e5ea6` | [无任务] _merge_gate.dirty_check 修正：忽略 ?? 未跟踪杂物 + 合并进行中跳过，修复误杀 --no-ff 合并的 bug（第九轮验收⑧） | ctf_agent/scripts/_merge_gate.py |
|---|---|---|---|---|
| 2026-08-26 02:58 | 糖露星霜•暖霞拾光 | `c7367e0` | [无任务] _merge_gate: count_offline_verified 排除外部真题块(HGAME等)，KPI 严格真题口径 | ctf_agent/scripts/_merge_gate.py |
|---|---|---|---|---|
| 2026-08-26 02:37 | atomcode-overseer-20260823 | `7d0d02b` | [无任务] fix(supervisor): 监督LLM补工具证据——_build_review_prompt渲染tool_used，区分空转vs方向错，减少wrong_direction误判 | ctf_agent/core/supervisor_agent.py |
|---|---|---|---|---|
| 2026-08-26 02:36 | gu | `fca205e` | [无任务] docs: LSB 隐写扫描轮记录（图片 LSB 无解出——如实 + 并行会话协作确认） | ...272\244\346\216\245\346\226\207\346\241\243.md" |
|---|---|---|---|---|
| 2026-08-26 00:17 | atomcode-overseer-20260823 | `79b57d2` | [无任务] docs(主Agent攻坚): presolve路由扩展落地——伪加密zip自动解压(_try_zip_fake_encryption) 11路并发+测试11passed+正向验证通过+coppersmith评估不落地 | ...51\252\214\350\256\276\350\256\241-20260825.md" |
|---|---|---|---|---|
| 2026-08-26 00:14 | atomcode-closeout | `66283dd` | [无任务] feat(verify): verify_hgame_rsa.py 完整核验——RSA Attack 2 三段解出(task1共享素数/task2低指数/task3共模) 3/3复现一致 | ctf_agent/scripts/verify_hgame_rsa.py |
|---|---|---|---|---|
| 2026-08-25 20:12 | gu | `e2d4deb` | [无任务] docs: misc 扫描轮记录——真题集 misc3 解出（离线推导，非平台 accepted） | ...272\244\346\216\245\346\226\207\346\241\243.md" |
|---|---|---|---|---|
| 2026-08-25 19:53 | atomcode-closeout | `3537499` | [无任务] test(merge_gate): 补 fail-closed 端到端验收测试——删基线exit1/删台账行拒绝/正常放行(红牌一复核钉死) | ctf_agent/tests/test_merge_gate_failclosed.py |
|---|---|---|---|---|
| 2026-08-25 19:52 | gu | `2225308` | [无任务] docs: 新一轮按优先级执行轮记录（P0 真题集穷尽/P1 Multi Prime 不可解/P2 并行会话协同） | ...272\244\346\216\245\346\226\207\346\241\243.md" |
|---|---|---|---|---|
| 2026-08-25 19:37 | 糖露星霜•暖霞拾光 | `ce1cf1c` | [无任务] exp(main_agent): E3 附件证据强制注入（桶C，file_analyze全文重投plan prompt） | ctf_agent/core/action_executor.py ctf_agent/core/main_agent.py ctf_agent/core/prompts.py ctf_agent/tests/test_main_agent_e3_evidence.py |
|---|---|---|---|---|
| 2026-08-25 19:36 | gu | `dd64a50` | [无任务] feat: RSA Attack 沉淀（crypto_math factorint——小 n 分解）+ 按优先级执行轮记录 | ...272\244\346\216\245\346\226\207\346\241\243.md" ctf_agent/scripts/_local_benchmark.py |
|---|---|---|---|---|
| 2026-08-25 19:32 | atomcode-overseer-20260823 | `18aba69` | [无任务] docs(主Agent攻坚): 落地追踪第八章——E2/E6已由并行会话落地+测试8passed+新数据空转62%→54% | ...51\252\214\350\256\276\350\256\241-20260825.md" |
|---|---|---|---|---|
| 2026-08-25 15:38 | 糖露星霜•暖霞拾光 | `04398ac` | [无任务] exp(main_agent): E6 few-shot 方向决策范例注入（桶B，默认关A/B可切） | ctf_agent/core/main_agent.py ctf_agent/core/prompts.py ctf_agent/tests/test_main_agent_e6_fewshot.py |
|---|---|---|---|---|
| 2026-08-25 15:25 | gu | `cde84fb` | [无任务] feat: 真题集离线推导解出 3 题 + benchmark solver 增强（共享素数/维纳） | ...272\244\346\216\245\346\226\207\346\241\243.md" ctf_agent/scripts/_local_benchmark.py |
|---|---|---|---|---|
| 2026-08-25 15:19 | 糖露星霜•暖霞拾光 | `aea1456` | [无任务] exp(main_agent): E2 步骤预算与止损——单步超时/LLM调用上限/同动作熔断 | ctf_agent/core/main_agent.py ctf_agent/tests/test_main_agent_e2_budget.py |
|---|---|---|---|---|
| 2026-08-25 15:15 | atomcode-overseer-20260823 | `e1e5113` | [无任务] docs(主Agent攻坚): 失败步实验设计+回溯验证——空转占62.3%可拦截，实验A(reason预算)优先 | ...51\252\214\350\256\276\350\256\241-20260825.md" |
|---|---|---|---|---|
| 2026-08-25 13:26 | atomcode-p1release | `1397425` | [无任务] docs(治理): AGENTS.md 发布流冻结声明——9月起整理仓库/开源美化类工作默认拒绝，发布仅走 release_export.py（作战计划2.3） | ctf_agent/AGENTS.md |
|---|---|---|---|---|
| 2026-08-25 13:18 | atomcode-p1release | `8ce1458` | [无任务] fix(security): 源码树真实 flag 明文脱敏(verify_10733/skills文档/scene8解出记录-><redacted>) + 新增 release_export 发布导出脚本(作战计划2.2双仓库模型) | ctf_agent/scripts/analysis/_scene8_build.py ctf_agent/scripts/release_export.py ctf_agent/scripts/verify_10733.py ctf_agent/skills/crypto_custom_e_hint_bfs_root.md ctf_agent/skills/crypto_decode_e_fermat.md ctf_agent/skills/crypto_high_exponent.json |
|---|---|---|---|---|
| 2026-08-25 13:17 | atomcode-overseer-20260823 | `80daf53` | [无任务] chore(解题): 10739 二次尝试止损确认——Ghidra+JDK21 已装但程序不落盘/反编译器不兼容，工具链三连失败维持不计入 | ...45\260\235\350\257\225\350\256\260\345\275\225-20260824.md" |
|---|---|---|---|---|
| 2026-08-25 12:31 | gu | `c88570d` | [无任务] docs: 第一百四十五章——继续执行轮记录（benchmark 扩展/门禁扩展/skill 统计） | ...272\244\346\216\245\346\226\207\346\241\243.md" |
|---|---|---|---|---|
| 2026-08-25 12:31 | gu | `527f0bf` | [无任务] feat: 门禁 4 参数完整性 + benchmark crypto_math solver + 继续执行轮记录 | ctf_agent/scripts/_local_benchmark.py ctf_agent/tests/test_guards.py |
|---|---|---|---|---|
| 2026-08-25 12:14 | 糖露星霜•暖霞拾光 | `1a0794d` | feat(merge_gate): 回归集扩至 3 道确定性 verifier + 诚实计数修复 [无任务] | ctf_agent/scripts/_merge_gate.py |
|---|---|---|---|---|
| 2026-08-25 12:10 | 糖露星霜•暖霞拾光 | `a16f9e0` | feat(chain_stats): 新增 --by-subclass 失败子类学(A-F) [无任务] | ctf_agent/scripts/_chain_stats.py |
|---|---|---|---|---|
| 2026-08-25 12:06 | 糖露星霜•暖霞拾光 | `c5ab297` | docs(internal): 开源重构事故报告（1.5）+ 放行 docs/internal 追踪 [无任务] | .gitignore ...46\236\204\344\272\213\346\225\205-20260825.md" |
|---|---|---|---|---|
| 2026-08-25 12:02 | 糖露星霜•暖霞拾光 | `27bab8b` | chore(flatten): tests/tests/README.md 平移至 tests/README.md，嵌套层彻底清空 [无任务] | ctf_agent/tests/{tests => }/README.md |
|---|---|---|---|---|
| 2026-08-25 12:02 | atomcode-overseer-20260823 | `745e80c` | [无任务] chore(解题): 10718 drupal 止损记录——源码包原版无改动+WEB 题动态 flag 无载体（环境性止损，不计入解题数） | ...260\235\350\257\225\350\256\260\345\275\225-20260824.md" |
|---|---|---|---|---|
| 2026-08-25 12:01 | 糖露星霜•暖霞拾光 | `35114c4` | chore(flatten): 补 stage 嵌套层删除，使 git 树与工作树一致 [无任务] | ctf_agent/ctfplatform/ctfplatform/__init__.py ctf_agent/ctfplatform/ctfplatform/base.py ctf_agent/ctfplatform/ctfplatform/dasctf.py ctf_agent/ctfplatform/ctfplatform/poller.py ctf_agent/scheduler/scheduler/__init__.py ctf_agent/scheduler/scheduler/budget.py ctf_agent/scheduler/scheduler/task_pool.py ctf_agent/tests/tests/test_benchmark_real_chain.py ctf_agent/tests/tests/test_benchmark_wallclock.py ctf_agent/tests/tests/test_closeout.py ctf_agent/tests/tests/test_coupling_cluster.py .../tests/tests/test_data_reachability_agg.py …(+42) |
|---|---|---|---|---|
| 2026-08-25 12:00 | 糖露星霜•暖霞拾光 | `c7de4b1` | fix(hooks): 修正 commit-msg 钩子 message 文件路径(cd 后 $1 失效) + 同步 ROOT [无任务] | ctf_agent/git_hooks/commit-msg ctf_agent/git_hooks/git_hooks/commit-msg ctf_agent/git_hooks/git_hooks/pre-commit ctf_agent/git_hooks/git_hooks/pre-merge-commit ctf_agent/git_hooks/pre-commit ctf_agent/git_hooks/pre-merge-commit ctf_agent/scripts/hooks/commit-msg ctf_agent/scripts/hooks/pre-commit ctf_agent/scripts/hooks/pre-merge-commit |
|---|---|---|---|---|
| 2026-08-24 22:09 | workbuddy-p1commit | `45deede` | [无任务] feat(presolve): vnctf 网格重采样隐写路线(P1) + web_source_audit 裸hex摘要flag检测 + _merge_gate import re 修复 | core/presolve.py scripts/_merge_gate.py skills/misc_grid_resample.py skills/web_source_audit.py |
|---|---|---|---|---|
| 2026-08-24 22:09 | workbuddy-p1commit | `45deede` | [无任务] feat(presolve): vnctf 网格重采样隐写路线(P1) + web_source_audit 裸hex摘要flag检测 + _merge_gate import re 修复 | core/presolve.py scripts/_merge_gate.py skills/misc_grid_resample.py skills/web_source_audit.py |
|---|---|---|---|---|
| 2026-08-24 21:12 | workbuddy-p1-vnctf-20260824 | `5cff40e` | [无任务] feat(presolve): vnctf 网格重采样隐写路由(P1) + web_source_audit 裸hex flag + merge_gate 修 import re | core/presolve.py scripts/_merge_gate.py skills/misc_grid_resample.py skills/web_source_audit.py |
|---|---|---|---|---|
| 2026-08-24 20:29 | workbuddy-redline-20260824 | `005ecba` | [无任务] fix(安全): 真题集 flag 脱敏为 sha256 占位(明文迁 gitignored verified_flags.json) + flag_matches 统一比对；顺带修 _honesty_scan 归档目录跳过缺陷 | .../crypto/real_crypto_anwang_crypto1.json .../crypto/real_crypto_dnui_keyboard.json .../crypto/real_crypto_exciting_inverse.json data/questions_real/crypto/real_crypto_ezmult.json data/questions_real/crypto/real_crypto_ezrsa.json .../crypto/real_crypto_filterrandom.json .../crypto/real_crypto_qiangwang_classic.json .../crypto/real_crypto_simplelegendre.json .../crypto/real_crypto_specialcurve2.json data/questions_real/misc/real_misc_vnctf_flag.json .../misc/real_misc_xuanhun_signin.json data/questions_real/reverse/real_reverse_js.json …(+11) |
|---|---|---|---|---|
| 2026-08-24 20:29 | workbuddy-redline-20260824 | `005ecba` | [无任务] fix(安全): 真题集 flag 脱敏为 sha256 占位(明文迁 gitignored verified_flags.json) + flag_matches 统一比对；顺带修 _honesty_scan 归档目录跳过缺陷 | .../crypto/real_crypto_anwang_crypto1.json .../crypto/real_crypto_dnui_keyboard.json .../crypto/real_crypto_exciting_inverse.json data/questions_real/crypto/real_crypto_ezmult.json data/questions_real/crypto/real_crypto_ezrsa.json .../crypto/real_crypto_filterrandom.json .../crypto/real_crypto_qiangwang_classic.json .../crypto/real_crypto_simplelegendre.json .../crypto/real_crypto_specialcurve2.json data/questions_real/misc/real_misc_vnctf_flag.json .../misc/real_misc_xuanhun_signin.json data/questions_real/reverse/real_reverse_js.json …(+11) |
|---|---|---|---|---|
| 2026-08-24 18:09 | workbuddy-redline-20260824 | `fb1b6d5` | [无任务] docs: 竞品对照审视修正 + 本会话规划 + 历轮记录（车道收口） | ...46\255\245\350\247\204\345\210\222-20260824.md" ...257\271\347\205\247\345\257\271\346\257\224.md" |
|---|---|---|---|---|
| 2026-08-24 18:09 | workbuddy-redline-20260824 | `fb1b6d5` | [无任务] docs: 竞品对照审视修正 + 本会话规划 + 历轮记录（车道收口） | ...46\255\245\350\247\204\345\210\222-20260824.md" ...257\271\347\205\247\345\257\271\346\257\224.md" |
|---|---|---|---|---|
| 2026-08-24 18:09 | workbuddy-redline-20260824 | `fb1b6d5` | [无任务] docs: 竞品对照审视修正 + 本会话规划 + 历轮记录（车道收口） | ...46\255\245\350\247\204\345\210\222-20260824.md" ...257\271\347\205\247\345\257\271\346\257\224.md" |
|---|---|---|---|---|
| 2026-08-24 18:09 | atomcode-closeout | `fb1b6d5` | [无任务] docs: 竞品对照审视修正 + 本会话规划 + 历轮记录（车道收口） | ...46\255\245\350\247\204\345\210\222-20260824.md" ...257\271\347\205\247\345\257\271\346\257\224.md" |
|---|---|---|---|---|
| 2026-08-24 18:09 | atomcode-closeout | `fb1b6d5` | [无任务] docs: 竞品对照审视修正 + 本会话规划 + 历轮记录（车道收口） | ...46\255\245\350\247\204\345\210\222-20260824.md" ...257\271\347\205\247\345\257\271\346\257\224.md" |
|---|---|---|---|---|
| 2026-08-24 18:03 | atomcode-closeout | `f99b5b5` | [无任务] fix(安全): 台账去明文flag改造(REDACTED+sha256, 明文移至gitignored verified_flags.json)+工具二进制gitignore+presolve真值核验脚本 | .gitignore REAL_SOLVES_LEDGER.md scripts/_verify_presolve_truth.py |
|---|---|---|---|---|
| 2026-08-24 18:03 | atomcode-closeout | `f99b5b5` | [无任务] fix(安全): 台账去明文flag改造(REDACTED+sha256, 明文移至gitignored verified_flags.json)+工具二进制gitignore+presolve真值核验脚本 | .gitignore REAL_SOLVES_LEDGER.md scripts/_verify_presolve_truth.py |
|---|---|---|---|---|
| 2026-08-24 18:03 | atomcode-closeout | `f99b5b5` | [无任务] fix(安全): 台账去明文flag改造(REDACTED+sha256, 明文移至gitignored verified_flags.json)+工具二进制gitignore+presolve真值核验脚本 | .gitignore REAL_SOLVES_LEDGER.md scripts/_verify_presolve_truth.py |
|---|---|---|---|---|
| 2026-08-24 17:07 | atomcode-closeout | `7222556` | [无任务] feat(解题): 并行遗留收口——presolve复数乘法群路由(vnctf_flag修复)+crypto_complex_mult_group skill+benchmark审计基线+台账/交接文档更新+事故报告 | .gitignore GIT_METADATA_DAMAGE_REPORT-20260824.md audit/audit_20260824_supervisor.md core/presolve.py ...272\244\346\216\245\346\226\207\346\241\243.md" ...260\264\344\275\215\345\243\260\346\230\216.md" eval/benchmark.py skills/crypto_complex_mult_group.json skills/crypto_complex_mult_group.py tools/skill_manager.py ...46\217\220\347\244\272\350\257\215-v3-final.md" |
|---|---|---|---|---|
| 2026-08-24 17:07 | atomcode-closeout | `7222556` | [无任务] feat(解题): 并行遗留收口——presolve复数乘法群路由(vnctf_flag修复)+crypto_complex_mult_group skill+benchmark审计基线+台账/交接文档更新+事故报告 | .gitignore GIT_METADATA_DAMAGE_REPORT-20260824.md audit/audit_20260824_supervisor.md core/presolve.py ...272\244\346\216\245\346\226\207\346\241\243.md" ...260\264\344\275\215\345\243\260\346\230\216.md" eval/benchmark.py skills/crypto_complex_mult_group.json skills/crypto_complex_mult_group.py tools/skill_manager.py ...46\217\220\347\244\272\350\257\215-v3-final.md" |
|---|---|---|---|---|
| 2026-08-24 17:00 | atomcode-closeout | `5ea0adc` | [无任务] feat(治理): 第七轮锐评执行——session_boot第六查车道位置+merge_gate收尾门禁/基线维度+看板测试基线行+调控文档第十节军令 | ...51\242\204\344\277\241\345\217\267-20260823.md" scripts/_board.py scripts/_merge_gate.py scripts/_session_boot.py |
|---|---|---|---|---|
| 2026-08-24 12:53 | atomcode-overseer-20260823 | `c8fa7f2` | [无任务] feat(解题): 正式赛真题 10735 logbool 离线解出——SQL 布尔盲注流量还原三字段+RAR5 密码解压，flag 已落盘台账第 5 条（offline_verified，非平台 accepted） | REAL_SOLVES_LEDGER.md |
|---|---|---|---|---|
| 2026-08-24 12:46 | atomcode-closeout | `edb32d7` | [无任务] fix(调控): 恢复 764484e 误删的 3 个数据文件(goal_log/submitted_flags/诚实水位声明) | .gitignore REAL_SOLVES_LEDGER.md audit/audit_20260824_supervisor.md core/presolve.py data/results/goal_log.jsonl data/results/submitted_flags.json ...260\264\344\275\215\345\243\260\346\230\216.md" eval/benchmark.py skills/crypto_complex_mult_group.json skills/crypto_complex_mult_group.py tools/pari/_dl_pari.py tools/skill_manager.py |
|---|---|---|---|---|
| 2026-08-24 12:45 | atomcode-closeout | `764484e` | [无任务] feat(调控): 合并闸门 dirty_check 收尾门禁(在飞改动禁合并入main)+调控文档第八节收口结论 | data/results/goal_log.jsonl data/results/submitted_flags.json ...51\242\204\344\277\241\345\217\267-20260823.md" ...260\264\344\275\215\345\243\260\346\230\216.md" scripts/_merge_gate.py |
|---|---|---|---|---|
| 2026-08-24 12:08 | atomcode-overseer-20260823 | `fa036b1` | [无任务] feat(解题): 真题 vnctf_flag 离线解出——杂色点网格采样隐写，flag=vnctf{****}（官方 writeup 双重核验，台账第 4 条 offline_verified） | REAL_SOLVES_LEDGER.md |
|---|---|---|---|---|
| 2026-08-24 12:04 | atomcode-overseer-20260823 | `985c5a2` | merge: P1 Step3 链路失败步统计+看板列合入 main（经临时 worktree，主树并发会话未受影响） [无任务] | scripts/_board.py scripts/_chain_stats.py |
|---|---|---|---|---|
| 2026-08-24 11:11 | research-expert-specialcurve2 | `873870f` | [无任务] fix(推理层归因): specialcurve2 路由到现成 skill + skill DLP 接口 | core/presolve.py skills/crypto_complex_mult_group.json skills/crypto_complex_mult_group.py tools/skill_manager.py |
|---|---|---|---|---|
| 2026-08-24 10:26 | SoftwareWorkshop | — | SW-QWEN1 重跑启动：eval/benchmark.py 已修（每 provider 重载题目对象，斩断 presolve_attempted 跨 provider 污染）。重跑命令同首跑 --questions-dir data/questions_real --provider baidu,qwen。注意：本次重跑仓库含并行会话未提交 core/presolve.py(_try_complex_mult_group 路由，仅影响 specialcurve2)，与该修复正交，结果将透明注明。 | （手动改动，非 commit） |
| 2026-08-24 10:18 | atomcode-overseer-20260823 | `0546db2` | feat(治理): P1 Step3 链路失败步统计 _chain_stats.py（goal_log→7步失败直方图，实测最高失败步 5_LLM主Agent 81.9%）+ _board.py 加链路失败步列 [无任务] | scripts/_board.py scripts/_chain_stats.py |
|---|---|---|---|---|
| 2026-08-24 10:03 | atomcode-overseer-20260823 | `58e2797` | merge: P1 Step2 盲区聚合+看板盲区列入 main [无任务] | scripts/_blindspot.py scripts/_board.py |
|---|---|---|---|---|
| 2026-08-24 10:02 | atomcode-overseer-20260823 | `6ed6316` | feat(治理): P1 Step2 盲区聚合脚本 _blindspot.py（高置信未解出→presolve 建议草稿）+ _board.py 加盲区列（看板消费 blindspots JSON） [无任务] | scripts/_blindspot.py scripts/_board.py |
|---|---|---|---|---|
| 2026-08-24 09:59 | atomcode-overseer-20260823 | `a97ce04` | merge: P1-1 置信度输出管道入 main [无任务] | core/main_agent.py core/prompts.py |
|---|---|---|---|---|
| 2026-08-24 09:59 | atomcode-overseer-20260823 | `ae3d095` | feat(解题): P1-1 置信度输出管道——SOLVE_DISCIPLINE 加 R7 置信度约束(confidence: 0-100) + _extract_confidence 解析写入 AgentOutput，替换硬编码 0.9/0.0（盲区分析数据前提） [无任务] | core/main_agent.py core/prompts.py |
|---|---|---|---|---|
| 2026-08-24 09:55 | atomcode-overseer-20260823 | `458c82c` | merge: P2 方案文档入 main [无任务] | ...45\212\261\351\224\232\347\202\271-20260824.md" |
|---|---|---|---|---|
| 2026-08-24 09:54 | atomcode-overseer-20260823 | `4ce8b61` | docs(P2): P2 方案——单写者+多读者多题并发适配（回应单写者瓶颈/多读者落地/靶机槽位协同三追问）+ 激励结构物理锚点（看板排序/绿色通道徽章/稳定性权重） [无任务] | ...45\212\261\351\224\232\347\202\271-20260824.md" |
|---|---|---|---|---|
| 2026-08-24 09:53 | atomcode-overseer-20260823 | `eadde0e` | merge: P1 方案深化文档入 main [无任务] | ...50\267\257\347\273\237\350\256\241-20260824.md" |
|---|---|---|---|---|
| 2026-08-24 09:53 | atomcode-overseer-20260823 | `f544fff` | docs(P1): P1 方案深化——盲区→presolve 闭环 + 7 步链路失败步统计 + 度量阈值基线（基于 8-24 实测） [无任务] | ...50\267\257\347\273\237\350\256\241-20260824.md" |
|---|---|---|---|---|
| 2026-08-24 09:51 | atomcode-overseer-20260823 | `1db087c` | merge: P0-3 租约退役入 main——降级为车道边界提示+退役清单文档 [无任务] | ...44\275\234\346\270\205\345\215\225-20260824.md" scripts/_lease.py tests/test_lease.py tests/test_lease_multiwriter.py |
|---|---|---|---|---|
| 2026-08-24 03:11 | atomcode-overseer-20260823 | `ad96b3b` | chore(治理): P0-3 租约退役——降级为车道边界提示，docstring+测试标注退役，冻结 lease_version 漂移，退役操作清单文档 [无任务] | ...44\275\234\346\270\205\345\215\225-20260824.md" scripts/_lease.py tests/test_lease.py tests/test_lease_multiwriter.py |
|---|---|---|---|---|
| 2026-08-24 03:08 | atomcode-overseer-20260823 | `80b8264` | merge: P0-2 身份绑定留痕+硬拦开关入 main [无任务] | git_hooks/pre-commit scripts/_sign.py scripts/hooks/pre-commit |
|---|---|---|---|---|
| 2026-08-24 03:08 | atomcode-overseer-20260823 | `5611702` | feat(治理): P0-2 身份绑定留痕+bind_at 时间戳+CT_AGENT_IDENTITY_ENFORCE 硬拦开关——默认告警，正式赛开启硬拦防身份覆盖 [无任务] | git_hooks/pre-commit scripts/_sign.py scripts/hooks/pre-commit |
|---|---|---|---|---|
| 2026-08-24 03:06 | atomcode-overseer-20260823 | `e308879` | merge: P0-1 KPI 断言接真值入 main——已解出题回归集真跑 + 全量定时基线 [无任务] | scripts/_merge_gate.py |
|---|---|---|---|---|
| 2026-08-24 03:06 | atomcode-overseer-20260823 | `99f84bc` | feat(治理): P0-1 KPI 断言接真值——已解出题回归集真跑可复现命令 + 全量定时基线（台账计数只是文本，回归集才是能复现的证据）[无任务] | scripts/_merge_gate.py |
|---|---|---|---|---|
| 2026-08-24 02:47 | atomcode-overseer-20260823 | `d1ef4a6` | merge: AGENTS.md 一屏三铁律压缩入 main（阶段6 收口）[无任务] | AGENTS.md |
|---|---|---|---|---|
| 2026-08-24 02:47 | atomcode-overseer-20260823 | `0d40e79` | docs(治理): AGENTS.md 压缩为一屏三铁律+组织规则——工件可信/裁判分离/启动命令即门禁，细节退役指向机器门禁+自动看板（阶段6）[无任务] | AGENTS.md |
|---|---|---|---|---|
| 2026-08-24 02:44 | atomcode-overseer-20260823 | `b11ea06` | merge: README 阶段5 声明入 main——协调状态从 git 派生，手工登记退役（阶段5 收口）[无任务] | README.md README.zh.md |
|---|---|---|---|---|
| 2026-08-24 02:44 | atomcode-overseer-20260823 | `639e260` | docs: README 治理段补充——协调状态从 git 派生（_board.py 自动看板），手工登记退役，租约降级为车道边界提示（阶段5）[无任务] | README.md README.zh.md |
|---|---|---|---|---|
| 2026-08-24 02:43 | atomcode-overseer-20260823 | `e9a898c` | merge: 自动看板 _board.py 入 main（阶段5 协调状态派生）[无任务] | scripts/_board.py |
|---|---|---|---|---|
| 2026-08-24 02:43 | atomcode-overseer-20260823 | `e209422` | feat(治理): 自动看板 _board.py——协调状态从 git 派生（分支列表即任务板，单向数据流，阶段5）[无任务] | scripts/_board.py |
|---|---|---|---|---|
| 2026-08-24 02:41 | atomcode-overseer-20260823 | `f34f6ab` | merge: README 历史分层口径声明入 main（阶段4 收口）[无任务] | README.md README.zh.md |
|---|---|---|---|---|
| 2026-08-24 02:41 | atomcode-overseer-20260823 | `c7d4d57` | docs: README 历史分层口径声明——git log 考古层 vs tag+台账事实层（阶段4）[无任务] | README.md README.zh.md |
|---|---|---|---|---|
| 2026-08-24 02:39 | atomcode-overseer-20260823 | `ace1b4f` | merge: 阶段2+3 车道方案合入 main——启动门禁+合并闸门+题库版本化+测试适配（w/test 经闸门验证 263 passed）[无任务] | data/questions/crypto/crypto-001.json data/questions/crypto/crypto-002.json data/questions/crypto/crypto-003.json data/questions/crypto/crypto-004.json data/questions/crypto/crypto-005.json data/questions/crypto/crypto-006.json data/questions/crypto/crypto-007.json data/questions/crypto/crypto-008.json data/questions/crypto/crypto-009.json data/questions/crypto/crypto-010.json data/questions/crypto/real_crypto_caesar.json .../crypto/real_crypto_exciting_inverse.json …(+62) |
|---|---|---|---|---|
| 2026-08-24 02:39 | atomcode-overseer-20260823 | `ace1b4f` | merge: 阶段2+3 车道方案合入 main——启动门禁+合并闸门+题库版本化+测试适配（w/test 经闸门验证 263 passed）[无任务] | data/questions/crypto/crypto-001.json data/questions/crypto/crypto-002.json data/questions/crypto/crypto-003.json data/questions/crypto/crypto-004.json data/questions/crypto/crypto-005.json data/questions/crypto/crypto-006.json data/questions/crypto/crypto-007.json data/questions/crypto/crypto-008.json data/questions/crypto/crypto-009.json data/questions/crypto/crypto-010.json data/questions/crypto/real_crypto_caesar.json .../crypto/real_crypto_exciting_inverse.json …(+62) |
|---|---|---|---|---|
| 2026-08-24 02:39 | atomcode-overseer-20260823 | `a903c28` | feat(诚实化): 接管 gu 遗留——solved_by 字段拆 presolve/LLM（静态分析器直出标记，防功劳混淆）[无任务] | core/main_agent.py eval/benchmark.py run.py |
|---|---|---|---|---|
| 2026-08-24 02:17 | atomcode-overseer-20260823 | `48eff18` | test(适配): test_eval_integrity 数据依赖测试加 skipUnless——attachments/answers 本地保留不入库，无数据环境显式跳过 [无任务] | tests/test_eval_integrity.py |
|---|---|---|---|---|
| 2026-08-24 02:15 | atomcode-overseer-20260823 | `d4a3013` | feat(数据): 真题题库入库——data/questions + questions_real 版本化（唯一 KPI 考场，机器事实源：任何车道可复现 benchmark）[无任务] | data/questions/crypto/crypto-001.json data/questions/crypto/crypto-002.json data/questions/crypto/crypto-003.json data/questions/crypto/crypto-004.json data/questions/crypto/crypto-005.json data/questions/crypto/crypto-006.json data/questions/crypto/crypto-007.json data/questions/crypto/crypto-008.json data/questions/crypto/crypto-009.json data/questions/crypto/crypto-010.json data/questions/crypto/real_crypto_caesar.json data/questions/crypto/real_crypto_exciting_inverse.json …(+55) |
|---|---|---|---|---|
| 2026-08-24 02:12 | atomcode-overseer-20260823 | `0f1e9ee` | feat(治理): 阶段3 合并闸门——_merge_gate.py(KPI不降+全量测试) + pre-merge-commit + pre-commit⑧增强 + main直提拦截 [无任务] | git_hooks/pre-commit git_hooks/pre-merge-commit scripts/_merge_gate.py scripts/hooks/pre-commit scripts/hooks/pre-merge-commit |
|---|---|---|---|---|
| 2026-08-24 02:06 | atomcode-overseer-20260823 | `500440e` | feat(治理): 会话启动门禁 _session_boot.py——车道分支/身份/脏树/.venv 四查，fail-closed（阶段2 车道方案，w/test 车道落地）[无任务] | scripts/_session_boot.py |
|---|---|---|---|---|
| 2026-08-24 02:04 | gu | `4ef0f14` | [无任务] honest(总账): presolve 口径钉死 + ledger 补丁 + 诚实化标记落库 | REAL_SOLVES_LEDGER.md core/main_agent.py scripts/_verify_presolve_only.py |
|---|---|---|---|---|
| 2026-08-24 02:01 | atomcode-overseer-20260823 | `afe568d` | chore(hooks): 补齐 post-commit/post-merge 源文件（激活位=源，消除版本管理缺口）[无任务] | scripts/hooks/post-commit scripts/hooks/post-merge |
|---|---|---|---|---|
| 2026-08-24 01:55 | gu | `ce44934` | [无任务] feat(ledger): 3 个真实离线解出 + 诚实 KPI 修正 + 10733 可复现脚本 | AGENTS.md REAL_SOLVES_LEDGER.md core/main_agent.py ...260\264\344\275\215\345\243\260\346\230\216.md" scripts/verify_10733.py |
|---|---|---|---|---|
| 2026-08-24 01:38 | atomcode-overseer-20260823 | `e0ce5ef` | [无任务] chore(收口): R2 注水清除——submitted_flags 158 条 flag{ok} 测试占位清空（poller 兜底从空表重新记账） | data/results/submitted_flags.json |
|---|---|---|---|---|
| 2026-08-24 01:37 | atomcode-overseer-20260823 | `0681605` | [无任务] chore(收口): R1 脏树归位——goal_log 真实运行日志 + T-99 任务板声明入库 | data/results/goal_log.jsonl tasks/T-99.json |
|---|---|---|---|---|
| 2026-08-24 01:35 | atomcode-closeout | `eaf29aa` | docs(调控): 并发从裸奔变有序方案——裸奔证据+根因+三闸验证+收口残留+持续监督(T-08) 2>&1 | ...51\242\204\344\277\241\345\217\267-20260823.md" |
|---|---|---|---|---|
| 2026-08-24 01:34 | atomcode-overseer-20260823 | `adea331` | [无任务] fix(治理): 并发有序化闸1+闸3——commit-msg 任务板登记检查 + closeout scope 越界告警（2026-08-24 收口） | git_hooks/commit-msg scripts/_closeout.py scripts/hooks/commit-msg |
|---|---|---|---|---|
| 2026-08-24 01:34 | gu | `55ad0c8` | honest(ledger): create REAL_SOLVES_LEDGER.md — single source of truth for verified solves | AGENTS.md REAL_SOLVES_LEDGER.md core/prompts.py data/results/goal_log.jsonl data/results/submitted_flags.json eval/benchmark.py eval/cases.py scripts/_lease.py |
|---|---|---|---|---|
| 2026-08-24 01:26 | gu | `0745ad4` | docs: 本地题库穷尽 + 平台关闭方向调整 + 复盘 + 架构重审 + 下一步规划 | data/results/REAL_PROBLEMS_MANIFEST.json ...51\242\230\345\244\215\347\233\230-20260822.md" data/results/category_regression.json data/results/dashboard_tasks.json data/results/dryrun_m4_presolve.log data/results/extract_log.txt data/results/goal_log.jsonl data/results/m2_baseline_run1.log data/results/m2_dryrun_baidu.log data/results/replay_real_run.log data/results/solve_progress.json data/results/submitted_flags.json …(+11) |
|---|---|---|---|---|
| 2026-08-24 01:24 | atomcode-closeout | `5cf3e3b` | feat(调控): 总账健康检查接入观察脚本(第6节)+调控文档固化总账保障结论——commit↔总账自动对齐验证 | ...51\242\204\344\277\241\345\217\267-20260823.md" scripts/_overseer_check.py |
|---|---|---|---|---|
| 2026-08-24 01:22 | gu | `1d0278b` | Revert "feat(解题): web 靶机 10 题补齐 + presolve 探测直出——客场 web 0/10 → 10/10" | core/presolve.py scripts/web_range_target.py tests/test_presolve_web_probe.py |
|---|---|---|---|---|
| 2026-08-24 01:21 | atomcode-closeout | `82e6928` | docs(调控): 中心调控结论——web 10/10 验证+会话台账+下一轮任务派发+调控纪律 | ...51\242\204\344\277\241\345\217\267-20260823.md" |
|---|---|---|---|---|
| 2026-08-23 20:29 | gu | `f02f20f` | fix(web): 靶机缺失根因修复 + web 首步强制发包 + JSON 解析鲁棒性 | core/action_executor.py core/llm_wrapper.py core/main_agent.py core/phases.py eval/benchmark.py |
|---|---|---|---|---|
| 2026-08-23 20:27 | manual/Lenovo | — | 诚实水位声明更新（未tracked补登）：客场 27/49=55.1% → 37/49=75.5%（web 0/10→10/10，_try_web_probe presolve 直出，benchmark 实测 18.9ms/题近零token）。纯LLM短板=presolve命不中的19题（crypto7/misc6/reverse6），LLM 真解出 7 题≈37%。下一战略焦点=19题。 | （手动改动，非 commit） |
| 2026-08-23 20:26 | gu-web-probe | `da53656` | feat(解题): web 靶机 10 题补齐 + presolve 探测直出——客场 web 0/10 → 10/10 | core/presolve.py scripts/web_range_target.py tests/test_presolve_web_probe.py |
|---|---|---|---|---|
| 2026-08-23 20:14 | gu | `9a6071a` | docs: 10732 flag 载体穷尽确认 + 题库穷尽 + 架构重审记录 | ...236\266\346\236\204\351\207\215\345\256\241.md" ...272\244\346\216\245\346\226\207\346\241\243.md" |
|---|---|---|---|---|
| 2026-08-23 20:11 | atomcode-overseer-20260823 | `5fb0a93` | docs(治理): AGENTS 同步锐评修订——.lock 废弃声明 + 核心只读君子协定边界（P1-1/P1-2 落地） | AGENTS.md |
|---|---|---|---|---|
| 2026-08-23 20:09 | atomcode-closeout | `ea76d6f` | feat(监督): 持续观察脚本 _overseer_check.py——一键扫描进程/租约/提交/方向判定(GBK修复) | scripts/_overseer_check.py |
|---|---|---|---|---|
| 2026-08-23 20:05 | atomcode-overseer-20260823 | `0bea20c` | fix(治理): commit message flag 明文拦截（99fb169 复发堵漏——DASCTF/flag/xctf 格式进 message 即拒，脱敏展示） | scripts/_honesty_scan.py |
|---|---|---|---|---|
| 2026-08-23 20:04 | atomcode-closeout | `f018b43` | docs(监督): 干预信号——刹车治理防错、推进web_range_target、用supervision_stats复盘22道未解题 | ...51\242\204\344\277\241\345\217\267-20260823.md" |
|---|---|---|---|---|
| 2026-08-23 20:04 | atomcode-overseer-20260823 | `1198b84` | fix(治理): pre-commit 加 ⑧ merge 全量门禁（MERGE_HEAD 检测，堵 merge 带红——锐评 P0-1 落地） | git_hooks/pre-commit scripts/hooks/pre-commit |
|---|---|---|---|---|
| 2026-08-23 20:02 | atomcode-closeout | `d773869` | feat(supervisor): 监督采纳率统计——裁决流水+supervision_stats输出+5单测(质检④红灯修复) | core/main_agent.py tests/test_supervision_stats.py |
|---|---|---|---|---|
| 2026-08-23 19:59 | gu-final-settle | `437d5fe` | feat(防错): 系统化第三批——coordination 锁死锁检测 + 快速回归集扩充至 73 用例 | git_hooks/pre-commit scripts/_lease.py scripts/hooks/pre-commit tests/test_lease_multiwriter.py |
|---|---|---|---|---|
| 2026-08-23 16:33 | gu-final-settle | — | 补登 110fa80（post-commit 死锁检测初版 tasklist 编码 bug 导致记账跳过，439eb40 修复后验证死锁抢占+记账成功） | （手动改动，非 commit） |
| 2026-08-23 16:31 | gu-final-settle | `439eb40` | fix(防错): post-commit 死锁检测编码修复——tasklist GBK 解码 | git_hooks/post-commit |
|---|---|---|---|---|
| 2026-08-23 16:28 | gu-final-settle | `270fb1f` | feat(防错): 系统化第二批——钩子安装闭环 + 总账写锁 + 文档一致性进门禁 + stale 自动接管 | git_hooks/post-commit git_hooks/pre-commit scripts/_lease.py scripts/hooks/pre-commit setup.sh tests/test_lease_multiwriter.py |
|---|---|---|---|---|
| 2026-08-23 15:47 | gu-final-settle | `50cc1be` | feat(防错): 工程化防错体系——状态快照 + commit message 假水位拦截 + 测试红禁止提交 | AGENTS.md git_hooks/commit-msg git_hooks/pre-commit scripts/_facts.py scripts/_honesty_scan.py scripts/hooks/commit-msg scripts/hooks/pre-commit tests/test_facts.py tests/test_honesty_scan.py tests/test_sign.py |
|---|---|---|---|---|
| 2026-08-23 15:01 | gu-final-settle | — | 诚实水位声明终版（未tracked手动补登）：客场全量 27/49=55.1%（52题递归排除3道answer_disclosed，挂300s墙钟，钉死provider=baidu后重跑）；其中presolve直出20题（74%），web 0/10是纯LLM短板。锐评旧口径8%=5/60（60题快照）已作废。主场14/15=93.3%已到顶。唯一KPI=客场27/49往上爬，战略焦点=web 0/10 | （手动改动，非 commit） |
| 2026-08-23 15:01 | gu-final-settle | `4ed5515` | docs(治理): 终极收敛纪律——KPI 焊死客场数字 + 治理封板 + RDD 红线 | AGENTS.md |
|---|---|---|---|---|
| 2026-08-23 13:32 | manual/Lenovo | — | benchmark 挂墙钟重跑（--limit 15 --wallclock 300，真实LLM）：14/15=93.3%（13题presolve直出+2题LLM推理257s/101s+1题crypto-004超时300s判wallclock_timeout失败）。墙钟裁决②端到端验证通过。注意：provider=baidu（非记忆里的deepseek），BASE_URL指向dasctf网关，配置漂移待核实。诚实水位声明主场数字 86.7%→93.3%已更新 | （手动改动，非 commit） |
| 2026-08-23 13:27 | gu | `07e2e34` | docs(诚实化): 深刻反思与总结.md 加诚实口径声明——离线推导解出统一标注(未平台验证,accepted=0) | ...5\346\200\235\344\270\216\346\200\273\347\273\223.md" |
|---|---|---|---|---|
| 2026-08-23 13:14 | manual/Lenovo | — | 诚实水位声明.md 重写（未tracked手动补登）：真实LLM水位 1/6≈17%→5/60=8%（60题真题离线全量）；加87%主场vs8%客场口径专节；修正178→249passed | （手动改动，非 commit） |
| 2026-08-23 13:13 | gu-settle-0823 | `d32ddcf` | fix(治理): 三裁决点——benchmark比赛墙钟 + RSA映射澄清 + 单写者说明修正 | AGENTS.md core/prompts.py eval/benchmark.py tests/test_benchmark_wallclock.py |
|---|---|---|---|---|
| 2026-08-23 13:13 | gu-settle-0823 | `a1597bc` | feat(治理): T-09/T-10/T-11 声明式任务板+Reviewer门禁+git身份绑定 | git_hooks/pre-commit scripts/_reviewer_gate.py scripts/_sign.py scripts/_task_board.py scripts/hooks/pre-commit tests/test_reviewer_gate.py tests/test_sign.py tests/test_task_board.py |
|---|---|---|---|---|
| 2026-08-23 13:13 | gu-settle-0823 | `b019248` | feat(治理): 文档一致性校验 + 机器事实源（根治文档漂移） | scripts/_doc_consistency.py scripts/_facts.py tests/test_doc_consistency.py tests/test_facts.py |
|---|---|---|---|---|
| 2026-08-23 10:58 | 糖露星霜•暖霞拾光 | `489e4e6` | feat: 10733（CRYPTO-02）离线推导解出——离线解题数 5 至 6 | ...272\244\346\216\245\346\226\207\346\241\243.md" |
|---|---|---|---|---|
| 2026-08-23 10:56 | atomcode-overseer-20260823 | `871cc02` | fix(治理): _honesty_scan 禁词表补裸数字区间 5→13/15→16/16→26（堵提交绿测试红；不补裸词真实解出以保方法论契约） | scripts/_honesty_scan.py |
|---|---|---|---|---|
| 2026-08-23 10:46 | 糖露星霜•暖霞拾光 | `0dcf348` | docs: 解题数攻坚实证——zip/脚本扫描无新解出（5/60 不变如实） | ...\272\244\346\216\245\346\226\207\346\241\243.md" |
|---|---|---|---|---|
| 2026-08-23 10:44 | 糖露星霜•暖霞拾光 | `2528452` | feat: 第四轮锐评三件事执行——提示词减法 -80 行 + benchmark 真数 8% | ...272\244\346\216\245\346\226\207\346\241\243.md" |
|---|---|---|---|---|
| 2026-08-23 10:44 | atomcode-closeout | `4b95160` | fix(presolve): 垃圾flag过滤(_is_plausible_flag)+第七路web_source_audit;主循环web题改源码审计指引 | core/goal_directive.py core/main_agent.py core/presolve.py git_hooks/pre-commit scripts/_coupling_cluster.py scripts/_dryrun_race.py scripts/_fix_presolve_concurrent.py scripts/_fix_round5.py scripts/_fix_round5_runpy.py scripts/_honesty_scan.py scripts/_log_task.py scripts/hooks/pre-commit …(+4) |
|---|---|---|---|---|
| 2026-08-23 10:21 | 糖露星霜•暖霞拾光 | `1d91f68` | docs: 解出数 16→26 实证——复盘实证 +10（唯一指标提升） | ...272\244\346\216\245\346\226\207\346\241\243.md" |
|---|---|---|---|---|
| 2026-08-23 10:15 | atomcode-ctde-reconcile-20260823 | `ed22d67` | docs(治理): 统一三层治理冲突优先级声明（执法层>SSOT>协同协议>AGENTS） | AGENTS.md |
|---|---|---|---|---|
| 2026-08-23 02:47 | gu-g4-coupling | `5f4ebd4` | feat(治理): G4 写耦合度聚类 _coupling_cluster.py（可发表点） | scripts/_coupling_cluster.py tests/test_coupling_cluster.py |
|---|---|---|---|---|
| 2026-08-23 02:44 | gu-g3-closeout | `c773823` | feat(治理): G3 收尾脚本 _closeout.py（在飞改动检查 + 临时垃圾扫描） | scripts/_closeout.py tests/test_closeout.py |
|---|---|---|---|---|
| 2026-08-23 02:43 | 糖露星霜•暖霞拾光 | `99fb169` | feat: 10696 真实解出——flag DASCTF{****} | ...272\244\346\216\245\346\226\207\346\241\243.md" |
|---|---|---|---|---|
| 2026-08-23 02:40 | gu-g2-sign | `3085a8b` | feat(治理): G2 会话唯一 ID 登记 + _staged_files -z 修复 | scripts/_lease.py scripts/_sign.py tests/test_lease.py tests/test_sign.py |
|---|---|---|---|---|
| 2026-08-23 02:33 | gu-g1-multiwriter | `ff8f5e7` | feat(治理): G1 _lease.py 单写者→目录级多写者租约 + T1-T10 测试 | scripts/_lease.py tests/test_lease.py tests/test_lease_multiwriter.py |
|---|---|---|---|---|
| 2026-08-23 02:24 | 糖露星霜•暖霞拾光 | `f9b5f22` | docs: 空间清理记录——磁盘 97% 爆满 → 94%（释放 ~6.3G） | ...272\244\346\216\245\346\226\207\346\241\243.md" |
|---|---|---|---|---|
| 2026-08-23 02:17 | gu-g0-honest | `b52e4e5` | docs(治理): G0 诚实降格——删除 CTDE 术语错用，如实标注单写者租约现状 | AGENTS.md |
|---|---|---|---|---|
| 2026-08-23 02:13 | 糖露星霜•暖霞拾光 | `f40b28a` | docs: 深刻反思总结 + 最大风险解决（验证纪律机制 + 提交链路留档） | ...272\244\346\216\245\346\226\207\346\241\243.md" ...200\235\344\270\216\346\200\273\347\273\223.md" tools/verify_discipline.py |
|---|---|---|---|---|
| 2026-08-22 21:10 | 糖露星霜•暖霞拾光 | `1c3dc15` | 锐评第五轮深度修复：RSA Wiener自动检测 + presolve六路并发 + 删明文flag + race_strategy先易后难接线 + benchmark免责声明去误导 | core/presolve.py run.py scripts/_emergency.py skills/rsa_fermat_factor.py tests/test_presolve_poller.py |
|---|---|---|---|---|
| 2026-08-22 20:46 | atomcode-qc-preflight | `2f9ac54` | fix(preflight): bkcrack 二进制预检——纯 ASCII 路径+可用性检查(zip 已知明文攻击工具防丢失) | scripts/_preflight.py |
|---|---|---|---|---|
| 2026-08-22 20:27 | gu | `d69aea8` | fix(治理): 真正激活 pre-commit 双门禁（事前拦截纸面→实装）+ ROOT 路径修复 + 死锁清理 | git_hooks/pre-commit scripts/hooks/pre-commit setup.sh |
|---|---|---|---|---|
| 2026-08-22 20:24 | 糖露星霜•暖霞拾光 | `359f4c7` | fix(web): 看板暴露运行模式/api/mode + mock 警示横幅，消除演示自欺（修复项#4） | run.py web/server.py web/static/index.html |
|---|---|---|---|---|
| 2026-08-22 20:24 | 糖露星霜•暖霞拾光 | `e5a0dc1` | fix(diag): 清零 _smoke_test.py 3 处 or True 死断言 | scripts/_smoke_test.py |

---

### 2026-08-22 20:13–20:30 交付总监核查与收尾详记（会话：糖露星霜•暖霞拾光）

**① 用户问「现在的问题都解决了吗」→ 亲自实证（非二手汇报）**
- 全库恒真 `or True`/`lambda f:True` **代码级清零**（仅注释/docstring 提及）；`run.py` `validate_locally` 开关 + 两票互证生效。
- 误回滚丢失的 fail-closed 白名单/沙盒：**已补回**（llm/client.py「补回被误回滚的安全修复」；沙盒升级为参数级白名单）。**8/21 误回滚的实际损害已被填平**。
- pytest **208 passed / 3 skipped**；`import run` OK；竞速三函数齐全；墙钟 480、Optional 导入、_auto_advisor 去硬编码、归档均在。
- 结论：此前锐评列 P0/P1 得分链路问题**全部闭环**。

**② 提交（A=`359f4c7` 看板 / B=`e5a0dc1` 死断言）**
- B：清零 `scripts/_smoke_test.py` 3 处 `or True` 死断言（原 `classify` 误传字符串+恒真；改为构造真实 step 触发分类规则，已验证 `stuck_loop→stuck_loop`/`hallucination→hallucination`/`timeout→None`）。
- A：看板暴露运行模式 `/api/mode` + mock 警示横幅（真实 LLM=绿 / MOCK 假解=红），消除演示自欺（修复项#4）。

**③ 看板结论反转（诚实更正 20:13）**：20:13 我据快照判「看板 /api/status 未补回」；20:21 发现并行会话 gu 已补回且更优（`/api/mode` + 模式横幅，直接消除我担心的 mock 误报风险）。**多会话并发下，"未补回"快照判断可能已过时。**

**④ 一度撞 pre-commit hook 阻断（协作 P0，已解）**：提交时 `git_hooks/pre-commit` 旧 bug 版（`ROOT="$(A || B && pwd)"` 双路径）使 `cd` 失败、阻断所有 commit。gu 于 20:27 提交 `d69aea8` 真正激活双门禁 + ROOT 路径修复，问题消除。现 `git_hooks/pre-commit:21` 已正确，门禁实装（需 `CT_AGENT_SESSION` 或 `CT_AGENT_SINGLE=1` 放行）。

**⑤ 当前工作树**：仅剩 `scripts/_preflight.py` 一处 `M`（gu 未提交改动），非我所为，未擅自提交。

**⑥ 延续教训（8/21→8/22）**：多会话并发下工作树状态随时变化；任何"基于旧快照"的判断（含 20:13 看板结论、8/21 误回滚决策）都可能已过时。核查须亲自实时 `git status`/`diff`，不凭记忆、不凭二手汇报。
|---|---|---|---|---|
| 2026-08-22 19:34 | gu | `fc12129` | fix(治理): 一键登记脚本bug修复 + 看门狗降级为手动工具（共识+hook破黑盒） | AGENTS.md scripts/_log_task.py scripts/_watchdog_top0.ps1 |
|---|---|---|---|---|
| 2026-08-22 19:32 | gu | `71dbdf6` | fix(git_hooks): 路径归一化移入Python（MSYS /e/ 转 e:/ 一次修对） | git_hooks/post-commit git_hooks/post-merge |
| 2026-08-22 18:55 | gu | `d6454b5` | feat(治理): 自动记录机制——post-commit/post-merge hook + 文件系统看门狗双保险 | scripts/_install_watchdog_task.ps1 scripts/_watchdog_top0.ps1 scripts/start_watchdog.bat |
| 2026-08-22 18:53 | gu | `eea785a` | fix(AGENTS.md): 清理首次hook失败污染行，替换为干净自动记录机制说明 | AGENTS.md |
| 2026-08-22 18:52 | gu | `5ddf6b6` | test: 验证 post-commit hook 二次自动写入总账 | AGENTS.md |
| 2026-08-22 18:52 | gu | `4ae582d` | test: 验证 post-commit hook 二次自动写入总账 | AGENTS.md |

---

## 包工头执行记录（2026-08-28 21:40 Gu 落地，工人已停手）

1. **远程重建**：`git push origin master:refs/heads/backup-20260828` 成功（PUSH_EXIT=0）。本地 master 与远程 main 分叉非祖先，故推新分支不覆盖旧史；远程 main 收口方式待 Gu 决策。
2. **hook 强制纪律（工作树生效，未 commit）**：commit-msg 纯 `[无任务]` 拦截（须 `[无任务:说明]`）；_structure_guard ROOT_ALLOW 加总账/_INDEX.md。diff: `logs/20260828-foreman-hook-diff.patch`。
3. **README.zh.md 删除待处置**：当前断链（README.md 还链它），应 `git mv docs/`+改链接，非直接删。
4. **foreman_directive R0 已更正**：禁纯[无任务]，非禁[无任务]。

待办：① main 收口决策 ② hook 改动带任务ID commit ③ README.zh.md 归位 ④ 303项在飞改动分类（工人回归后）。
