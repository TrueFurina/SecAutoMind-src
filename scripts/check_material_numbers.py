#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""材料口径门禁：自动比对 docs/ PPT/ 官网 中的关键数字与 count_stats.py 真值。

为什么需要它
------------
本项目历史上有过三次材料数字漂移，全部靠人肉发现：
  - 并行会话新增 tools/_shared_args.yaml 后，YAML 工具 90 -> 91
  - 求解器 169 -> 170
  - 官网长期写「140 运行时工具」，而 140 既不等于 90 也不等于 142，属凭空漂移
写死的数字在提交完成的下一秒就可能过期，靠人肉同步永远追不上。

它检查三件事
------------
1) 黑名单：已作废旧口径复活（带上下文匹配，避免误伤行号/端口等无关数字）
2) 锚点比对：材料里出现的「Go N 文件」「N 运行时工具」「N 求解器」必须等于真值
3) 修复清单一致性：`docs/口径修复清单.md` 声明的门禁状态必须与本次一致
   （2026-10-16 补——它被 TOOL_EXEMPT 豁免扫描，因此此前**无任何判据能发现它过期**，
   实测其自 09-09 起一直写着「结论：FAIL」而门禁早已 PASS）

退出码：0 = 通过；1 = 口径漂移（禁止合入 / 禁止打包）
"""

import json
import os
import re
import subprocess
import sys
from datetime import date, datetime, timedelta, timezone

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
PY = sys.executable

# 判定「历史快照」的日期基准**必须固定时区**（2026-10-26 实锤事故）：
# `is_historical()` 用文件名内嵌日期与"今天"比较，而 `date.today()` 取的是**本机时区**。
# 于是同一提交在 UTC+8 的开发者机器与 UTC 的 GitHub Actions 上得到**相反结论**：
#   · 北京 2026-10-26 03:08 → 文件名含 20261025 视为"早于今天" → 豁免 → 门禁绿
#   · UTC   2026-10-25 19:08 → (10,25) 不早于 (10,25) → 不豁免 → caliber 报 9 处、docs-lint 报 1 处
# 表现为「本地全绿、CI 全红」，且换一天又不复现 —— 极难归因。
# 修法：一律按**东八区**取今天，让 CI 与本地对同一提交给出同一结论。
CN_TZ = timezone(timedelta(hours=8))


def today_cn():
    """今天（东八区）。所有"历史快照"判定都用它，不用 date.today()。"""
    return datetime.now(CN_TZ).date()

# 扫描范围：对外材料。代码/数据/日志不扫（里面出现数字是正常的）。
SCAN_DIRS = ["docs", "SecAutoMind_PPT", "官网"]
# 根目录材料**自动发现** *.md，不写死清单 —— 09-09 实锤：本门禁曾因写死
# SCAN_FILES 而完全漏扫根目录的《提交前终检清单》《决赛对标分析》等作战材料，
# 导致 09-03 一代旧口径（90 工具 / 226 测试 / 26 包 / 31 internal）长期无人发现。
# 写一个新 .md 却忘了登记进清单 = 门禁静默失效，这是不可接受的失效模式。
SCAN_FILES = ["README.md", "README_CN.md", "SECURITY.md", "AGENTS.md"]
SCAN_EXT = {".md", ".html", ".py", ".txt"}

# ---------------------------------------------------------------------------
# 1) 黑名单：已作废的旧口径。必须带上下文，否则 "662" 可能只是行号或端口。
# ---------------------------------------------------------------------------
BANNED = [
    (r"662\s*文件|242\s*(个)?测试|123,149|153,987", "旧口径 A（662/242/123,149/153,987）"),
    (r"677\s*文件|250\s*(个)?测试|125,954|158,247", "旧口径 B（677/250/125,954/158,247）"),
    (r"151\s*(个)?求解器", "旧求解器数 151"),
    (r"140\s*(个)?(运行时)?工具", "三不管数字 140 工具（真值 91 YAML / 143 运行时）"),
    # 2026-10-18 新增：143 是**删 tools/lightx.yaml 之前**的运行时工具数。官网 og:description
    # (`<meta property="og:description" content="4 类 Agent × 143 工具 × 13 角色…">`) 里的它
    # 正是本表修好属性值盲区前的那类漏检——可见文本早已改成 142，属性里还留着 143。
    # 「N 工具」裸写法没有锚点（90 YAML / 142 运行时 / 52 内置三个口径都简称"工具"，猜哪个都是猜），
    # 故按禁用旧口径处理：带「工具」二字的 143 在任何口径下都不可能是对的。
    #
    # 🔴 2026-10-24 **解禁**：新增 `tools/bkcrack.yaml`（9d2cc8a）后真值回到
    # **YAML 91 / 运行时 143**（91 + 52 内置）。143 不再是旧口径，本条必须撤掉，
    # 否则门禁会把**正确**的当值陈述判成"旧口径复活"（实测一次命中 22 处）。
    # 反向改为禁用 90/142（见下一条；本次只解禁 143，**不**禁 90，理由见下）。
    (r"Go\s*613\s*文件|613\s*文件", "手写漂移的 Go 文件数 613"),
    # 09-03 一代旧口径：曾长期存活于根目录《提交前终检清单》，因门禁漏扫根目录而未被发现
    # 2026-10-18 口径变更：删除幻影条目 tools/lightx.yaml 后，工具 YAML 真值 91 -> 90。
    # 🔴 2026-10-24 **再次反转**：新增 `tools/bkcrack.yaml`（9d2cc8a）后真值回到 91
    # （运行时 143），故 143 解禁（见上一条），90 变成旧值。
    #
    # ⚠️ 但**本次刻意不把 90 列入禁用**，原因是一条硬约束：
    #   「90 工具」现存 53 处、分布 17 个文件，大头在 `SecAutoMind_PPT/make_*.py` ——
    #   而那 7 份 PPT 已被 `docs/final-artifacts.freeze.json` 按**生成器 sha256** 上锁。
    #   改生成器 ⇒ 必须重跑全部 PPT 才能过 freeze 门禁。赛前数小时做这件事，
    #   风险远大于「PPT 口号写着 90 而真值 91」这一处口径误差。
    # ⇒ 因此这里只解禁 143、不新增 90 禁令：门禁不会把正确的 143 判红，
    #   也不会在 PPT 冻结期间制造一批无法修复的红。
    # 📌 待办（赛后、解冻 PPT 后一次性做）：把 17 个文件的「90 工具 / YAML 90」统一改 91，
    #   重跑 7 份 PPT，再恢复本条禁令 `90\s*(个)?(工具|YAML)`。
    #   在此之前，对外材料涉及 YAML 工具数一律以 `count_stats.py` 实跑为准（现 91）。
    (r"226\s*(个)?测试|228\s*(个)?测试|224\s*(个)?测试", "旧测试文件数（现 318）"),
    # 2026-10-23 收窄：原条目里的裸 `26/26` 会误伤**真值**——基准集扩到 26 集后，
    # `docs/quant_effect.md` 的「基准集达标 26/26」是完全正确的当值陈述，却被判成
    # 「旧测试包数 26」复活（同一串数字两种语义）。按本项目一贯纪律「数字必须紧跟单位词
    # 才判定口径」，改为要求 `26/26` 后面跟「(个)(测试)包」；裸 `26/26` 不再判红。
    (r"24/26\s*测试|26/26\s*(?:个)?\s*(?:测试)?包|26\s*包全绿|26\s*(个)?包测试",
     "旧测试包数 26（现 38）"),
    # 2026-10-18 更新：原注"现 32"已过期。31 既不是 internal 子目录数（35）
    # 也不是 internal 包数（38），两个口径都禁止再出现这个值。
    (r"31\s*internal|internal\s*(子)?(目录|包)\s*\**\s*31", "旧 internal 数 31（现 子目录 35 / 包 38）"),
    (r"111,933|113,\d{3}", "旧非测试行数（现 129,955）"),
    # ── 09-05 一代分发体积：Setup 33.6 MB / 绿色版 158 MB ────────────────────
    # 那一代产物是 159,051,447 B 的 `+dirty` 构建（09-04），早已被 89.5 MB 的
    # 纯 Go 构建取代。体积差近一倍，写错的后果是评委按图索骥找不到对应文件。
    (r"33\.6\s*MB|158\s*MB", "旧分发体积（33.6MB/158MB，现 20.3MB/89.6MB）"),
    # ── 技术栈断言：cgo ──────────────────────────────────────────────────
    # 2026-10-18 实测：release.yml 三平台一律 `CGO_ENABLED=0`，SQLite 用 glebarez
    # 纯 Go 驱动，全仓 `import "C"` 数量为 0 —— 早已不依赖 cgo。
    # 但材料仍在四处宣称「cgo 构建 / cgo sqlite / 原生 cgo 编译 / Go/cgo 单文件」，
    # 而同一批 PPT 里 `集大成版` 写的是「纯 Go 免 CGO」→ **同一事实三种口径**。
    # 这类断言没有数字，锚点机制管不到，只能按"禁用旧断言"处理。
    (r"cgo\s*sqlite|sqlite\s*[（(]?\s*cgo", "cgo sqlite 断言（现为 glebarez 纯 Go 驱动）"),
    (r"cgo\s*构建|Go\s*/\s*cgo", "cgo 构建断言（现 CGO_ENABLED=0 纯 Go 构建）"),
    (r"原生\s*cgo\s*编译", "原生 cgo 编译断言（现纯 Go 交叉编译）"),
]

# ---------------------------------------------------------------------------
# 2) 锚点比对：材料中出现的数字必须等于真值。
#    (正则, 真值字段名, 人类可读名称)
# ---------------------------------------------------------------------------
# 字段名必须与 count_stats.py 输出一致（实测是 ctf_solvers，不是 solvers）。
# 取不到真值时**必须崩**，不能静默跳过 —— 静默跳过的门禁等于没有门禁。
# 所有正则的数字必须写成命名组 (?P<n>...) —— 有些正则带可选前缀组，
# 用 group(1) 会取到 None 或取错组（曾踩：internal 那条数字其实在第 3 组）。
# (?<![\d.]) 前缀：排除章节号/版本号/端口号被当成规模数（实测误报源：
#   "### 5.2 Agent" 里的 2、"v1.7.25" 里的 25、"8090 端口" 里的 8090）。
# (?!化) 后缀：排除"18 个角色化子代理"被误判成 RBAC 角色数（那是 Agent 数）。
ANCHORS = [
    (r"Go\s*(?P<n>\d+)\s*文件", "go_files", "Go 文件数"),
    # 09-15 新增：材料里"711 Go 文件"（数字在前）同样常见 —— 此前只认"Go 711 文件"，
    # 导致 `规划-移植与优化总纲.md` 的 711（真值 715）漏检。同属「锚点覆盖不全」类盲区。
    (r"(?<![\d.])(?P<n>\d+)\s*Go\s*文件", "go_files", "Go 文件数（数字在前）"),
    # 2026-10-18 新增：官网顶部 stats 长期写「140 运行时**安全**工具」——数字与「运行时工具」
    # 之间夹了「安全」二字，原锚点只认「N 运行时工具」，于是真值已 143 时 140 仍长期存活、
    # 且 [5/16] 用例的 probe 写的是「140 运行时工具」（无「安全」），与官网真实写法不一致，
    # 属「锚点覆盖不全 + 测试 probe 与真实材料脱节」的双重盲区。加可选「安全」补上。
    (r"(?<![\d.])(?P<n>\d+)\s*(个)?运行时(安全)?工具", "runtime_tools", "运行时工具数"),
    (r"(?<![\d.])(?P<n>\d+)\s*(个)?(确定性)?求解器", "ctf_solvers", "CTF 求解器数"),
    # 2026-10-03 新增：求解器口径**拆分**为「真求解器 / 检测器」两类。
    # 背景（诚实性）：176 个注册项里有一批 Solver 只做关键词/魔数检测，返回硬编码中文提示
    # （如 "攻击链: TTP战术技术程序"），**永远不可能等于真 flag**（flag 为 ASCII）。
    # 材料若宣称「176 求解器全部能解题」即被读成注水；现要求写清 117 真求解器 + 59 检测器，
    # 三者必须自洽（real + detectors == solvers），见 count_stats.py::ctf_solver_breakdown。
    # 2026-10-23 新增（第 6 处「锚点覆盖不全」盲区，实测）：PPT 数据卡把总数写成
    # 「N 预解组件」而非「N 求解器」——上面那条锚点只认「求解器」，于是 deck 里
    # 「181 预解组件 130真求解器+59检测器」长期存活：181 ≠ 130+59=189，**同屏自相矛盾**
    # 却没有任何判据能发现（本文件第 155 行注释早就点名过这个形态，但当时只补了
    # 「拆分字面量」（Python 源码）一条，漏了 PPT 里的纯文本写法）。
    (r"(?<![\d.])(?P<n>\d+)\s*(个)?预解组件", "ctf_solvers", "求解器总数（预解组件）"),
    (r"(?<![\d.])(?P<n>\d+)\s*(个)?真求解", "ctf_real_solvers", "真求解器数"),
    (r"(?<![\d.])(?P<n>\d+)\s*(个)?(启发式\s*)?检测器", "ctf_detectors", "检测器数"),
    # 09-09 新增：此前只锚定 3 个数，导致「测试文件/工具 YAML/技能/Agent/角色/internal」
    # 整类数字漂移无人把关（终检清单写 226 测试时真值已 257）。
    (r"(?<![\d.])(?P<n>\d{3})\s*(个)?测试文件", "test_files", "测试文件数"),
    # 09-28 新增：官网 stats 区写的是「N 自动化测试文件」——中间插了"自动化"，
    # 上面那条锚点匹配不到（数字与"测试文件"之间只能有空白）→ 长期漏检。
    (r"(?<![\d.])(?P<n>\d{3})\s*(个)?自动化测试文件", "test_files", "测试文件数（自动化×）"),
    (r"测试文件\s*\**(?P<n>\d+)", "test_files", "测试文件数（后置）"),
    # 2026-10-04 新增：材料另有一种「裸 N 测试」简写 —— `127,196 行 Go · 279 测试 · 0 panic`
    # 与 `Go 735 文件（279 测试）`。上面三条都要求带"文件"二字，这类简写**完全无锚点**，
    # 于是真值已 286 时 279 仍长期存活：PPT 构建脚本 ×3 + 打印版合订本 + 技术报告（3 文件 5 处）。
    # 同属「锚点覆盖不全」盲区（与 09-15「711 Go 文件」数字在前、09-28「N 自动化测试文件」同族）。
    # 后缀排除串：避免吃掉"测试文件/测试包/测试用例"等既有锚点的匹配（否则会重复命中同一数字）。
    (r"(?<![\d.])(?P<n>\d{3})\s*(个)?测试"
     r"(?!文件|包|用例|覆盖|通过|全绿|结果|脚本|报告|环境|数据|集|计划|方案|流程|项|点|案|机|工具|是)",
     "test_files", "测试数（裸写/后置）"),
    (r"工具\s*YAML\s*\**\s*(?P<n>\d+)", "tools_yaml", "工具 YAML 数"),
    # 2026-10-04 新增（第二处「锚点覆盖不全」，与上面那条 10-04「裸 N 测试」同族）：
    # 材料另有一种**正序**写法「N YAML 工具/配方」——上面那条只认「工具YAML<数字>」的逆序，
    # 于是「91 YAML 工具」（规划总纲 / PPT数字清单）与「90 个 YAML 内置工具」全部漏检。
    # 后者连 BANNED 都漏：`90\s*(个)?(工具|YAML)` 要求「个」后**紧跟**工具/YAML，
    # 而实际写的是「90 个 YAML」(个与 YAML 间有空格) → 正则失配、长期漂移无人发现。
    # 实测现行材料 13 处写 90（真值 91），分布 README_CN / 技术报告 / 打印版合订本 /
    # 演示视频脚本 / PPT 制作脚本 等。加锚点后由修复器机械同步，不再靠人肉 grep。
    # 负向守卫排除「N YAML 角色/配置/参数/字段」等**非工具**的 YAML 计数，
    # 免得把 roles_yaml(13) 之类误当工具数改掉。
    # 2026-10-18 新增：「N+ YAML」这种**带加号的取整宣称**此前完全无锚点 ——
    # 实测冻结产物里写着「100+ YAML 配方」，而工具 YAML 真值已降到 90（生成器早已改成
    # 「90 个 YAML 配方」，产物没重跑）。加号把它伪装成"约数"，比写错数字更难发现：
    # 上面所有锚点都要求「数字紧跟 YAML/个」，`100+` 的 `+` 一律让它们失配。
    (r"(?<![\d.])(?P<n>\d{2,3})\s*\+\s*(?:个)?\s*YAML", "tools_yaml", "工具 YAML 数（N+ YAML 取整宣称）"),
    (r"(?<![\d.])(?P<n>\d{2,3})\s*(个)?\s*YAML\s*(?!\s*(?:角色|配置|参数|字段))",
     "tools_yaml", "工具 YAML 数（正序：N YAML …）"),
    # 2026-10-04 新增：**数字与单位被拆成两个相邻字符串字面量**的写法 ——
    # `('90', 'YAML 工具配方')` / `('270', '测试文件')`。
    # 文本锚点要求"数字紧跟单位"，看不见它；产物读回（check_artifact_numbers.py）
    # 时同一形状的 runs 会拼成「90 YAML 工具配方」「270 测试文件」，于是同一页
    # 出现「91 工具 vs 90 YAML」「286 测试文件 vs 270 测试文件」的自相矛盾。
    # 故在**源侧**也补锚点，与产物门形成「源—产物」双保险（源侧能被 CI 抓到）。
    (r"""['"](?P<n>\d{2,4})['"]\s*,\s*['"]\s*YAML""", "tools_yaml",
     "工具 YAML 数（拆分字面量：数字, YAML）"),
    (r"""['"](?P<n>\d{2,4})['"]\s*,\s*['"]\s*测试文件""", "test_files",
     "测试文件数（拆分字面量：数字, 测试文件）"),
    # 2026-10-13 新增（第 6 处「锚点覆盖不全」，与上两条同族）：PPT 数据卡的
    # **headline 裸数字** —— `('176', '预解组件\n118真求解器+59检测器')`。headline 是
    # 独立字符串字面量、后面不跟"求解器"，上面按「N 求解器 / N 真求解」锚定的三条全部失配，
    # 于是同一处出现「176 预解组件」与「118+59=177」自相矛盾（分解数更新了、headline 漏更）。
    # 补锚点后该形态可被机验，由修复器机械同步。实测命中 make_champion_ppt.py / make_final_ppt.py。
    (r"""['"](?P<n>\d{3})['"]\s*,\s*['"][^'"]*预解""", "ctf_solvers",
     "求解器总数（拆分字面量：数字, 预解组件）"),
    (r"(?<![\d.])(?P<n>\d+)\s*(个)?内置\s*(MCP\s*)?工具", "builtin_tools", "内置 MCP 工具数"),
    (r"(?<![\d.])(?P<n>\d+)\s*(个)?技能(包)?", "skills", "技能包数"),
    # (?<![一-龥]) 排除 "3人2Agent" 这类「数字紧跟中文」的误命中
    (r"(?<![\d.])(?<![一-龥])(?P<n>\d+)\s*(个)?(角色化\s*)?Agent", "agents_md", "Agent(md) 数"),
    (r"(?<![\d.])(?P<n>\d+)\s*(个)?角色(定义)?(?!化)", "roles_yaml", "RBAC 角色数"),
    # 2026-10-18 拆分口径：以前这一条把「目录」与「包」都锚到 internal_dirs。
    # 实测 internal/ **一级子目录 = 34**，而 `go list ./internal/...` **= 37**（含 mcp/builtin 等二级包），
    # 材料写「N 个 internal 包」时指的是后者。混用导致同一份 PPT 里「37 个 internal 包」与
    # 「32 包分层」并存、谁也不知道哪个对。现按词面分开锚定。
    (r"internal\s*(子)?目录\s*\**\s*(?P<n>\d+)", "internal_dirs", "internal 子目录数"),
    (r"internal\s*包\s*\**\s*(?P<n>\d+)", "internal_packages", "internal 包数（后置）"),
    # 前置写法「37 个 internal 包」此前**无锚点**（门禁看不见 → 改对数字也不算数）。
    (r"(?<![\d.])(?P<n>\d+)\s*个\s*internal\s*包", "internal_packages", "internal 包数（前置）"),
    # 「N 包分层」：这个措辞在材料里存在多年，但**从来没有人能说清它是什么口径**；
    # 历史值 27→31→32→33 的递增轨迹恰好与 internal 包增长同步（实测 internal 包 = 37），
    # 故在此**明确定义**：包分层 = internal 包数（按分层目录组织的 Go 包总数）。
    # 有了定义才能机验；不定义就永远是手工 ±1 的自由心证（27→31→32→33 就是这么来的）。
    (r"(?<![\d.])(?P<n>\d+)\s*包分层", "internal_packages", "包分层（= internal 包数）"),
    # 「N 包测试全绿」= 有测试的包数（28），**不等于** go list 总包数（41）。
    # 两者混用正是「26 包」长期漂移却无人能自动校验的根因 —— 以前真值源里根本没有这个数。
    (r"(?<![\d.])(?P<n>\d+)\s*(个)?包(测试|全绿|有测)", "test_packages", "有测试的包数"),
    # 2026-10-23 新增（第 7 处盲区，实测）：材料/PPT 数据卡/官网 stats 另写「N/N 测试包」。
    # 上面那条要求数字**紧跟**「包」，而这里数字与「包」之间夹了「测试」、且数字是 A/B 形态
    # → 长期漏检：deck 与官网写「37/37 测试包」而真值已 38，没有任何判据报红。
    # ⚠️ 必须强制「测试包」二字：`N/M 包` 另有「40 个包里 26 个」的语义（docs 里真实存在
    #    「26/40 包」），放宽成可选会把那种表述误判成"测试包数"。
    (r"(?<![\d.])(?P<n>\d+)/\d+\s*测试包", "test_packages", "有测试的包数（N/N）"),
    # 09-15 新增：代码行数此前**完全没有锚点** —— 122,131 / 125,998 / 126,396 这类数字
    # 只能靠人肉比对，正是官网"行数差 7 倍却长期无人发现"的根因之一。
    (r"(?<![\d,.])(?P<n>\d{2,3},\d{3})\s*行", "non_test_lines", "非测试代码行数"),
    # 2026-10-13 新增（同属「锚点覆盖不全」族，第 5 处）：材料另写「N 非测试行 / N 含测试」——
    # 数字与「行/含测试」之间夹了「非测试/含测试」二字，上面那条要求数字**紧跟**「行」，
    # 于是 `提交前硬门槛核查清单.md` 文首的「126,659 非测试行」（真值早已 128,094）长期漏检；
    # 又因**表格体**（`| 测试文件 | 237 |`，数字与单位间夹 `|`）同样不受锚点约束，
    # 自动同步器只刷新了同行的「299 测试文件 / 751 Go 文件」，令同一行出现「已刷新」与旧值自相矛盾。
    # 补锚点后该形态可被机验，修复器亦能机械同步。
    (r"(?<![\d,.])(?P<n>\d{2,3},\d{3})\s*非测试行", "non_test_lines", "非测试代码行数（非测试行）"),
    (r"(?<![\d,.])(?P<n>\d{2,3},\d{3})\s*含测试", "total_lines", "总行数（含测试）"),
    # 2026-10-18 新增（第 7 处「锚点覆盖不全」）：**分发体积**此前完全无锚点。
    # 实测 `草稿内容版.pptx` 仍写「Setup 安装版 33.6 MB / 绿色版 158 MB」，而 installer/
    # 实物是 20.3 MB / 89.5 MB（09-05 那代产物早已不存在）。#52 只修了三份生成器产物，
    # 这两处因为真值源里没有对应字段而**永远无法被机验**——写什么都算对。
    # 口径：MB = 10^6（与官网下载按钮「绿色版 · 89.5 MB」同一分母），见 count_stats.size_mb。
    (r"Setup\s*安装版\s*(?P<n>\d+(?:\.\d+)?)\s*MB", "setup_mb", "Setup 安装包体积(MB)"),
    (r"安装版\s*[（(][^）)\n]{0,12}?(?P<n>\d+(?:\.\d+)?)\s*MB", "setup_mb",
     "Setup 安装包体积(MB，括注式)"),
    (r"绿色版\s*[·・（(]?\s*(?P<n>\d+(?:\.\d+)?)\s*MB", "exe_mb", "绿色版单文件体积(MB)"),
]

# 历史档案豁免：文件**内容里**带 CALIBER-SNAPSHOT 标记即视为历史快照。
# 用文件内标记而非维护文件清单 —— 规则可审计（打开文档就能看见），不会因重命名/新增
# 文件而悄悄失效。加标记时必须同时在文首写明「锚定哪个基线」。
SNAPSHOT_MARK = "CALIBER-SNAPSHOT"

# 文件名内嵌历史日期（如 xxx_20260905.md）→ 自动视为该日快照。
# 用「文件名日期」而非手写清单，新写的材料带新日期，规则不会因新增文件悄悄失效。
HIST_DATE_RE = re.compile(r"2026(\d{2})(\d{2})")

# ⚠️ 反向例外：名字带旧日期但**仍是现行作战材料**，不得豁免。
# 判据是「决赛现场还会照着念/照着做」，不是「文件多旧」。
# 精确文件名（不用模糊前缀），改这里必须在提交信息里说明理由。
FORCE_CURRENT = {
    "提交前终检清单_20260903.md",       # 决赛打包作战手册，现场照着走
    "PPT数字清单_E1E5_20260905.md",      # PPT 改数字的现行依据
    "final-race-readiness_20260905.md", # 赛前就绪度检查，仍在用
}

# 修复/生成类脚本：它们**必须列举**旧数字才能完成替换，列举 ≠ 使用。
# 精确文件名，理由同上（secret_guard 的 SELF_EXEMPT 同款教训）。
TOOL_EXEMPT = {
    "fix_stale_numbers.py",          # 批量替换旧数字的修复脚本
    # 2026-10-18：交付物数字定点修正脚本（SecAutoMind_PPT/ 在扫描范围内，实测被自己误伤——
    # docstring 记载旧值、代码里 old 元组必须列举旧字面量才能替换）。
    # ⚠️ 豁免代价：本文件内容过期时没有判据能发现（#43 教训）。缓解：它的自测在
    #    scripts/check_artifact_numbers.py 这一侧——产物改完必须门禁转 PASS，脚本本身不承载结论。
    "fix_artifact_numbers.py",
    # 2026-10-18：交付 PPT 的**过期技术断言/体积**定点修正脚本。同上——它的 RULES
    # 必须逐条列出旧串（"33.6 MB" → "20.3 MB"）才能替换，列举 ≠ 使用。
    # 代价与缓解同上：产物是否真改对，由产物门禁（check_artifact_numbers）说话。
    "fix_stale_claims.py",
    # ↓ 下面两个都在 scripts/，而 scripts/ **当前不在 SCAN_DIRS 内**（实测门禁扫不到它们）。
    #   登记是前瞻性的：哪天把 scripts/ 纳入扫描，这两个文件必然带着漂移字面量
    #   （同步器的 docstring 要举例、它的自测要故意注入），届时会被自己误伤。
    #   实测 is_historical() 对二者均返回 True，豁免链本身有效。
    "fix_material_numbers.py",       # 真值同步器：docstring 里举 126,659 -> 126,675 作说明
    "fix_material_numbers_test.py",  # 自测**必须**故意写一个漂移数字才能验证修复器（列举 ≠ 使用）
    "_qc_final.py",                  # PPT 质检脚本，正则里必须写旧数字才能查它
    "PPT_制作提示词.md",              # 同一份旧数字禁用清单的说明文档
    # 历史修复清单（2026-09-09 一次门禁输出的快照）：它的功能就是**列举**当时报出的 94 处
    # 旧数字/漂移，豁免扫描是必须的。⚠️ 2026-10-16 更正一处不实注释：本门禁**从不写它**
    # （此前注释称"门禁自己产出、覆盖更新"，实测无任何写入逻辑 → 该清单自 09-09 起无人刷新，
    # 漂移修完、门禁已 PASS，文件却仍写「结论：FAIL」）。现由 check_ledger() 双向钉死状态，
    # 过期即红 —— 与 #41「产物↔生成器一致性」同款判据。
    "口径修复清单.md",
}

# 规范文档自身（它要列举禁用清单来说明规则，列举 ≠ 使用）
EXEMPT_FILES = ["AGENTS.md"]

SKIP_DIR_PARTS = {".git", ".workbuddy", "node_modules", "logs", "data", "installer"}

# 明细显示上限。设太小的后果已实测：报 112 处却只显示 25 条，
# 让人误以为只有 25 处（截断本身也是一种「掩盖失败」）。
MAX_SHOW = 500


def coerce_num(raw, want):
    """把材料里抽到的数字与真值统一成同类型再比 —— **两个门禁共用这一个实现**。

    计数字段是整数（行数带千分位，如 126,396）；体积字段（setup_mb / exe_mb）是
    1 位小数。2026-10-18 首次引入小数锚点时，两处各自 `int(m.group("n"))` 都直接
    抛 ValueError（材料门禁与产物门禁各踩一次）——正是「同一判据写两遍」的老毛病。
    """
    raw = raw.replace(",", "")
    if "." in raw or isinstance(want, float):
        return float(raw), float(want)
    return int(raw), int(want)


def find_local_installer_products():
    """本检出是否真的有 installer/ 产物（决定体积真值为 null 是"环境缺件"还是"脚本坏了"）。"""
    base = os.path.join(ROOT, "installer")
    if not os.path.isdir(base):
        return []
    return [f for f in os.listdir(base) if f.lower().endswith(".exe")]


# 真值依赖「二进制实物」的锚点字段：二进制不入库（`.gitignore` `installer/*`），
# 故 CI 检出里恒为 null。两个门禁（材料 / 产物）必须用同一套口径判断"缺件"与"故障"，
# 否则一个绿一个红 —— 这里定义一次，两处调用。
ARTIFACT_DEPENDENT_TRUTH = ("setup_mb", "exe_mb")


def missing_anchor_fields(truth, local_binaries=None):
    """锚点字段缺失清单（缺失即崩）。**体积字段按"产物在不在"分流**：

    · 产物不在本检出 → 记为「未核验」（CI 常态，不是故障）；
    · 产物在、却读不出体积 → 仍算缺失（count_stats 真坏了），必须红。
    """
    if local_binaries is None:
        local_binaries = bool(find_local_installer_products())
    return [k for _p, k, _l in ANCHORS
            if truth.get(k) is None
            and not (k in ARTIFACT_DEPENDENT_TRUTH and not local_binaries)]


def load_truth():
    """从单一真值源取数。取不到就直接崩 —— 没有真值的门禁毫无意义。"""
    out = subprocess.run(
        [PY, os.path.join(ROOT, "scripts", "count_stats.py"), "--json"],
        cwd=ROOT, capture_output=True, text=True,
    )
    if out.returncode != 0:
        raise SystemExit("FATAL: count_stats.py 执行失败，无法取得真值：\n" % out.stderr)
    return json.loads(out.stdout)


_HTML_TAG_RX = re.compile(r"<[^>]*>")


def is_html_path(rpath):
    return rpath.lower().endswith((".html", ".htm"))


def scan_texts(line, is_html):
    """返回该行要做模式匹配的探针序列：[(text, via_attr), ...]。

    非 HTML：原文一份（via_attr=False），语义与 2026-10-18 之前完全一致。

    HTML：两份 —— ①「标签→空格」后的可见文本（via_attr=False）；②**原文**
    （via_attr=True）。第 ② 份修的是 2026-10-18 发现的属性值盲区：
    `<[^>]*>` 把整个标签连同属性值换成空格，于是写在属性里的文字
    （典型如 `<meta content="…143 工具…">`）对 BANNED 与 ANCHORS **双双不可见**。
    实测官网 og:description 的「143 工具」（删 lightx 前的旧运行时数）正是这样
    漏检的：同一文件可见文本早已改成 142，属性里还留着 143，门禁常年 PASS。

    方向性保证「只可能更严」：属性文本此前**完全不被检查**，加扫后要么与真值一致
    （结论不变），要么报出（比此前严）；不存在把旧命中变放行的路径。
    去重由调用方负责（同一处两边都命中只报一次）。

    本函数是门禁与 fix_material_numbers.py 的**共享检测语义**——两边必须调用同一个，
    否则会出现「门禁红、修复器看不见」的死循环。
    """
    if not is_html:
        return [(line, False)]
    stripped = _HTML_TAG_RX.sub(" ", line)
    if stripped == line:
        return [(line, False)]
    return [(stripped, False), (line, True)]


def iter_files():
    seen = set()
    for d in SCAN_DIRS:
        base = os.path.join(ROOT, d)
        if not os.path.isdir(base):
            continue
        for dirpath, dirnames, filenames in os.walk(base):
            dirnames[:] = [x for x in dirnames
                           if x not in SKIP_DIR_PARTS and not x.startswith("_")]
            for fn in filenames:
                if os.path.splitext(fn)[1].lower() in SCAN_EXT:
                    if fn.startswith("_"):  # PPT QA 中间产物（gitignore 已排除，磁盘仍在）
                        continue
                    p = os.path.join(dirpath, fn)
                    if p not in seen:
                        seen.add(p)
                        yield p
    # 根目录 *.md 自动发现（含 SCAN_FILES，这里统一处理，去重由 seen 保证）
    for fn in sorted(os.listdir(ROOT)):
        if os.path.splitext(fn)[1].lower() != ".md":
            continue
        p = os.path.join(ROOT, fn)
        if os.path.isfile(p) and p not in seen:
            seen.add(p)
            yield p


def rel(path):
    return os.path.relpath(path, ROOT).replace("\\", "/")


def is_historical(rpath):
    """历史档案判定：内容带 SNAPSHOT_MARK，或**路径**内嵌早于今天的日期。

    用 rpath 而非 basename：像 docs/evidence-20260905/ 这种按日期分目录归档的证据包，
    目录名带日期、文件名不带，只看 basename 会漏判。
    """
    base = os.path.basename(rpath)
    if base in FORCE_CURRENT:
        return False  # 名字虽旧，但仍是现行材料 —— 必须检查
    if base in TOOL_EXEMPT:
        return True   # 修复脚本必须列举旧数字，列举 ≠ 使用
    for m in HIST_DATE_RE.finditer(rpath):
        mm, dd = int(m.group(1)), int(m.group(2))
        today = today_cn()          # 固定东八区，勿改回 date.today()（见文件头注释）
        if (mm, dd) < (today.month, today.day):
            return True
    return False


LEDGER_REL = os.path.join("docs", "口径修复清单.md")
# 机器可读状态行：清单必须自带且与本次门禁结论一致。格式刻意写得死板，
# 便于人读、便于机验，也便于测试注入。
LEDGER_STATUS_RE = re.compile(r"^当前门禁状态：\s*(PASS|FAIL)\s*$", re.MULTILINE)


def check_ledger(verdict):
    """`docs/口径修复清单.md` 若存在，其声明的门禁状态必须与本次一致。

    实锤（2026-10-16）：该文件是 09-09 一次门禁输出的快照，记「结论：FAIL」。
    此后漂移全部修完、门禁转 PASS，但文件无人刷新 —— 而它被 TOOL_EXEMPT 豁免扫描
    （要列举旧数字），所以**没有任何判据能发现它已过期**，读者会以为仓库仍在 FAIL。
    这正是 #41 的「产物 ↔ 真值漂移」同款失效形态，只是对象换成了一份文档。

    判据：文件不存在 → 跳过（可选件，不强制存在）；
          存在但缺状态行 / 状态与本次结论不符 → 红（fail-closed，过期不许蒙混）。
    """
    path = os.path.join(ROOT, LEDGER_REL)
    if not os.path.isfile(path):
        return []
    try:
        with open(path, "r", encoding="utf-8") as fh:
            text = fh.read()
    except OSError as e:
        return ["%s 无法读取：%s" % (LEDGER_REL, e)]
    m = LEDGER_STATUS_RE.search(text)
    if not m:
        return ["%s 缺少机器可读状态行（应为独占一行「当前门禁状态：PASS|FAIL」）"
                "—— 过期清单无判据可查" % LEDGER_REL]
    if m.group(1) != verdict:
        return ["%s 声明「当前门禁状态：%s」但本次门禁结论为 %s"
                " —— 清单已过期，须据本次输出刷新" % (LEDGER_REL, m.group(1), verdict)]
    return []


def main():
    truth = load_truth()
    # 自检：锚点用到的字段必须全部存在于真值中。缺失就崩，绝不静默跳过。
    # ⚠️ 2026-10-18 例外：`setup_mb` / `exe_mb` 的真值来自 installer/ 下的**实物**，
    # 而二进制不入库（`.gitignore` `installer/*`）→ CI 检出里这两个字段天然是 null。
    # 若也按"缺失即崩"处理，caliber-gate 会恒红（实测首跑就打红）。
    # 但「本机明明有 installer 产物却读不出体积」仍是真故障（count_stats 坏了），必须红 ——
    # 故这里不是无条件豁免，而是按「产物在不在」分流。
    ARTIFACT_TRUTH = ARTIFACT_DEPENDENT_TRUTH
    missing = missing_anchor_fields(truth)
    if missing:
        raise SystemExit(
            "FATAL: count_stats.py 未返回锚点字段 %s（脚本字段名可能已改）。\n"
            "门禁绝不静默跳过检查 —— 请先修复字段名，否则本门禁形同虚设。" % missing
        )
    banned_hits, anchor_hits = [], []
    # 「本检出无法核验」的锚点（真值为 null）：只作显式登记，不计违规 —— 见下面体积锚点处注释
    unverifiable = []
    exempted = 0
    scanned = 0   # 2026-10-14 补：扫描覆盖数（见下方 fail-closed 判据）

    for path in iter_files():
        scanned += 1
        rpath = rel(path)
        try:
            with open(path, "r", encoding="utf-8", errors="ignore") as fh:
                lines = fh.readlines()
        except Exception:
            continue
        is_snapshot = SNAPSHOT_MARK in "".join(lines[:40]) or is_historical(rpath)
        # HTML 材料的探针由 scan_texts() 产出（可见文本 + 原文属性值两份），
        # 语义与修复器 fix_material_numbers.py 共享。
        # 历史沿革：2026-09-15 曾把「标签→空格」当作 HTML 的完整解法（治的是数字与单位
        # 被标签隔断那一类盲区，如 `>268</div><div>自动化测试文件`）；2026-10-18 发现它
        # 顺手挖了另一个坑——属性值里的文字被一起吃掉了，见 scan_texts() 文档字符串。
        # 用"替换为空格"而非"删除"，避免把相邻文本粘起来产生新误报。
        for lineno, raw_line in enumerate(lines, 1):
            probes = scan_texts(raw_line, is_html_path(rpath))
            if is_snapshot:
                # 历史档案豁免口径不变：BANNED 命中数豁免（HTML 含属性值探针）
                exempted += sum(
                    len([1 for pat, _ in BANNED if re.search(pat, text)])
                    for text, _via in probes
                )
                continue
            if rpath in EXEMPT_FILES:
                continue
            # 去重：同一处（同行同模式同结论）在「可见文本」与「HTML 属性值」
            # 两个探针下都命中时只报一次，避免一行被计两遍。
            seen = set()
            for text, via_attr in probes:
                suffix = "（HTML 属性值）" if via_attr else ""
                for pat, why in BANNED:
                    if re.search(pat, text):
                        key = ("B", rpath, lineno, why)
                        if key in seen:
                            continue
                        seen.add(key)
                        banned_hits.append((rpath, lineno, why + suffix, text.strip()[:120]))
                for pat, akey, label in ANCHORS:
                    m = re.search(pat, text)
                    if not m:
                        continue
                    want = truth.get(akey)
                    # 2026-10-18：分发体积（setup_mb / exe_mb）的真值来自 installer/ 下的实物，
                    # 而**二进制不入库**（`.gitignore` `installer/*`）→ CI 检出里这两个字段是
                    # null。此时不能崩（`int(None)` / `float(None)` 都抛异常，实测把 caliber-gate
                    # 直接打红），也不能装作验过：显式记一笔「本检出无法核验」。
                    # 防退化不靠这里——靠自测第 15 条（真值存在时「错必红/对必绿」双向钉）。
                    if want is None:
                        ukey = ("U", rpath, lineno, label)
                        if ukey in seen:
                            continue
                        seen.add(ukey)
                        unverifiable.append((rpath, lineno, label + suffix))
                        continue
                    # 计数字段整数 / 体积字段 1 位小数，统一走 coerce_num（两个门禁共用一个实现）
                    got, want = coerce_num(m.group("n"), want)
                    if got != want:
                        akey2 = ("A", rpath, lineno, label, got, want)
                        if akey2 in seen:
                            continue
                        seen.add(akey2)
                        anchor_hits.append((rpath, lineno, label + suffix, got, want,
                                            text.strip()[:120]))

    # 2026-10-14 补（门禁审计 · 空洞绿）：本门禁的全部结论都由「违规项计数」构成，
    # 因此**扫到 0 个文件时会无条件全绿** —— SCAN_DIRS 写错目录名、目录被 gitignore
    # （`官网/` 曾长期未入版本库，2026-10-18 才随材料修正入库；被 .gitignore 排除
    # 是同类风险的现实来源）、或扫描扩展名被改空，都会让门禁静默失效却报 PASS。
    # 这正是 _audit_llm_pool.py 当年「池文件缺失 → 空池 → 全绿」的同款失效形态。
    # 判据：扫描覆盖数为 0 本身必须算红（fail-closed），绝不允许「没扫到 = 没问题」。
    if scanned == 0:
        raise SystemExit(
            "FATAL: 本门禁扫描到 0 个材料文件（SCAN_DIRS=%s，根目录 *.md 亦为空）。\n"
            "  「一个都没扫到」与「扫了且全部一致」是两回事 —— 后者才是 PASS。\n"
            "  常见原因：目录名写错 / 目录被 .gitignore 排除 / SCAN_EXT 被改空。\n"
            "  门禁绝不把「没扫到」当成「没问题」放行。" % (SCAN_DIRS,))

    print("=" * 70)
    print("材料口径门禁 · 真值来自 scripts/count_stats.py --json")
    print("  锚定 HEAD: %s" % truth.get("head"))
    print("  扫描材料文件 %d 个（覆盖数为 0 即 FAIL，见上）" % scanned)
    print("  go_files=%s  test_files=%s  ctf_solvers=%s  runtime_tools=%s  "
          "tools_yaml=%s  builtin_tools=%s  go_packages=%s  test_packages=%s"
          % (truth.get("go_files"), truth.get("test_files"), truth.get("ctf_solvers"),
             truth.get("runtime_tools"), truth.get("tools_yaml"), truth.get("builtin_tools"),
             truth.get("go_packages"), truth.get("test_packages")))
    if exempted:
        print("  [豁免] 历史档案中 %d 处旧口径已豁免（文首已声明锚定旧基线）" % exempted)
    if unverifiable:
        keys = sorted({lbl for _f, _l, lbl in unverifiable})
        print("  [未核验] %d 处「%s」：本检出缺 installer/ 产物（二进制不入库），"
              "真值为 null —— 已显式登记，不计违规" % (len(unverifiable), "、".join(keys)))
    print("-" * 70)

    if banned_hits:
        print("  [FAIL] 已作废旧口径复活 %d 处：" % len(banned_hits))
        for fp, ln, why, txt in banned_hits[:MAX_SHOW]:
            print("    %s:%d  (%s)" % (fp, ln, why))
            print("        %s" % txt)
    else:
        print("  [PASS] 无已作废旧口径")

    if anchor_hits:
        print("  [FAIL] 材料数字与真值不符 %d 处：" % len(anchor_hits))
        for fp, ln, label, got, want, txt in anchor_hits[:MAX_SHOW]:
            # 体积锚点是 1 位小数，计数字段是整数 —— 统一按「谁带小数按两位以内输出」
            fmt = "%g" if isinstance(got, float) or isinstance(want, float) else "%d"
            print(("    %s:%d  %s=" + fmt + "，真值=" + fmt) % (fp, ln, label, got, want))
            print("        %s" % txt)
    else:
        print("  [PASS] 材料数字与真值一致")

    verdict = "FAIL" if (banned_hits or anchor_hits) else "PASS"
    ledger_issues = check_ledger(verdict)
    if ledger_issues:
        print("  [FAIL] 口径修复清单状态与本次门禁不符 %d 处：" % len(ledger_issues))
        for x in ledger_issues:
            print("    " + x)
    else:
        print("  [PASS] 口径修复清单状态与本次门禁一致（或未提供该可选件）")

    print("=" * 70)
    if banned_hits or anchor_hits or ledger_issues:
        print("  结论：FAIL —— 口径漂移（或清单过期），禁止合入/打包。")
        if anchor_hits and not banned_hits:
            # 锚点漂移是**纯机械**的：数字本来就该等于 count_stats 真值。
            # 与其让人肉 grep 11 处，不如给一条可执行的修复命令（修复器复用本门禁的
            # ANCHORS 表，判定口径与这里逐字相同，不存在"两套规则"）。
            print("  修复：python scripts/fix_material_numbers.py --apply --check")
        return 1
    print("  结论：PASS —— 材料口径与单一真值源一致。")
    return 0


if __name__ == "__main__":
    sys.exit(main())
