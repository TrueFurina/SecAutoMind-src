# WorkBuddy 借鉴与落地清单（2026-10-18）

> **文档定位**：`docs/产品优化规划.md` 的配套落地文档。前三轮对话（安装目录 → 用户数据根 → 全机 12 处落点）的磁盘级盘点结论，收敛为可执行项。
> **数字口径**：一律以 `scripts/count_stats.py` 与本文标注的实跑命令为准，不手写、不凭记忆。
> **性质**：方案 + 实施记录。§3.6 为 2026-10-18 已落地的 P0 数据层与结构层；其余章节仍为建议。

---

## 0. 一句话结论

WorkBuddy 值得借鉴的是**"能力可扩展而不膨胀"的工程范式**，不是产品形态。
本项目在该范式上已完成约三分之二（skill 渐进披露、tool_search、子代理上下文隔离、上下文预算），
**真正缺的不是"市场"，是元数据**——本轮实测：工具与技能的来源/版本/授权/信任级字段覆盖率全部为 0。

---

## 1. 三档分类

| 档位 | 项 | 判断依据 |
|---|---|---|
| **已具备，别重复造** | skill 渐进披露 · tool_search · 子代理上下文隔离 · 上下文预算与摘要 | `skills/README.md`（ADK `skill` 中间件）、`internal/config/config.go:264`（`ToolSearchEnable`）、`internal/multiagent/sub_agent_context.go`、`context_budget.go` |
| **值得借鉴** | ① 插件与连接器元数据 ② 产物完整性（索引已存在，缺 sha256） ③ 自然语言定时任务 | 见 §3–§5，均带实测缺口证据 |
| **不该照搬** | Electron 桌面壳 · 通用生产力插件 · 云端账号与同步 · 多专家市场 | 与"单二进制 Go + 私有部署 + 安全垂直"定位冲突；18 agents + 13 roles + 23 skills 已够，再加是注水 |

---

## 2. 实测证据：元数据缺口（本轮新测）

### 2.1 口径先对齐（防止自造数字）

`scripts/count_stats.py` 权威口径：**90 个 YAML 工具**。
本轮 `glob('tools/*.yaml')` 得到 **92 个文件**，差异来自两个非工具声明：

- `tools/_shared_args.yaml`（顶层 `shared_args:`，被各工具以 YAML anchor 引用，**计入** 91 的历史口径）
- `tools/risk_policy.yaml`（顶层 `policy_version/default_risk/default_hitl/tools`，**被 `TOOLS_YAML_EXCLUDE` 排除**）

⇒ 90 个真工具 + 1 个 `_shared_args` = 91。**本文一律用 91，不新造 92。**

### 2.2 字段覆盖率（实跑）

统计命令：

```bash
python -c "
import glob,re
files=sorted(glob.glob('tools/*.yaml'))
for k in ['version','source','license','author','checksum','sha256','trust','category','tags','vendor']:
    n=sum(1 for f in files if re.search(r'^'+k+r':',open(f,encoding='utf-8',errors='replace').read(),re.M))
    print(k, f'{n}/{len(files)}')
"
```

| 资产 | 数量（权威口径） | version | source | license | trust | checksum |
|---|---|---|---|---|---|---|
| 工具 YAML | 91 | **0/91** | **0/91** | **0/91** | **0/91** | **0/91** |
| 技能 SKILL.md | 23 | **0/23** | — | **0/23** | — | — |
| 插件 | 2 | 无清单 | — | — | — | — |

补充事实：

- 工具 YAML 现有顶层字段仅 `name / command / enabled / short_description / description / parameters / args / allowed_exit_codes`（`internal/config/config.go:1411` `ToolConfig` 共 9 字段）。
- 技能 frontmatter 仅 `name / description / metadata.tags`（22/23 有 tags）。
- **`allowed-tools` 是解析器已支持但零个技能使用的字段**（`internal/skillpackage/frontmatter.go:57`）——典型的"能力有、资产没用"。
- 插件：`plugins/browser-extension/.../manifest.json` 是 Chrome 扩展清单，不是产品级插件清单；`plugins/burp-suite/` 无任何 manifest。

### 2.3 缺口是四层连通的

| 层 | 位置 | 现状 |
|---|---|---|
| 数据层 | `tools/*.yaml` | 无来源/版本/信任字段 |
| 结构层 | `internal/config/config.go:1411` | `ToolConfig` 无对应字段 |
| API 层 | `internal/handler/config_read.go:44` | `ToolConfigInfo` 无对应字段 |
| UI 层 | `web/templates/index.html` | 未核（标注：**未验证**） |

只补数据层 = 加了没人读的字段，正是 `AGENTS.md` 第八条的同款失败模式。**必须四层一起动。**

---

## 3. P0 · 插件与连接器元数据

### 3.1 为什么是"补元数据"而不是"做市场"

安全场景最在意"这个工具哪来的、谁签的、什么版本"。WorkBuddy 的
`~/.workbuddy/.connectors-marketplace.meta.json` 只用了三个字段就解决了远端同步与完整性：

```json
{ "etag": "...", "sha256": "...", "sourceKey": "workbuddy-connector-official\nhttps://static.workbuddy.cn/connectors-config-v2/connectors-config.zip" }
```

可直接照搬的语义：`etag` 条件请求、`sha256` 完整性校验、`sourceKey` 记录来源 URL。

### 3.2 最小 schema（4 字段，不贪多）

工具 YAML 平铺新增（与现有 9 个扁平字段风格一致）：

```yaml
version: "1.0.0"          # 工具自身版本，非项目版本
source: "self"            # self | upstream
upstream: "https://..."   # source=upstream 时必填，否则留空
license: "Apache-2.0"     # 无则填 "unknown"，禁止留空
trust: "builtin"          # builtin | verified | community
```

**为什么是 4+1 个而不是 10 个**：`checksum` 对 YAML 声明无意义（校验对象是可执行文件，不是配方）；
`category`/`tags` 属检索优化，等有真实需求再加。先让"来源可追溯"成立。

### 3.3 改动点（四层）

| # | 文件 | 改动 |
|---|---|---|
| 1 | `internal/config/config.go:1411` | `ToolConfig` 加 `Version/Source/Upstream/License/Trust` |
| 2 | `internal/handler/config_read.go:44` | `ToolConfigInfo` 加同名字段；`:68-73` 填充 |
| 3 | `tools/*.yaml` | 分批填值（**数据改动，不受冻结闸门限制**） |
| 4 | `internal/app/web/static/js/settings.js` | 工具项展示来源/信任级/许可证/上游链接（运行时前端在此，**不是** `web/templates/index.html`；根 `web/` 须同步，见 §3.7） |

### 3.4 验收判据（按第八条，防"写了不接线"）

```bash
# ① 数据覆盖：90 个工具全部有 version/source/trust
python scripts/audit_asset_metadata.py --check                  # rc=0
# ② 真实链路：API 真的返回给前端（不是只定义字段）
go test ./internal/handler/ -run TestGetToolsMetaWiring         # PASS
# ③ 变异验证：删掉 GetTools 里 Source 的填充，测试必须变红
# ④ 元数据自洽：有许可证就必须有来源（单向不变量，license_known=65 / upstream_known=68 ）
go test ./internal/config/ -run TestToolsMetadataConsistency    # PASS
# ⑤ 前端副本一致：改一处不改另一处 = 改动静默失效
python scripts/check_web_asset_parity.py                        # rc=0
# ⑥ 徽章渲染（运行时断言，非源码正则）
node --test internal/app/web/static/js/tool-meta-badges.test.cjs
```

**审计脚本先做盘点工具，不进 CI**；等元数据填满、API 接通后，再升级为门禁并补变异测试
（`AGENTS.md` 第四条：门禁自身必须有回归测试）。

### 3.5 成本与风险

- 成本：struct + API 约半天；90 个 YAML 填值 1–2 天（可按 `tools/` 分类分批）。
- 风险：低。`yaml.Unmarshal` 非 strict 模式，新增字段不会破坏既有解析；填值不改 `command`，不影响执行。
- 风险：`trust` 取值若无判定标准，会退化为"全部 builtin"的形式主义。**需先定义三档含义并写进文档。**

### 3.6 已实施记录（2026-10-18）

#### 字段语义（唯一解释，改动前先读这一节）

| 字段 | 取值 | 判定依据 |
|---|---|---|
| `source` | `self` / `upstream` | **配方来源**，不是依赖来源。`python3 -c` / `sh -c` 内联脚本 = `self`（哪怕依赖 impacket/requests）；封装外部 CLI（amass/nmap）= `upstream` |
| `trust` | `builtin` / `verified` / `community` | `builtin`=随发行版分发（事实，无需证据）；`verified`=内置且有可复现证据（`evidence` 指向 golden/e2e/真机记录）；`community`=外部导入未验证 |
| `license` | SPDX 或 `unknown` | **未逐个人工核实前一律 `unknown`**，禁止凭印象填写 |
| `version` | 语义化版本 | 配方自身版本，非上游工具版本 |

#### 改动清单

| 文件 | 改动 |
|---|---|
| `internal/config/config.go:1422-1430` | `ToolConfig` 新增 `Version/Source/Upstream/License/Trust/Evidence` 六字段 |
| `internal/handler/config_read.go:53-59` | `ToolConfigInfo` 新增同名 JSON 字段 |
| `internal/handler/config_read.go:81-86` | `GetConfig` 填充六个字段 |
| `internal/handler/config_read.go:278-288` | **`GetTools` 填充同样六字段**（前端真正读的接口） |
| `tools/*.yaml`（90 个） | `enabled:` 之后插入 `version/source/license/trust` 四行；其中 68 个补 `upstream`、65 个把 `license` 从 `unknown` 改为经 GitHub/发行包元数据核实的真实许可证 |
| `tools/lightx.yaml` | **仅加注释**：记录"上游核实失败、疑为幻影条目"的结论（未改语义，`enabled` 仍为 false） |
| `internal/app/web/static/js/settings.js` | 工具项渲染来源/信任级/许可证/上游链接徽章（`buildToolMetaBadges` 纯函数） |
| `internal/app/web/static/css/style.css` | 新增 lic-badge / lic-unverified / upstream-link 三种徽章样式 |
| `web/static/{js,css}` | **与嵌入副本逐字节同步**（parity 门禁要求，见 §3.7） |
| `internal/app/web/static/js/tool-meta-badges.test.cjs` | 徽章渲染 8 例运行时测试（含变异验证） |
| `internal/handler/tool_meta_wiring_test.go` | 自包含回归测试（含变异验证） |
| `internal/config/tools_metadata_test.go` | 元数据一致性回归测试（**单向**不变量，含三次变异验证） |
| `scripts/audit_asset_metadata.py` | 覆盖率盘点工具（非门禁）；新增 `upstream` 覆盖与单向一致性检查 |

#### 实测结果

```
工具总数: 90
  version   90/90  100.0%
  source    90/90  100.0%
  trust     90/90  100.0%
  license   65/90  72.2%（其中 unknown=25，已核实=65）
  不一致     0  个（license 已核实的工具均标注 source=upstream 与 upstream）
  upstream  70/90  77.8%
  source 分布: self=18, upstream=72
技能总数: 23
  allowed-tools 0/23  0.0%（解析器已支持，资产未使用）
```

#### 验证证据

| 项 | 命令 | 结果 |
|---|---|---|
| 全量构建 | `go build ./...` | rc=0（改动前后均绿） |
| Go 真实解析 | `go test ./internal/config/ -run TestToolsMetadataConsistency` | tools=90，self=18，upstream=72，license_known=65，upstream_known=68，PASS |
| **真实 HTTP 往返** | 临时测试走 `gin` 调 `GetTools` | HTTP 200，响应体 **54233 字节**，含 `"source":"upstream"` / `"trust":"builtin"` / `"version":"1.0.0"`（验证后已删） |
| 包回归 | `go test ./internal/config/ ./internal/handler/ -count=1` | rc=0，两包均 ok |
| 永久回归 | `go test ./internal/handler/ -run TestGetToolsMetaWiring` | PASS（自包含，不依赖开发机 config.yaml，CI 可跑） |
| **许可证批量核实** | `gh api repos/<owner>/<repo>` + 读 LICENSE 原文 | 63 个候选仓库解析出 **60 个**（3 个 404），60 个 license 全部有据可查 |
| **补救核实（第二轮）** | Kali 工具页反查上游 + SourceForge 元数据 + GNU 官网 | 12 → **2** 未解决：新增 5 个 license + 3 个 upstream（详见取数方法 5/6） |
| 元数据一致性 | `go test ./internal/config/ -run TestToolsMetadataConsistency` | PASS：tools=90, self=18, upstream=72, license_known=65, upstream_known=68 |
| 变异验证 | 删掉 `ffuf` 的 `upstream` 行 | 测试变红 rc=1，报"ffuf: license=\"MIT\" 已核实，但 upstream 为空" |
| 变异验证 | 给 `angr`（`self`）填 `license: "MIT"` | 测试变红 rc=1，报"angr: ...source=\"self\" 不是 upstream"；恢复后转绿 |
| 变异验证 | 删掉 `fierce` 的 `upstream`（保留 GPL-3.0） | 测试变红 rc=1，报"fierce: license=\"GPL-3.0\" 已核实，但 upstream 为空"；恢复后转绿 |

#### 🔴 一个必须自我修正的判据（写过头了的"防死数据"）

`tools_metadata_test.go` 最初写的是双向断言：`license 未核实 ⇒ upstream 必须为空`。
本轮给 `gdb`/`objdump`/`strings` 填上游（已从 GNU 官方页确认）但 license 留 `unknown` 时，
**这条断言直接把我自己的正确数据判成错误**。

已改为**单向不变量**：只断言「已核实许可证 ⇒ 必须是 upstream 且有上游地址」。
理由：「上游已核实、许可证未核实」是正当状态而非死数据——把已确认的上游一并抹空，
等于扔掉已经拿到的证据。死数据指的是**无来源的许可证**（凭什么说自己是 MIT 却说不出是谁），
不是**无许可证的来源**。审计脚本的一致性检查同步改为同向。

顺带发现并修掉一个统计口径 bug：`upstream_known` 原先只统计有许可证的工具，报 65 而
审计脚本报 68，二者对不上恰恰暴露了计数放错了分支。
| 审计脚本 | `python scripts/audit_asset_metadata.py --check` | rc=0（license 60/90；新增 upstream 覆盖与一致性检查） |
| JS 语法 | `node --check settings.js` | OK |
| 改动范围 | `git diff --stat -- tools/` | 90 files changed, **360 insertions(+), 0 deletions** —— 无行尾污染 |

#### 许可证核实的取数方法（可复现）

不凭记忆、不猜 SPDX，全部来自 GitHub API 与上游 LICENSE 原文：

1. `gh api repos/<owner>/<repo>` 取 `license.spdx_id` —— 60 个可用，其中 12 个为 `NOASSERTION`（GitHub 认不出标准 SPDX）。
2. `NOASSERTION` 与 `None` 的 18 个改用 `repos/<repo>/contents/<LICENSE>` 读原文判定（例：`amass` 首行即 `License: Apache2.0`；`nmap` 为 `Nmap Public Source License` 自定义许可证，GitHub 归不了 SPDX 是正确行为）。
3. 自定义许可证**只写真实名称**，不编造 SPDX 标识：nmap→`Nmap Public Source License`，volatility3→`Volatility Software License`，wpscan→`WPScan Public Source License`（双授权，商用需另购），xxd→`Vim`。
4. GitHub 探测不到 LICENSE 的 6 个仓库，改读 README 的 License 段取证据：hashcat=MIT（`docs/license.txt` 首行 `The MIT License (MIT)`）、dirsearch=GPL-2.0、xsser=GPL-3.0、zsteg=MIT。
5. **仓库 404 时改用 Kali 工具页反查上游**：Kali 每个工具页都列出上游 Homepage，这是绕过失效仓库名的可靠入口。本轮靠它定位了 `nbtscan` → `resurrecting-open-source-projects/nbtscan`（此前四处猜仓库名全 404）。
6. **上游不在 GitHub 的改用发行包元数据定许可证**：SourceForge 项目页有结构化 License 字段。foremost=**Public Domain**、steghide=**GPL-2.0**（"GNU General Public License version 2.0 (GPLv2)"）均出自该字段，而非凭印象。
7. 仓库**不存在、或无法取得权威声明**的一律留 `unknown`，绝不用记忆补（见边界 2）。

#### 如实标注的边界

1. **license 已核实 65/90，剩余 25 个是 `unknown`**。其中 18 个 `self` 自研工具本身无上游许可证，25−18=**7 个 upstream 工具未能核实**（见边界 2）；`upstream` 已核实 70 个。
2. **7 个上游工具填不上，是核实失败而不是遗漏**。取数过程如实记录：
   - **仓库确已消失**：`hashpump`（`bwall/HashPump` 被多篇教程引用，但 `gh api` 与 GitHub 网页双双 404；`gh api users/bwall/repos` 返回空——该账号下已无任何仓库。**旧教程引用的链接不等于它还在**）。已进一步确认 Kali 未收录该工具（工具页 404）且各教程均为 `git clone`+`make` 源码安装、无发行包元数据可反查；唯一存活的相关仓库 `sTorro/HashPumpWIN32` 是 2014 年的 Windows 移植、0 星、2018 年后停更，**不是上游**。
   - **工具本身查无实据**：`lightx`（配方描述"轻量级资产发现与漏洞扫描工具"，但多轮搜索后仍找不到任何同名工具，**疑为仓库中的幻影条目，建议人工复核配方本身是否可用**）。
   - **混合许可 + 镜像被反爬**：`gdb`/`objdump`/`strings` 属 GNU binutils-gdb，上游 `sourceware.org/git/gitweb.cgi?p=binutils-gdb.git` 已从 GNU 官方页确认并填入；但该包同时带 `COPYING`(GPLv2)/`COPYING3`(GPLv3)/`COPYING.LIB`(LGPL) 属混合许可，而 sourceware 与 sourcehut 两个官方镜像对本机分别返回 **Anubis / go-away 反爬挑战页**，逐文件许可无法核实，故 license 留 `unknown`。
   - **仓库存在但无任何许可声明**：`dnsenum`、`waybackurls`（根目录无 LICENSE/CHECKING，README 无 License 段，GitHub 许可检测为空）。二者上游均**已核实并填入**（`fwaeytens/dnsenum`、`tomnomnom/waybackurls`），只差许可证。
   - 其中 `dotdotpwn`/`fierce`/`foremost`/`nbtscan`/`steghide` 五个已在本轮补齐——此前判定"无法定位"是我只试了 GitHub 直猜仓库名，未尝试 Kali 工具页反查与发行包元数据这两条路。
3. **`radare2` 是混合许可**，只记了 `LGPL-3.0`（原文："Most of radare2 is licensed under the LGPLv3"，另有 GPL 依赖与插件）。字段是单值，装不下 SBOM，需要精细合规时应另行生成。
4. **`terrascan` 的上游仓库已归档**（`tenable/terrascan`，`archived=true`）。许可证仍为 Apache-2.0，但该配方跟随的是一个停止维护的上游。
5. **`foremost` 记为 Public Domain，但其 GitHub 镜像 `korczis/foremost` 探测不到许可证**。Public Domain 出自 SourceForge 项目元数据字段（原作者 jessekornblum/kriskendall/namikus，与 Kali 版本 banner 一致），非 GitHub。两个来源不冲突但口径不同，已采信官方项目页。
6. **`nbtscan` 的许可证版本存在口径差异**：程序自带 banner 写 "GNU GPL 2+"，仓库 `COPYING` 与 GitHub 检测均为 GPL-2.0。此处采信 COPYING（GPL-2.0），差异已在本文记录。
7. **`nginx`/`wget` 类依赖未单独核实**——本清单只核到"封装的外部 CLI 本身"，不追它依赖的解释器与系统库。
8. **前端徽章已补齐 license 与 upstream，但 `version` 刻意不渲染**（见 3.7）。
9. **前端无视觉回归验证**。徽章逻辑有 8 项 `node --test` 运行时断言（含 HTML 转义注入用例），但**没在浏览器里看过真实渲染效果**。
10. **新 JS 测试未被 CI 驱动**。仓库里已有 17 个 `*.test.cjs`，同样没有任何 CI job 或脚本执行它们（`ci.yml` 全文无 `node --test`），属既有缺口。新测试沿用同一惯例，`node --test <file>` 手工可跑。
9. **全量测试未跑**。按实验服务器规则，全量测试应在服务器（Go 1.25.4）执行；本次只跑了受影响的 config / handler / app 三包。
10. **审计脚本未接 CI**。它是盘点工具，不是门禁；升级为门禁前需补回归测试与变异验证。
11. **`allowed-tools`（23 个技能 0 使用）非刻意留白，而是刻意不做**：`internal/skillpackage` 只解析不执行，解析后无任何运行时消费点。在接线之前填值只会制造死数据。

---

### 3.7 前端渲染层（P0 第四层，2026-10-18 续）

#### 🔴 踩到的坑：前端有两份物理副本，只改一份会让另一份静默失效

`internal/app/app_webfs.go:11-12` 的 `go:embed` 路径**相对于该 .go 文件所在包目录**（`internal/app/`），
所以真正嵌入 exe 的是 `internal/app/web/`；而根目录 `web/` 只是工作副本。

本次第一轮改动只落在了 `internal/app/web/static/`，**未同步根副本**，随即被
`scripts/check_web_asset_parity.py` 抓红（2 个文件 content_mismatch：`static/js/settings.js`、`static/css/style.css）。
这正与该脚本 docstring 记录的已发生事故同源（commit `8805a04` 就是一次手工补同步）。

修法与复验（按规范方向）：

```bash
cp internal/app/web/static/js/settings.js web/static/js/settings.js   # 回填工作副本
python scripts/check_web_asset_parity.py --sync    # 规范方向 web/ → embed，应为 no-op
python scripts/check_web_asset_parity.py          # rc=0
go test ./internal/app/ -run TestTmpEmbedWhichSettingsJS   # 证伪：读嵌入副本确认改动真在里面
```

> 最后一步不是多余的。`go:embed` 到底指向哪份，**看路径推导容易错，读嵌入内容才能坐实**。
> 该测试验证后即删（临时探针）。

对比对规则：两份均为**统一 CRLF 且同带 UTF-8 BOM**，脚本对文本资产按 CRLF→LF 归一化后算哈希，
所以行尾不会造成假红；真正差异是本轮新增的 28 行 CSS + 49 行 JS（`git diff --numstat` 两边各 28/49，0 deletions）。

#### 改动内容

把工具项的元数据徽章逻辑抽成模块级纯函数 `buildToolMetaBadges(tool)`（`settings.js:1363`），
`renderToolsList` 改为调用它。徽章语义：

| 徽章 | 条件 | 样式 |
|---|---|---|
| 自研 / 上游 | `tool.source` | 橙（原有） |
| 内置 / 已验证 / 外部 | `tool.trust` 命中 `TOOL_TRUST_META` | 橙（原有） |
| 许可证 | `source=upstream` 且 license 非 `unknown` | **绿**；超 16 字符截断为 15 字符 + `…`，全文进 title |
| 许可证未核实 | `source=upstream` 且 license 为 `unknown`/空 | **灰** |
| ↗ 上游链接 | `source=upstream` 且 `upstream` 非空 | **蓝**，`target=_blank rel="noopener noreferrer"`，`onclick` 阻止冒泡以免误触发展开详情 |

**刻意不渲染的字段：**

- **`version`**。90 个工具全部是 `"1.0.0"`（配方自身版本，非上游工具版本），渲染 90 遍无信息量。
- **`unknown` 许可证不逐个显示"未知"**。30 个相同文字只会制造噪音，改为灰字"许可证未核实"一态概括。

**安全处理**：license 名与 upstream URL 都过 `settingsEscapeAttr`（内部 `escapeHtml` + 引号转义），
测试用 `"><img src=x onerror=alert(1)>` 当许可证名断言不产生标签注入。

#### 测试

`internal/app/web/static/js/tool-meta-badges.test.cjs`（8 例，全部 `node --test` 运行时断言，
非源码正则）。做法：从 settings.js 切出 `settingsEscapeAttr` + `TOOL_TRUST_META` + `buildToolMetaBadges`，
用 `new Function` 求值，`escapeHtml` 以无 DOM 等价实现替身（原实现依赖 `document.createElement`）。

| # | 用例 |
|---|---|
| 1 | 自研工具只出来源/信任级，无许可证与链接 |
| 2 | 外部 MCP 工具（无字段）返回空串，含 null/undefined |
| 3 | 已核实许可证出绿徽章 + 链接三属性齐全 |
| 4 | `unknown`/空/null/undefined 四种都出灰徽章且不出链接 |
| 5 | 长许可证截断、title 留全文 |
| 6 | HTML 注入被转义 |
| 7 | 信任级取自统一表，未知值不渲染成 undefined |
| 8 | upstream 缺登记时来源徽章提示"未登记" |

变异验证：把 `if (tool.license && tool.license !== 'unknown')` 改成 `if (false && ...)`，
测试如预期 3 例变红（3、5、6），恢复后 8/8 转绿。

---

## 4. P1 · 产物索引

### 4.1 现状（2026-10-18 复核纠正）

**此前判断"没有产物索引层"是错的。** 实际 `internal/handler/chat_uploads.go` 已有一套相当完整的产物体系：

- **4 个源**：`chat_uploads` / `tmp/reduction` / `tmp/workspace` / `data/conversation_artifacts`
- **接口齐全**：`List` / `Export` / `Download` / `ResolvePath` / `GetContent` / `PutContent` / `Delete` / `Mkdir` / `Rename` / `Upload`
- **RBAC 完整**：`pathAllowed` 按会话归属鉴权，`chat_upload_artifacts` 表记录 `relative_path → conversation_id/owner_user_id`

真实缺口只有一项：**没有完整性字段（sha256）**。也就是说，"有哪些产物"能查，"这个产物是否被篡改过"不能证。

### 4.2 已实施：完整性校验（2026-10-18）

不新建表——新建 `artifacts` 会与 `chat_upload_artifacts` 形成第二套真值源。在原表上补三列：

| 列 | 语义 |
|---|---|
| `sha256` | 上传时流式计算；空 = 历史数据未登记（不伪造） |
| `size` | 落盘后 `Stat` 取值 |
| `kind` | 按扩展名粗分类（image/pcap/archive/script/doc/binary/other），仅展示用 |

改动清单：

| 文件 | 改动 |
|---|---|
| `internal/database/rbac.go:160` | `CREATE TABLE` 加三列（新库直接建出） |
| `internal/database/database.go` | `migrateChatUploadArtifactMetaColumns()`：老库幂等补列 |
| `internal/database/chat_upload.go` | Upsert 签名扩展；新增 `ListChatUploadArtifacts` / `GetChatUploadArtifactMeta` |
| `internal/handler/chat_uploads.go` | 上传时 `io.MultiWriter` 边写边算 sha256；新增 `Verify` handler |
| `internal/app/app.go:1208` | 注册 `GET /chat-uploads/verify` |

`Verify` 语义：重算文件 sha256 与登记值比对，返回 `registered / expected / actual / match / sizeMatch`。
范围**仅覆盖对话上传目录**；`__reduction__/`、`__workspace__/`、`__conversation_artifact__/` 前缀返回 400 并说明原因。

验证证据：

| 项 | 结果 |
|---|---|
| `go build ./...` | rc=0 |
| `go test ./internal/database/ ./internal/handler/ -count=1` | rc=0，两包均 ok |
| 老库迁移（临时测试，验证后已删） | PASS，含"二次调用幂等"断言 |
| `rbac_access_test` 扩展 | 断言 sha256/size/kind 可读回 |

**未做（如实标注）**：

1. ~~陈旧哈希风险~~ → **已闭环（2026-10-18）**，见 §4.5。
2. ~~前端不展示（API 已可用）~~ → **已闭环（2026-10-18）**，见 §3.7：工具项已渲染来源/信任级/许可证/上游链接徽章；`version` 刻意不渲染（90 个全为 `"1.0.0"` 的配方版本，无信息量）。
3. 虚拟前缀源的完整性未覆盖。

### 4.3 为什么值得做

直接服务 `产品优化规划.md` 的"可信层"：评委点一下就能看到某条结论对应哪个证据文件，
比再写一段"我们很诚实"的文字有效。

### 4.4 风险

1. ~~陈旧哈希~~ → **已闭环**：`PutContent` 后置空（§4.5）。Rename 经核实只改路径、内容不变，哈希应保留，不需失效。
2. 前端是单文件 `web/templates/index.html`（682 KB），加面板需谨慎，避免破坏现有布局。
3. `Verify` 每次全量读文件，超大文件应加流式上限或超时。

---

### 4.5 陈旧哈希闭环（2026-10-18）

`PutContent` 写盘后调用 `InvalidateChatUploadArtifactHash`，把 `sha256` 置空、`size` 更新，保留归属行。

**为什么置空而不是重算**：重算会让一次编辑自动获得"已验证"身份，反而掩盖"内容已变更"这一事实。
置空后 `Verify` 返回 `hashAvailable=false`，语义是"登记过、内容已变、未重新登记"。

**Rename 为什么不需要失效**：`RenameChatUploadArtifactPath` 只 UPDATE `relative_path`，内容未变，哈希随路径保留是正确的。测试已显式断言这一点。

`Verify` 三态：

| 状态 | 返回 | 含义 |
|---|---|---|
| 行不存在 | `registered=false` | 从未登记 |
| 行存在、sha 为空 | `registered=true, hashAvailable=false` | 内容已变更，哈希失效 |
| 行存在、sha 非空 | `hashAvailable=true, match=...` | 可比对 |

验证证据：

| 项 | 结果 |
|---|---|
| `go build ./...` | rc=0 |
| `go test ./internal/database/ ./internal/handler/ -count=1` | rc=0，两包均 ok |
| 测试断言 | Rename 后哈希保留；Invalidate 后 sha 为空、size 更新、行仍存在 |
| 接线顺序 | `chat_uploads.go:1446` WriteFile → `:1455` Invalidate |

**未覆盖**：`PutContent` 的 handler 级 e2e（需构造 session 与 gin 上下文）。
当前靠"DB 方法单测 + 接线位置 grep"两道保障，未做真实 HTTP 往返验证。

---

## 5. P2 · 自然语言定时任务（不建议决赛前做）

- 底座已有：`internal/handler/batch_task_manager.go`、`batch_queue_executor.go`。
- 缺口：自然语言 → cron 表达式的映射层、RBAC 与范围校验（防止定时任务越界跑）。
- **判断：决赛前不做。** 它不进入答辩叙事主线，且引入"无人值守的自动化攻击"这一高风险面，
  与 HITL 的现有边界需要重新论证。

---

## 6. 三个"不抄"

| 不抄 | 理由 |
|---|---|
| Electron 桌面壳 | 单二进制 Go 是交付硬要求，也是相对 WorkBuddy 的优势 |
| 通用生产力插件（文档/表格/PPT） | 稀释安全叙事，评委不会加分 |
| 云端账号与同步 | 私有部署/离线靶场是卖点，云端依赖是负资产 |

补充：`~/.workbuddy` 与 `~/.workbuddy-ai`、`D:\WorkBuddy` 与 `D:\WorkBuddyAI` 四套并存，
说明"改名/升级"会在用户机器上留下永久垃圾。**本项目应尽早把数据根路径定死并写进配置**，避免重演。

---

## 7. 顺序与时间窗

> **2026-10-24 更正**：下表原按「决赛 2026-12-15、冻结 12-01 起」编排，该日期已作废。
> 现行真值（`config.share.yaml` → `freeze_gate.py --status`）：决赛 **2027-03-01**，
> 冻结窗 **2027-02-15 ~ 2027-03-01**。原 P0/P1 的**执行顺序与内容不变**，只是窗口整体后移。

| 时间 | 动作 | 依据 |
|---|---|---|
| 2026-10-18 ~ 2026-11-15 | P0：struct + API + 90 个 YAML 填值 + 审计脚本 | 已于 2026-10-18 落地（§3.6/§3.7） |
| 2026-11-15 ~ 2026-11-30 | P1：产物完整性（sha256 + `Verify`）；**索引与列表已存在，不重做** | 已于 2026-10-18 落地（§4.2/§4.5） |
| 2027-02-15 ~ 2027-03-01 | **冻结：只做构建 + 全测 + 交付包自检 + 演练** | `AGENTS.md` 第七条；真值见 `freeze_gate.py --status` |
| 决赛后 | P2：定时任务 | 需重新论证 HITL 边界 |

---

## 8. 未验证项（如实标注）

1. ~~前端是否已有工具详情面板~~ → **已核清**：真正运行时前端是 `internal/app/web/static/js/`（`go:embed` 进二进制），**不是** `web/templates/index.html`；且前端请求的是 `/api/config/tools`（`GetTools`），**不是** `/api/config`（`GetConfig`）。已按真实链路接线，并补了 HTTP 往返验证。
2. ~~`plugins/` 目录的加载发现机制~~ → **已核清（2026-10-24）**：**没有运行时加载机制，也不需要**。
   Go 侧对 `plugins/` **零引用**（`grep -rn "plugins/" --include=*.go internal/ cmd/` 无命中）。
   它是**手工安装的客户端产物**目录：Burp 扩展（`build-mvn.sh` → jar，装进 Burp）与浏览器扩展
   （`chrome://extensions` → Load unpacked）。两者都以 HTTP + 令牌回连本服务 ——
   属"客户端"，不是"插件宿主"。因此不存在"burp 插件如何被运行时识别"这个问题。
3. ~~运行时连接器密钥的落盘方式~~ → **已核清（2026-10-24）**：**明文写 `config.yaml`，无加密**。
   `internal/handler/config_yaml.go:saveConfig()` 先把现有文件复制成 `config.yaml.backup`，
   再逐节把 `api_key` 写回 YAML，最后 `os.WriteFile(path, buf.Bytes(), 0644)`（该文件第 143 行）。
   即：无 keyring、无加密；FOFA / ZoomEye / Quake / Shodan / AI 的 key 与 `.backup` 副本同为 **0644**。
   `secret_guard.py` 只管交付包，管不到运行期 —— 与 WorkBuddy 的 `~/.workbuddy-key-fallback/connector-keys`
   相比，本项目暴露面是「配置文件权限」。
   **建议（未做）**：把落盘权限由 `0644` 收紧为 `0600`。本次不改：动 `.go` 会触发交付二进制重建，
   开赛前不动代码，已记入待办。
4. `trust` 三档的判定标准 —— **已定义**（§3.6 字段语义表）；当前 90/90 为 `builtin`，尚无 `verified`。
5. **全量测试未跑**。按实验服务器规则，涉及全库的测试应在 `172.16.222.99`（Go 1.25.4）执行；本机仅跑了 config / handler / app 三包。
6. ~~前端徽章无视觉回归验证~~ → **已闭环（2026-10-18 第六轮）**：用 Playwright 加载真实 `auth.js`+`settings.js`+`style.css` 在真实 Chromium（`chromium_headless_shell-1243`）里按 `renderToolsList` 的 DOM 模板渲染 6 个样本工具（ffuf/nmap/exec/dnsenum/gdb/burp-ext），断言三种新徽章的计算样式。实测全部正确——lic-badge 绿 `rgb(76,175,80)`、lic-unverified 灰 `rgb(158,158,158)`、upstream-link 蓝 `rgb(0,102,255)`；nmap 长许可证截断为「Nmap Public Sou…」且 title 留全文「已核实许可证：Nmap Public Source License」；深色主题下三色均在场可读。唯一 console 报错是 harness 的 `file://` fetch 警告（无害，非 JS 错误）。
   **附带发现（非回归、待定）**：source/trust 来源徽章填色为蓝 `rgb(0,102,255)` 而非预期的橙——经 `git show HEAD:style.css` 比对确认这是**既有行为**（`.external-tool-badge` 在第 29297 行覆盖了第 11329 行的橙色，原版与新版计算样式逐字节一致），与本轮改动无关；新徽章用了更高优先级的专属类，配色不受该覆盖影响。是否把来源徽章改回橙属独立议题，不在本任务范围。
7. **JS 测试无 CI 驱动**。仓库现有 17 个 `*.test.cjs` 均无 CI job 或脚本执行，属既有缺口；新的 `tool-meta-badges.test.cjs` 同样只能手工 `node --test` 跑。
8. **前端双副本同步仅在本机验证**。`check_web_asset_parity.py` rc=0 已复跑，但该门禁在 CI 上的真实表现未观察（CI 需 Linux 检出两侧全 LF，本机两侧均为 CRLF，归一化规则对此已作处理，但未实测）。

## 9. 后续可做项（按性价比排序）

### 9.0 收尾清单：启用中的 upstream 工具，谁还没核实完

按 `tools/*.yaml` 实跑统计：**65 个启用的 upstream 工具中，6 个仍有元数据缺口，仅 1 个缺上游登记**。

| 工具 | license | upstream | 缺口 | 卡在哪 |
|---|---|---|---|---|
| `hashpump` | unknown | （未登记） | license + upstream | 上游仓库已消失；Kali 未收录；无发行包元数据。且**配方 `enabled: true`**——上游已死却仍对外提供，是这份清单里最该处理的一条 |
| `gdb` | unknown | sourceware binutils-gdb | license | 混合许可（COPYING/COPYING3/COPYING.LIB 三种），两个官方镜像被反爬拦截 |
| `objdump` | unknown | sourceware binutils-gdb | license | 同上 |
| `strings` | unknown | sourceware binutils-gdb | license | 同上 |
| `dnsenum` | unknown | `fwaeytens/dnsenum` | license | 仓库存在但无任何许可声明 |
| `waybackurls` | unknown | `tomnomnom/waybackurls` | license | 仓库存在但无任何许可声明 |

> 注：`self` 自研工具的 license 本来就不该有值——它们封装的是本仓库自己写的配方（含 `python3`/`sh` 内联脚本），没有上游许可证可核实。统计缺口时须区分，否则会把 18 个 `self` 误算成 18 个"未完成"。

### 9.1 建议动作

| # | 事项 | 说明 |
|---|---|---|
| 1 | **`hashpump`：上游已死但配方仍启用** | 这是清单里唯一"缺上游 + 启用中"的组合。上游仓库消失、需从已不存在的源码手工编译，建议与 `lightx` 一并处置（置灰或删除）。**未擅自改 `enabled`**——属语义变更，需你确认。 |
| 2 | `lightx`：删除幻影条目 | 多轮检索 + 全仓 grep + requirements.txt/run.sh 均证实无此工具，配方 `enabled: false` 与之相符。建议删除 `tools/lightx.yaml` 并同步清理 `tools/risk_policy.yaml` 的引用。**未擅自删**。 |
| 3 | binutils 三件套的许可 | 上游已填（sourceware binutils-gdb），但该包混合 GPLv2/GPLv3/LGPL，且两个官方镜像均被反爬拦截。需换网络环境或直接读源码头部确认。 |
| 4 | `dnsenum`/`waybackurls` 的许可 | 上游已登记，仅差许可证。二者仓库均无任何许可声明，需联系作者或改用宿主发行包（Debian/Alpine）的 copyright 反查。 |
| 4 | ~~在浏览器里看一眼徽章渲染~~ → **已完成（第六轮）** | Playwright 真实渲染验证通过，见 §8 第 6 项；唯一 console 报错是 harness 的 `file://` 警告，无害。 |
| 5 | 把 18 个 `.test.cjs` 接进 CI | 现在全是孤儿测试；需先确认 CI 环境有 Node。 |
| 6 | `radare2` 生成真实 SBOM | 单值 `license` 字段装不下混合许可。 |
| 7 | 升级 `terrascan` 上游 | 当前指向已归档的 `tenable/terrascan`，应确认是否有新家。 |
