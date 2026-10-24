# 羊城杯初赛交接文档（2026-10-24 · 本科院校组）

> 交接给下一任 Agent 继续攻坚。本文件是当前已知情报的全部，接手后**直接照此行动**，
> 不要重复探查平台结构（已有实测结论），先把 16 题逐题拿下。

---

## 一、赛事基本信息（已核实）

| 项 | 值 |
|---|---|
| 比赛 | 2026 年"羊城杯"网络安全大赛**初赛 · 本科院校组** |
| 平台 | `https://ycb-bk.dasctf.com` |
| 比赛页 | `https://ycb-bk.dasctf.com/compete/1750/detail` → 登录后 `https://ycb-bk.dasctf.com/1750/competePage/3241` |
| 时间 | **2026-10-24 10:00–14:00**（4 小时，已过半，13:30 前须完成主体攻坚） |
| 队伍 | **芒得很职**（选手：张敏杰；用户 ID 442455） |
| 计分 | 动态分值：每题初始 500，解出人数越多分值越低；题目 10 时与 12 时分批放出 |
| 排名 | 交接时 0 分，约 221 名（动态） |
| 平台性质 | 人类比赛，dasctf「教学竞赛靶场」（**无 Agent 竞技场**），须浏览器登录态操作 |

## 二、登录与页面操作（实测）

- **登录状态**：浏览器（豆包内浏览器 bu 会话）已登录，登录信息存 localStorage：
  - `jwtToken-1750` = `Bearer <玩家会话 JWT —— 从浏览器 localStorage 的 jwtToken-1750 读取，**不要写进任何文件/聊天**>…`（完整值在浏览器 localStorage，可直接读）
  - 相关键：`userInfo-1750`、`playerOrigin-1750`、`entryType-1750=TEAM`、`authList-1750`
- **API 协议**：`/slab-match/api/v1/player/ctf/...`（**西湖论剑同款协议**），请求须带
  `Authorization: Bearer <jwt>` 头；裸 fetch 返回 `40401 未能读取到有效Token`。
  - 题目列表：`GET /slab-match/api/v1/player/ctf/exercise-list?matchId=1750&stageId=3241`
    ⚠️ 实测仍报 `40001 缺少竞赛id`——**参数未完全逆向成功**，别在这上面耗时间，
    直接浏览器 DOM 操作（题号导航是 div，点击加载右侧详情）。
- **页面读取法**：`bu.navigate(比赛页)` → `bu.find("1-1")` 拿题号 ref → `bu.click(ref)` →
  `bu.get_page_text()` 读详情（题目名/内容/分值/靶机地址/靶机操作按钮）。
  ⚠️ 该环境 bu API 较旧：`snapshot()` 只接受无参（视口内元素），`get_page_text()` 无参，
  `find(text)` 返回 ref 数组；不要传 `within/max_chars/search_type` 等参数（会报 TypeError）。

## 三、题目清单（10:00 第一批可见 16 题，12:00 第二批待出）

题号导航（点击查看详情）：**1-1, 1-2, 1-3（WEB）；2-1…2-6, 2-12（PWN/MISC?）；3-1,3-2,3-3,3-5（CRYPTO）；5-1（REVERSE）；6-1（AI）**
分类页签：WEB / PWN / MISC / CRYPTO / REVERSE / AI（数字 1/2/3 是分类，1=WEB、2=?, 3=CRYPTO、5=REVERSE、6=AI）

已探明：
- **1-1 pdfchallenge（WEB，500 分，中等）**：题面"简单的转换工具"。靶机服务 = **md2pdf**
  （Markdown→PDF），`POST /render`（Content-Type: text/plain，body=markdown，返回 PDF）。
  - 靶机地址：`http/3000 -> 1.14.76.59:32353`（⚠️ **靶机实例可能已因探测被打挂**，
    接手先 `GET /` 探活，挂了就在页面点【销毁靶机】→确认→【开启场景】重建，换新端口）
  - 漏洞方向（未验证）：file:// 资源读取（img/iframe/link/object/embed/xinclude）、
    YAML front matter、SSRF；出题端大概率 weasyprint/pandoc 系。
  - ⚠️ **教训：不要并发打靶**，14 连发 POST 把靶机打挂过（全部超时 WinError 10060）。

## 四、解题引擎（SecAutoMind 现成能力，直接可用）

代码根 `E:\Program\SecAutoMind`，Go 包 `internal/ctfplatform`，全绿基线：
- **presolve**（`Presolve` 并发链 + 注册表 189 求解器 + **Python 兜底** 79 西湖论剑 skills +
  **跨原语递归解码链** tryCodingChain）：静态题（编码/古典密码/附件分析）直接喂文本可解。
  - Python 兜底：env `SECAUTOMIND_PYTHON_FALLBACK=true`（默认开）、`SECAUTOMIND_XHLJ_LEGACY=
    E:\Program\SecAutoMind\data\ctf_benchmark\xhlj_legacy`
- **Go 运行前置**（AGENTS.md 第五条，必设，否则 go 全挂）：
  ```powershell
  $env:APPDATA="$env:USERPROFILE\AppData\Roaming"
  $env:TMP="D:\tmp_gotest"; $env:TEMP="D:\tmp_gotest"; $env:TMPDIR="D:\tmp_gotest"
  $go = "D:\DevCache\go\bin\go.exe"; Set-Location E:\Program\SecAutoMind
  ```
- **附件分析**：下载附件 → 用 presolve 或 `xhlj_legacy\runner.py`（Python 兜底）解。
- 测试/工具：`& $go test ./internal/ctfplatform/ -run TestCodingChain -v`（4/4 绿）等。

## 五、接手后的行动清单（按优先级）

1. **探活/重建 1-1 靶机**（GET / 探活；挂了就页面销毁重建）→ 单发载荷测 `POST /render`
   （先基础 markdown 确认渲染正常、记耗时）→ 试 file:// 读取链拿 flag → 页面【提交 flag】。
2. **逐题读题**（DOM 点击导航）建立 16 题清单：题名+类型+靶机/附件+难度；静态题优先。
3. **静态题批量攻坚**：附件下载 → presolve/Python 兜底/编码链直解 → 提交。
4. **靶机题**（WEB/PWN）：开场景 → 按题型打（web 常见漏洞 / pwn 用 pwntools）。
5. **12:00 第二批题**：放出后立即读取。
6. 提交 flag 用页面输入框【提交flag】（页面有 `input "请输入flag"` + 提交按钮）。
7. ⚠️ 全程节流：单题探测串行、每题 ≤3 次连发；靶机操作（开/毁）间隔 ≥30s。

## 六、踩坑记录（务必遵守）

- ❌ 并发 14 连发 POST → 靶机打挂全超时（WinError 10060 / timed out）
- ❌ 裸 fetch（无 Authorization 头）→ `40401`
- ❌ exercise-list 参数逆向未成（40001 缺少竞赛id）——**别再试，走 DOM**
- ✅ 浏览器 bu API 是旧版：snapshot()/get_page_text() 无参、find() 返回数组、click 用 ref
- ✅ 登录态用 localStorage 的 jwtToken-1750 可复用（脚本 fetch 带 Authorization 头）

## 七、参考

- 本机 python venv：`C:/Users/Lenovo/.workbuddy/binaries/python/envs/default/Scripts/python.exe`
  （含 pypdf/fitz/weasyprint/pdfplumber/httpx，可 PDF 文本提取与 HTML→PDF 复现）
- 探测脚本残留：`E:\Program\SecAutoMind\.workbuddy\tmp\ycb_md2pdf_probe.py`（批量载荷，可改单发）
- SecAutoMind 赛时文档：`docs/ctf2_arena_integration_20261023.md`（快闪赛 19:00 用，勿混）
- **今晚还有 1024 快闪赛 Agent 赛道 19:00–20:00**（CTF²，SecAutoMind 自动参赛，另一战场）

---

## 八、10:40–10:55 接手复核（新增，实测）

### 8.1 已确认的事实（可直接用）

| 项 | 实测结果 |
|---|---|
| 靶机 `1.14.76.59:32353` | **GET `/` 200**（Express + 静态页，3856B，`Last-Modified: 2026-10-23`） |
| 渲染接口 | `POST /render`，`Content-Type: text/plain`，body=原始 markdown（前端第 64 行 `fetch('/render',{method:'POST',headers:{'Content-Type':'text/plain'},body:md})`）✅ 交接给的形式正确 |
| **渲染引擎** | **headless Firefox**：PDF 元数据 `/Producer: cairo 1.18.4`、`/Creator: Mozilla Firefox 153.5.1` |
| **单次渲染耗时** | **35 s（冷）/ 64 s（暖后）** —— ⚠️ 任何 `< 90 s` 的超时都会误判为"靶机挂了" |
| `/flag`、`/flag.txt`、`/app/flag.txt`、`/api/flag` | 404（`/flag` 偶发 000=连接未响应，不要在这上面耗时间） |

### 8.2 当前状态：实例已不可用，**必须重建**（阻塞中）

```
POST /render  -> HTTP 500, body: "BiDi timeout: session.new"     (22s)
```

即使最简载荷 `# ok` 也 500。已等 2 分钟 + 间隔重试 3 次，稳定复现 ⇒ **不是瞬时抖动，是浏览器会话池耗尽/geckodriver 卡死**。

**处置（需要浏览器登录态，Agent 无法代办）**：
页面点【销毁靶机】→ 确认 → 【开启场景】→ 拿新 `IP:端口`，然后**只发一次**下面的载荷。

### 8.3 重建后的第一发（别多发）

已备好单发多探，一次渲染同时试 5 个路径，避免多次请求再打死它：

```bash
# 1) 改 .workbuddy/tmp/ycb_oneshot.md 里的路径（如需），跑一次即可
C:/Users/Lenovo/.workbuddy/binaries/python/envs/default/Scripts/python.exe \
  .workbuddy/tmp/ycb_oneshot.py http://<新IP:新端口>
# 输出会逐页打印 PDF 文本；命中 file:// 就能直接看到 /etc/passwd 或 flag 内容
```

载荷内容（`ycb_oneshot.md`）：`iframe file:///etc/passwd` + `file:///flag` + `file:///flag.txt`
+ `file:///app/flag.txt` + `file:///tmp/flag`。

判读法：
- **能读到 `/etc/passwd`** → file:// 通，flag 那几页里直接看；
- **只有空白/报错** → file:// 被同源策略挡住，改走 SSRF（`<iframe src="http://127.0.0.1:PORT/...">`）
  或 `<img src="http://169.254.169.254/...">`；
- **再 500 `BiDi timeout`** → 说明实例一碰就死，优先换思路（先做静态题攒分）。

### 8.4 纪律修正（血泪）

- 单次渲染 **35–64 s**，所以客户端超时必须 **≥ 180 s**，否则会把"正常但慢"误判成"挂了"。
- **绝对串行**，两次渲染间隔 **≥ 60 s**。本实例的 BiDi 会话不回收，连发几次就永久 500。
- 探活只用 `GET /`（毫秒级），**不要用 POST 探活**（每次 35 s+ 且消耗唯一的浏览器会话）。

### 8.5 静态题直解通道（2026-10-24 10:57 实测，**用这个别用 Python 兜底**）

新增 `cmd/presolve/main.go`（20 行封装，调用生产同一条 `Presolver.Presolve` 链路）。
已编译到 `.workbuddy/tmp/presolve.exe`，直接可用：

```bash
printf '题干/密文...' | .workbuddy/tmp/presolve.exe --category crypto
.workbuddy/tmp/presolve.exe --text-file q.txt --category misc --json
# --timeout 60s 默认；--id 只影响日志
```

命中率抽测（同一台机、同一批样本）：

| 输入 | Go 引擎 | Python 兜底 `runner.py` |
|---|---|---|
| 明文 `flag{presolve_smoke_2026}` | ✅ 4 ms | ❌ 空手 |
| base64(`flag{hello_world}`) | ✅ 2 ms | ❌ 空手 |
| hex(`flag{nested}`) | ✅ 4 ms | ❌ 空手 |
| base64(hex(`flag{nested}`)) | ❌ 872 ms | ❌ 空手 |

**结论**：Go 引擎单层编码可靠；**双层链解不动，先手工剥一层再喂**。
`runner.py` 四个样本全空还带 `coroutine 'web_xxe_file_read' was never awaited` 警告，
**不要当主力**（那个 async 没 await 是真缺陷，赛后再修）。

## 九、12:00–12:50 复核补充（供并发会话直接取用）

### 9.1 平台 API（已打通，比 DOM 快得多）

竞赛 id 走 **HTTP 头 `matchId`**，不在 query 里（这就是 `exercise-list?matchId=` 一直报「缺少竞赛id」的原因）。

```bash
export YCB_JWT='<player jwt>'
B=https://ycb-bk.dasctf.com/slab-match/api/v1/player/ctf
# 题目树（含 16 题 id / hasSolved）
curl -s -H "Authorization: Bearer $YCB_JWT" -H "matchId: 1750" "$B/exercise-list?stageId=3241"
# 题目详情（题面/附件 url/靶机 endpoints）
curl -s -H "Authorization: Bearer $YCB_JWT" -H "matchId: 1750" "$B/exercise?exerciseId=12086&stageId=3241"
# 开环境 / 销毁（DELETE 有效，expire-exercise-env 其实是"续期"）
curl -s -X POST -H "Authorization: Bearer $YCB_JWT" -H "matchId: 1750" -H "Content-Type: application/json" \
  -d '{"exerciseId":12061,"stageId":3241}' "$B/build-exercise-env"
curl -s -X DELETE -H "Authorization: Bearer $YCB_JWT" -H "matchId: 1750" "$B/exercise?exerciseId=12061&stageId=3241"
# 提交（字段是 exerciseId + flag，内层内容，不带 DASCTF{}）
curl -s -X POST -H "Authorization: Bearer $YCB_JWT" -H "matchId: 1750" -H "Content-Type: application/json" \
  -d '{"exerciseId":12063,"flag":"..."}' "https://ycb-bk.dasctf.com/slab-match/api/v1/player/answer-panel/answer"
```

### 9.2 各题确认结论（别再重复走）

| 题 | 结论 |
|---|---|
| **12062 FluxPipe** | `/graphql` 是**诱饵**（任何查询都只回 schema，含 `execCommand` 但不可调用）；`/api/v1/health` 泄露 `fpx_protocol: listening:4001` + erlang 4369，但**这两个端口从外部不可达**（代理只映射 4000）；`/api/v1/pipelines` 的 `name/search/q/status/order/limit` **全部被忽略**（同一参数两次结果不同），不是注入点 |
| **12063 GraphNexus** | 已被解出。链路：`/graph` 页注释给了帧格式 `[MAGIC:4][OPCODE:1][LEN:4][PAYLOAD]`（MAGIC=0x4E585553）→ `SUBSCRIBE {topic:"graph"}` 直接给 `read,query,export,import` → QUERY 载荷是**裸文本**（不是 JSON）→ `SQL(...)` 命令进 H2 → `CALL EXEC('/readflag')` |
| **12086 NeuralVault** | `GET /api/info` 给完整规格（10 客户端/5 轮/32 维/16 类，`audit_key` 16 hex，`token`），但服务端**只暴露 `/api/info` 与 `/api/submit`**；爆了 70+ 路由（含 `/api/v1/*`、`/federated/*`、`/audit/*`）无梯度下发入口 → 拿不到数据，此题在此靶机上做不了 |
| **12067 Goodbye!shell** | `read(0, rbp-0x20, 0x30)` 溢出 **16 字节**（只够 rbp+rip）；非 PIE；二进制里只有 `pop rsi;ret`（0x4010d9）一个 gadget，无 `pop rdi`、无 `syscall`；seccomp 只禁 execve/execveat（ORW 可行）。**无泄露点 + 栈地址未知**，1 小时内做不出链 |
| **12080 Jammed** | 两页打字机记录。⚠️ **以另一会话 12:15 的结论为准（本条我的判读已被推翻）**：page1 序号列字母经映射 `h=0,x=1,n=2,u=3,l=4,e=5,k=6,d=7,c=8,b=9` 可得 01–24 全排列；按此配对后两页**片段 20/24 一致，仅 4 处冲突（07,09,21,23）**。但拼接后 SHA-256 仍不匹配（已穷举字母→数字 4096 种、单/双字符替换、8 种排序×4 字段×3 变换）⇒ 密码构造另有含义。`treasure.zip` 为 AES，内含 `flag.txt` 35B |
| **12081 skin secret** | 29 张 CS2 皮肤渲染图（15 张 1920×1296 / 14 张 1000×649），背景统一 `#101014`：无 LSB、无尾部数据、无异常 chunk、无文本。按武器名首字母拼不出东西（2、3 号都是 M4A1-S） |
| **12079 Chronos** | 真 4DGS：`deformation.pth` = time net + hexplane grid + pos/rotation/opacity 编码；点云 80k。正投影渲染只有 4 团物体+噪声，无铭文。需完整 4DGS 管线 |
| **12084 千千的咲** | Unreal APK（`libUnreal.so` 100MB + `main.obb.png` 实为 zip，内含 `.pak/.ucas/.utoc`）。已逐条搜 538 个 APK 条目 + obb 内 7 个条目，**无 `DASCTF{` 明文** |
| **12083 Lost_Memory** | 附件在百度网盘（`pan.baidu.com/s/1AcARbgNFM8Ab6O0vrJjvhQ?pwd=j58q`，解压密码 `0QhPwlXHOFclWIwBW0JPQWM2mhpzysmU`），需登录下载 |
