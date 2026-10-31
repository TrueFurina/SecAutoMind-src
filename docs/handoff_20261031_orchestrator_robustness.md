# 交接卡 · orchestrator 鲁棒性 + 外部池工件管道（2026-10-31）

> 按 `docs/templates/交接卡模板.md` 九字段填写。空字段均已写"无"或"未验证"，无占位符。

---

## 1. 项目快照

- **仓库 / 分支 / HEAD**：`E:\Program\SecAutoMind` / `docs/race-day-card` / `7f4262f`
- **本轮时间窗**：2026-10-31 08:00–12:40（GMT+8）
- **当前阶段**：赛前活跃期（决赛日期本身存在冲突，见 §8-A1，未拍板）
- **一句话现状**：工件管道（含目录形态附件）已打通、LLM 请求有总时长硬截止、并发默认降到 1；
  单题 `public_morse_image` 已由纯 LLM agentic 解出；外部池 8 道纯离线题 0/8，属当前模型真实能力水位。

## 2. 目标任务

- **目标**（逐字抄需求原文，**未改写**）：
  > 本会话相关记忆先落盘，我要交付别的agent+整理项目文件夹，而且各种md数量过多，能合并的就合并
- **明确不做**（范围外，防止蔓延）：
  1. 不碰任何 PPT 产物（`SecAutoMind_PPT/**` 永久冻结，见 `SecAutoMind_PPT/FROZEN_DO_NOT_TOUCH.md`）
  2. 不合并 `docs/zh-CN/` 与 `docs/en-US/`（32 对双语对照，是文档站正文，不是重复稿）
  3. 不合并 `docs/README.md` 与 `docs/INDEX.md`（前者=文档站入口，后者=agent 文档状态索引）
  4. 不改他人在途 WIP（工作区有大量非本会话改动，见 §6）
- **完成定义**（可测）：① 记忆已落盘且可 `grep` 到；② 接手 agent 仅凭本卡即可复现一次跑批；
  ③ md 减量有 git/归档痕迹，且 `python scripts/check_agent_docs.py` 仍 rc=0。

## 3. 最快实现路径（可直接执行）

```bash
cd E:/Program/SecAutoMind
export PYTHONIOENCODING=utf-8        # 必须，否则门禁 emoji 输出 GBK 报错假红
```

1. **读三份入口**（只读这三份，不要全仓读）：
   `AGENTS.md` → `docs/QUICKSTART_NEXT_AGENT.md` → `docs/AGENT_ROUTES.md`
2. **验管道（本机，不需网络）**：
   ```bash
   python scripts/test_artifact_inject.py; echo "RC=$?"     # 期望 40 项 PASS，RC=0
   python scripts/check_agent_docs.py;    echo "RC=$?"      # 期望 结论：PASS，RC=0
   ```
3. **上服务器跑单题（真跑，唯一合规姿势）**：
   ```bash
   ssh user@172.16.222.99
   cd /home/user/SecAutoMind
   python3 scripts/session_registry.py claim --id <你的会话id> --slice <切片> --port <空闲端口> \
     --channel xfyun --owner <你> --note "<目的>"
   set -a; . /home/user/.xfyun_env; set +a
   nohup python3 -u scripts/ctf_stepfun_orchestrator.py \
     --provider xfyun --artifact-dir /home/user/SecAutoMind/data/questions_external_bench/_attachments \
     --benchmark data/questions_external_bench/external_bench.json \
     --only-ids <题目id> --agentic --max-iter 24 --wall-budget 900 --timeout 180 --concurrency 1 \
     --out /home/user/<你的输出>.json --slice <切片> > /home/user/<你的输出>.log 2>&1 &
   ```
   跑完必须 `python3 scripts/session_registry.py release --id <你的会话id>`。
4. **判读结果**：`--out` 的 `summary.tool_calls_blocked` 应为 0；
   `details[0].latency` 若精确等于 `2×timeout` 且 `tool_calls=0` ⇒ 是并发/服务端长尾，不是模型不会做（见 §5-2）。

## 4. 涉及文件（具体路径）

| 路径 | 作用 | 本轮是否已改 |
|---|---|---|
| `scripts/ctf_stepfun_orchestrator.py` | 跑批主控：工件准备、守卫、LLM 调用、agentic 循环 | **是**（`b96d0a5` + `7f4262f`） |
| `scripts/test_artifact_inject.py` | 工件/守卫/截断/降级的回归测试（40 项） | **是** |
| `data/questions_external_bench/external_bench.json` | 终局外部池 40 题（crypto 26 + misc 14） | 否（已同步到服务器） |
| `data/questions_external_bench/_attachments/<pid>/` | 40 个题目的真实附件目录，共 19.5MB | 否（已同步到服务器） |
| `scripts/session_registry.py` | 跑批占位登记（claim/release，活跃 ≤5） | 否 |
| `.workbuddy/memory/2026-10-31.md` | 本会话全部结论与数字 | **是**（已追加） |
| `.workbuddy/memory/MEMORY.md` | 长期记忆（KPI 口径、赛时纪律） | **是**（追加并发铁律） |
| `docs/handoff_20261031_orchestrator_robustness.md` | 本卡 | **是**（新增） |

## 5. 已知陷阱（具体事故形态）

| 陷阱 | 具体形态（什么时候会咬人） | 规避动作 |
|---|---|---|
| **并发 ≥3 打讯飞会全局长尾超时** | 8 题一批、`--concurrency 5`：其中 3 题**首次调用即 180s 硬截止、`tool_calls=0`、360.0s 收口**，连预算都没开始花；同题 `--concurrency 1` 则正常跑 23 轮 | 一律 `--concurrency 1`（默认已改 1，≥3 会打警告） |
| `urllib` 的 `timeout` 是 per-recv 级 | 服务端慢速滴流字节时 `urlopen(timeout=180)` **永不触发**；实测单请求挂死 **23 分钟**、CPU 0%、ESTAB 不释放 | 已封装 `_urlopen_deadline`（线程 + `join` 到点即弃）；**新写 HTTP 调用必须走它**，别直接用 `urlopen` |
| 超时异常会炸掉整题并丢弃已积累推理 | 改前：第 5 轮超时 → 整题 `error`、`raw_head=""`、`got_len=0`，看起来像"模型不会做"，其实前面已做对 | 已在 `call_llm_agentic` 内降级为文本继续，连续 2 次才收口；新加异常路径**不许**冒泡出循环 |
| 全文正则守卫分不清"字节串/注释里的 `..`" | 曾把 agent 正确的 PNG 解析代码拦 2 次（代码里有 `b"..\x00"` 之类） | 已改 `sys.addaudithook` 精确拦 `open` 的绝对路径与 `..` 组件；**别再往 `_ARTIFACT_MODE_PATTERNS` 里加路径类正则** |
| 工件模式 `fs-access` 会拦 `os.listdir('.')` / `os.getcwd()` | agent 想看自己目录有哪几个文件时被拒（1 次/批） | 目前是**有意设计**（文件清单已由 prompt 注入）；若要放宽，需连同回归一起改，别单改正则 |
| 目录形态附件没有 `zip` 字段 | `prepare_artifacts` 旧实现只认 `zip_name` + zip 文件 → 外部池 **40/40 题拿不到附件**，misc 题纯文本必输 | 已加目录分支（`copytree`）；新增题库时确认字段形态是 `zip` 还是 `_attachments/<pid>/` 目录 |
| `.workbuddy/**` 与 `.workbuddy-ai/**` 未跟踪且被 gitignore | 删了**不可恢复**（无 git 兜底） | 任何删除先 `tar czf` 归档 + `tar tzf` 校验条目数，再删源 |
| 本地 remote-tracking ref 不可信 | `git log origin/main..HEAD` 返回 0 是因为 `origin/main` **根本不存在**（本仓远端叫 `ghssh`），会被误读成"已全部推送" | 判推送状态用 `git branch -r --contains <sha>`；本轮实测：`b96d0a5` 已在 `ghssh/docs/race-day-card`，`7f4262f` **不在任何 remote** |
| 门禁本地假红 | Windows GBK 控制台下 emoji 输出 `UnicodeError` → rc=1 假红 | 跑任何 python 门禁前 `export PYTHONIOENCODING=utf-8` |

## 6. 依赖与约束

- **服务器口径**（固定事实）：**跑实验 / 解题都在 `172.16.222.99`**（`ssh user@172.16.222.99` 免密）；
  **本机只做编排与日志**。在本机 `127.0.0.1:18086` 起实例跑题 = **不合规**。
- **前置依赖**：服务器 `/home/user/.xfyun_env`（讯飞 key，`set -a; . 它; set +a`）；
  服务器已同步 `scripts/ctf_stepfun_orchestrator.py` 与 `data/questions_external_bench/`（19.5MB 附件）。
- **不可动的东西**：
  1. `SecAutoMind_PPT/**`（永久冻结，用户明令）
  2. `data/ctf_benchmark/solves_ledger.jsonl` 现有 9 条（全是确定性 solver 口径 `engine=hash_crack`，
     **混写 LLM 结果会污染口径**）
  3. 工作区里**非本会话**的改动（`git status` 大量 WIP；提交时只 `git add` 显式文件，严禁 `git add -A`）
- **环境坑**：见 `AGENTS.md` 第五条；本轮真正相关的已列在 §5。

## 7. 验收标准（可测）

- [ ] `python scripts/test_artifact_inject.py` → 期望 **40 项 PASS**（少于 40 说明回归被删，不是"变快了"）
- [ ] `python scripts/check_agent_docs.py` → 期望末行 `结论：PASS`、`RC=0`
- [ ] 跑批 JSON `summary.tool_calls_blocked == 0`；`details[0].tool_calls > 0`
- [ ] 反向验证：把 `--concurrency` 改回 5 跑同一道题，应复现"`tool_calls=0` + latency≈2×timeout"；
      若复现不出来，说明服务端长尾已变，§5-1 的结论需重新测（**不要直接沿用**）

## 8. 默认假设（未拍板项，可被推翻）

| # | 假设 | 若被推翻的影响 |
|---|---|---|
| A1 | 决赛仍按 `config` 的 2027-03-01 准备（公告写 2026-11-07，冲突未终裁） | 所有"赛前窗口"判断与排期作废，需立刻切到抢分模式 |
| A2 | `public_morse_image` **不计入** KPI 分母（不在 `AUTHORIZED_KPI_SOLVES` 14 道，也不在外部池 40 道） | 若实际应计入，KPI 分子+1，需重算能力率 |
| A3 | 外部池 40 题里 14 道"附件只有服务端脚本"的题**注定失败**（沙箱禁网） | 若后续开放网络或本地起服务端，这 14 道的分母口径需重定义 |
| A4 | 8 题 0/8 是"模型真实能力水位"，不是管道问题（依据：5 题用满 24 轮仍在打转） | 若查出管道仍有缺陷，则 0/8 不成立，需重跑 |

## 9. 上下文元数据

- **生成者 / 时间**：WorkBuddy agent / 2026-10-31 12:40 (GMT+8)
- **上一份交接**：`docs/handoff_1024_final_20261024.md`、`docs/handoff_ycb_20261024.md`（均已被本卡取代）
- **相关文档**（`docs/INDEX.md` 条目）：`docs/AGENT_ROUTES.md`、`docs/QUICKSTART_NEXT_AGENT.md`、
  `docs/收尾清单.md`、`docs/服务器实机验证_Runbook_20261020.md`
- **未验证 / 仍未知**：
  1. `7f4262f` 的推送（只查了本地 remote-tracking ref，**未** `git ls-remote` 复核）
  2. 外部池剩余 32 题（含 14 道需联网题）的真实解出率——本轮只测了 8 道纯离线 + 1 道 ocr
  3. `--max-iter 48` 是否能把"打转的 5 题"救回来（未测）
