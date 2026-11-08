# CTF-Agent 融合留存说明

> 📄 **本项目门面文档是 [`README.zh.md`](./README.zh.md)**（架构、KPI 口径、诚实横幅全在那边）。
> 本文件只记录**融合来源与迁移范围**，不是项目说明——有意的分叉，见
> `MIGRATION_DELTA_20261024.md` 第 14 行「有意分叉：两边各自保留，不回灌、不覆盖」。

**融合日期**：2026-10-24（先核心批次）
**操作人**：AI 协助（智能筛选复制，未删除/未修改任何源文件）
**用户决策**：范围=先核心；方式=智能化迁移（排除运行垃圾，保留代码+治理）

## 为什么有这个目录
西湖论剑 CTF-Agent 项目（自研多智能体 CTF 攻防 Agent，含门禁/反注水治理体系与真题解出记录）
计划全量融入 SecAutoMind。本批次按用户决策先行迁移**核心代码与治理资产**，
后续批次可再补题库附件与历史记录（源仓库 E:\Program\西湖论剑\ 保持不动）。

## 目录内容（本批次）
| 内容 | 来源 | 说明 |
|---|---|---|
| `ctf_agent/core|agents|skills|tests|tools|benchmarks|web|config|scripts|hooks|eval|prompts|knowledge/` | 西湖论剑/ctf_agent/ | 核心代码、技能库、测试、治理钩子（源结构保持） |
| `ctf_agent/data/results/` | ctf_agent/data/results/ | 仅 .md/.json 治理记录（交接文档 166 章、竞品对照等），排除题库附件大二进制。**注意**：该目录被 `.gitignore` 的 `/data/*` 排除，属**本地副本**内容，不在版本库内（克隆后不会有） |
| `ctf_agent/` 根散文件 | ctf_agent/ | config.py 等入口与配置（仅小文本） |
| `协同任务总账-TOP0.md` 等根治理文档 | 西湖论剑/ | 总账/AGENTS/CLAUDE/CONTRIBUTING/README/LICENSE |
| `_manifest.json` | 本次生成 | 迁移清单：日期/范围/排除规则/文件数与体量 |

## 排除项（智能化迁移规则）
- `ctf_agent/logs/` 21GB 运行日志（运行垃圾，不入仓库）
- 题库附件大二进制（.png/.jpg/.pcap/.exe/.zip 等，>8MB 单文件）
- `__pycache__/.venv/backups/worktree/_git_backup/`（环境与备份）

## 后续批次（未迁移，待定）
- ctf_agent/data/attachments 题库附件（82M，需逐字节校验后迁）
- 历史记录类（backups/idea-stage/2027-prep/deliverables）
- git 历史合并（当前未做——两套治理体系钩子冲突，另行评估）

## 源基线
- 源仓库 commit：d76572f2（分支 w/t2-cybench-scaffold）+ 工作区改动快照
- 源仓库保持不动，本目录为独立副本，可独立演进
