# Security-Agent 融合留存说明

**融合日期**：2026-10-14
**操作人**：AI 协助（仅复制，未删除任何源文件）

## 为什么有这个目录
挑战杯（揭榜挂帅专项赛 XH-202609）**只能提交一个作品**。已确定以 **SecAutoMind** 作为唯一提交作品，
**Security-Agent 不再作为独立作品**。为在源文件夹被手动删除前不丢失其成果，将 Security-Agent 的
提交材料、源码与文档**整体复制留存**于本目录（位于 SecAutoMind 仓库内）。

> 原文件夹 `E:\Program\2026挑战杯：Security-Agent-安全事件研判智能体\` 由用户**手动删除**，
> 本目录即其留存的唯一副本。

## 目录内容
| 子目录 | 来源 | 说明 |
|---|---|---|
| `submission/` | Security-Agent/submission/ | 提交材料包：程序材料(Dockerfile/部署手册)、技术报告.md、方案介绍PPT.pptx、演示视频分镜脚本.md、原创性及保密性声明.md（空白模板） |
| `security_agent/` | Security-Agent/security_agent/ | 源码（106 文件 / 43 .py），Python + LLM 架构 |
| `docs/` | Security-Agent/docs/ | 架构/使用/测试等文档（21 篇） |
| `reports/` | Security-Agent/reports/ | 评测报告等 |
| `root_files/` | Security-Agent 根级关键文件 | GOAL_PROMPT.md / HANDOVER.md / todo.md / README* / SECURITY.md / pyproject.toml / test_ai.py / XH-202614 研究 PDF |

## 边界（本次未做）
- **未做代码级合并**：Security-Agent 为 Python+LLM 架构，SecAutoMind 为 Go+大模型架构，两者架构不同；
  本目录仅为「留存」，非「整合进 SecAutoMind 代码树」。如需把 Security-Agent 的能力深度并入 SecAutoMind，
  需另行评估（独立任务）。
- **未删除任何源文件**：删除原 Security-Agent 文件夹由用户手动执行。
- **未提交 git**：本目录为 SecAutoMind 仓库内的新增未跟踪文件，是否纳入版本管理由用户决定。

## 随 Security-Agent 带过来的两个已知缺口（供后续决策）
1. **演示视频 .mp4 缺失**：原 Security-Agent 仅有「演示视频分镜脚本.md」，从未录制实际视频。
2. **声明函为空白模板**：`submission/03_声明函/原创性及保密性声明.md` 的【学校全称】/【手机号】/签字/盖章均未填。

若后续要把 Security-Agent 的叙事并入 SecAutoMind 单一提交，这两项需另行补齐。
