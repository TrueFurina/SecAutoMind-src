# Skip 审计报告 — 2026-09-17 15:34:46

> pytest 汇总：425 passed / **16 skipped**（解析命中 16 条 skip 记录）


## 数据/附件缺失（合法 skip：本地比赛数据 git 不入库、源不可得） — 15 条

| # | 测试文件:行 | 原因 |
|---|---|---|
| 1 | `tests\test_eval_integrity.py:62` | data/attachments 或 data/answers 不在版本库（本地保留），无数据环境跳过 |
| 2 | `tests\test_eval_integrity.py:55` | data/attachments 或 data/answers 不在版本库（本地保留），无数据环境跳过 |
| 3 | `tests\test_eval_integrity.py:39` | data/attachments 或 data/answers 不在版本库（本地保留），无数据环境跳过 |
| 4 | `tests\test_eval_integrity.py:159` | data/attachments 或 data/answers 不在版本库（本地保留），无数据环境跳过 |
| 5 | `tests\test_eval_integrity.py:173` | data/attachments 或 data/answers 不在版本库（本地保留），无数据环境跳过 |
| 6 | `tests\test_presolve_skill_wiring.py:39` | 10732 附件未解压 |
| 7 | `tests\test_presolve_skill_wiring.py:109` | 10733 附件未解压 |
| 8 | `tests\test_presolve_skill_wiring.py:145` | 10734 附件不存在 |
| 9 | `tests\test_presolve_skill_wiring.py:184` | 10733 附件未解压 |
| 10 | `tests\test_presolve_skill_wiring.py:201` | 10733 附件未解压 |
| 11 | `tests\test_skill_real_race_chain.py:50` | 10732 附件未解压到 data\race_extract\10732\deep2\PKCS#1.v1.5.enc（先跑 unzip） |
| 12 | `tests\test_skill_real_race_chain.py:122` | 10734 附件不存在: data\race_attachments\10734_MISC-01 |
| 13 | `tests\test_skill_real_race_chain.py:139` | 10734 附件不存在: data\race_attachments\10734_MISC-01 |
| 14 | `tests\test_web_target_wiring.py:61` | 10725 附件不存在: data\race_attachments\10725_cmsms-2.2.8-install.expanded.zip |
| 15 | `tests\test_web_target_wiring.py:144` | 10725 附件不存在: data\race_attachments\10725_cmsms-2.2.8-install.expanded.zip |

## 环境未开启（合法 skip：真实 LLM smoke / API key 未配置） — 1 条

| # | 测试文件:行 | 原因 |
|---|---|---|
| 1 | `tests\test_real_llm_smoke.py:47` | 真实 LLM smoke 未开启（设 CTF_AGENT_REAL_LLM_SMOKE=1 才跑，避免 CI 空耗） |

## 可疑缺口（无法归类 -> fail-closed 报警，需人工判定是否为代码覆盖缺口） — 0 条

_无_


---

**治理规约**：data_missing / env_off 为已知合法 skip（数据集不入库、真实 LLM 未开启），CI 静默跳过正确。任何 `suspect` 类 skip 出现即触发工具退出码非 0（fail-closed）——新增的不可解释 skip 必红灯，逼人工判定是否把覆盖缺口伪装成了绿灯。
