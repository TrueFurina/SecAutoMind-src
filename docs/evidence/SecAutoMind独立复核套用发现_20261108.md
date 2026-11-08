# SecAutoMind 独立复核套用发现_20261108

> 来源：MARL-ECDSA 夜班独立复核线（同日晚，另一项目）收口后，按其 AGENTS.md 与《最佳实践_多会话并行独立复核》对 SecAutoMind 做的首轮外部盘点。只读复核，未动任何他人 WIP 与代码。

## 一、总评

本项目宪章（AGENTS.md 17 路由 + 收尾清单八项 + 诚实铁律 + session_registry 并发互斥）与 MARL-ECDSA 一夜沉淀出的独立复核 runbook **高度同构、独立演化收敛**——互证两条实践路线都成立。近期提交（PASS→FAIL 事实回改、证据按提交态重采集、C4 反注水结构化）显示宪章在被真实执行而非摆设。

## 二、本轮实证过的清白项（照实记功）

1. `git_cred_repo/` 凭证夹具：已被 .gitignore 覆盖、未入 git、由 `gen_exec_artifacts*.py` 合成产生、`API_KEY='abc123'` 明显为诱饵夹具——**非泄漏**。
2. `data/session_registry.json`：已忽略，合规。
3. 未提交的 3 个 M 文件（answer_key_filter/_leak_provenance/emoji_binary）为并行 WIP——按纪律视为待验证线索，本复核未触碰。

## 三、发现清单（按可执行度排序）

| # | 发现 | 建议（本线不代动） | 依据 |
|---|---|---|---|
| S1 | **三类运行副产物未纳管**：根目录 `bind{1,2,3}.json.audit.json`、`ssrf_runtime_*.json`（端口快照）、`purellm_full188.json` 全不在 .gitignore，长期堆积会使"脏工作树"常态化、淹没真 WIP（与 MARL 侧 361 件根散件同 pathology） | 生成脚本改输出到既有 ignored 目录（如 execution/），或 .gitignore 增补三类模式；现存残留按本仓规矩归档或清离 | git check-ignore 实测未覆盖 |
| S2 | **audit 写入方本机未定位**：bindN.json.audit.json 内容近空（0 调用 0 拦截）却落在仓库根——疑似某运行时按 **cwd 相对路径**写审计件（与 MARL 侧 verify 工具 cwd 假 FAIL 同类缺陷：产物落点依赖调用位置） | 服务器可达后 `lsof`/全局搜写点；把审计输出改绝对路径或配置项 | 本机 grep cmd/ internal/ gen* 无命中，如实记"未定位" |
| S3 | **实验服务器 172.16.222.99 当前本机不可达**（L2，同 MARL 侧事件）：本项目第零条规定一切解题/实验上服务器，故本轮所有需实机验证的项（重跑 benchmark、起实例）全部**阻塞待链路恢复**；两项目共享同一台机，这是单点 | 恢复优先级列最高；长期看两项目共机需 awareness（session_registry 已有端口/切片互斥，跨项目共用的前提是它一直被遵守） | ping/TCP/ssh 三探均超时（21:0x 复测） |
| S4 | 宪章层面的正反馈建议：AGENTS.md"常驻区导航"五件套（改哪儿/收尾/读哪份/接手看什么/交给下会话）恰好等于 MARL 侧今晚才补上的"唯一入口索引"实践——可直接注明互认，防未来会话给本项目重复造轮 | 无需动作，记录同构性 | 两仓文本对照 |

## 四、边界声明

未跑任何命令级测试（工作树含他人 WIP，py_compile 全量可能撞上未完工改动产生误导性红）；S2 写入方定位、S3 实机项均**未验证/待服务器可达**。按本仓铁律如实标注。
