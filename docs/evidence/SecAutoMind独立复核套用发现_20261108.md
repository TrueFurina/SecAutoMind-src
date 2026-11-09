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
| S2 | ~~写入方未定位~~ **已定位（11-09 追认）**：`scripts/ctf_stepfun_orchestrator.py:1130` 写 `args.out + ".audit.json"`——`--out` 为相对名且 cwd=仓库根时审计件直接落根，正是"产物落点依赖调用位置"的 cwd 相对路径缺陷（设计意图完好：第 21 行注释明确 audit 件用于逐题复现"模型有没有抄答案"） | 一行修法二选一（owner 拍板）：①audit 路径锚定 `dirname(out)`/专用 data 子目录；②.gitignore 增补 `/*.audit.json` 根层模式并把现存 bind1-3 归档清离 | 本地 grep 实锤；服务器两副本无 writer 痕迹，属纯本地运行产物 |
| S3 | **实验服务器曾不可达（L2）**，11-09 13:54 已恢复（ping 63ms、ssh 通，中断约 17 小时）；两项目共享同一台机仍是单点，且中断跨越了 MARL 侧一次预验与本次同步欠账（后者已清） | 保持"恢复优先级最高+跨项目共机 awareness"注记；session_registry 的端口/切片互斥只有在两线都遵守时才成立 | ping/ssh 实测恢复（11-09 13:5x）；MARL 侧事件登记件互引 |
| S4 | 宪章层面的正反馈建议：AGENTS.md"常驻区导航"五件套（改哪儿/收尾/读哪份/接手看什么/交给下会话）恰好等于 MARL 侧今晚才补上的"唯一入口索引"实践——可直接注明互认，防未来会话给本项目重复造轮 | 无需动作，记录同构性 | 两仓文本对照 |

## 四、提交门禁自曝的增量发现（620d371 过闸时实测输出）

| # | 发现 | 定性 |
|---|---|---|
| S5 | 仓内**已入库真赛事品牌 flag 明文 126 条**（门禁自标"真泄露，优先清"），另历史遗留 flag 共 2075 条、未入库副本 1162 条（git add 即转泄露） | 这是比 S1 更重的既有面——门禁机制本身在跑且口径诚实（PASS 判定与豁免清单都在），但"优先清"三字挂着的 126 条需要一张处置排期表（遮蔽/转 sha256/历史处理），并确认 PUBLIC 分支是否曾带它们出过 |
| S6 | 该密钥门禁的产出结构值得反哺 MARL-ECDSA 侧：真 key 指纹库/占位符分类/未跟踪副本预警/`--audit-allowlist` 审计口——比 MARL 侧"只扫 staged"强一个量级，恰好补上 MARL 盘点里那条"存量永久盲区" | 实践互哺项：MARL 的 secrets_scan 可参考其"全仓扫描+未跟踪预警+指纹反查"三件套 |

## 五、边界声明

未跑任何命令级测试（工作树含他人 WIP，py_compile 全量可能撞上未完工改动产生误导性红）；S3 实机项曾阻塞、11-09 链路恢复后仍待本仓会话按第零条上机验证；S5 的 126 条来自门禁自身输出（本次提交时实跑所见），处置排期属本仓 owner。S2 定位、S1/S3 实况为磁盘/网络实测。按本仓铁律如实标注。


## 六、执行追记（11-09，用户"都继续"全队列授权后）

- **S1/S2 止血落地**：.gitignore 增补 `*.audit.json`、`data/ctf_benchmark/ssrf_runtime_*.json`、`data/ctf_benchmark/purellm_full*.json` 等四模式；根层 bind1-3 三件审计残留移入 `backup/root_scratch_20261109/`（未删除）。未跟踪清单由 30+ 收敛至 20（其余为他人 WIP 正常项）。**S2 根治（audit 路径锚定 dirname(out)）仍留 orchestrator owner**——止血只消噪音，不改行为。
- **S5 升级——PUBLIC 分支携带实证**：对远端跟踪引用直接清点（只读，不打印内容）：`ghssh/main` 含 `flag{…}` 形态字面量 **807 处/208 文件**、`ghssh/delivery/secautomind-v1.7.17` 含 115 处（多为 internal Go 测试与平台代码内的夹具形态）。真品牌 vs 自产合成的占比需用 `scripts/audit_flag_provenance.py` 的溯源分类对远端引用跑一遍（该工具现面向工作树，扩展 ref 扫描留 owner）——在此之前**"PUBLIC 是否已外发真题 flag"按"存在携带、占比待分类"如实挂账**。ls-remote 本次被重置（网络面），远端最新态以本地缓存 refs 为准。
