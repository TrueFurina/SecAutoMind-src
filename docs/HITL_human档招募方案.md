# HITL human 档 · 外部导师 randomized 评测招募方案

> **定位**：`docs/hitl_failure_boundary.md` 的 machine 档（超时挂死 / 落库失败 / 覆盖冲突 / 越界裁决 /
> 参数篡改）已 5/5 真跑 PASS。**human 档（false-approve / false-block）仍 OPEN**——这本质上是
> 「真人在环」问题，Go 测试替代不了，需要 ≥8 名外部导师做 blinded randomized 评测。
> 本文件把「招募谁、怎么测、怎么算、怎么判」落成可执行方案。
>
> **边界**：human 档是 P2 长期项，同时是挑战杯之外的学术论文产出（规划 §4.2「副 RQ-B，发表优先」），
> **不阻塞决赛参赛资格**（P0 是仿真平台联调，见 `docs/产品优化规划.md` §三）。

---

## 1. 招募目标

| 项 | 要求 |
|---|---|
| 人数 | ≥8 名（跨校，越多统计力越强；8 是规划 §4.2 的最低线） |
| 画像 | 网络安全 / CTF / 系统安全方向的高年级本科生或研究生、导师、安全工程师 |
| 先决 | 熟悉「什么操作在授权测试中算高危」（命令执行 / 提权 / 数据删除 / 横向移动） |
| 排除 | 本项目队员、指导教师、任何参与 SecAutoMind 开发的人（避免利益相关 bias） |

**招募渠道**：跨校 CTF 战队群 / 网安社团 / 指导教师左雨庭的课程学生（已合作）/ 安恒或 DASCTF 参赛圈。

## 2. 评测协议（randomized + blinded）

### 2.1 场景池

构造 **N 条请求**（建议 N≥40，含干扰项），每条请求标注「真值类别」：

| 类别 | 定义 | 期望裁决 |
|---|---|---|
| 高危（应拦截） | 命令执行 / 提权 / 数据删除 / 越权访问 | **approve 属 false-approve（误批）** |
| 安全（应放行） | 只读侦察 / 信息收集 / 无害扫描 | **block 属 false-block（误拒）** |

场景池由**非参评成员**预先标注真值，标注后对导师**封闭**（blinded）。

### 2.2 随机化

- 场景顺序对每位导师独立随机打乱；
- 混入 ≥20% 干扰项（边界模糊、需要专业判断的场景），避免导师「看到就机械归类」；
- 每位导师独立裁决，互不沟通（防锚定/从众）。

### 2.3 打分

对每位导师统计两个率：

- **false-approve 率** = 误批的高危数 / 高危总数（放行本应拦截的操作，最危险）；
- **false-block 率** = 误拒的安全数 / 安全总数（阻断本应放行的操作，影响效率）。

### 2.4 数据收集

每轮裁决记录一行（CSV），字段：`participant_id / scenario_id / category(高危|安全) / decision(approve|block) / 裁决耗时秒 / 备注`。

数据收集后由脚本 `scripts/calc_hitl_human_rate.py` 计算每位导师两个率 + 全体均值。

## 3. 阈值与结论判定（阈值待 MPU-2 定）

| 指标 | 阈值 | 说明 |
|---|---|---|
| false-approve 率 | < X% | 待 MPU-2 定；误批高危是不可接受的安全失效，阈值应**从严** |
| false-block 率 | < Y% | 待 MPU-2 定；误拒安全影响效率，阈值可稍宽 |

判定：**false-approve 率必须全员达标**（一个导师误批高危都不可接受）；false-block 率取全体均值达标即可。**阈值未定前，只报告数据、不断言 PASS**——这延续本项目「无阈值不宣称」的铁律。

## 4. 伦理与合规

- **知情同意**：导师知情「参与的是 HITL 审批可靠性的学术评测」，可随时退出；
- **脱敏**：记录中不出现导师真实姓名（用 `participant_id` 匿名化），不记录裁决对象的具体目标资产；
- **零真实攻击**：场景池是**假想请求文本**，不对任何真实目标执行操作。

## 5. 复现与交付

```bash
# 1) 收集完 CSV 后，一键计算两个率 + 判定
python scripts/calc_hitl_human_rate.py --csv hits_human.csv

# 2) 更新失效边界报告（把 human 档从 OPEN 推进为实测数据）
python scripts/run_hitl_boundary.py          # machine 档保持真跑，human 档引用实测 CSV
```

交付物：`docs/hitl_failure_boundary.md`（human 档补实测数据）+ `hits_human.csv`（脱敏）+ 论文一节的「HITL 人机协同失效边界」实证。

---

## 附：与现有资产的衔接

- `scripts/run_hitl_boundary.py`：machine 档 5/5 真跑 + human 档如实标 OPEN（结构上禁止把 human 改写成 PASS，防造假）；
- `docs/hitl_failure_boundary.md`：三档失效模式矩阵的单一真值源；
- 本方案落地后，human 档的「OPEN」升级为「实测数据 + 阈值判定」，但阈值未定前仍标「待定」。
