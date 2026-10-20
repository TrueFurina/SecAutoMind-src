class Tool:
    """工具基类。

    `requires` 是该工具**调用必需的入参键**，必须与 `run()` 实际读取的键
    逐项一致。它是单一事实源：

    - MCP 层据此生成 `tools/list` 的 `inputSchema.required`（客户端按声明传参）；
    - MCP 层据此在调用失败时给出**点名缺哪个参数**的可操作提示。

    2026-10-14 新增。此前 `required` 对所有工具硬编码为 `["event"]`，
    而实测 11 个工具中 6 个只传 event 必然失败（`analysis` / `*_observation`
    缺失）——即**声明与实现不符**，任何遵循声明的客户端都调不动这些工具；
    同时失败提示把缺 `command` 也一并归因为"缺上游阶段参数"，把调用方引向
    错误方向。声明与实现必须同源，故收敛到这个字段。

    `authority` / `limitations`（2026-10-19 新增）
    ------------------------------------------------
    工具结论的**权威等级**必须由工具自己声明，不能由出口层猜：出口层不知道
    某条 `details` 是查表得来的还是模型编的。这两个字段是 `_contract` 的
    唯一事实源（见 `security_agent/mcp/contract.py`），出口层只负责搬运。

    等级取值与 REA 对齐：
      - `observed`：直接读落盘事实（知识库 / 命令输出）；
      - `derived` ：确定性规则从观测推导，可复现；
      - `inferred`：模型或启发式推断，存在不确定性。

    `limitations` 写**该等级固有**的局限（不随单次调用变），例如"仅比对
    知识库内已有资产，未覆盖未纳管主机"。单次调用的临时限制走
    `ToolObservation` 的 `limitations` 字段，两者在出口合并。
    """

    name = ""
    #: 调用本工具必需的入参键（含 `event`，如需要）。
    requires: tuple[str, ...] = ()
    #: 结论权威等级，默认保守取 derived；查表类工具应显式声明 observed。
    authority: str = "derived"
    #: 该工具固有的证据局限（与单次调用无关）。
    limitations: tuple[str, ...] = ()
    #: 工具契约版本，随 `_contract.evidence.toolVersion` 下发。
    version: str = "0.1.0"

    def run(self, **kwargs):
        raise NotImplementedError
