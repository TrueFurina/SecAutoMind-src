#!/usr/bin/env python3
"""SecAutoMind 外部 MCP：安全事件研判与误报剔除（防御侧）。

通过 **stdio + JSON-RPC 2.0** 暴露 10 个安全事件研判工具，供 SecAutoMind
（或任意支持 MCP 的客户端：Cursor / VS Code / Claude Code 等）调用。

设计边界（与 SecAutoMind 的关系）
--------------------------------
1. **独立进程，不改 B 的代码**：本服务以「外部 MCP 联邦」方式接入，
   不进入 SecAutoMind 主二进制，因而不影响其「单二进制部署」硬要求。
2. **零第三方依赖**：核心链路只用 Python 标准库。不需要 `mcp` 包、不需要 PyYAML
   （配置解析见 `_parse_flat_yaml`），`pip install` 失败也能跑。
3. **stdout 只走协议**：所有日志一律写 stderr。stdio 传输下 stdout 混入任何
   非 JSON-RPC 字节都会让客户端解析失败——这是 stdio MCP 最常见的翻车点。

用法
----
    python mcp_security_triage_agent.py                     # MCP stdio 模式
    python mcp_security_triage_agent.py --config /path.yaml  # 指定配置
    python mcp_security_triage_agent.py --selftest           # 本机自检（不走协议）

自检模式跑**全工具出口矩阵**：动态遍历 `tools/list`，逐个工具做双向断言（按声明
的最小必需参数集必须调得通；抽掉声明的必需参数必须失败且点名），并校验
`required` 与实现同源、observation 还原清单完备。新增工具自动纳入，无需改自检
代码。这样在接入前就能确认「每个工具都真能用」，而不是只证明某一个能跑，
也避免只在客户端里看到「启动失败」却查不到原因。
"""
from __future__ import annotations

import argparse
import os
import sys
from pathlib import Path
from typing import Any

SCRIPT_DIR = Path(__file__).resolve().parent
DEFAULT_CONFIG = SCRIPT_DIR / "security_triage_agent_config.yaml"

# 配置文件键 → 环境变量名。两侧同源，避免"写了不读"。
_ENV_MAP: dict[str, str] = {
    "use_real_llm": "SECURITY_AGENT_USE_REAL_LLM",
    "llm_provider": "SECURITY_AGENT_LLM_PROVIDER",
    "llm_base_url": "SECURITY_AGENT_LLM_BASE_URL",
    "llm_api_key": "SECURITY_AGENT_LLM_API_KEY",
    "llm_model": "SECURITY_AGENT_LLM_MODEL",
    "llm_timeout_seconds": "SECURITY_AGENT_LLM_TIMEOUT",
    "command_tool_enabled": "SECURITY_AGENT_ENABLE_COMMAND_TOOL",
}

# 需归一为 "1"/"0" 的布尔型键
_BOOL_KEYS = {"use_real_llm", "command_tool_enabled"}
_TRUE_WORDS = {"1", "true", "yes", "on"}


def _fix_stdio_encoding() -> None:
    """Windows 默认 cp936，中文日志写 stderr 会抛 UnicodeEncodeError 直接崩服务。"""
    for stream in (sys.stderr, sys.stdout):
        reconfigure = getattr(stream, "reconfigure", None)
        if callable(reconfigure):
            try:
                reconfigure(encoding="utf-8")
            except (ValueError, OSError):
                pass


def _parse_flat_yaml(text: str) -> dict[str, str]:
    """极简扁平 YAML 解析：仅支持顶层 `key: value`。

    刻意不引入 PyYAML——本项目核心运行零第三方依赖。**限制如实声明**：
    不支持嵌套、不支持列表、不处理引号内的 `#`。需要复杂结构时请改用
    环境变量（优先级高于配置文件）。
    """
    result: dict[str, str] = {}
    for raw in text.splitlines():
        line = raw.split("#", 1)[0].strip()
        if not line or ":" not in line:
            continue
        key, _, value = line.partition(":")
        key, value = key.strip(), value.strip()
        if not key:
            continue
        if len(value) >= 2 and value[0] == value[-1] and value[0] in "\"'":
            value = value[1:-1]
        result[key] = value
    return result


def _apply_config(config: dict[str, str]) -> list[str]:
    """把配置映射为环境变量。**已存在的环境变量优先，不被覆盖**。"""
    applied: list[str] = []
    for key, env_name in _ENV_MAP.items():
        if key not in config or env_name in os.environ:
            continue
        value = str(config[key]).strip()
        if key in _BOOL_KEYS:
            value = "1" if value.lower() in _TRUE_WORDS else "0"
        os.environ[env_name] = value
        applied.append(f"{key} -> {env_name}")
    return applied


def _load_config(path: Path) -> list[str]:
    if not path.is_file():
        print(f"[security-triage-agent] 未找到配置，使用默认值: {path}", file=sys.stderr)
        return []
    try:
        applied = _apply_config(_parse_flat_yaml(path.read_text(encoding="utf-8")))
    except OSError as exc:  # noqa: BLE001 - 配置读不了不应阻断启动
        print(f"[security-triage-agent] 配置读取失败，使用默认值: {exc}", file=sys.stderr)
        return []
    print(f"[security-triage-agent] 已加载配置 {path}（生效 {len(applied)} 项）", file=sys.stderr)
    return applied


def _build_server():
    """延迟 import：确保 SCRIPT_DIR 已进 sys.path，且日志已配好编码。"""
    if str(SCRIPT_DIR) not in sys.path:
        sys.path.insert(0, str(SCRIPT_DIR))
    from security_agent.app import build_app
    from security_agent.mcp import McpServer

    app = build_app()
    return McpServer(tool_registry=app.tool_registry), app


def _selftest() -> int:
    """本机自检：**逐个工具**确认在 MCP 通道上真实可调用（不走 stdio 协议）。

    为什么不是「真调一次 asset_lookup 就收工」：上游项目已三度踩中同一族缺陷
    ——能力实现了但出口没接线，或被 fail-open 伪装成成功（工具返回
    `isError=False` 却一步没做）。单点调用与 `tools/list` 都照不出来：
    前者覆盖不了其余工具，后者只证明清单存在。

    故改为跑**全工具出口矩阵**：动态遍历 `tools/list`，对每个工具做双向断言
    ——充分性（按工具自己声明的最小必需参数集必须调得通）+ 必要性（逐个抽掉
    声明的必需参数必须失败、且提示点名该参数）；另含 `required` 与实现同源、
    observation 还原清单完备等接线断言。检查逻辑与上游同源，不维护第二份清单，
    见 `security_agent/mcp/matrix.py`。

    新增工具会自动纳入本自检，无需改这里。
    """
    server, app = _build_server()
    registry = app.tool_registry

    from security_agent.mcp.server import OBSERVATION_ARGUMENTS

    # 命令工具默认关闭（SECURITY_AGENT_ENABLE_COMMAND_TOOL=0），但它的契约
    # （required 不含 event、唯一必需入参是 command）仍需被验证，故自检显式打开。
    if "command_executor" not in registry.tools:
        from security_agent.mcp import McpServer
        from security_agent.tools.implementations import (
            CommandExecutionTool,
            ToolRegistry,
        )

        registry = ToolRegistry(list(registry.tools.values()) + [CommandExecutionTool()])
        server = McpServer(tool_registry=registry)

    names = sorted(registry.tools)
    print(f"工具数: {len(names)}")
    for name in names:
        print(f"  - {name}")

    from security_agent.mcp.matrix import ToolMatrix

    result = ToolMatrix(server, OBSERVATION_ARGUMENTS).run()
    print(f"\n出口矩阵: 断言 {result.checked} 条，失败 {len(result.failures)} 条")
    for line in result.failures[:10]:
        print(f"  [FAIL] {line}")

    if result.failures:
        print("\n[FAIL] 自检未通过：工具出口矩阵存在失败项。")
        return 1
    print("\n[OK] 自检通过：全部工具在 MCP 通道上均真实可调用。")
    return 0


def main(argv: list[str] | None = None) -> int:
    _fix_stdio_encoding()
    parser = argparse.ArgumentParser(
        description="SecAutoMind 外部 MCP：安全事件研判与误报剔除（stdio）"
    )
    parser.add_argument(
        "--config",
        default=str(DEFAULT_CONFIG),
        help="配置文件路径（默认同目录 security_triage_agent_config.yaml）",
    )
    parser.add_argument(
        "--selftest",
        action="store_true",
        help="本机自检：列出工具并真调一次，不启动 MCP 协议",
    )
    args = parser.parse_args(argv)

    _load_config(Path(args.config))

    if args.selftest:
        return _selftest()

    server, app = _build_server()
    names = sorted(app.tool_registry.tools)
    print(
        f"[security-triage-agent] MCP server 就绪，等待 stdio 请求"
        f"（{len(names)} 个工具: {', '.join(names)}）",
        file=sys.stderr,
    )
    server.serve_stdio()
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
