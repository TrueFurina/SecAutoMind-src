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

自检模式会真调一次工具并打印结果，便于在接入前确认「能不能用」，
避免只在客户端里看到「启动失败」却查不到原因。
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
    """真调一次工具，确认链路可用（不走 MCP 协议）。"""
    server, app = _build_server()
    names = sorted(app.tool_registry.tools)
    print(f"工具数: {len(names)}")
    for name in names:
        print(f"  - {name}")

    # 真调一次：按 id 取库内权威事件（不依赖任何上游参数）
    response = server.handle(
        {
            "jsonrpc": "2.0",
            "id": 1,
            "method": "tools/call",
            "params": {
                "name": "asset_lookup",
                "arguments": {"event": {"id": "EVENT-001"}},
            },
        }
    )
    result = (response or {}).get("result", {})
    preview = ""
    content = result.get("content") or []
    if content:
        preview = str(content[0].get("text", ""))[:200]
    print(f"\n自检调用 asset_lookup(EVENT-001): isError={result.get('isError')}")
    print(f"  返回预览: {preview}")

    if result.get("isError"):
        print("\n[FAIL] 自检未通过：工具调用返回错误。")
        return 1
    print("\n[OK] 自检通过。")
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
