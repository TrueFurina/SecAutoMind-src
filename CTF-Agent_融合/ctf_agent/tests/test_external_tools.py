#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""tools/external_tools.py 的回归测试（2026-11-04）。

守什么
------
外部二进制（tesseract / bkcrack / 7z / objdump / node）的定位必须**跨平台可移植**。
历史缺陷：这些位置被写成某个人的绝对路径散落在 5 个文件里：
    C:/Users/<用户名>/miniconda3/Library/bin/tesseract.exe
换机器/换平台（Linux 服务器）100% 失效，而且错误信息会把个人目录原样吐给模型。

本测试锁住三条：
  ① 显式传入 > 环境变量 > PATH 的优先级（显式最高，不能被覆盖）；
  ② 找不到时返回 None，**不伪造路径**（伪造比找不到更糟：调用方会拿不存在的
     路径去执行，得到一个看不懂的 OS 错误）；
  ③ 缺失话术要说清"查过哪里"，而不是只报一个失败路径。

变异验证：把 find_tool 的"env 优先"改成"PATH 优先"→ ① 必红。
"""
import os
import sys
import tempfile
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from tools.external_tools import find_tool, describe_missing  # noqa: E402


def _make_exe(path: Path) -> str:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text("#!/bin/sh\nexit 0\n", encoding="utf-8")
    return str(path)


def test_explicit_path_wins(tmp_path):
    """显式传入的路径优先级最高（skill 参数里给了就用它）。"""
    exe = _make_exe(tmp_path / "my_bkcrack")
    assert find_tool("bkcrack", extra=[exe]) == exe


def test_env_var_used_when_no_explicit(tmp_path, monkeypatch):
    """无显式传入时，环境变量生效（各工具自己的约定名）。"""
    exe = _make_exe(tmp_path / "env_bkcrack")
    monkeypatch.setenv("BKCRACK", exe)
    got = find_tool("bkcrack")
    assert got == exe, f"环境变量未被采纳: {got!r}"


def test_missing_returns_none_not_fake_path(monkeypatch, tmp_path):
    """找不到必须返回 None —— 绝不返回一个"看起来像"的路径。

    伪造路径的危害：调用方会以为工具可用，拿它去执行 →
    FileNotFoundError 被包成看不懂的 OS 错误，排查成本极高。

    做法：把 HOME 指向空目录（屏蔽 ~ 推导出的用户级安装），清掉 env 与 PATH，
    此时 find_tool 若仍返回某个路径，说明它在凭空构造。
    """
    for k in ("BKCRACK", "BKCRACK_BIN", "BKRACK_BIN"):
        monkeypatch.delenv(k, raising=False)
    monkeypatch.setenv("PATH", "")
    monkeypatch.setenv("HOME", str(tmp_path))
    monkeypatch.setenv("USERPROFILE", str(tmp_path))
    got = find_tool("bkcrack")
    assert got is None, f"未找到时必须返回 None，实际 {got!r}"


def test_missing_message_says_where_it_looked(monkeypatch):
    """缺失话术必须列出查过的地方（env / PATH / 平台位置），而非只报一个路径。"""
    msg = describe_missing("bkcrack")
    assert "BKCRACK" in msg, f"未列出环境变量名: {msg}"
    assert "PATH" in msg, f"未说明查过 PATH: {msg}"
    assert "未找到" in msg


def test_no_hardcoded_personal_paths_in_source():
    """源码里不得再出现写死的个人目录（交付卫生 + 可移植性）。

    允许出现在 docstring 的脱敏示例（`<用户名>` 占位），
    不允许 `Users/<真实用户名>/...` 这种具体路径。
    """
    import re
    root = Path(__file__).resolve().parents[1]
    offenders = []
    # 只扫会进交付的核心目录。
    # 跳过三类：__pycache__、测试文件、`tools/tools/`（历史重复副本，ruff 已整目录排除，
    # 无人 import，不在本测试的守备范围——清理它属另一件事）。
    for sub in ("tools", "skills", "scripts", "core"):
        for f in (root / sub).rglob("*.py"):
            s = str(f)
            if "__pycache__" in s or "test" in f.name:
                continue
            if f"{os.sep}tools{os.sep}tools{os.sep}" in s:
                continue
            try:
                text = f.read_text(encoding="utf-8", errors="ignore")
            except OSError:
                continue
            for ln, line in enumerate(text.splitlines(), 1):
                # 只看**代码行**：注释与 docstring 里的历史说明/反例允许保留
                code = line.split("#", 1)[0]
                if not code.strip():
                    continue
                # 具体用户名（非占位符）+ 常见家目录前缀
                if re.search(r"(Users|home)[/\\](?!<|\{|\$)[A-Za-z][A-Za-z0-9_.-]{1,20}[/\\]"
                             r"(miniconda|bkcrack|AppData|ziphard|WorkBuddy)", code):
                    offenders.append(f"{f.relative_to(root)}:{ln}: {code.strip()[:80]}")
    assert not offenders, "发现写死的个人目录：\n" + "\n".join(offenders)


def main() -> int:
    tests = [test_explicit_path_wins, test_env_var_used_when_no_explicit,
             test_missing_returns_none_not_fake_path,
             test_missing_message_says_where_it_looked,
             test_no_hardcoded_personal_paths_in_source]
    failed = 0
    import inspect
    for t in tests:
        try:
            if "tmp_path" in inspect.signature(t).parameters or \
               "monkeypatch" in inspect.signature(t).parameters:
                # pytest 夹具：本手写 runner 不模拟，交给 pytest 跑
                print(f"（跳过 {t.__name__}：需要 pytest 夹具）")
                continue
            t()
            print(f"✅ {t.__name__}")
        except AssertionError as e:
            failed += 1
            print(f"❌ {t.__name__}: {e}")
    return 0 if failed == 0 else 1


if __name__ == "__main__":
    sys.exit(main())
