r"""附件路径跨平台归一（2026-11-12）。

病根：`data/questions_external` 池的 42 个题目 JSON 里有 39 个把附件路径写成
Windows 反斜杠（`data\questions_external\crypto\...\chal.sage`）。POSIX 上
`os.path.join(_CTF_ROOT, p)` 会把这整串当成**一个文件名** → 附件一律「找不到」，
presolve 读不到附件 → 所有依赖附件的确定性链路静默返回 None。表象与「求解器
不灵」完全相同，极易误归因为代码缺陷。

本该在加载层解析，故修点选在 `core.solver_sandbox._resolve_existing`：
非 Windows 平台把 `\` 归一成本平台分隔符（Windows 上是空操作）。

⚠️ 判别力说明：本机（Windows）反斜杠天然就是分隔符，**这些用例在 Windows 恒绿、
做不出变异**；只有在 Linux（服务器 / CI）上跑才有判别力。变异方式：把
`_resolve_existing` 里那段 `p.replace("\\", os.sep)` 删掉，Linux 上第 1 条必须红。
"""

import os

from core import solver_sandbox as SS

_BACKSLASH = (r"data\questions_external\crypto\ext_gctf2023_primes"
              r"\_attachments\chal.sage")
_FORWARD = _BACKSLASH.replace("\\", "/")


def test_backslash_attachment_path_resolves():
    """反斜杠写法的附件必须能解析到真实文件（Linux 上这是本次事故的复现点）。"""
    r = SS._resolve_existing(_BACKSLASH)
    assert r is not None, "反斜杠路径解析失败：附件会被静默丢失"
    assert os.path.exists(r), r


def test_forward_slash_path_still_resolves():
    """回归：POSIX 写法的附件解析不能被这次改动破坏。"""
    r = SS._resolve_existing(_FORWARD)
    assert r is not None and os.path.exists(r), r


def test_absolute_path_passthrough():
    """绝对路径且存在 → 原样返回。"""
    r = SS._resolve_existing(os.path.abspath(_FORWARD))
    assert r is not None and os.path.exists(r), r


def test_missing_path_returns_none():
    """不存在的路径必须返回 None，不许假装解析成功。"""
    assert SS._resolve_existing("data/questions_external/__definitely_missing__.bin") is None
