"""外部二进制的跨平台定位（2026-11-04）。

为什么需要
----------
解题链依赖若干**系统级**外部程序（tesseract / bkcrack / 7z / objdump / node）。
历史上这些位置被写成**某个人的绝对路径**散落在 5 个文件里：

    <盘符>:/Users/<用户名>/miniconda3/Library/bin/tesseract.exe
    <盘符>:/Users/<用户名>/bkcrack_161/bkcrack.exe
    ...

（示例已脱敏：真实文件里写的是具体用户名。这也正是问题之一——
交付物不该带出开发机的个人目录。）

后果有两层：
  ① 换机器/换平台（Linux 服务器）100% 失效；
  ② 错误信息把个人路径原样吐给模型/日志，属**交付卫生**问题——
     实测把 `C:\\Users\\Lenovo\\...\\node.exe` 当"未找到原因"报给模型。

本模块把定位收敛成一个入口，优先级：
  ① 显式环境变量（各工具自己的约定名，如 TESSERACT / BKCRACK / REA_NODE）
  ② PATH（shutil.which）
  ③ 各平台常见安装位置（由 HOME / Program Files / 常见前缀推导，**不写死用户名**）
  ④ 找不到 → 返回 None（**不伪造路径**，调用方据此明确降级）

明确不做的事
------------
不在这里"猜"更多路径。猜错比找不到更糟：调用方会以为工具可用，
拿一个不存在的路径去执行，得到一个看不懂的 OS 错误。
"""
from __future__ import annotations

import os
import shutil
from typing import Optional

#: 每个工具的环境变量名前缀约定（与各厂商/SDK 保持一致的优先）
_ENV_KEYS = {
    "tesseract": ("TESSERACT", "TESSERACT_CMD"),
    "bkcrack": ("BKCRACK",),
    "7z": ("SEVENZIP", "SZ_PATH"),
    "objdump": ("OBJDUMP",),
    "node": ("REA_NODE", "NODE"),
}

#: 平台常见位置（用 ~ / Program Files 等标准锚点推导，不用个人用户名）
_COMMON = {
    "tesseract": {
        "nt": [
            r"C:\Program Files\Tesseract-OCR\tesseract.exe",
            r"C:\Program Files (x86)\Tesseract-OCR\tesseract.exe",
            r"C:\tools\tesseract\tesseract.exe",
            r"C:\tools\Tesseract-OCR\tesseract.exe",
        ],
        "posix": ["/usr/bin/tesseract", "/usr/local/bin/tesseract"],
    },
    "bkcrack": {
        "nt": [],
        "posix": ["/usr/local/bin/bkcrack", "/usr/bin/bkcrack"],
    },
    "7z": {
        "nt": [r"C:\Program Files\7-Zip\7z.exe"],
        "posix": ["/usr/bin/7z", "/usr/local/bin/7z"],
    },
    "objdump": {
        "nt": [],
        "posix": ["/usr/bin/objdump"],
    },
    "node": {
        "nt": [r"C:\Program Files\nodejs\node.exe"],
        "posix": ["/usr/bin/node", "/usr/local/bin/node"],
    },
}

#: Windows 上常见的「用户级」安装（含 conda / AppData），仍用 ~ 推导
_USER_LEVEL_NT = {
    "tesseract": [
        r"miniconda3\Library\bin\tesseract.exe",
        r"miniconda3_new\Library\bin\tesseract.exe",
        r"AppData\Local\Programs\tesseract\tesseract.exe",
        r"AppData\Local\Tesseract-OCR\tesseract.exe",
    ],
    "bkcrack": [
        r"bkcrack_161\bkcrack.exe",
    ],
}


def _platform_key() -> str:
    return "nt" if os.name == "nt" else "posix"


def find_tool(name: str, extra: Optional[list] = None) -> Optional[str]:
    """按统一优先级定位外部程序；找不到返回 None。

    Args:
        name: 工具名（tesseract / bkcrack / 7z / objdump / node）
        extra: 调用方附带的额外候选（如 skill 参数里显式给的路径），
               排在最前——显式传入优先于一切约定
    """
    key = name.lower()

    # ① 显式传入
    for p in (extra or []):
        if p and os.path.isfile(str(p)):
            return str(p)

    # ② 环境变量
    for env in _ENV_KEYS.get(key, ()):
        v = os.environ.get(env, "").strip()
        if v and os.path.isfile(v):
            return v

    # ③ PATH
    exe = shutil.which(key)
    if exe:
        return exe

    # ④ 平台常见位置
    plat = _platform_key()
    for p in _COMMON.get(key, {}).get(plat, []):
        if os.path.isfile(p):
            return p

    # ⑤ 用户级安装（~ 推导）
    home = os.path.expanduser("~")
    if plat == "nt":
        for rel in _USER_LEVEL_NT.get(key, []):
            p = os.path.join(home, rel)
            if os.path.isfile(p):
                return p
    else:
        # 🔴 POSIX 的 `~/.local/bin`（XDG 约定）：无 root 时的标准落点——官方安装脚本、
        # pip --user、以及 `conda create -p ~/xxx` 后的手工软链都放这里。
        # 2026-11-08 服务器实证：非交互 ssh 的 PATH 里**没有** `~/.local/bin`
        # （实测只有 /usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin），
        # 于是 `shutil.which` 恒失败、tesseract 装了也报「未找到」。
        for rel in (os.path.join(".local", "bin", key),
                    os.path.join("bin", key)):
            p = os.path.join(home, rel)
            if os.path.isfile(p):
                return p

    return None


def find_tesseract(extra: Optional[list] = None) -> Optional[str]:
    return find_tool("tesseract", extra)


def find_bkcrack(extra: Optional[list] = None) -> Optional[str]:
    return find_tool("bkcrack", extra)


def describe_missing(name: str) -> str:
    """缺失时的统一话术：说清「查过哪里」而不是只报一个失败路径。

    实测教训：错误信息若只写 `xxx 不存在: C:\\Users\\Lenovo\\...`，
    读者（和模型）会以为"这台机器没装"，而不是"这个路径不该写死"。
    """
    tried = []
    for env in _ENV_KEYS.get(name.lower(), ()):
        tried.append(f"env:{env}")
    tried.append("PATH")
    plat = _platform_key()
    tried.extend(_COMMON.get(name.lower(), {}).get(plat, [])[:2])
    return (f"{name} 未找到（已查 {' / '.join(tried)}）。"
            f"请安装后加入 PATH，或用环境变量指定（见 tools/external_tools.py）")
