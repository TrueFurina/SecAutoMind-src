#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""把 scripts/git-hooks/ 下的钩子安装进 .git/hooks（幂等，可重跑）。

背景：git 不跟踪 .git/hooks/，克隆/换机后本地密钥门禁会消失。
本脚本负责（重）安装，已存在的同名钩子先备份为 <name>.bak 再覆盖。

用法：
    python scripts/install_git_hooks.py            # 安装/刷新全部钩子
退出码：0 = 全部成功；1 = 任一失败（fail-closed）。
"""
import os
import shutil
import sys

try:
    sys.stdout.reconfigure(encoding="utf-8")
except Exception:
    pass

HERE = os.path.dirname(os.path.abspath(__file__))
SRC = os.path.join(HERE, "git-hooks")
GIT_DIR = os.path.normpath(os.path.join(HERE, "..", ".git"))
DST = os.path.join(GIT_DIR, "hooks")


def main():
    if not os.path.isdir(SRC):
        print(f"FATAL: 源目录不存在：{SRC}")
        return 1
    if not os.path.isdir(GIT_DIR):
        print(f"FATAL: 未找到 .git（请在仓库根内运行）：{GIT_DIR}")
        return 1
    os.makedirs(DST, exist_ok=True)

    failed = []
    for name in sorted(os.listdir(SRC)):
        src = os.path.join(SRC, name)
        if not os.path.isfile(src) or name.startswith("."):
            continue
        dst = os.path.join(DST, name)
        if os.path.exists(dst):
            bak = dst + ".bak"
            shutil.copy2(dst, bak)
            print(f"  [backup] {name} -> hooks/{os.path.basename(bak)}")
        shutil.copy2(src, dst)
        os.chmod(dst, 0o755)
        print(f"  [install] {name} -> .git/hooks/{name}")
        if not os.access(dst, os.X_OK):
            failed.append(name)

    if failed:
        print(f"FAIL：以下钩子安装后不可执行：{failed}")
        return 1
    print("PASS：本地钩子已就位（每次 git commit 自动跑 secret_guard）。")
    return 0


if __name__ == "__main__":
    sys.exit(main())
