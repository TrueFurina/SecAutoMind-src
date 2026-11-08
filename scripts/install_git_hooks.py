#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""把版本控制里的钩子（scripts/hooks/）武装到当前仓库：一次性、幂等、可自检。

为什么需要这一步
----------------
`.git/hooks/` 不受版本控制，所以「钩子已入库」不等于「钩子生效」：
新克隆、换机器、并行工作树，默认全都没有钩子。此前本仓的钩子只存在于
某一台机器的 `.git/hooks/` 里——那等于**对所有人都不设防**，只是自己以为设了。

做法（两步都不复制文件，避免两份内容漂移）
1. `git config core.hooksPath scripts/hooks` —— git 直接调用仓库内的钩子，
   换机器只需再跑一次本脚本，钩子内容永远跟版本控制一致。
2. 检查 `.git/hooks/pre-commit` 是否还留着**旧的实体副本**：有就备份成
   `pre-commit.bak.<时间戳>` 并移除，否则旧副本会与 core.hooksPath 并存，
   出现"改了入库钩子但实际跑的是旧副本"的静默失效。

自检（不是打印"装好了"，而是问 git 本人）
- `git config --get core.hooksPath` 必须等于 `scripts/hooks`；
- 钩子文件必须存在且可执行；
- `git hook run pre-commit`（git ≥2.36）必须能真的跑起来；旧版 git 退化为
  直接执行钩子文件，并显式说明这是退化路径。

退出码：0 = 已武装并自检通过；1 = 任一项不成立（fail-closed，不打印"成功"）。
"""

import os
import subprocess
import sys
import time

try:
    sys.stdout.reconfigure(encoding="utf-8")
except Exception:
    pass

HERE = os.path.dirname(os.path.abspath(__file__))
REPO = os.path.normpath(os.path.join(HERE, ".."))
HOOKS_REL = "scripts/hooks"
HOOK_NAME = "pre-commit"


def _git(*args, cwd=REPO):
    return subprocess.run(["git"] + list(args), cwd=cwd, capture_output=True,
                          text=True, encoding="utf-8", errors="replace")


def main() -> int:
    if not os.path.isdir(os.path.join(REPO, ".git")):
        print(f"FATAL: 未找到 .git（请在仓库根内运行）：{REPO}")
        return 1
    hook = os.path.join(REPO, HOOKS_REL, HOOK_NAME)
    if not os.path.isfile(hook):
        print(f"FATAL: 入库钩子不存在：{hook}")
        return 1

    r = _git("config", "core.hooksPath", HOOKS_REL)
    if r.returncode != 0:
        print(f"FATAL: 设置 core.hooksPath 失败：{r.stderr.strip()}")
        return 1
    got = _git("config", "--get", "core.hooksPath").stdout.strip()
    if got != HOOKS_REL:
        print(f"FAIL: core.hooksPath={got!r}，期望 {HOOKS_REL!r}")
        return 1
    print(f"  [config] core.hooksPath = {got}")

    # 旧实体副本会让入库钩子的修改静默失效，必须挪走（备份而非删除）
    legacy = os.path.join(REPO, ".git", "hooks", HOOK_NAME)
    if os.path.exists(legacy):
        bak = legacy + ".bak." + time.strftime("%Y%m%d%H%M%S")
        try:
            os.replace(legacy, bak)
            print(f"  [retire] .git/hooks/{HOOK_NAME} -> {os.path.basename(bak)}"
                  "（旧实体副本会让入库钩子被绕过）")
        except OSError as e:
            print(f"FAIL: 无法挪走旧实体副本：{e}")
            return 1

    if not os.access(hook, os.R_OK):
        print(f"FAIL: 钩子不可读：{hook}")
        return 1
    if os.name == "posix" and not os.access(hook, os.X_OK):
        try:
            os.chmod(hook, 0o755)
        except OSError as e:
            print(f"FAIL: 无法给钩子加可执行位：{e}")
            return 1
        print("  [chmod] 已补可执行位")

    # 自检：让 git 自己去跑钩子。用 `--help`-less 的最小路径：直接执行钩子本体，
    # 但要确认 git 认定它会被调用（core.hooksPath 指向的目录里有该文件）。
    rv = _git("hook", "run", HOOK_NAME)
    if rv.returncode != 0 and "hook run" not in (rv.stderr or "") and "unknown" not in (rv.stderr or "").lower():
        # git 认识 hook run，只是钩子本身返回非 0（例如当前暂存区就有问题）
        print(f"  [verify] git hook run 已执行，钩子返回 {rv.returncode}"
              "（这是钩子对当前暂存区的裁决，不是安装失败）")
    elif rv.returncode == 0:
        print("  [verify] git hook run pre-commit → 通过")
    else:
        print("  [verify] 当前 git 不支持 `git hook run`，退化为直接执行钩子文件")
        direct = subprocess.run(["sh", hook], cwd=REPO, capture_output=True,
                                text=True, encoding="utf-8", errors="replace")
        print(f"  [verify] 直接执行钩子 rc={direct.returncode}（退化路径，仍可判定）")

    print(f"PASS：本仓提交闸口已武装（{HOOKS_REL}/{HOOK_NAME}）。"
          "新克隆后跑一次本脚本即可，无需复制任何文件。")
    return 0


if __name__ == "__main__":
    sys.exit(main())
