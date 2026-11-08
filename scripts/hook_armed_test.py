#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""断言「新克隆装完钩子一定生效」——用真提交验，不只看配置文件。

为什么需要它
------------
钩子入库 ≠ 钩子生效。`.git/hooks/` 不受版本控制，`core.hooksPath` 也只是仓库级配置：
新克隆、换机器、CI 机器上默认**全都没有拦截**。此前本仓的钩子只存在于某一台机器的
`.git/hooks/` 里，其余所有克隆（包括公开仓的任何读者）都没有防线——这就是"以为设了"。

三条断言（都在**临时克隆**里做，绝不碰当前仓库）
1. `python scripts/install_git_hooks.py` 之后 `core.hooksPath == scripts/hooks`；
2. **变异验证**：把钩子改成 `exit 1` 后，一次真 `git commit` 必须失败——
   证明 git 真的调用了它（配置文件写对了不等于会被调用）；
3. 还原钩子后同一次 `git commit` 必须成功——证明它平时不会误拦正常提交。
   顺带断言钩子本体包含三道检查（答案明文 / 密钥 / workflow YAML），
   防止"合并时悄悄丢了一条"。

退出码：0 = 三条全过；1 = 任一不成立（fail-closed，不打印"通过"）。

用法：
    python scripts/hook_armed_test.py            # 本地/CI 通用
"""

import os
import shutil
import subprocess
import sys
import tempfile

try:
    sys.stdout.reconfigure(encoding="utf-8")
except Exception:
    pass

HERE = os.path.dirname(os.path.abspath(__file__))
REPO = os.path.normpath(os.path.join(HERE, ".."))
FAILS = []


def check(name, ok, detail=""):
    print(f"  [{'PASS' if ok else 'FAIL'}] {name}" + ("" if ok else f"  {detail}"))
    if not ok:
        FAILS.append(name)


def git(*args, cwd):
    return subprocess.run(["git"] + list(args), cwd=cwd, capture_output=True,
                          text=True, encoding="utf-8", errors="replace")


def py():
    return sys.executable or "python"


def main() -> int:
    if not os.path.isfile(os.path.join(REPO, "scripts", "hooks", "pre-commit")):
        print(f"FATAL: 入库钩子不存在：{REPO}/scripts/hooks/pre-commit")
        return 1
    # 注意：下面一律用**临时克隆里**的那份文件，而不是当前工作树里的。
    # 判据必须对着"新克隆实际会拿到什么"（= 已提交内容）说话；
    # 拿工作树副本去验，会把未提交的改动当成已生效（本测试第一版就踩了这个坑：
    # 克隆到的是旧安装器 + 旧钩子，于是四条断言全红，而工作树里明明是新的）。
    tmp = tempfile.mkdtemp(prefix="hookarmed_")
    clone = os.path.join(tmp, "clone")
    try:
        # 本地克隆不加 --depth（git 会忽略并警告），加 core.longpaths：
        # 本仓有超长路径（外部题附件），Windows 默认 260 字符上限会让 checkout 直接失败。
        r = git("-c", "core.longpaths=true", "clone", "--quiet", REPO, clone, cwd=tmp)
        if r.returncode != 0:
            print(f"FATAL: 临时克隆失败：{r.stderr.strip()[:400]}")
            return 1
        hook_src = os.path.join(clone, "scripts", "hooks", "pre-commit")
        if not os.path.isfile(hook_src):
            print("FATAL: 克隆里没有 scripts/hooks/pre-commit —— 钩子没入库")
            return 1
        body = open(hook_src, encoding="utf-8", errors="replace").read()
        for needle in ("check_redaction_consistency.py", "secret_guard.py",
                       "check_workflows_yaml.py"):
            check(f"钩子含 {needle}", needle in body, "合并时漏了一道检查")
        git("config", "user.email", "hook-armed@example.invalid", cwd=clone)
        git("config", "user.name", "hook-armed", cwd=clone)

        r = subprocess.run([py(), "scripts/install_git_hooks.py"], cwd=clone,
                           capture_output=True, text=True, encoding="utf-8",
                           errors="replace")
        check("安装脚本退出码 0", r.returncode == 0, (r.stdout or r.stderr)[-300:])
        hp = git("config", "--get", "core.hooksPath", cwd=clone).stdout.strip()
        check("core.hooksPath 指向 scripts/hooks", hp == "scripts/hooks", f"got={hp!r}")
        legacy = os.path.join(clone, ".git", "hooks", "pre-commit")
        check("旧的实体副本已挪走（否则入库钩子会被绕过）",
              not os.path.exists(legacy), legacy)

        # 探针文件放仓库内（.gitignore 挡不到的位置），提交后还原
        probe = os.path.join(clone, "scripts", "guard_probe_tmp.txt")
        with open(probe, "w", encoding="utf-8") as fh:
            fh.write("hook-armed probe\n")
        git("add", "--", "scripts/guard_probe_tmp.txt", cwd=clone)

        # 变异 1：钩子无条件失败 → git commit 必须被拦
        hook_in_clone = os.path.join(clone, "scripts", "hooks", "pre-commit")
        with open(hook_in_clone, "w", encoding="utf-8", newline="\n") as fh:
            fh.write("#!/bin/sh\nexit 1\n")
        r = git("commit", "-m", "hook-armed mutation probe", cwd=clone)
        check("变异钩子（exit 1）确实让 commit 失败", r.returncode != 0,
              (r.stdout + r.stderr)[-300:])

        # 还原 → 同一次 commit 必须成功
        # 用前面读到的原文写回，不 shutil.copyfile(hook_src, ...)：src 与 dst 现在是同一个
        # 文件（都指向克隆里那份），copyfile 会抛 SameFileError（实测过一次）。
        with open(hook_in_clone, "w", encoding="utf-8", newline="\n") as fh:
            fh.write(body)
        r = git("commit", "-m", "hook-armed restore probe", cwd=clone)
        check("还原钩子后正常提交成功（不误拦）", r.returncode == 0,
              (r.stdout + r.stderr)[-300:])
    finally:
        shutil.rmtree(tmp, ignore_errors=True)

    print()
    if FAILS:
        print(f"HOOK-ARMED: FAIL ({len(FAILS)}) -> {FAILS}")
        return 1
    print("HOOK-ARMED: PASS（新克隆装完即生效：变异拦得住，正常提交不误拦）")
    return 0


if __name__ == "__main__":
    sys.exit(main())
