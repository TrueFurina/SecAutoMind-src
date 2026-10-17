# -*- coding: utf-8 -*-
"""交付二进制来源门禁 —— 发出去的 exe 必须由**当前 HEAD**构建。

为什么需要（2026-10-18 实测：交付包里三个 exe、无一是当前源码）
------------------------------------------------------------
从 Go buildinfo 里读出真实构建来源后，交付面同时存在三份互不相同的程序：

  · `installer/SecAutoMind-Setup-1.7.28-x64.exe` 内嵌 → `344e5bd`（09-30 04:47）
  · `installer/secautomind-ai.exe`               → `4eb753a`（09-07 08:49）
  · `提交包_20260905/01_程序材料/secautomind-ai.exe` → `74abc04`+dirty（09-04）

这与 #52 的 PPT 事故是同一类病：**产物在交付面上，生成它的东西在版本库里，
两者之间没有任何东西对账**。PPT 那轮只锁了 pptx 的 sha256，二进制这边连
"这份 exe 是哪次提交编的"都没人问过 —— 于是源码里修掉的 7 critical + 8 high
依赖漏洞、presolve 占位符短路（#51）在评委手里那份程序里全都不存在。

判据（全部可机验，不依赖 go 工具链）
------------------------------------
  1. 二进制里必须能解析出 `mod\tsecautomind-ai\t<version>`（解析不到 = 来路不明 → 红）；
  2. version 必须是 `vX.Y.Z-0.<时间戳>-<commit>` 伪版本，且 commit == 当前 HEAD
     （tag 构建不带 commit ⇒ 无法对齐 ⇒ 红，别用"打了 tag"当挡箭牌）；
  3. 不允许 `+dirty`（脏树编出来的二进制无法从任何提交复现）；
  4. 安装包（NSIS）要解开内嵌 payload 再判一遍 —— 裸 exe 新、安装包里的旧，
     是本次实测最阴的一种：包名写着 1.7.28，里面的程序是 09-30 的。
     解包工具（7z）不可用时**显式报 SKIP 并列出未核验项**，不假装通过。

用法：
  python scripts/check_binary_version.py                  # 本地/CI（CI 里通常无 exe → SKIP）
  python scripts/check_binary_version.py --require-binaries  # 打包链路：一个都查不到即红
"""
import argparse
import fnmatch
import os
import re
import shutil
import subprocess
import sys
import tempfile

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
MODULE = "secautomind-ai"

# 受管（必须与 HEAD 一致）与历史快照（登记但不管）两类目录。
# 历史快照按日期命名，语义就是"当时提交的那份"，强行要求它跟 HEAD 一致等于篡改历史。
MANAGED_DIRS = ["installer"]
HISTORICAL_PATTERNS = ["SecAutoMind_提交包_*", "*提交包_*"]

_MOD_RE = re.compile(rb"mod\t" + MODULE.encode() + rb"\t([^\t\x00-\x1f]+)")
_PSEUDO_RE = re.compile(r"^v\d+\.\d+\.\d+-\d+\.(\d{14})-([0-9a-f]{7,12})(\+dirty)?$")


def _load_parser():
    """复用 count_stats.read_buildinfo —— **单一实现**。

    为什么要复用而不是各写一套：验收报表（count_stats）与判红门禁（本脚本）一旦
    各解析各的，就会出现"报表说 09-30、门禁说没问题"这种互不认账的局面，
    而交付包里三份不同构建之所以能长期共存，正是因为**没有任何一处**在看这个字段。
    """
    here = os.path.dirname(os.path.abspath(__file__))
    if here not in sys.path:
        sys.path.insert(0, here)
    import count_stats  # noqa: WPS433（刻意延迟导入，便于测试替换）
    return count_stats.read_buildinfo


parse_buildinfo = _load_parser()


def find_exes(root, dirs, patterns):
    found = []
    for d in dirs:
        base = os.path.join(root, d)
        if not os.path.isdir(base):
            continue
        for name in sorted(os.listdir(base)):
            if name.lower().endswith(".exe"):
                found.append(os.path.join(base, name))
    for name in sorted(os.listdir(root)):
        if not any(fnmatch.fnmatch(name, p) for p in patterns):
            continue
        base = os.path.join(root, name)
        if not os.path.isdir(base):
            continue
        for dirpath, _dn, fns in os.walk(base):
            for fn in sorted(fns):
                if fn.lower().endswith(".exe"):
                    found.append(os.path.join(dirpath, fn))
    return found


def _seven_zip():
    for p in (shutil.which("7z"), r"D:/7-Zip/7z.exe",
              r"C:/Program Files/7-Zip/7z.exe"):
        if p and os.path.isfile(p):
            return p
    return None


def setup_payload(setup):
    """解出 NSIS 安装包里内嵌的主程序路径；解不出返回 (None, 原因)。"""
    seven = _seven_zip()
    if not seven:
        return None, "无 7z 解包工具"
    tmp = tempfile.mkdtemp(prefix="binver_")
    r = subprocess.run([seven, "x", setup, "-o" + tmp, "-y", "*.exe"],
                       capture_output=True, text=True)
    if r.returncode != 0:
        shutil.rmtree(tmp, ignore_errors=True)
        return None, "7z 解包失败"
    for name in sorted(os.listdir(tmp)):
        if name.lower().endswith(".exe") and name.lower() != "uninstall.exe":
            return os.path.join(tmp, name), ""
    shutil.rmtree(tmp, ignore_errors=True)
    return None, "包内无主程序"


def is_setup(name):
    return name.startswith("SecAutoMind-Setup-") and name.lower().endswith(".exe")


def check_one(path, head, label="", tmp_cleanup=None):
    """→ (problems, notes)。"""
    problems, notes = [], []
    info = parse_buildinfo(path)
    if info is None:
        problems.append("%s：解析不到 Go buildinfo —— 来路不明的可执行物，不能发出去" % label)
        return problems, notes
    if info["dirty"]:
        problems.append("%s：构建自带 `+dirty`（%s）—— 脏树产物无法从任何提交复现"
                        % (label, info["version"]))
    if not info["commit"]:
        problems.append("%s：版本 %s 不是伪版本（无 commit），无法与 HEAD 对齐 —— "
                        "tag 构建请在构建前记下提交，别让产物失去可追溯性"
                        % (label, info["version"]))
    elif not (head.startswith(info["commit"]) or info["commit"].startswith(head)):
        problems.append("%s：构建自 %s，当前 HEAD %s —— **产物落后于源码**，"
                        "源码里修掉的问题在这份程序里仍然存在"
                        % (label, info["commit"][:12], head[:12]))
    if not problems:
        notes.append("%s → %s（%s）" % (label, info["commit"][:12], info["built_at"]))
    return problems, notes


def main(argv=None):
    ap = argparse.ArgumentParser(description="交付二进制来源门禁")
    ap.add_argument("--root", default=ROOT, help="仓库根（测试用）")
    ap.add_argument("--head", default=None, help="覆盖 HEAD（测试用；默认取 git rev-parse HEAD）")
    ap.add_argument("--require-binaries", action="store_true",
                    help="一个受管二进制都找不到时判红（打包链路必开）")
    ap.add_argument("--strict-unchecked", action="store_true",
                    help="存在「未能核验」的受管件时判红（打包链路必开："
                         "安装包里的程序才是评委真正跑的那份）")
    args = ap.parse_args(argv)

    head = args.head
    if not head:
        r = subprocess.run(["git", "rev-parse", "HEAD"], cwd=args.root,
                           capture_output=True, text=True)
        if r.returncode != 0:
            print("[BLOCK] 取不到 HEAD（%s）" % r.stderr.strip()[:120])
            return 1
        head = r.stdout.strip()

    managed = find_exes(args.root, MANAGED_DIRS, [])
    historical = find_exes(args.root, [], HISTORICAL_PATTERNS)

    print("交付二进制来源门禁 · HEAD=%s" % head[:12])
    print("  受管 %d 个（目录 %s）/ 历史快照 %d 个（只登记不判）"
          % (len(managed), ",".join(MANAGED_DIRS), len(historical)))

    problems, notes, unchecked = [], [], []
    for path in managed:
        label = os.path.relpath(path, args.root).replace(os.sep, "/")
        if is_setup(os.path.basename(path)):
            payload, why = setup_payload(path)
            if payload is None:
                # 不静默放过：安装包里的程序才是评委真正跑的那份
                unchecked.append("%s：%s —— **安装包内嵌程序未核验**" % (label, why))
                continue
            try:
                p, n = check_one(payload, head, label + "（内嵌 payload）")
                problems += p
                notes += n
            finally:
                shutil.rmtree(os.path.dirname(payload), ignore_errors=True)
        else:
            p, n = check_one(path, head, label)
            problems += p
            notes += n

    for path in historical:
        label = os.path.relpath(path, args.root).replace(os.sep, "/")
        info = parse_buildinfo(path)
        tag = ("%s%s" % (info["commit"][:12], "+dirty" if info["dirty"] else "")
               if info and info["commit"] else "未解析")
        print("  [HIST] %s → %s（按日期命名的历史快照，不要求与 HEAD 一致）" % (label, tag))

    checked = len(managed) - len([u for u in unchecked])
    print("  实际核验 %d / %d 个受管二进制" % (checked, len(managed)))
    for n in notes:
        print("  [OK] " + n)
    for u in unchecked:
        print("  [WARN] " + u)

    if problems:
        print("\n[BLOCK] %d 处问题：" % len(problems))
        for p in problems:
            print("  · " + p)
        print("\n修法：python installer/build_installer.py（构建 + 自证一条链）")
        return 1

    if not managed:
        if args.require_binaries:
            print("\n[BLOCK] --require-binaries 已开，但 %s 下一个 exe 都没有 —— "
                  "交付面缺程序材料，不能报通过。" % "/".join(MANAGED_DIRS))
            return 1
        print("\n[SKIP] 本检出无受管 exe（%s 为空或未产出）——**本轮未核验任何二进制**。"
              % "/".join(MANAGED_DIRS))
        print("       打包链路请带 --require-binaries，让「缺程序」在打包那一刻就红。")
        return 0

    if checked == 0:
        print("\n[BLOCK] 找到 %d 个受管 exe，但一个都没能核验（解包工具缺失？）—— "
              "这种「看上去跑过了」的绿是最危险的。" % len(managed))
        return 1

    if unchecked and args.strict_unchecked:
        print("\n[BLOCK] --strict-unchecked 已开，但有 %d 项受管二进制未能核验：" % len(unchecked))
        for u in unchecked:
            print("  · " + u)
        print("        安装包里的程序才是评委真正跑的那份，查不到就别发出包。")
        return 1

    print("\n[PASS] %d 个受管二进制均由当前 HEAD 构建%s"
          % (checked, "；%d 项未核验（见上）" % len(unchecked) if unchecked else ""))
    return 0


if __name__ == "__main__":
    sys.exit(main())
