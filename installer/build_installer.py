# -*- coding: utf-8 -*-
"""一键重建 Windows 交付物：`secautomind-ai.exe` + NSIS 安装包，并**自证来源**。

为什么需要这个脚本（2026-10-18 实测的三版本并存事故）
----------------------------------------------------
交付包里同时躺着三个**互不相同**的主程序，且没有一个是当前 HEAD 的构建：

  · `installer/SecAutoMind-Setup-1.7.28-x64.exe` 内嵌 → 提交 `344e5bd`（09-30）
  · `installer/secautomind-ai.exe`               → 提交 `4eb753a`（09-07）
  · `提交包_20260905/01_程序材料/secautomind-ai.exe` → `74abc04` **+dirty**（09-04）

后果：源码里修掉的 7 critical + 8 high 依赖漏洞、presolve 占位符短路（#51）等，
**在评委拿到的程序里全都不存在**；而后两者的体积差近一倍（159MB vs 89MB），
评委也无从判断该跑哪个。根因不是"忘了打包"，而是**构建不在任何链路上**：
`release.yml` 只编三平台裸二进制，NSIS 安装包全靠人肉找 makensis 手敲，
.NSI 里版本号还是写死的 `1.7.25`（与实际产出的 `1.7.28` 均不一致）。

本脚本把"构建"变成可复跑、可机验的一步：
  1. 工作树脏 → 直接拒绝（杜绝 `+dirty` 版本流入交付面）；
  2. 版本号取自 `config.share.yaml` 的 `version`（与交付包同名规则同源，不手敲）；
  3. `go build` 用 release 同款参数（`-trimpath -ldflags "-H windowsgui -w -s"`）；
  4. `makensis /DAPP_VERSION=<ver>` 产出安装包；
  5. **回读自证**：从 exe 与安装包内嵌 payload 里解析 Go buildinfo，
     断言 commit == 当前 HEAD 且不带 `+dirty`，否则非零退出。

用法：
  python installer/build_installer.py                 # 全流程（需 makensis 与 7z）
  python installer/build_installer.py --exe-only      # 只编裸 exe
  python installer/build_installer.py --makensis D:/nsis_env/NSIS/makensis.exe
  python installer/build_installer.py --verify-only   # 只核验现有产物

makensis 获取（本机没有时）：`conda create -p D:/nsis_env -c conda-forge nsis -y`
"""
import argparse
import hashlib
import os
import re
import shutil
import subprocess
import sys
import tempfile

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
INSTALLER_DIR = os.path.join(ROOT, "installer")
EXE = os.path.join(INSTALLER_DIR, "secautomind-ai.exe")
NSI = os.path.join(INSTALLER_DIR, "SecAutoMind-Setup.nsi")
CONFIG = os.path.join(ROOT, "config.share.yaml")
MODULE = "secautomind-ai"

# Go 二进制里 buildinfo 的模块行：`mod\t<module>\t<version>`
_MOD_RE = re.compile(rb"mod\t" + MODULE.encode() + rb"\t([^\t\x00-\x1f]+)")
# 伪版本 `v1.2.3-0.YYYYMMDDhhmmss-<12位commit>`（`go build` 在非 tag 提交上的形态）
_PSEUDO_RE = re.compile(r"^v\d+\.\d+\.\d+-\d+\.(\d{14})-([0-9a-f]{7,12})(\+dirty)?$")


def read_version():
    with open(CONFIG, "r", encoding="utf-8", errors="ignore") as fh:
        for line in fh:
            m = re.match(r'\s*version:\s*"?([\w.\-]+)"?', line)
            if m:
                return m.group(1).lstrip("vV")
    raise SystemExit("[BLOCK] %s 里找不到 version 字段（版本号无真值源，拒绝用兜底值出包）"
                     % os.path.relpath(CONFIG, ROOT))


def git(*args):
    return subprocess.run(["git"] + list(args), cwd=ROOT, capture_output=True,
                          text=True).stdout.strip()


def head_commit():
    return git("rev-parse", "HEAD")


def is_dirty():
    """只判**影响二进制内容**的改动（Go 源码 / go.mod / go.sum）。

    不判整个工作树：改 README、改本脚本、改 .nsi 都不会进二进制，
    若一并算脏，正常迭代（先改脚本再构建）永远过不去，最后必然有人加
    `--force` 之类的旁路 —— 门禁一旦能被顺手绕过就等于没有。
    """
    out = git("status", "--porcelain", "--untracked-files=all", "--",
              "*.go", "go.mod", "go.sum")
    return bool(out)


def build_exe():
    if is_dirty():
        raise SystemExit(
            "[BLOCK] 工作树有未提交改动 —— 拒绝构建。\n"
            "        带脏树编出来的二进制会带 `+dirty` 后缀、无法从任何提交复现，\n"
            "        而这正是 09-05 那份 159MB 交付 exe 的问题（74abc04+dirty）。\n"
            "        先提交或 stash，再重跑。")
    env = dict(os.environ)
    env.update({
        "GOOS": "windows", "GOARCH": "amd64", "CGO_ENABLED": "0",
        # 本机 go 不在 PATH 时的常规前置（无该项时 Go 无法建缓存目录）
        "APPDATA": env.get("APPDATA") or os.path.join(
            os.path.expanduser("~"), "AppData", "Roaming"),
    })
    go = shutil.which("go") or "go"
    cmd = [go, "build", "-trimpath", "-ldflags", "-H windowsgui -w -s",
           "-o", EXE, "./cmd/server"]
    print("[BUILD] %s" % " ".join(cmd))
    r = subprocess.run(cmd, cwd=ROOT, env=env)
    if r.returncode != 0:
        raise SystemExit("[BLOCK] go build 失败（RC=%d）" % r.returncode)
    print("[BUILD] -> %s (%s B)" % (os.path.relpath(EXE, ROOT), os.path.getsize(EXE)))


def find_makensis(explicit=None):
    if explicit:
        return explicit
    env = os.environ.get("MAKENSIS")
    if env and os.path.isfile(env):
        return env
    for p in (shutil.which("makensis"),
              r"D:/nsis_env/NSIS/makensis.exe",
              r"C:/Program Files (x86)/NSIS/makensis.exe",
              r"C:/Program Files/NSIS/makensis.exe"):
        if p and os.path.isfile(p):
            return p
    return None


def build_setup(makensis, ver):
    out = os.path.join(INSTALLER_DIR, "SecAutoMind-Setup-%s-x64.exe" % ver)
    cmd = [makensis, "/DAPP_VERSION=%s" % ver, "/V2", NSI]
    print("[PACK] %s" % " ".join(cmd))
    r = subprocess.run(cmd, cwd=INSTALLER_DIR)
    if r.returncode != 0:
        raise SystemExit("[BLOCK] makensis 失败（RC=%d）" % r.returncode)
    if not os.path.isfile(out):
        raise SystemExit("[BLOCK] 预期产物不存在：%s（.nsi 的 OutFile 与版本号是否一致？）"
                         % os.path.relpath(out, ROOT))
    print("[PACK] -> %s (%s B)" % (os.path.relpath(out, ROOT), os.path.getsize(out)))
    return out


def parse_buildinfo(path):
    """从 Go 二进制里解析 (commit, dirty, version_str)；解析不到返回 None。"""
    with open(path, "rb") as fh:
        data = fh.read()
    m = _MOD_RE.search(data)
    if not m:
        return None
    ver = m.group(1).decode("ascii", "replace")
    pm = _PSEUDO_RE.match(ver)
    if pm:
        return {"version": ver, "commit": pm.group(2), "dirty": bool(pm.group(3))}
    # tag 构建（v1.7.28）不含 commit，无法与 HEAD 对齐 → commit 视为未知
    return {"version": ver, "commit": "", "dirty": ver.endswith("+dirty")}


def extract_setup_payload(setup, dest):
    """用 7z 解出 NSIS 里内嵌的 exe 路径；不可用则返回 None。"""
    seven = None
    for p in (shutil.which("7z"), r"D:/7-Zip/7z.exe",
              r"C:/Program Files/7-Zip/7z.exe"):
        if p and os.path.isfile(p):
            seven = p
            break
    if not seven:
        return None
    r = subprocess.run([seven, "x", setup, "-o" + dest, "-y", "*.exe"],
                       capture_output=True, text=True)
    if r.returncode != 0:
        return None
    for name in os.listdir(dest):
        if name.lower().endswith(".exe") and name.lower() != "uninstall.exe":
            return os.path.join(dest, name)
    return None


def verify(ver, setup=None):
    """回读自证：产物必须由当前 HEAD 构建、且不带 dirty。"""
    head = head_commit()
    problems = []

    info = parse_buildinfo(EXE)
    if info is None:
        problems.append("%s：解析不到 Go buildinfo（不是 Go 二进制/被裁剪过？）"
                        % os.path.relpath(EXE, ROOT))
    else:
        if info["dirty"]:
            problems.append("%s：构建自脏树（%s）" % (os.path.relpath(EXE, ROOT), info["version"]))
        if not info["commit"]:
            problems.append("%s：版本 %s 不含 commit 伪版本，无法与 HEAD 对齐"
                            % (os.path.relpath(EXE, ROOT), info["version"]))
        elif not head.startswith(info["commit"]):
            problems.append("%s：构建自 %s，当前 HEAD 是 %s —— **产物落后于源码**"
                            % (os.path.relpath(EXE, ROOT), info["commit"][:12], head[:12]))
        else:
            print("  [OK] exe 提交 %s == HEAD" % info["commit"][:12])

    if setup:
        tmp = tempfile.mkdtemp(prefix="nsis_payload_")
        try:
            payload = extract_setup_payload(setup, tmp)
            if payload is None:
                print("  [SKIP] 安装包内嵌 payload 无法解出（缺 7z？）——本轮只核验裸 exe")
            else:
                p = parse_buildinfo(payload)
                if p is None:
                    problems.append("%s：内嵌 payload 解析不到 buildinfo" % os.path.basename(setup))
                elif p["dirty"] or not p["commit"] or not head.startswith(p["commit"]):
                    problems.append("%s：内嵌 payload 构建自 %s（dirty=%s），与 HEAD %s 不一致"
                                    % (os.path.basename(setup), p["commit"][:12] or "?",
                                       p["dirty"], head[:12]))
                else:
                    print("  [OK] 安装包内嵌 payload 提交 %s == HEAD" % p["commit"][:12])
        finally:
            shutil.rmtree(tmp, ignore_errors=True)

    print("  版本（config.share.yaml）= %s   HEAD = %s" % (ver, head[:12]))
    print("  sha256(exe) = %s" % hashlib.sha256(open(EXE, "rb").read()).hexdigest()[:16])

    if problems:
        print("\n[BLOCK] 交付二进制来源校验失败 %d 处：" % len(problems))
        for x in problems:
            print("  · " + x)
        return 1
    print("\n[PASS] 交付二进制由当前 HEAD 构建，可复现（commit=%s，无 dirty）" % head[:12])
    return 0


def main(argv=None):
    ap = argparse.ArgumentParser(description="重建 Windows 交付物并自证来源")
    ap.add_argument("--exe-only", action="store_true", help="只编裸 exe，不做安装包")
    ap.add_argument("--verify-only", action="store_true", help="只核验现有产物")
    ap.add_argument("--makensis", default=None, help="makensis.exe 路径")
    args = ap.parse_args(argv)

    ver = read_version()
    if args.verify_only:
        setup = os.path.join(INSTALLER_DIR, "SecAutoMind-Setup-%s-x64.exe" % ver)
        return verify(ver, setup if os.path.isfile(setup) else None)

    if not os.path.isfile(EXE):
        print("[INFO] 尚未构建裸 exe，先构建")
    build_exe()

    setup = None
    if not args.exe_only:
        mk = find_makensis(args.makensis)
        if not mk:
            raise SystemExit(
                "[BLOCK] 找不到 makensis —— 安装包做不出来，拒绝只留下一个裸 exe 就报成功。\n"
                "        装法：conda create -p D:/nsis_env -c conda-forge nsis -y\n"
                "        或显式传 --makensis <path>；确实只要裸 exe 时用 --exe-only。")
        setup = build_setup(mk, ver)
    return verify(ver, setup)


if __name__ == "__main__":
    sys.exit(main())
