#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""行尾门禁 —— 保证「该 LF 的脚本是 LF、该 CRLF 的脚本是 CRLF」。

背景（2026-09-30 交付审计，实锤缺陷）：
    本仓此前没有 .gitattributes，脚本行尾完全由各机器 core.autocrlf 决定。
    scripts/make_delivery_package.py 是**字节级复制**（shutil.copy2，不走 git 过滤器），
    于是**工作副本怎么存，交付包里就是什么样**。对已产出的
    dist/SecAutoMind-v1.7.25-share.tar.gz 开箱复核，发现：

        run.sh                          CRLF(501)   ← Linux 上 bash 直接炸
        upgrade.sh                      CRLF(411)   ← 同上
        setup_venv.bat                  LF(74)      ← Windows 批处理应为 CRLF
        start.bat / stop.bat / *.ps1    CRLF        ← 正确

    CRLF 的 .sh 在 Linux 上执行的表现是 `$'\r': command not found`，
    对交付给评委的一键部署包是**致命**的（同一类问题已在 start.bat 端口写死那次暴露过）。

规则单一真值源是仓库根的 `.gitattributes`；本脚本内置同一份规则表，并在
    --check-attr-sync 下比对两者，防止「改了 .gitattributes 却没改脚本」的静默漂移。

用法：
    python scripts/check_line_endings.py                # 检查（默认：git 跟踪 + 未忽略的未跟踪文件）
    python scripts/check_line_endings.py --json         # 机器可读
    python scripts/check_line_endings.py --dir DIR      # 检查任意目录（递归；交付包 staging 用）
    python scripts/check_line_endings.py --fix          # 就地修正仓内文件（按规则重写行尾）
    python scripts/check_line_endings.py --check-attr-sync   # 仅校验 .gitattributes 与本表一致

退出码：
    0 = 全部合规
    1 = 存在不合规（列出文件与目标行尾）
    2 = 检查无法完成（fail-closed：不在 git 仓库且未给 --dir、目录不存在等）
"""
import argparse
import fnmatch
import json
import os
import subprocess
import sys

try:
    sys.stdout.reconfigure(encoding="utf-8")
except Exception:
    pass

HERE = os.path.dirname(os.path.abspath(__file__))
ROOT = os.path.dirname(HERE)
GITATTRIBUTES = os.path.join(ROOT, ".gitattributes")

# ── 规则表：glob → 目标行尾。必须与 .gitattributes 保持一致（--check-attr-sync 校验）
RULES = [
    ("*.sh", "lf"),
    ("*.bash", "lf"),
    ("*.bat", "crlf"),
    ("*.cmd", "crlf"),
    ("*.ps1", "crlf"),
    ("*.psm1", "crlf"),
]

# --dir 递归时跳过的目录（含第三方/产物，非本仓脚本）
SKIP_DIRS = {
    ".git", ".workbuddy", "__pycache__", "node_modules", ".venv", "venv",
    ".pytest_cache", ".idea", ".vscode", "dist", "build", ".cache",
}


def target_eol(name):
    """按 basename 匹配规则，返回 'lf' / 'crlf' / None（不受管）。"""
    base = name.replace("\\", "/").rsplit("/", 1)[-1]
    for pat, eol in RULES:
        if fnmatch.fnmatch(base, pat):
            return eol
    return None


def inspect(data, target):
    """返回 (status, detail)。status ∈ ok / bad / mixed / binary。"""
    if b"\x00" in data:
        return "binary", "含 NUL 字节，按二进制跳过"
    crlf = data.count(b"\r\n")
    lf = data.count(b"\n")
    lone_lf = lf - crlf
    lone_cr = data.count(b"\r") - crlf
    if crlf and lone_lf:
        return "mixed", "混合行尾：CRLF=%d、孤立LF=%d" % (crlf, lone_lf)
    if target == "lf":
        if crlf == 0 and lone_cr == 0:
            return "ok", ""
        return "bad", "CRLF=%d、孤立CR=%d" % (crlf, lone_cr)
    # crlf
    if lone_lf == 0 and lone_cr == 0:
        return "ok", ""
    return "bad", "孤立LF=%d、孤立CR=%d" % (lone_lf, lone_cr)


def convert(data, target):
    """归一化到目标行尾（二进制原样返回）。"""
    if b"\x00" in data:
        return data
    normalized = data.replace(b"\r\n", b"\n").replace(b"\r", b"\n")
    if target == "crlf":
        normalized = normalized.replace(b"\n", b"\r\n")
    return normalized


def repo_files():
    """git 跟踪 + 未被 .gitignore 忽略的未跟踪文件（后者同样会被打进交付包）。"""
    proc = subprocess.run(
        ["git", "ls-files", "-z", "-co", "--exclude-standard"],
        cwd=ROOT, capture_output=True,
    )
    if proc.returncode != 0:
        return None
    out = proc.stdout.decode("utf-8", "replace")
    return [p for p in out.split("\0") if p]


def walk_dir(base):
    for dirpath, dirnames, filenames in os.walk(base):
        dirnames[:] = [d for d in dirnames if d not in SKIP_DIRS]
        for fn in filenames:
            yield os.path.join(dirpath, fn)


def check_attr_sync():
    """校验 .gitattributes 覆盖且不违背内置规则表。返回 (ok, problems)。"""
    problems = []
    if not os.path.exists(GITATTRIBUTES):
        return False, [".gitattributes 不存在（行尾策略失去单一真值源）"]
    declared = {}
    with open(GITATTRIBUTES, "r", encoding="utf-8") as fh:
        for raw in fh:
            line = raw.strip()
            if not line or line.startswith("#"):
                continue
            parts = line.split()
            if len(parts) >= 2 and parts[0].startswith("*"):
                eol = next((p.split("=", 1)[1] for p in parts[1:]
                            if p.startswith("eol=")), None)
                if eol:
                    declared[parts[0]] = eol
    for pat, eol in RULES:
        if pat not in declared:
            problems.append(".gitattributes 未声明规则 %s -> eol=%s" % (pat, eol))
        elif declared[pat] != eol:
            problems.append(".gitattributes 中 %s 为 eol=%s，本脚本规则表为 eol=%s"
                            % (pat, declared[pat], eol))
    for pat, eol in declared.items():
        if pat not in dict(RULES):
            problems.append(".gitattributes 多出本脚本未覆盖的规则 %s -> eol=%s"
                            % (pat, eol))
    return (not problems), problems


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--dir", default=None, help="检查指定目录（递归），默认检查 git 工作树")
    ap.add_argument("--fix", action="store_true", help="就地修正（仅仓内模式可用）")
    ap.add_argument("--json", action="store_true", help="机器可读输出")
    ap.add_argument("--check-attr-sync", action="store_true",
                    help="仅校验 .gitattributes 与内置规则表一致")
    args = ap.parse_args()

    if args.check_attr_sync:
        ok, problems = check_attr_sync()
        if args.json:
            print(json.dumps({"ok": ok, "problems": problems}, ensure_ascii=False))
        else:
            print("行尾策略一致性检查（.gitattributes ↔ 规则表）")
            for p in problems:
                print("  [FAIL] %s" % p)
            if ok:
                print("  [OK] .gitattributes 与规则表一致（%d 条规则）" % len(RULES))
        return 0 if ok else 1

    if args.dir:
        # --dir 用于检查任意目录（如交付包 staging），不承担「仓库策略一致性」职责
        ok_attr, attr_problems = True, []
    else:
        ok_attr, attr_problems = check_attr_sync()

    if args.dir:
        base = os.path.abspath(args.dir)
        if not os.path.isdir(base):
            print("[FAIL-CLOSED] 目录不存在：%s" % base, file=sys.stderr)
            return 2
        files = list(walk_dir(base))
        display_root = base
    else:
        if args.fix:
            pass  # 修正只允许仓内模式，下面的 files 即为仓内文件
        files = repo_files()
        if files is None:
            print("[FAIL-CLOSED] 不是 git 工作树，且未指定 --dir", file=sys.stderr)
            return 2
        files = [os.path.join(ROOT, f.replace("/", os.sep)) for f in files]
        display_root = ROOT

    checked, bad, skipped, fixed = [], [], [], []
    for path in files:
        name = os.path.basename(path)
        tgt = target_eol(name)
        if tgt is None or not os.path.isfile(path):
            continue
        try:
            with open(path, "rb") as fh:
                data = fh.read()
        except OSError as e:
            bad.append((path, "读取失败：%s" % e))
            continue
        status, detail = inspect(data, tgt)
        if status == "binary":
            skipped.append(path)
            continue
        checked.append((path, tgt))
        if status == "ok":
            continue
        if args.fix and not args.dir:
            try:
                with open(path, "wb") as fh:
                    fh.write(convert(data, tgt))
            except OSError as e:
                bad.append((path, "写入失败：%s" % e))
                continue
            after, detail_after = inspect(open(path, "rb").read(), tgt)
            if after == "ok":
                fixed.append((path, tgt))
            else:
                bad.append((path, "修正后仍不合规：%s" % detail_after))
        else:
            bad.append((path, "%s（应为 %s）" % (detail, tgt.upper())))

    rel = lambda p: os.path.relpath(p, display_root).replace("\\", "/")

    if args.json:
        print(json.dumps({
            "root": display_root,
            "checked": len(checked),
            "ok": len(checked) - len(bad) - 0,
            "bad": [{"file": rel(p), "detail": d} for p, d in bad],
            "fixed": [{"file": rel(p), "to": t} for p, t in fixed],
            "skipped_binary": [rel(p) for p in skipped],
            "attr_sync_ok": ok_attr,
            "attr_problems": attr_problems,
        }, ensure_ascii=False, indent=2))
    else:
        print("行尾门禁 · 受管脚本 %d 个 · 根 %s" % (len(checked), display_root))
        for p, t in fixed:
            print("  [FIXED] %s -> %s" % (rel(p), t.upper()))
        for p, d in bad:
            print("  [FAIL] %s：%s" % (rel(p), d))
        if not ok_attr:
            for p in attr_problems:
                print("  [FAIL] %s" % p)
        if skipped:
            print("  · 跳过二进制 %d 个" % len(skipped))
        if bad or not ok_attr:
            print("  [BLOCK] 行尾不合规 %d 个（该 LF 的 .sh 在 Linux 上会报"
                  " $'\\r': command not found）" % (len(bad)))
        else:
            print("  [PASS] 全部合规：.sh=LF、.bat/.cmd/.ps1=CRLF，且策略表一致")
    return 1 if (bad or not ok_attr) else 0


if __name__ == "__main__":
    sys.exit(main())
