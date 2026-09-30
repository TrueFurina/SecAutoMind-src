#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""前端资源副本一致性门禁（web/ ↔ internal/app/web/）。

背景（2026-09-30 审计发现）：
    前端资源在本仓库存在**两份物理副本**，且没有任何自动同步机制：
      · ``web/``              —— 开发工作副本（根目录）
      · ``internal/app/web/`` —— **真正被编译进 exe 的那份**
    依据 ``internal/app/app_webfs.go``：
        //go:embed web/templates/*.html
        //go:embed web/static/css/* web/static/js/* web/static/i18n/* ...
    go:embed 路径**相对于该 .go 文件所在包目录**，因此实际嵌入的是
    ``internal/app/web/``，而非根目录 ``web/``。

    这意味着：只改根 ``web/`` 而不同步到 ``internal/app/web/``，
    前端改动**在 exe 里完全不生效**，且无任何报错——典型的静默漂移。

    该坑已经真实发生过一次：commit ``8805a04``
    ("fix: sync wizard frontend into embed source + embed logo.png")
    就是一次手工补同步。

两份副本的**合法差异**（不是漂移，勿误判）：
    ``.gitignore`` 第 57-59 行全局忽略 ``vendor/``（Go 约定），
    仅显式反忽略 ``internal/app/web/static/vendor/``。
    因此根 ``web/static/vendor/`` 里的第三方库**不入库**：
      · 全新 clone：根 web/ 62 个文件，internal/app/web/ 71 个
      · 两者交集必须逐字节一致

判定不变量（fail-closed）：
    **凡是存在于根 ``web/`` 的文件，都必须在 ``internal/app/web/`` 中
    以相同相对路径、相同字节存在。**
    反向不要求（embed 副本可含 vendor 等额外文件）。

用法：
    python scripts/check_web_asset_parity.py              # 人类可读，漂移则 exit 1
    python scripts/check_web_asset_parity.py --json        # 机器可读（CI 用）
    python scripts/check_web_asset_parity.py --sync        # 把 web/ 同步进 embed 副本（会改文件）

可测性参数（供变异验证 / 单元测试用，常规勿需）：
    --root <dir>     仓库根，默认由本脚本位置推导
    --source <dir>   工作副本目录，默认 <root>/web
    --target <dir>   嵌入副本目录，默认 <root>/internal/app/web

铁律：
    1. 本脚本默认**只读**；只有显式 ``--sync`` 才写文件。
    2. 比对用**原始字节**（embed 按字节烘焙，不做行尾归一化）。
    3. 取不到任一副本目录 → **exit 2**（fail-closed，绝不当成"通过"）。
"""
import os
import sys
import json
import shutil
import hashlib
import argparse

# ---------------------------------------------------------------- 常量

DEFAULT_REL_SOURCE = os.path.join("web")
DEFAULT_REL_TARGET = os.path.join("internal", "app", "web")

# 根 web/ 中被 .gitignore 忽略、因而不入库的目录（合法差异，非漂移）
IGNORED_IN_SOURCE_PREFIXES = ("static/vendor/",)

EXIT_OK = 0
EXIT_DRIFT = 1
EXIT_ENV = 2


# ---------------------------------------------------------------- 工具


def file_hash(path):
    """返回文件内容的 sha256（原始字节，不做任何归一化）。"""
    h = hashlib.sha256()
    with open(path, "rb") as f:
        for chunk in iter(lambda: f.read(1 << 20), b""):
            h.update(chunk)
    return h.hexdigest()


def scan(root):
    """扫描目录，返回 {相对路径(posix风格): sha256}。"""
    out = {}
    for dirpath, _dirs, files in os.walk(root):
        for name in files:
            full = os.path.join(dirpath, name)
            if not os.path.isfile(full):
                continue
            rel = os.path.relpath(full, root).replace(os.sep, "/")
            out[rel] = file_hash(full)
    return out


def is_ignored_in_source(rel):
    """该相对路径是否属于"根副本里被 gitignore、属合法差异"的类别。"""
    return any(rel.startswith(p) for p in IGNORED_IN_SOURCE_PREFIXES)


# ---------------------------------------------------------------- 核心


def compare(source_dir, target_dir):
    """执行比对，返回结果字典。"""
    result = {
        "source_dir": source_dir,
        "target_dir": target_dir,
        "source_count": 0,
        "target_count": 0,
        "missing_in_target": [],   # 根 web/ 有、embed 副本缺 → 硬漂移
        "content_mismatch": [],    # 两边都有但字节不同     → 硬漂移
        "extra_in_target": [],     # embed 副本多出来的（应仅为 vendor）
        "ok": False,
        "hard_issues": [],
    }

    if not os.path.isdir(source_dir):
        result["hard_issues"].append("源目录不存在: %s" % source_dir)
        return result
    if not os.path.isdir(target_dir):
        result["hard_issues"].append("目标目录不存在: %s" % target_dir)
        return result

    src = scan(source_dir)
    tgt = scan(target_dir)
    result["source_count"] = len(src)
    result["target_count"] = len(tgt)

    for rel, digest in sorted(src.items()):
        if rel not in tgt:
            result["missing_in_target"].append(rel)
        elif tgt[rel] != digest:
            result["content_mismatch"].append(rel)

    for rel in sorted(set(tgt) - set(src)):
        result["extra_in_target"].append(rel)

    result["hard_issues"].extend(
        ["missing_in_target: %s" % r for r in result["missing_in_target"]]
    )
    result["hard_issues"].extend(
        ["content_mismatch: %s" % r for r in result["content_mismatch"]]
    )

    result["ok"] = not result["hard_issues"]
    return result


def do_sync(source_dir, target_dir, result):
    """把源副本中与目标不一致的文件复制到目标（仅这些文件）。"""
    copied = []
    for rel in result["missing_in_target"] + result["content_mismatch"]:
        src = os.path.join(source_dir, os.sep.join(rel.split("/")))
        dst = os.path.join(target_dir, os.sep.join(rel.split("/")))
        os.makedirs(os.path.dirname(dst), exist_ok=True)
        shutil.copy2(src, dst)
        copied.append(rel)
    return copied


# ---------------------------------------------------------------- 输出


def render_human(result):
    lines = []
    lines.append("前端资源副本一致性检查")
    lines.append("  源(工作副本) : %s  [%d 个文件]" % (result["source_dir"], result["source_count"]))
    lines.append("  目标(嵌入副本): %s  [%d 个文件]" % (result["target_dir"], result["target_count"]))
    lines.append("")

    if result["hard_issues"] and not result["missing_in_target"] and not result["content_mismatch"]:
        lines.append("环境错误：")
        for issue in result["hard_issues"]:
            lines.append("  ! %s" % issue)
        return "\n".join(lines)

    miss = result["missing_in_target"]
    mism = result["content_mismatch"]
    extra = result["extra_in_target"]

    ignored_extra = [r for r in extra if is_ignored_in_source(r)]
    other_extra = [r for r in extra if not is_ignored_in_source(r)]

    if miss:
        lines.append("[X] 以下 %d 个文件在嵌入副本中缺失（改了根 web/ 但没同步 → exe 里不生效）：" % len(miss))
        for r in miss[:40]:
            lines.append("      - %s" % r)
        if len(miss) > 40:
            lines.append("      ... 另有 %d 个" % (len(miss) - 40))
        lines.append("")

    if mism:
        lines.append("[X] 以下 %d 个文件两边内容不一致：" % len(mism))
        for r in mism[:40]:
            lines.append("      - %s" % r)
        if len(mism) > 40:
            lines.append("      ... 另有 %d 个" % (len(mism) - 40))
        lines.append("")

    if ignored_extra:
        lines.append("[i] 嵌入副本额外 %d 个文件（属预期：根副本被 .gitignore 忽略的 vendor/ 第三方库）：" % len(ignored_extra))
        lines.append("")
    if other_extra:
        lines.append("[!] 嵌入副本额外 %d 个文件（非预期，请确认是否需要回填到根 web/）：" % len(other_extra))
        for r in other_extra[:20]:
            lines.append("      - %s" % r)
        lines.append("")

    if result["ok"]:
        lines.append("[OK] 两份前端副本一致——嵌入副本完整覆盖工作副本，无漂移。")
    else:
        lines.append("[FAIL] 检测到前端资源漂移：缺失 %d 个，内容不一致 %d 个。"
                     % (len(miss), len(mism)))
        lines.append("")
        lines.append("修法（二选一）：")
        lines.append("  a) 自动同步：python scripts/check_web_asset_parity.py --sync")
        lines.append("  b) 手工同步后复跑本检查：")
        lines.append("     cp -r web/static web/templates internal/app/web/")

    return "\n".join(lines)


# ---------------------------------------------------------------- main


def main():
    parser = argparse.ArgumentParser(
        description="前端资源副本一致性门禁（web/ ↔ internal/app/web/）"
    )
    parser.add_argument("--root", default=None, help="仓库根目录（默认由脚本位置推导）")
    parser.add_argument("--source", default=None, help="工作副本目录（默认 <root>/web）")
    parser.add_argument("--target", default=None, help="嵌入副本目录（默认 <root>/internal/app/web）")
    parser.add_argument("--json", action="store_true", help="输出 JSON（CI 用）")
    parser.add_argument("--sync", action="store_true", help="把源副本同步到嵌入副本（会写文件）")
    args = parser.parse_args()

    if args.root:
        root = os.path.abspath(args.root)
    else:
        root = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))

    source_dir = os.path.abspath(args.source) if args.source else os.path.join(root, DEFAULT_REL_SOURCE)
    target_dir = os.path.abspath(args.target) if args.target else os.path.join(root, DEFAULT_REL_TARGET)

    result = compare(source_dir, target_dir)

    env_error = bool(result["hard_issues"]) and not result["missing_in_target"] and not result["content_mismatch"]

    if args.sync and not env_error:
        if result["ok"]:
            if not args.json:
                print("[OK] 无需同步：两份前端副本已一致。")
        else:
            copied = do_sync(source_dir, target_dir, result)
            if args.json:
                print(json.dumps({"synced": copied, "count": len(copied)}, ensure_ascii=False))
            else:
                print("[SYNC] 已同步 %d 个文件到嵌入副本：" % len(copied))
                for r in copied:
                    print("      + %s" % r)
                print()
                # 同步后立即复验（改完必验）
                recheck = compare(source_dir, target_dir)
                if recheck["ok"]:
                    print("[OK] 复验通过：两份前端副本已一致。")
                else:
                    print("[FAIL] 复验未通过，仍有漂移，请人工检查。")
                    print(render_human(recheck))
                    return EXIT_DRIFT
        return EXIT_OK

    if args.json:
        print(json.dumps(result, ensure_ascii=False, indent=2))
    else:
        print(render_human(result))

    if env_error:
        return EXIT_ENV
    return EXIT_OK if result["ok"] else EXIT_DRIFT


if __name__ == "__main__":
    sys.exit(main())
