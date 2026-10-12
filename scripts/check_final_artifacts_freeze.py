# -*- coding: utf-8 -*-
"""决赛交付物冻结门禁 —— 给「压缩包 / 答辩 PPT / 演示视频」上锁。

机制与 `check_golden_freeze.py` 同源：把冻结对象的 sha256 记进
`docs/final-artifacts.freeze.json`；默认 `--check` 逐项比对，**任一变动即 BLOCK
（fail-closed）**，防止决赛前误改/被并发会话覆盖。有意变更后用 `--update` 重新上锁。

保护对象（按命名约定匹配；缺失即记 absent，不误报）：
  · 答辩 PPT     `SecAutoMind_PPT/*.pptx`
  · 交付压缩包   `dist/SecAutoMind-*-share.tar.gz`
  · 演示视频     `**/XH-*演示视频*.mp4`（成片名按 `演示视频脚本_SecAutoMind_202609.md` 的约定）

用法：
  python scripts/check_final_artifacts_freeze.py            # 校验（本地 / CI）
  python scripts/check_final_artifacts_freeze.py --update   # 有意变更后重新上锁
"""
import hashlib
import json
import os
import sys

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
MANIFEST = os.path.join(ROOT, "docs", "final-artifacts.freeze.json")


def sha256(path):
    h = hashlib.sha256()
    with open(path, "rb") as fh:
        for chunk in iter(lambda: fh.read(1 << 20), b""):
            h.update(chunk)
    return h.hexdigest()


def collect():
    """收集受保护对象 → {逻辑名: 绝对路径}。"""
    out = {}
    ppt_dir = os.path.join(ROOT, "SecAutoMind_PPT")
    if os.path.isdir(ppt_dir):
        for n in sorted(os.listdir(ppt_dir)):
            if n.endswith(".pptx"):
                out["ppt/" + n] = os.path.join(ppt_dir, n)

    dist = os.path.join(ROOT, "dist")
    if os.path.isdir(dist):
        for n in sorted(os.listdir(dist)):
            if n.endswith("-share.tar.gz"):
                out["package/" + n] = os.path.join(dist, n)

    for r, ds, fs in os.walk(ROOT):
        d = r.replace(os.sep, "/")
        if any(x in d for x in ("/.git", "/.workbuddy", "/node_modules", "/toolchain")):
            continue
        for n in fs:
            if n.lower().endswith(".mp4") and "演示视频" in n:
                out["video/" + n] = os.path.join(r, n)
    return out


def build_manifest():
    arts = collect()
    return {
        "schema": 1,
        "note": "决赛交付物冻结清单；有意变更后跑 --update 重新上锁。此文件应入库，任何改动即视为解冻。",
        "artifacts": {
            name: {"path": os.path.relpath(p, ROOT).replace(os.sep, "/"),
                   "sha256": sha256(p), "size": os.path.getsize(p)}
            for name, p in arts.items()
        },
    }


def main(argv):
    update = "--update" in argv
    cur = build_manifest()

    if update:
        os.makedirs(os.path.dirname(MANIFEST), exist_ok=True)
        with open(MANIFEST, "w", encoding="utf-8") as fh:
            json.dump(cur, fh, ensure_ascii=False, indent=2)
            fh.write("\n")
        print("已重新上锁：%d 项 -> %s" % (len(cur["artifacts"]), os.path.relpath(MANIFEST, ROOT)))
        for k in sorted(cur["artifacts"]):
            print("  🔒 %s" % k)
        return 0

    if not os.path.isfile(MANIFEST):
        print("[BLOCK] 冻结清单缺失：%s（先跑 --update 上锁）" % os.path.relpath(MANIFEST, ROOT))
        return 1

    with open(MANIFEST, "r", encoding="utf-8") as fh:
        old = json.load(fh)

    exp = old.get("artifacts", {})
    got = cur.get("artifacts", {})
    problems = []

    # 受保护对象（PPT / 压缩包 / 视频）均被 .gitignore 排除或尚未产出时，CI 检出里一个都不存在。
    # 此时不是"被改动"，应优雅跳过，否则本门禁在 CI 上恒红（噪音门禁比没门禁更糟）。
    if not got:
        print("[SKIP] 本检出未发现任何受保护对象（PPT/压缩包/视频 未随 git 分发或尚未产出）——跳过冻结校验。")
        print("       本地有这些产物时本门禁会严格校验；有意变更后请 --update 重新上锁。")
        return 0

    for name in sorted(set(exp) | set(got)):
        if name not in got:
            problems.append("%s：清单内存在但磁盘缺失（被删/改名？）" % name)
        elif name not in exp:
            problems.append("%s：磁盘新增但未上锁（请 --update）" % name)
        elif exp[name].get("sha256") != got[name].get("sha256"):
            problems.append("%s：内容已变（sha256 %s… -> %s…）"
                            % (name, exp[name].get("sha256", "")[:12], got[name]["sha256"][:12]))

    print("决赛交付物冻结门禁 · 受保护 %d 项" % len(exp))
    for name in sorted(exp):
        mark = "🔒" if name in got and exp[name].get("sha256") == got[name].get("sha256") else "⚠️"
        print("  %s %s" % (mark, name))
    if problems:
        print("\n[BLOCK] 冻结对象被改动 %d 处：" % len(problems))
        for p in problems:
            print("  · " + p)
        print("  若为有意变更：跑 python scripts/check_final_artifacts_freeze.py --update 重新上锁，并随提交入库。")
        return 1
    print("\n[PASS] 冻结对象与清单一致（压缩包 / 答辩 PPT / 演示视频均未被改动）。")
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
