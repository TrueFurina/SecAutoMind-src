# -*- coding: utf-8 -*-
"""决赛交付物冻结门禁 —— 给「压缩包 / 答辩 PPT / 演示视频」上锁。

机制与 `check_golden_freeze.py` 同源：把冻结对象的 sha256 记进
`docs/final-artifacts.freeze.json`；默认 `--check` 逐项比对，**任一变动即 BLOCK
（fail-closed）**，防止决赛前误改/被并发会话覆盖。有意变更后用 `--update` 重新上锁。

保护对象（按命名约定匹配；缺失即记 absent，不误报）：
  · 答辩 PPT     `SecAutoMind_PPT/*.pptx`
  · 交付压缩包   `dist/SecAutoMind-*-share.tar.gz`
  · 演示视频     `**/XH-*演示视频*.mp4`（成片名按 `演示视频脚本_SecAutoMind_202609.md` 的约定）

🔴 退役留痕（schema 2，2026-10-17 补）
   受保护对象都是 `.gitignore` 的本地二进制，**不在版本控制内**。这意味着一旦
   `--update` 时某实物不在磁盘上，直接重写 `artifacts` 就会把它**连同历史哈希一起
   静默抹掉**——保护面缩小了，却没有任何记录说明它曾经被锁过、为什么不再锁。
   2026-10-17 实测踩到：`ppt/演示模板版.pptx` 与 `package/*.tar.gz` 在本机不存在
   （跨盘检索 + git 历史双查无果），若无退役机制，一次 --update 就会让它们无声消失。
   故 schema 2 起：`--update` 把磁盘缺失项自动迁入 `retired` 段（保留原哈希/大小/
   路径 + 退役时间 + 原因），`--check` 对"退役项重新出现在磁盘"报红（复活必须显式）。

用法：
  python scripts/check_final_artifacts_freeze.py            # 校验（本地 / CI）
  python scripts/check_final_artifacts_freeze.py --update   # 有意变更后重新上锁
"""
import datetime
import hashlib
import json
import os
import sys

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
MANIFEST = os.path.join(ROOT, "docs", "final-artifacts.freeze.json")

# 自动退役时写入的默认原因：必须醒目到让操作者去补真实原因，
# 否则"退役"会沦为给删除行为洗白的一行字。
RETIRED_DEFAULT_REASON = ("磁盘上已不存在（被删/未生成/改名？）——由 --update 自动迁移留痕，"
                          "**需人工复核并改写为真实原因**")


def _now():
    return datetime.datetime.now().isoformat(timespec="seconds")


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


def build_manifest(old=None):
    """收集受保护对象并构造清单。

    old —— 上一版清单（仅 `--update` 传入）。磁盘上消失的项**迁入 retired** 而不是
    被静默删除：受保护对象全是 gitignore 的本地二进制，删了就从版本历史里也找不回，
    若无留痕，保护面的缩小将无人知晓。
    """
    arts = collect()
    retired = dict((old or {}).get("retired") or {})
    demoted = []
    for name, entry in ((old or {}).get("artifacts") or {}).items():
        if name not in arts and name not in retired:
            retired[name] = {
                "path": entry.get("path", ""),
                "sha256": entry.get("sha256", ""),
                "size": entry.get("size", 0),
                "retired_at": _now(),
                "reason": RETIRED_DEFAULT_REASON,
            }
            demoted.append(name)
    return {
        "schema": 2,
        "note": "决赛交付物冻结清单；有意变更后跑 --update 重新上锁。此文件应入库，任何改动即视为解冻。"
                "retired 段登记已退出冻结的对象（含退役时的哈希/大小/时间/原因），"
                "删它等于抹掉保护面变化的历史，勿手删。",
        "artifacts": {
            name: {"path": os.path.relpath(p, ROOT).replace(os.sep, "/"),
                   "sha256": sha256(p), "size": os.path.getsize(p)}
            for name, p in arts.items()
        },
        "retired": retired,
    }, demoted


def main(argv):
    update = "--update" in argv
    old = None
    if update and os.path.isfile(MANIFEST):
        with open(MANIFEST, "r", encoding="utf-8") as fh:
            old = json.load(fh)
    cur, demoted = build_manifest(old)

    if update:
        os.makedirs(os.path.dirname(MANIFEST), exist_ok=True)
        with open(MANIFEST, "w", encoding="utf-8") as fh:
            json.dump(cur, fh, ensure_ascii=False, indent=2)
            fh.write("\n")
        print("已重新上锁：%d 项 -> %s" % (len(cur["artifacts"]), os.path.relpath(MANIFEST, ROOT)))
        for k in sorted(cur["artifacts"]):
            print("  🔒 %s" % k)
        if demoted:
            print("\n⚠️ 以下 %d 项本次不在磁盘上，已迁入 retired 段留痕（**未静默删除**）："
                  % len(demoted))
            for k in sorted(demoted):
                print("  📦 %s" % k)
            print("  请把 retired 段里各项的 reason 改写为真实原因（被删/未生成/改名？）；"
                  "若日后实物回来，本门禁会对「退役项复活」报红，须显式 --update 纳回。")
        return 0

    if not os.path.isfile(MANIFEST):
        print("[BLOCK] 冻结清单缺失：%s（先跑 --update 上锁）" % os.path.relpath(MANIFEST, ROOT))
        return 1

    with open(MANIFEST, "r", encoding="utf-8") as fh:
        old = json.load(fh)

    exp = old.get("artifacts", {})
    got = cur.get("artifacts", {})
    retired = old.get("retired") or {}
    problems = []

    # 🔴 空洞绿防线（2026-10-14 门禁审计）：CI 检出不含受保护产物 → got 为空 → 走下面的
    # SKIP 分支。这本是有意设计（否则 CI 恒红），但它同时打开一个洞：**清单被清空时
    # CI 也走 SKIP 报绿** —— 门禁的"上锁"语义被架空，等于没有门禁。
    # 纪律：清单必须真的锁了东西；清单一行没有 = 未上锁 = fail-closed。
    if not exp:
        print("[BLOCK] 冻结清单 %s 未上锁任何交付物（artifacts 为空）。"
              % os.path.relpath(MANIFEST, ROOT))
        print("       若清单被误清空：从 git 历史恢复；若确未产出交付物："
              "先产出后跑 --update 上锁，不要靠空清单让本门禁静默放行。")
        return 1

    # 受保护对象（PPT / 压缩包 / 视频）均被 .gitignore 排除或尚未产出时，CI 检出里一个都不存在。
    # 此时不是"被改动"，应优雅跳过，否则本门禁在 CI 上恒红（噪音门禁比没门禁更糟）。
    # 注意：走到这里说明清单已锁了 %d 项，跳过的是"实物不在本检出"，不是"清单没锁"。
    if not got:
        print("[SKIP] 本检出未发现任何受保护对象（清单已锁 %d 项，但 PPT/压缩包/视频 "
              "未随 git 分发或尚未产出）——跳过实物比对。" % len(exp))
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

    # 🔴 退役项复活必须显式（schema 2 新增判据）：退役 ≠ 可以悄悄回来。
    # 若不做这条，"退役"会沦为给删除行为洗白的通道——把不想保护的项扔进 retired，
    # 下次它带着新内容回来时连"磁盘新增未上锁"都不会报（名字已在 retired 里注册过）。
    for name in sorted(retired):
        if name in got:
            problems.append("%s：**已退役项重新出现在磁盘上**——复活必须显式 --update 纳回冻结，"
                            "不得靠退役段绕过上锁" % name)
        reason = (retired[name] or {}).get("reason", "")
        if not reason or reason.startswith(RETIRED_DEFAULT_REASON[:12]):
            problems.append("%s：retired 段原因仍为自动占位文本，需人工改写为真实原因" % name)

    print("决赛交付物冻结门禁 · 受保护 %d 项（退役 %d 项）" % (len(exp), len(retired)))
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
