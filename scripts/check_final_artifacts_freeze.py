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


def _generator_map():
    """→ {产物文件名: 生成脚本相对路径}（复用产物门禁的 AST 解析，单一规则源）。

    为什么冻结清单要记生成器（2026-10-18 实锤）：
      实测三份答辩 PPT 的**冻结产物与生成器内容不一致** —— 生成器早已改成「91 个 YAML 配方 /
      纯 Go sqlite / 29.1% 真求解器」，冻结产物却还写着「100+ YAML 配方 / cgo sqlite /
      33.6 MB 安装包（实物 20 MB）」。产物不在 git 里，生成器在 git 里 → 没人对账，
      于是产物带着 3 处失真表述一路躺到交付包。只锁产物 sha 是锁不住这种漂移的：
      sha 一致只说明"没人动过产物"，说明不了"产物还是生成器的输出"。
    """
    try:
        import sys as _sys
        here = os.path.dirname(os.path.abspath(__file__))
        if here not in _sys.path:
            _sys.path.insert(0, here)
        import check_artifact_numbers as can
        return can.generator_map(ROOT)
    except Exception as exc:
        # 不能静默降级成 {}：那会让「已有生成器但清单没记哈希」这条判据静默失效
        print("[WARN] 生成器映射不可用（%s: %s）——本轮只能靠清单里已记录的哈希核对，"
              "「缺 generator 字段」的缺口查不出来" % (type(exc).__name__, exc), file=sys.stderr)
        return {}


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

    art_entries = {
        name: {"path": os.path.relpath(p, ROOT).replace(os.sep, "/"),
               "sha256": sha256(p), "size": os.path.getsize(p)}
        for name, p in arts.items()
    }

    # 记下「产出该产物的生成脚本」的 sha256：日后生成器一改，--check 立刻报
    # 「生成器已变但产物没重新生成/上锁」。这是"产物↔生成器契约"的可机验型式；
    # 只锁产物 sha 查不出"产物是旧生成器的输出"（两者都不变也能 sha 一致）。
    gmap = _generator_map()
    for name, entry in art_entries.items():
        gen_rel = gmap.get(os.path.basename(name))
        if not gen_rel:
            continue
        gen_abs = os.path.join(ROOT, gen_rel)
        if os.path.isfile(gen_abs):
            entry["generator"] = {"path": gen_rel, "sha256": sha256(gen_abs)}

    # 🔴 退役项「复活」的收口（2026-10-18 实测缺陷修复）：
    # 旧实现只做「artifacts → retired」单向迁移，实物回来后 --update 会把它重新纳入 artifacts
    # 却**不摘掉 retired 条目** → --check 的「复活必报」判据从此永久红，无任何合法出路。
    # 正确语义：复活 = 显式 --update，此时把 retired 条目降级为 artifacts 里的历史字段
    # （previous_retirement），**历史不丢**，且 retired 段不再重复登记。
    revived = []
    for name in list(retired):
        if name in arts:
            prev = retired.pop(name) or {}
            art_entries[name]["revived_at"] = _now()
            art_entries[name]["previous_retirement"] = {
                "sha256": prev.get("sha256", ""),
                "size": prev.get("size", 0),
                "retired_at": prev.get("retired_at", ""),
                "reason": prev.get("reason", ""),
            }
            revived.append(name)

    return {
        "schema": 2,
        "note": "决赛交付物冻结清单；有意变更后跑 --update 重新上锁。此文件应入库，任何改动即视为解冻。"
                "retired 段登记已退出冻结的对象（含退役时的哈希/大小/时间/原因），"
                "删它等于抹掉保护面变化的历史，勿手删。"
                "退役项复活的正确姿势：把实物放回原位后跑 --update —— 该条目会从 retired 摘出、"
                "重新上锁，并把退役时的哈希/时间/原因保留在 artifacts 的 previous_retirement 字段里。"
                "artifacts.*.generator 记录产出该件的生成脚本及其上锁时的 sha256：生成器一改而产物"
                "没重跑，--check 即红（只锁产物 sha 查不出「产物是旧生成器的输出」）。",
        "artifacts": art_entries,
        "retired": retired,
    }, demoted, revived


def main(argv):
    update = "--update" in argv
    old = None
    if update and os.path.isfile(MANIFEST):
        with open(MANIFEST, "r", encoding="utf-8") as fh:
            old = json.load(fh)
    cur, demoted, revived = build_manifest(old)

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
        if revived:
            print("\n♻️ 以下 %d 项实物已回来，本次从 retired 摘出并重新上锁（历史保留在 "
                  "previous_retirement 字段）：" % len(revived))
            for k in sorted(revived):
                print("  ♻️ %s" % k)
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
    # ⚠️ 但「生成器↔产物契约」必须在**跳过之前**判 —— 生成器是 git 跟踪文件，CI 里有；
    #    产物没有。若一起跳过，CI 就永远发现不了「生成器改了、产物没重跑」这种漂移。
    gmap = _generator_map()
    for name in sorted(exp):
        base = os.path.basename(name)
        rec = (exp[name] or {}).get("generator") or {}
        if gmap.get(base) and not rec:
            problems.append("%s：已有生成器 %s 但清单未记录其哈希（无法判产物是否陈旧）"
                            "—— 请 --update 重新上锁" % (name, gmap[base]))
            continue
        if not rec:
            continue
        gen_abs = os.path.join(ROOT, rec.get("path", ""))
        if not os.path.isfile(gen_abs):
            problems.append("%s：清单记录的生成器 %s 不存在（被删/改名？）"
                            % (name, rec.get("path")))
            continue
        if sha256(gen_abs) != rec.get("sha256"):
            problems.append("%s：**生成器 %s 已改动但产物未重新上锁** —— 现有产物是旧生成器的"
                            "输出（实测教训：生成器改成「91 个 YAML」，产物还是「100+ YAML」）。"
                            "修法：重跑生成器 → 复跑产物门禁 → --update 重新上锁"
                            % (name, rec.get("path")))

    if not got:
        if problems:
            print("[BLOCK] 本检出无产物实物，但生成器↔产物契约有 %d 处问题：" % len(problems))
            for p in problems:
                print("  · " + p)
            return 1
        print("[SKIP] 本检出未发现任何受保护对象（清单已锁 %d 项，但 PPT/压缩包/视频 "
              "未随 git 分发或尚未产出）——跳过实物比对。" % len(exp))
        print("       生成器↔产物契约已核验（%d 份生成器哈希一致）。"
              "本地有这些产物时本门禁会严格校验；有意变更后请 --update 重新上锁。"
              % len(gmap))
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
        print("\n[BLOCK] 冻结面/生成器契约问题 %d 处：" % len(problems))
        for p in problems:
            print("  · " + p)
        print("  若为有意变更：重跑生成器 → 复跑 scripts/check_artifact_numbers.py → "
              "跑 python scripts/check_final_artifacts_freeze.py --update 重新上锁，并随提交入库。")
        return 1
    print("\n[PASS] 冻结对象与清单一致（压缩包 / 答辩 PPT / 演示视频均未被改动），"
          "且 %d 份生成器哈希与上锁时一致（产物仍是当前生成器的输出）。" % len(gmap))
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
