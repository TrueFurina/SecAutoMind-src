#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""基准「能力分母」门禁：把自报 honesty 与磁盘实物机验对齐，输出可引用的分母。

## 为什么需要它（2026-10-25 实锤）

`cross_bench.json` 的 `honesty` 段自报「12 题附件仍存在 / 76 题缺失」，但**这个数字
从来没有被任何脚本对过磁盘**——它是 `scripts/build_cross_bench.py` 建库时的快照
（`attachment_available = bool(existing)`，判据是**源库**里至少有一个附件存在）。
后果：所有「命中 X / 88」或「命中 6/12」的说法，分母都没有机验来源。

逐题对账后发现声明附件的 12 题其实分四档，混在一起报就会得出错误结论：

  | 档位 | 含义 | 本地 | CI 检出 |
  |---|---|---|---|
  | FULL | 全部文件在盘、无 git 排除 | ✅ | ✅ |
  | LOCAL_ONLY | 有文件在盘，但含 git 排除项（仅留本机） | ✅ | ❌ |
  | DATA_ABSENT_EXCLUDED | 一个文件都不在盘，**且缺失全由 git 排除解释** | ❌ | ❌ |
  | DATA_ABSENT_LOST | 一个文件都不在盘，**且有文件既未排除又不存在** | ❌ | ❌ |

所以：
  - 拿 `honesty.attachment_available`（12）做分母 → 把 3 道无数据的题算进能力缺口（**虚高缺口**）
  - 拿本地分母报 CI 命中 → 把 CI 不可能出现的文件算成能力（**虚高能力**）
  - 把 `DATA_ABSENT_LOST` 当正常 → **静默丢文件永久隐身**（最危险，D9 专治）

## 判据（全部 fail-closed）

  D1 清单可读且题数 ≥ MIN_PROBLEMS（截断/清空不得算通过）
  D2 附件根目录存在（否则"磁盘上没有"无法与"根本没目录"区分）
  D3 四档之和 == 声明附件题数（漏题即红）
  D4 `honesty.attachment_available` == 逐题 `attachment_available=true` 的题数
  D5 `honesty.attachment_missing` == 总题数 - D4 的题数
  D6 声明 `attachment_available` 却无 `attachment_files` 条目 → 契约违规
  D7 FULL + LOCAL_ONLY > 0（全无数据时任何"能力"结论都无分母意义）
  D8 FULL 档明细自洽（每个文件都在盘且未被排除）
  D9 🔴 无静默丢失：`DATA_ABSENT_LOST` 必须为空（缺失只能由 git 排除解释）

## 输出

`--json` 给机器读；默认打印人读表 + 一句可引用的分母（必须整句复制，不许只抄数字）。

用法：
  python scripts/bench_capability_denominator.py [--repo-root .] [--json]
  python scripts/bench_capability_denominator.py --self-test   # 变异自测
退出码：0 = 全过；1 = 有违规或自测失败。
"""
from __future__ import annotations

import argparse
import json
import os
import sys

CB_REL = os.path.join("data", "questions_real_bench", "cross_bench.json")
ATT_REL = os.path.join("data", "questions_real_bench", "attachments")

# 题数地板：与 check_cross_bench_manifest.py::MIN_PROBLEMS 同源，
# 防止清单被截断后"零覆盖也算过"。
MIN_PROBLEMS = 88

FULL = "FULL"
LOCAL_ONLY = "LOCAL_ONLY"
DATA_ABSENT_EXCLUDED = "DATA_ABSENT_EXCLUDED"
DATA_ABSENT_LOST = "DATA_ABSENT_LOST"

TIERS = (FULL, LOCAL_ONLY, DATA_ABSENT_EXCLUDED, DATA_ABSENT_LOST)


def load_doc(repo_root: str):
    with open(os.path.join(repo_root, CB_REL), encoding="utf-8") as fh:
        return json.load(fh)


def _file_present(att_root: str, pid: str, name: str) -> bool:
    """在盘且非空。空文件（历史上出现过 0 字节 zip）视为不存在。"""
    path = os.path.join(att_root, pid, name)
    try:
        return os.path.isfile(path) and os.path.getsize(path) > 0
    except OSError:
        return False


def classify(doc, att_root: str):
    """逐题分档。返回 (rows, tiers)。纯函数，自测与主门禁共用同一套判据。"""
    problems = doc.get("problems") or {}
    rows = []
    tiers = {t: [] for t in TIERS}
    for pid, p in problems.items():
        files = p.get("attachment_files") or []
        if not files:
            continue
        present, excluded, missing, missing_unexplained = [], [], [], []
        for f in files:
            name = f.get("name") or ""
            if _file_present(att_root, pid, name):
                present.append(name)
            else:
                missing.append(name)
                if not f.get("git_excluded"):
                    missing_unexplained.append(name)
            if f.get("git_excluded"):
                excluded.append(name)
        if present:
            # 有文件在盘：含 git 排除项 → 本地能解/CI 缺；否则完全在盘
            tier = LOCAL_ONLY if excluded else FULL
        elif missing_unexplained:
            # 无文件在盘，且有文件既未声明排除也不存在 → 静默丢失
            tier = DATA_ABSENT_LOST
        else:
            tier = DATA_ABSENT_EXCLUDED
        tiers[tier].append(pid)
        rows.append({
            "id": pid,
            "category": p.get("category") or "",
            "tier": tier,
            "declared": len(files),
            "present": len(present),
            "present_names": present,
            "missing_names": missing,
            "missing_unexplained": missing_unexplained,
            "git_excluded_names": excluded,
        })
    return rows, tiers


def violations(doc, att_root: str, att_exists: bool, min_problems: int = MIN_PROBLEMS):
    """纯判据 D1~D9 —— 返回 (违规列表, rows, tiers)。空列表 = 通过。"""
    bad = []
    problems = doc.get("problems") or {}
    empty = {t: [] for t in TIERS}
    if len(problems) < min_problems:
        bad.append("D1 题数 %d < 基线 %d（清单被截断/清空？零覆盖不得算通过）"
                   % (len(problems), min_problems))
    if not att_exists:
        bad.append("D2 附件根目录 %s 不存在——'磁盘上没有文件'无法与'根本没目录'区分，"
                   "不得据此计算分母" % ATT_REL)
        return bad, [], empty

    rows, tiers = classify(doc, att_root)
    declared = len(rows)

    # D3 四档之和 == 声明附件题数
    total_tiered = sum(len(v) for v in tiers.values())
    if total_tiered != declared:
        bad.append("D3 分档覆盖度不足：%d/%d（有题既没分档也没报错）" % (total_tiered, declared))

    # D4/D5 自报 honesty 必须等于逐题标志（同一份清单内部一致）
    hon = doc.get("honesty") or {}
    flag_true = sum(1 for p in problems.values() if p.get("attachment_available"))
    if "attachment_available" in hon and hon["attachment_available"] != flag_true:
        bad.append("D4 honesty.attachment_available=%s 与逐题 attachment_available=true 的题数 %d 不一致"
                   % (hon["attachment_available"], flag_true))
    if "attachment_missing" in hon:
        want_missing = len(problems) - flag_true
        if hon["attachment_missing"] != want_missing:
            bad.append("D5 honesty.attachment_missing=%s 与实物 %d（总题数 %d - available %d）不一致"
                       % (hon["attachment_missing"], want_missing, len(problems), flag_true))

    # D6 声明有附件却没有文件条目
    for pid, p in problems.items():
        if p.get("attachment_available") and not (p.get("attachment_files") or []):
            bad.append("D6 %s 声明 attachment_available=true 但 attachment_files 为空" % pid)

    # D7 全无数据 → 任何能力结论无意义
    if not tiers[FULL] and not tiers[LOCAL_ONLY]:
        bad.append("D7 FULL 与 LOCAL_ONLY 均为 0——没有任何题数据齐全，"
                   "此时命中率没有分母意义")

    # D8 FULL 档明细自洽
    for r in rows:
        if r["tier"] == FULL and (r["present"] != r["declared"] or r["git_excluded_names"]):
            bad.append("D8 %s 被判 FULL 但明细不自洽（present %d/%d, excluded %s）"
                       % (r["id"], r["present"], r["declared"], r["git_excluded_names"]))

    # D9 🔴 静默丢文件：缺失必须有 git 排除解释
    for r in rows:
        if r["tier"] == DATA_ABSENT_LOST:
            bad.append("D9 🔴 %s 静默丢数据：文件 %s 既未声明 git 排除、也不在磁盘上"
                       "（既不能本地解、也没留下任何解释）"
                       % (r["id"], ",".join(r["missing_unexplained"])))
    return bad, rows, tiers


def denominators(rows, tiers, total_problems=None):
    """可引用的分母。CI 会缺 git 排除文件，故 LOCAL_ONLY 不计入 CI 分母。"""
    d = {
        "declared_attachments": len(rows),
        "denominator_local": len(tiers[FULL]) + len(tiers[LOCAL_ONLY]),
        "denominator_ci": len(tiers[FULL]),
        "full": len(tiers[FULL]),
        "local_only": len(tiers[LOCAL_ONLY]),
        "data_absent_excluded": len(tiers[DATA_ABSENT_EXCLUDED]),
        "data_absent_lost": len(tiers[DATA_ABSENT_LOST]),
    }
    if total_problems is not None:
        d["total_problems"] = total_problems
        d["text_only"] = total_problems - d["declared_attachments"]
        d["denominator_any_path"] = d["denominator_local"] + d["text_only"]
    return d


# ---------------------------------------------------------------- 变异自测

def _make(root, plan, honesty_mode="correct", total=MIN_PROBLEMS, break_kind=None):
    """按档位造清单 + 磁盘。plan = [(pid, tier)]。

    honesty_mode: "correct" 用逐题 flag_true；"wrong_avail"/"wrong_missing" 注入虚报。
    break_kind: None | "ghost" | "drop_file" —— 额外破坏，用于变异。
    """
    probs = {}
    att_root = os.path.join(root, "attachments")
    os.makedirs(att_root, exist_ok=True)
    for pid, tier in plan:
        excluded = tier in (LOCAL_ONLY, DATA_ABSENT_EXCLUDED)
        entry = {"name": "a.txt", "size": 7, "answer_key_shape": excluded,
                 "git_excluded": excluded,
                 "exclude_reason": "整文件即 flag 明文" if excluded else ""}
        probs[pid] = {
            "id": pid, "category": "misc",
            "attachment_declared": True,
            "attachment_available": True,   # 建库时源库有 → 一律 true（与真实清单同构）
            "attachment_files": [entry],
        }
        if tier in (FULL, LOCAL_ONLY):
            d = os.path.join(att_root, pid)
            os.makedirs(d, exist_ok=True)
            with open(os.path.join(d, "a.txt"), "wb") as fh:
                fh.write(b"payload")
        # DATA_ABSENT_* 不建文件
    for i in range(max(0, total - len(probs))):
        probs["pad%03d" % i] = {"id": "pad%03d" % i, "category": "misc",
                                "attachment_declared": False,
                                "attachment_available": False, "attachment_files": []}
    flag_true = sum(1 for p in probs.values() if p.get("attachment_available"))
    hon = {"attachment_available": flag_true,
           "attachment_missing": len(probs) - flag_true}
    if honesty_mode == "wrong_avail":
        hon["attachment_available"] = 99
    elif honesty_mode == "wrong_missing":
        hon["attachment_missing"] = 999
    doc = {"version": 1, "honesty": hon, "problems": probs}

    if break_kind == "ghost":
        doc["problems"]["ghost"] = {"id": "ghost", "attachment_available": True,
                                    "attachment_files": []}
    elif break_kind == "drop_file":
        # 删掉一道 FULL 题的盘上文件（其文件**未**声明 git 排除）→ 静默丢失
        victim = next(pid for pid, t in plan if t == FULL)
        os.remove(os.path.join(att_root, victim, "a.txt"))
        doc["_victim"] = victim
    return doc, att_root


def self_test() -> int:
    """变异自测：每个变异都必须让门禁**变红**，否则"门禁有效"无从证明。"""
    import tempfile

    checks = []

    def expect(name, bad_subset, want_fail, detail=""):
        ok = bool(bad_subset) == want_fail
        checks.append((name, ok, detail or ("命中 %d 条" % len(bad_subset))))

    base_plan = [("f%d" % i, FULL) for i in range(8)]
    base_plan += [("lo1", LOCAL_ONLY)]
    base_plan += [("da%d" % i, DATA_ABSENT_EXCLUDED) for i in range(3)]

    with tempfile.TemporaryDirectory() as tmp:
        # ── 基线：8 FULL + 1 LOCAL_ONLY + 3 设计性缺失，honesty 正确 → 必须全绿
        doc, att = _make(os.path.join(tmp, "b"), base_plan)
        bad, rows, tiers = violations(doc, att, True)
        expect("基线（数据自洽）必须全绿", bad, False)
        den = denominators(rows, tiers, len(doc["problems"]))
        checks.append(("基线分母 local=9 / ci=8 / 无数据=3",
                       (den["denominator_local"], den["denominator_ci"],
                        den["data_absent_excluded"] + den["data_absent_lost"]) == (9, 8, 3),
                       json.dumps({k: den[k] for k in
                                   ("denominator_local", "denominator_ci",
                                    "data_absent_excluded", "data_absent_lost")})))

        # ── 变异 1：删掉一道 FULL 的盘上文件（文件未声明排除）→ 静默丢失 + D9 必须红
        doc1, att1 = _make(os.path.join(tmp, "m1"), base_plan, break_kind="drop_file")
        bad1, rows1, tiers1 = violations(doc1, att1, True)
        victim = doc1["_victim"]
        vrow = next(r for r in rows1 if r["id"] == victim)
        checks.append(("变异1 删除未排除的在盘文件 → 判为 DATA_ABSENT_LOST",
                       vrow["tier"] == DATA_ABSENT_LOST, "tier=%s" % vrow["tier"]))
        expect("变异1 静默丢失必须红（D9）",
               [b for b in bad1 if b.startswith("D9")], True)

        # ── 变异 2：attachment_available 虚报 → D4 必须红
        doc2, att2 = _make(os.path.join(tmp, "m2"), base_plan, honesty_mode="wrong_avail")
        bad2, _, _ = violations(doc2, att2, True)
        expect("变异2 attachment_available 虚报必须红（D4）",
               [b for b in bad2 if b.startswith("D4")], True)

        # ── 变异 3：attachment_missing 虚报 → D5 必须红
        doc3, att3 = _make(os.path.join(tmp, "m3"), base_plan, honesty_mode="wrong_missing")
        bad3, _, _ = violations(doc3, att3, True)
        expect("变异3 attachment_missing 虚报必须红（D5）",
               [b for b in bad3 if b.startswith("D5")], True)

        # ── 变异 4：全库无数据 → D7 必须红
        plan4 = [("da%d" % i, DATA_ABSENT_EXCLUDED) for i in range(12)]
        doc4, att4 = _make(os.path.join(tmp, "m4"), plan4)
        bad4, _, _ = violations(doc4, att4, True)
        expect("变异4 全库无数据必须红（D7）",
               [b for b in bad4 if b.startswith("D7")], True)

        # ── 变异 5：附件根目录不存在 → D2 必须红（fail-closed）
        doc5, _ = _make(os.path.join(tmp, "m5"), base_plan)
        bad5, _, _ = violations(doc5, os.path.join(tmp, "nope"), False)
        expect("变异5 附件目录缺失必须红（D2）",
               [b for b in bad5 if b.startswith("D2")], True)

        # ── 变异 6：清单被截断 → D1 必须红
        doc6, att6 = _make(os.path.join(tmp, "m6"), base_plan, total=10)
        bad6, _, _ = violations(doc6, att6, True)
        expect("变异6 清单被截断必须红（D1）",
               [b for b in bad6 if b.startswith("D1")], True)

        # ── 变异 7：声明 available 却无文件条目 → D6 必须红
        doc7, att7 = _make(os.path.join(tmp, "m7"), base_plan, break_kind="ghost")
        bad7, _, _ = violations(doc7, att7, True)
        expect("变异7 声明有附件却无条目必须红（D6）",
               [b for b in bad7 if b.startswith("D6")], True)

        # ── 变异 8：把"设计性缺失"误判成"静默丢失"的对称错误也要能发现
        #    （即：全部缺失文件都标了 git_excluded 时，D9 不得误报）
        bad8, rows8, _ = violations(doc, att, True)
        expect("变异8 设计性缺失不得被 D9 误报",
               [b for b in bad8 if b.startswith("D9")], False)

    print("=" * 64)
    print("  bench_capability_denominator 变异自测")
    print("=" * 64)
    failed = 0
    for name, ok, detail in checks:
        print(("  ✅ " if ok else "  🔴 ") + name + (("  ｜ " + detail) if not ok else ""))
        failed += 0 if ok else 1
    if failed:
        print("🔴 自测失败 %d/%d —— 门禁本身无效，不得据此计算分母" % (failed, len(checks)))
        return 1
    print("✅ 自测全过 %d/%d（每个变异都按预期变红，设计性缺失不误报）"
          % (len(checks), len(checks)))
    return 0


# ---------------------------------------------------------------- 主入口

def main(argv=None) -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--repo-root", default=".")
    ap.add_argument("--json", action="store_true")
    ap.add_argument("--self-test", action="store_true")
    args = ap.parse_args(argv)

    if args.self_test:
        return self_test()

    root = os.path.abspath(args.repo_root)
    try:
        doc = load_doc(root)
    except Exception as e:  # noqa: BLE001
        print("🔴 无法读取 %s：%s" % (CB_REL, e))
        return 1

    att_root = os.path.join(root, ATT_REL)
    bad, rows, tiers = violations(doc, att_root, os.path.isdir(att_root))
    den = denominators(rows, tiers, len(doc.get("problems") or {}))

    if args.json:
        print(json.dumps({"ok": not bad, "violations": bad,
                          "denominator": den, "rows": rows},
                         ensure_ascii=False, indent=2))
        return 0 if not bad else 1

    print("=" * 68)
    print("  基准能力分母（自报 honesty × 磁盘实物）")
    print("=" * 68)
    print("  总题数 %d ｜ 声明附件 %d ｜ 纯文本 %d"
          % (den["total_problems"], den["declared_attachments"], den["text_only"]))
    print("  分档：完全在盘 %d ｜ 仅本地 %d ｜ 设计性缺失 %d ｜ 静默丢失 %d"
          % (den["full"], den["local_only"],
             den["data_absent_excluded"], den["data_absent_lost"]))
    print()
    print("  %-42s %-8s %-21s %s" % ("problem", "cat", "tier", "missing / excluded"))
    for r in sorted(rows, key=lambda x: (x["tier"], x["id"])):
        note = []
        if r["missing_names"]:
            note.append("缺 %s" % ",".join(r["missing_names"]))
        if r["git_excluded_names"]:
            note.append("排除 %s" % ",".join(r["git_excluded_names"]))
        print("  %-42s %-8s %-21s %s"
              % (r["id"][:42], r["category"][:8], r["tier"], "; ".join(note)))
    print()
    print("  🔎 可引用分母（整句复制，不许只抄数字）：")
    print("     本地（含 git 排除但留在本机的文件）：%d 题" % den["denominator_local"])
    print("     CI 检出（git 排除文件不在）：%d 题" % den["denominator_ci"])
    print("     数据缺失（设计性排除 %d + 静默丢失 %d）：任何口径都不计入能力分母"
          % (den["data_absent_excluded"], den["data_absent_lost"]))
    if bad:
        print()
        print("🔴 违规 %d 条：" % len(bad))
        for b in bad:
            print("   - " + b)
        return 1
    print()
    print("✅ 自报数字与逐题标志一致；无静默丢失（D1~D9 全过）")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
