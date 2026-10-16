"""把从 A 库找回的 10733 附件登记进 cross_bench.json。

为什么需要本脚本（而不是手改 JSON）：
  cross_bench.json 是构建产物，手改会在下次 `build_cross_bench.py --src` 重跑时
  被覆盖，故这里做成**幂等**的一次性登记工具（`--dry-run` 可预演）。

🔴 **2026-10-16 更正（留痕，不静默改写）**：本脚本旧注释称"构建器无法运行
（A 库 questions_real 目录已不存在）"——**这是伪前提，实测不成立**：
`E:/Program/西湖论剑/ctf_agent/data/questions_real` 本机仍在，构建器可跑。
由此产生的真实风险（当时未察觉，2026-10-16 实跑生成器才发现）：生成器**不知道**
10733 要排除，重跑会把 `attachments/.gitignore` 写成只含 4 条 → 静默摘掉本 P0 红线
文件；且生成器不遮蔽题面 flag 明文 → 会把 `a87b812` 清掉的 2 条真 flag 重新写回
产物。这两条已在 `build_cross_bench.py` 里修（补 `GIT_EXCLUDED_ATTACHMENTS` /
`RECOVERED_ATTACHMENTS` / `sanitize_text`），并由 `scripts/check_cross_bench_manifest.py`
把三方一致性钉进 CI。**本脚本保留为幂等补登记工具**，不再是"唯一可行路径"。

用法：python scripts/register_recovered_attachment.py --id 10733 --file task.py
"""
import argparse
import hashlib
import io
import json
import os

CB = "data/questions_real_bench/cross_bench.json"
CB_GITIGNORE = "data/questions_real_bench/attachments/.gitignore"

RECOVERED_FROM = "本仓库 data/questions_real_bench/attachments/10733/task.py（2026-10-15 重新精读；A 库同源副本另存于 E:/Program/西湖论剑 git 历史 87550e0d）"
RECOVERED_REASON = (
    "附件含本实例 hint/c/n 三元组（task.py 末尾文档字符串内），足以让求解器直接还原 m "
    "⇒ 按答案形态处理并 git 排除（PUBLIC 仓禁答案材料入库）。"
    "分类于 2026-10-15：此前误判为『数据不完整、实例真值未留存』，实为归因错误 —— "
    "真值一直在附件里，属读附件不彻底（只读前半段就下结论）。"
)


def sha256_of(path):
    with open(path, "rb") as fh:
        return hashlib.sha256(fh.read()).hexdigest()


def resync_honesty(doc):
    """按实物重算 honesty 里的派生计数（不许手工 +1/-1）。

    2026-10-16 实测：产物里 `attachment_answer_key_files` / `attachment_files_git_excluded`
    停在 4，而实物已是 5 —— 正是本脚本某次登记后没同步派生计数造成的"自报数字与实物脱节"。
    派生的数字一律重算。
    """
    files = [f for p in (doc.get("problems") or {}).values()
             for f in (p.get("attachment_files") or [])]
    h = doc.setdefault("honesty", {})
    h["attachment_answer_key_files"] = sum(1 for f in files if f.get("answer_key_shape"))
    h["attachment_files_git_excluded"] = sum(1 for f in files if f.get("git_excluded"))


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--id", required=True)
    ap.add_argument("--file", required=True, help="附件文件名（须已在 attachments/<id>/ 下）")
    ap.add_argument("--att-dir", default="data/questions_real_bench/attachments")
    ap.add_argument("--dry-run", action="store_true")
    args = ap.parse_args()

    full = os.path.join(args.att_dir, args.id, args.file)
    if not os.path.exists(full):
        print("附件不存在: %s" % full)
        return 2

    with io.open(CB, encoding="utf-8") as fh:
        doc = json.load(fh)

    probs = doc["problems"]
    if args.id not in probs:
        print("cross_bench.json 无此题: %s" % args.id)
        return 2
    p = probs[args.id]

    files = p.setdefault("attachment_files", [])
    # 幂等：同名且已按答案形态登记，则只补来源标注后退出
    size = os.path.getsize(full)
    digest = sha256_of(full)
    for f in files:
        if f.get("name") == args.file:
            changed = False
            if f.get("sha256") != digest:
                f["sha256"] = digest
                f["size"] = size
                changed = True
            # 本实例含 hint/c/n 三元组，足以还原 m ⇒ 必须按答案形态 git 排除
            if not f.get("answer_key_shape") or not f.get("git_excluded"):
                f["answer_key_shape"] = True
                f["git_excluded"] = True
                f["exclude_reason"] = RECOVERED_REASON
                changed = True
            if not f.get("recovered_from"):
                f["recovered_from"] = RECOVERED_FROM
                changed = True
            if not changed:
                print("已登记且一致，无需改动: %s/%s" % (args.id, args.file))
                return 0
            if args.dry_run:
                print("DRY-RUN：将更新 %s/%s 的答案形态标注" % (args.id, args.file))
                return 0
            resync_honesty(doc)
            with io.open(CB, "w", encoding="utf-8", newline="") as fh:
                json.dump(doc, fh, ensure_ascii=False, indent=2)
            gi = io.open(CB_GITIGNORE, encoding="utf-8").read().splitlines()
            pat = "%s/%s" % (args.id, args.file)
            if pat not in gi:
                gi.append(pat)
                with io.open(CB_GITIGNORE, "w", encoding="utf-8", newline="\n") as fh:
                    fh.write("\n".join(gi) + "\n")
                print("已登记 .gitignore: %s" % pat)
            print("✅ 已更新 %s/%s：answer_key_shape+git_excluded+sha256+recovered_from"
                  % (args.id, args.file))
            return 0

    files.append({
        "name": args.file,
        "size": size,
        "sha256": digest,
        "answer_key_shape": True,
        "git_excluded": True,
        "exclude_reason": RECOVERED_REASON,
        "recovered_from": RECOVERED_FROM,
    })
    p["attachment_available"] = True
    p["attachment_recovered"] = True

    # honesty 段记账必须同步，否则 stats 与实物脱节
    h = doc.setdefault("honesty", {})
    h["attachment_recovered_count"] = int(h.get("attachment_recovered_count", 0)) + 1
    if "why" in h and "找回" not in h["why"]:
        h["why"] = h["why"].rstrip("。") + "。另：部分附件已于 2026-10-15 从 A 库 git 历史找回（见逐文件 recovered_from）。"

    if args.dry_run:
        print("DRY-RUN：将登记 %s/%s（%d 字节, sha256=%s）" %
              (args.id, args.file, size, digest[:16]))
        return 0

    resync_honesty(doc)
    with io.open(CB, "w", encoding="utf-8", newline="") as fh:
        json.dump(doc, fh, ensure_ascii=False, indent=2)

    # 同步 gitignore：新增 git 排除文件必须登记，否则 PUBLIC 仓会泄答案材料
    gi = io.open(CB_GITIGNORE, encoding="utf-8").read().splitlines()
    pat = "%s/%s" % (args.id, args.file)
    if pat not in gi:
        gi.append(pat)
        with io.open(CB_GITIGNORE, "w", encoding="utf-8", newline="\n") as fh:
            fh.write("\n".join(gi) + "\n")
        print("已登记 .gitignore: %s" % pat)

    print("✅ 已登记 %s/%s（%d 字节）answer_key_shape+git_excluded" % (args.id, args.file, size))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())