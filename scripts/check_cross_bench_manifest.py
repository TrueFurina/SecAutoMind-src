#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""cross-bench 产物清单一致性门禁（cross_bench.json / attachments/.gitignore / 生成器 三方对齐）。

## 为什么需要它（2026-10-16 实锤）

`data/questions_real_bench/` 下的 `cross_bench.json` 与 `attachments/.gitignore` 是
`scripts/build_cross_bench.py` 的**产物**，但历史上被**手工改过两轮**（PR #22 建清单、
PR #35 的 P0 清理 `a87b812` 遮蔽题面 flag 明文），而生成器**没有被同步**。生成器又不在
CI 里跑 → 漂移静默存在。实跑生成器（A 库 `E:/Program/西湖论剑` 本机仍在，
`register_recovered_attachment.py` 旧注释所称"已不存在"**是伪前提**）发现三条漂移：

  1. **P0 红线被静默摘除**：生成器不知道 `10733/task.py` 要排除 → 重跑会写出只含 4 条的
     `.gitignore`，此后任何 `git add -A` 都会把该 P0 文件重新纳入 PUBLIC 仓。
  2. **flag 明文被重新引入**：A 库 `description` 里抄了 writeup 的真 flag
     （`d0g3{71b2…}` / `flag{i_am_not_right…}`，二者 sha256 == 本题 flag_sha256），
     `a87b812` 已把产物里的明文遮蔽成 `前缀{****}`；生成器不遮蔽 → **重跑一次 = 再泄一次**。
  3. **自报数字与实物脱节**：`honesty.attachment_answer_key_files` /
     `attachment_files_git_excluded` 停在 4，实物已是 5。

三条都属于本项目反复踩的"看起来做过 vs 真的有效"。本门禁把"产物、生成器契约、
git 排除"三方钉成可复跑的机器判据，**任一方漂移即报红**。

## 判据（全部 fail-closed，空集/查不到一律红）

  C1 覆盖度自证：题数 ≥ 基线、逐题算到 description、附件清单非空、排除集非空
  C2 `.gitignore` 条目集合 == 产物 `git_excluded` 集合（双向）
  C3 生成器 `GIT_EXCLUDED_ATTACHMENTS` 键集合 == 产物 `git_excluded` 集合（双向）
  C4 答案形态集合 == `git_excluded` 集合（防 `flag.*` 漏排 → 会被提交进 PUBLIC 仓）
  C5 生成器 `RECOVERED_ATTACHMENTS` 键集合 == 产物带 `recovered_from` 的集合（双向）
  C6 题面（description/title）不得含 flag 明文——**权威判据是 sha256 相等**，
     不是"看着像 flag"（CRC32/LCG 类题面里的已知明文是合法输入，不得误伤）
  C7 `.gitignore` 每条都被 `git check-ignore` 命中（rc=0）且不在 `git ls-files` 中
  C8 红线钉：`PINNED_REDLINE` 里的文件必须仍在排除集内（见常量处说明）

用法：python scripts/check_cross_bench_manifest.py [--repo-root .]
退出码：0 = 全过；1 = 有违规。
"""
from __future__ import annotations

import argparse
import hashlib
import json
import os
import subprocess
import sys

# 生成器是判据的唯一真值源（契约表就在里面），直接 import 而不是复制一份常量——
# 复制就会再引入一次"两处不同步"的机会。
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import build_cross_bench as BC  # noqa: E402

CB_REL = os.path.join("data", "questions_real_bench", "cross_bench.json")
GI_REL = os.path.join("data", "questions_real_bench", "attachments", ".gitignore")
ATT_BASE = "data/questions_real_bench/attachments/"

# 题数基线地板：防止清单被截断/清空后"零覆盖也显示通过"。
MIN_PROBLEMS = 88

# 🔴 红线钉：这些文件必须**始终**在 git 排除集内。它们是 2026-10-15 P0 交付红线事件的
# 直接主角（答案/实例真值明文）。**若经用户拍板决定把其中某个改为入库**，必须显式改本处
# 并同步 docs/cross_bench_report.md —— 刻意做成"响的"红线，不给静默摘除留通道。
PINNED_REDLINE = {
    "10733/task.py": "2026-10-15 P0 事件主角：附件末尾文档字符串含本实例 hint/c/n 三元组",
    "real_crypto_anxun2020_aes/flag.txt": "整文件即 flag 明文",
    "real_misc_longjian2024_smallsword3/flag.txt": "整文件即 flag 明文",
    "real_reverse_upx/helloupx11": "二进制内嵌答案 flag 明文",
    "real_web_gongye_web2/index.php": "源码注释内含 flag 真值",
}


def load_doc(repo_root: str):
    with open(os.path.join(repo_root, CB_REL), encoding="utf-8") as fh:
        return json.load(fh)


def gitignore_lines(repo_root: str):
    path = os.path.join(repo_root, GI_REL)
    if not os.path.exists(path):
        return None
    out = []
    with open(path, encoding="utf-8") as fh:
        for ln in fh.read().splitlines():
            ln = ln.strip()
            if ln and not ln.startswith("#"):
                out.append(ln)
    return out


def _walk_files(doc):
    """产出 (pid, file_entry) 逐附件，覆盖度由调用方断言。"""
    for pid, p in (doc.get("problems") or {}).items():
        for f in p.get("attachment_files") or []:
            yield pid, f


def artifact_sets(doc):
    """从产物抽取四个集合（键形式 'pid/name'）。"""
    excluded, answer_key, recovered = set(), set(), set()
    examined = 0
    for pid, f in _walk_files(doc):
        examined += 1
        key = "%s/%s" % (pid, f.get("name"))
        if f.get("git_excluded"):
            excluded.add(key)
        if f.get("answer_key_shape"):
            answer_key.add(key)
        if f.get("recovered_from"):
            recovered.add(key)
    return {
        "examined": examined,
        "excluded": excluded,
        "answer_key": answer_key,
        "recovered": recovered,
    }


def response_in_statement(doc):
    """C6：题面里是否存在 **sha256 等于本题 flag_sha256** 的候选串。

    返回 (命中列表, 扫描题数)。判据是 sha256 相等——与
    scripts/audit_benchmark_validity.py::answer_in_statement 及
    internal/ctfplatform/answer_key_git_gate_test.go 同源，**不许改成"看着像 flag"**。
    """
    hits, scanned = [], 0
    for pid, p in (doc.get("problems") or {}).items():
        scanned += 1
        want = p.get("flag_sha256")
        if not want:
            continue
        for field in ("description", "title"):
            text = p.get(field) or ""
            # ⚠️ 必须用 finditer 取 group(0)（完整候选串）：FLAG_CAND_RE 带一个捕获组，
            #    findall 只会返回组 1（前缀），拿去算 sha256 必然不等 → 门禁恒绿。
            for m in BC.FLAG_CAND_RE.finditer(text):
                full = m.group(0)
                if hashlib.sha256(full.encode("utf-8")).hexdigest() == want:
                    hits.append((pid, field, full))
                    break
    return hits, scanned


def manifest_violations(doc, gi_lines, gen_excluded, gen_recovered,
                        pinned=None, min_problems=MIN_PROBLEMS):
    """纯判据（C1~C6、C8）——返回违规消息列表，空=通过。

    抽成纯函数是为了让变异自测与主门禁**共用同一套判据**，避免"测试过了但判的是别的东西"。
    """
    pinned = PINNED_REDLINE if pinned is None else pinned
    bad = []
    problems = doc.get("problems") or {}

    # ---- C1 覆盖度自证 ----
    if len(problems) < min_problems:
        bad.append("C1 题数 %d < 基线 %d（清单被截断/清空？零覆盖不得算通过）"
                   % (len(problems), min_problems))
    sets = artifact_sets(doc)
    if sets["examined"] == 0:
        bad.append("C1 附件清单为空——'扫了 0 个文件'不得算通过")
    if not sets["excluded"]:
        bad.append("C1 git 排除集为空——PUBLIC 仓红线无任何登记，判据失去意义")

    # ---- C2 .gitignore ↔ 产物 ----
    if gi_lines is None:
        bad.append("C2 %s 缺失" % GI_REL)
    else:
        gi = set(gi_lines)
        if gi != sets["excluded"]:
            only_gi = sorted(gi - sets["excluded"])
            only_doc = sorted(sets["excluded"] - gi)
            bad.append("C2 .gitignore 与产物 git_excluded 不一致"
                       "｜仅在 .gitignore：%s｜仅在产物：%s" % (only_gi, only_doc))

    # ---- C3 生成器排除契约 ↔ 产物 ----
    if gen_excluded != sets["excluded"]:
        bad.append("C3 生成器 GIT_EXCLUDED_ATTACHMENTS 与产物不一致"
                   "｜仅生成器有：%s｜仅产物有：%s"
                   % (sorted(gen_excluded - sets["excluded"]),
                      sorted(sets["excluded"] - gen_excluded)))

    # ---- C4 答案形态 ⊆/== 排除集 ----
    if sets["answer_key"] != sets["excluded"]:
        bad.append("C4 答案形态集合与 git 排除集合不一致（未排除的答案形态文件会被提交进 PUBLIC 仓）"
                   "｜答案形态未排除：%s｜已排除非答案形态：%s"
                   % (sorted(sets["answer_key"] - sets["excluded"]),
                      sorted(sets["excluded"] - sets["answer_key"])))

    # ---- C5 找回附件契约 ↔ 产物 ----
    if gen_recovered != sets["recovered"]:
        bad.append("C5 生成器 RECOVERED_ATTACHMENTS 与产物 recovered_from 不一致"
                   "｜仅生成器有：%s｜仅产物有：%s"
                   % (sorted(gen_recovered - sets["recovered"]),
                      sorted(sets["recovered"] - gen_recovered)))

    # ---- C6 题面不得含 flag 明文 ----
    hits, scanned = response_in_statement(doc)
    if scanned != len(problems):
        bad.append("C6 覆盖度不足：只扫了 %d/%d 题" % (scanned, len(problems)))
    for pid, field, cand in hits:
        bad.append("C6 题面即答案（sha256 命中）：%s.%s 含 %s —— 必须遮蔽为 前缀{****}"
                   % (pid, field, cand[:48]))
    # 遮蔽器必须对已提交数据是恒等变换（把生成器与产物绑在一起）
    for pid, p in problems.items():
        want = p.get("flag_sha256")
        for field in ("description", "title"):
            text = p.get(field) or ""
            if BC.sanitize_text(text, want or "") != text:
                bad.append("C6 生成器遮蔽器对 %s.%s 非恒等——产物与生成器口径不一致"
                           % (pid, field))

    # ---- C8 红线钉 ----
    for key, why in pinned.items():
        if key not in sets["excluded"]:
            bad.append("C8 🔴 红线钉失效：%s 不在 git 排除集中（%s）"
                       "—— 若为有意放开，须显式修改本门禁 PINNED_REDLINE 并留痕"
                       % (key, why))
    return bad


def git_violations(repo_root: str, gi_lines):
    """C7：.gitignore 每条都被规则命中且未被跟踪（在真实仓库上跑）。"""
    if not gi_lines:
        return []
    bad = []
    for pat in gi_lines:
        full = ATT_BASE + pat
        rc = subprocess.run(["git", "check-ignore", "-q", full],
                            cwd=repo_root).returncode
        if rc != 0:
            bad.append("C7 %s 未被 .gitignore 规则命中（check-ignore rc=%d）" % (full, rc))
    out = subprocess.run(["git", "ls-files", ATT_BASE],
                         cwd=repo_root, capture_output=True, text=True)
    if out.returncode != 0:
        bad.append("C7 git ls-files 失败（环境问题，不得当作通过依据）：%s"
                   % (out.stderr or "").strip())
        return bad
    tracked = {ln.strip() for ln in out.stdout.splitlines() if ln.strip()}
    for pat in gi_lines:
        full = ATT_BASE + pat
        if full in tracked:
            bad.append("C7 🔴 %s 仍在 git 跟踪中（.gitignore 对已跟踪文件无效）"
                       "—— 修复：git rm --cached 保留本地文件" % full)
    return bad


def main(argv=None) -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--repo-root", default=".")
    ap.add_argument("--min-problems", type=int, default=MIN_PROBLEMS)
    args = ap.parse_args(argv)

    root = os.path.abspath(args.repo_root)
    try:
        doc = load_doc(root)
    except Exception as e:  # noqa: BLE001
        print("🔴 无法读取 %s：%s" % (CB_REL, e))
        return 1

    gi_lines = gitignore_lines(root)
    gen_excluded = {"%s/%s" % k for k in BC.GIT_EXCLUDED_ATTACHMENTS}
    gen_recovered = {"%s/%s" % k for k in BC.RECOVERED_ATTACHMENTS}

    bad = manifest_violations(doc, gi_lines, gen_excluded, gen_recovered,
                              min_problems=args.min_problems)
    bad += git_violations(root, gi_lines or [])

    sets = artifact_sets(doc)
    print("=" * 64)
    print("  cross-bench 产物清单一致性门禁")
    print("=" * 64)
    print("  题数 %d | 附件条目 %d | git 排除 %d | 答案形态 %d | 找回附件 %d"
          % (len(doc.get("problems") or {}), sets["examined"],
             len(sets["excluded"]), len(sets["answer_key"]), len(sets["recovered"])))
    if bad:
        # 报红后**不打**"全部通过"日志（避免日志与结论自相矛盾）
        print("🔴 违规 %d 条：" % len(bad))
        for b in bad:
            print("   - " + b)
        return 1
    print("✅ 三方一致（产物 / attachments/.gitignore / 生成器契约表），题面无 flag 明文")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
