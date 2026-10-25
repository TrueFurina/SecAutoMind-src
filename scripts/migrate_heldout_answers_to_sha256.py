#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""heldout_evidence 判据迁移：`with_answers`/`no_answers` 明文 → `<field>_sha256`。

## 为什么要有这个脚本

`heldout_evidence/**.json` 里 `with_answers` / `no_answers` 已被
`redact_plaintext_flags.py` 的**文本路径**替换成 `前缀{****}`：

    "with_answers": "flag{****}",
    "with_answers_verdict": "TRUE"

问题：`flag{****}` 既不是真值也无法核验。哈希只落在本地 gitignore 的
`data/flag_truth.local.json` 里，仓库内的读者（评审、下游 clone）看到的
只是一个不可复核的 `TRUE` 断言 —— 证据不可复核等于没有证据。

根因见 `redact_plaintext_flags.py`：`TRUTH_KEYS` 只含
`("flag", "presolve_flag", "real_flag", "answer")`，不含这两个字段，
于是它们够不到「删字段 + 留 sha256」的字段级通道，只能被文本通道打码。

## 本脚本做什么

升级为字段级迁移（对齐 `external_westlake/benchmark.json` 既有规范）：

    "with_answers": null,
    "with_answers_sha256": "9f2c...",
    "with_answers_verdict": "TRUE"          # 不动，聚合口径不变

明文来源按序取第一个命中：
  1. 当前工作树该字段的明文（尚未脱敏的）
  2. `git show HEAD:<path>` 同 id 同字段明文
  3. **历史回溯**：`git log --all -- <path>` 由新到老逐个 rev 找，
     直到该 id/字段出现明文。`CTF-Agent_融合` 那份在 HEAD 已是遮蔽版，
     只能靠这步拿回真值。

三条都拿不到 → 写 `null` 并计入 `unresolved`，**绝不猜测**（fail-closed）。

幂等：字段已是 `null` 且 `_sha256` 已存在 → 跳过。
原值为 `None`（本来就没答案）→ 写 `_sha256: null`，计入 `empty`，不算未决。

## 判据纪律

`is_plaintext()` 复用 `secret_guard`（FLAG_CAND_RE + 占位符 + 可打印），
**绝不另写一套 flag 正则**。2026-10-25 复盘：本脚本首版自写了一个前缀白名单，
把「含逗号的三段数字答案」和「90 字符长答案」判成「不是明文」，未决从 0 虚增到 4055。

## 用法

    python scripts/migrate_heldout_answers_to_sha256.py --check
    python scripts/migrate_heldout_answers_to_sha256.py --apply
"""

from __future__ import annotations

import argparse
import hashlib
import json
import os
import subprocess
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT / "scripts"))
import secret_guard as sg  # noqa: E402  唯一判据

TARGET_DIRS = (
    "data/ctf_benchmark/heldout_evidence",
    "CTF-Agent_融合/ctf_agent/heldout_evidence",
)
FIELDS = ("with_answers", "no_answers")
# `baseline_naive_*` 不用 with_answers，答案样例放在 `sample_candidates`（字符串列表，
# 仅作人读）。它是**同一批真值的另一个出口**：2026-10-25 修好 FLAG_CAND_RE 之后
# 才显形 8 处（长 body / 含逗号两种盲点各 4 处）。遮蔽保持 `前缀{****}` 形态
# （展示不受影响），哈希放进平行列表，结构与消费方都不变。
SC_FIELD = "sample_candidates"
SC_SHA_FIELD = "sample_candidates_sha256"
MASK_MARK = "****"
MAX_HISTORY_REVS = 40  # 单文件最多回溯多少个历史版本


def sha256(s: str) -> str:
    return hashlib.sha256(s.encode("utf-8")).hexdigest()


def is_plaintext(v) -> bool:
    """与门禁同构：外形命中 且 不是占位符 且 可打印。"""
    if not isinstance(v, str) or not v.strip():
        return False
    if MASK_MARK in v:
        return False
    for m in sg.FLAG_CAND_RE.finditer(v):
        s = m.group(0)
        if sg.FLAG_PLACEHOLDER_RE.search(s):
            continue
        if not sg._flag_is_printable(s):
            continue
        return True
    return False


def _git(args: list[str]) -> str | None:
    try:
        p = subprocess.run(["git"] + args, cwd=str(ROOT),
                           capture_output=True, timeout=120)
    except Exception:
        return None
    if p.returncode != 0:
        return None
    return p.stdout.decode("utf-8", errors="replace")


def _load(text: str | None) -> dict | None:
    if not text:
        return None
    try:
        d = json.loads(text)
    except Exception:
        return None
    return d if isinstance(d, dict) else None


def index_by_id(rows: list) -> dict:
    """id → row。重复 id 置 None，交给顺序对齐兜底。"""
    idx: dict = {}
    dup: set = set()
    for r in rows:
        if not isinstance(r, dict):
            continue
        k = r.get("id")
        if k is None:
            continue
        if k in idx:
            dup.add(k)
        idx[k] = r
    for k in dup:
        idx[k] = None
    return idx


def history_plaintexts(rel: str, wanted: dict, field: str) -> dict:
    """历史回溯：id → 明文。wanted={id: True}，只找还没解决的那些。

    由新到老遍历该文件的 commit 版本，某 id 一旦拿到明文就锁定（取最新已知值，
    宁可新勿旧 —— 后期版本修正过错答案的情况多于反之）。
    """
    out: dict = {}
    if not wanted:
        return out
    log = _git(["log", "--all", "--format=%H", "-n", str(MAX_HISTORY_REVS), "--", rel])
    if not log:
        return out
    revs = [x for x in log.splitlines() if x.strip()]
    for rev in revs:  # 新 → 老
        if len(out) >= len(wanted):
            break
        doc = _load(_git(["show", f"{rev}:{rel}"]))
        if not doc:
            continue
        for r in doc.get("rows") or []:
            if not isinstance(r, dict):
                continue
            qid = r.get("id")
            if qid in wanted and qid not in out and is_plaintext(r.get(field)):
                out[qid] = r[field]
    return out


def migrate_file(path: Path, apply: bool, use_history: bool) -> dict:
    rel = path.relative_to(ROOT).as_posix()
    cur = json.loads(path.read_text(encoding="utf-8"))
    rows = cur.get("rows") or []

    head_idx: dict = {}
    if use_history:
        head = _load(_git(["show", f"HEAD:{rel}"]))
        if head:
            head_idx = index_by_id(head.get("rows") or [])

    stats = {"file": rel, "rows": len(rows), "migrated": 0, "already": 0,
             "empty": 0, "unresolved": 0, "cleared_plaintext": 0,
             "from_history": 0, "unrecoverable": 0,
             "unresolved_ids": [], "unrecoverable_ids": []}

    # 先收集本文件所有需要回溯的 (id, field)
    need: dict = {f: {} for f in FIELDS}
    resolved: dict = {f: {} for f in FIELDS}

    for f in FIELDS:
        for r in rows:
            if not isinstance(r, dict):
                continue
            v = r.get(f)
            k = f + "_sha256"
            if v is None and k in r:
                continue
            if is_plaintext(v):
                resolved[f][r.get("id")] = v
                continue
            cand = head_idx.get(r.get("id"))
            if isinstance(cand, dict) and is_plaintext(cand.get(f)):
                resolved[f][r.get("id")] = cand[f]
                continue
            if v is not None:  # 遮蔽值，需要回溯
                need[f][r.get("id")] = True

    for f in FIELDS:
        if need[f] and use_history:
            got = history_plaintexts(rel, need[f], f)
            for k, v in got.items():
                if k not in resolved[f]:
                    resolved[f][k] = v
                    stats["from_history"] += 1

    for i, r in enumerate(rows):
        if not isinstance(r, dict):
            continue
        qid = r.get("id")
        for f in FIELDS:
            sha_key = f + "_sha256"
            v = r.get(f)
            if v is None and sha_key in r:
                stats["already"] += 1
                continue
            if v is None:
                r[sha_key] = None
                stats["empty"] += 1
                continue
            src = resolved[f].get(qid)
            if src is not None:
                r[sha_key] = sha256(src)
                if is_plaintext(v):
                    stats["cleared_plaintext"] += 1
                r[f] = None
                stats["migrated"] += 1
            else:
                if MASK_MARK in str(v):
                    # 历史里就已是遮蔽值，回溯到底也拿不到明文 —— 真值不可恢复。
                    # 保留原样不动：这格本就不含明文（不违反红线），强行写
                    # `sha256: null` 反而抹掉「它曾被遮蔽」这个事实。
                    stats["unrecoverable"] += 1
                    if len(stats["unrecoverable_ids"]) < 10:
                        stats["unrecoverable_ids"].append({"id": qid, "field": f, "value": v})
                else:
                    stats["unresolved"] += 1
                    if len(stats["unresolved_ids"]) < 10:
                        stats["unresolved_ids"].append({"id": qid, "field": f, "value": v})

    # ── sample_candidates：遮蔽 + 平行哈希列表（结构不变）──
    for r in rows:
        if not isinstance(r, dict):
            continue
        sc = r.get(SC_FIELD)
        if not (isinstance(sc, list) and sc):
            continue
        sha_list = r.get(SC_SHA_FIELD)
        if not (isinstance(sha_list, list) and len(sha_list) == len(sc)):
            sha_list = [None] * len(sc)
        touched = False
        for i, v in enumerate(sc):
            if not is_plaintext(v):
                continue
            m = sg.FLAG_CAND_RE.search(v)
            if not m:
                continue
            sha_list[i] = sha256(v)
            sc[i] = m.group(1) + "{****}"
            stats["migrated"] += 1
            stats["cleared_plaintext"] += 1
            touched = True
        if touched:
            r[SC_SHA_FIELD] = sha_list

    # 写盘条件不能只看 migrated：整份都是空值（`with_answers: null`）的文件
    # migrated=0，但它同样需要补上 `*_sha256: null` 把「无答案」显式化。
    if apply and (stats["migrated"] or stats["empty"]):
        cur["_sha256_migration"] = {
            "date": "2026-10-25",
            "note": ("with_answers/no_answers 已由明文/遮蔽值迁移为 null + *_sha256；"
                     "verdict 字段保持原值，聚合口径不变"),
        }
        path.write_text(json.dumps(cur, ensure_ascii=False, indent=2) + "\n",
                        encoding="utf-8")
    return stats


def main() -> int:
    ap = argparse.ArgumentParser()
    g = ap.add_mutually_exclusive_group(required=True)
    g.add_argument("--check", action="store_true", help="只报告，不写盘")
    g.add_argument("--apply", action="store_true", help="写盘")
    ap.add_argument("--no-history", action="store_true",
                    help="跳过 git 历史回溯（快，但 HEAD 已遮蔽的拿不到真值）")
    args = ap.parse_args()

    tot = {k: 0 for k in ("migrated", "already", "empty", "unresolved",
                          "cleared_plaintext", "from_history", "unrecoverable",
                          "files", "files_changed")}
    print(f"heldout_evidence 判据迁移 · {'APPLY' if args.apply else 'CHECK'}")
    for d in TARGET_DIRS:
        base = ROOT / d
        if not base.is_dir():
            print(f"  [SKIP] 目录不存在：{d}")
            continue
        for p in sorted(base.rglob("*.json")):
            st = migrate_file(p, args.apply, not args.no_history)
            if not st["rows"]:
                continue
            tot["files"] += 1
            for k in ("migrated", "already", "empty", "unresolved",
                      "cleared_plaintext", "from_history", "unrecoverable"):
                tot[k] += st[k]
            if st["migrated"] or st["unresolved"] or st["unrecoverable"]:
                if st["migrated"]:
                    tot["files_changed"] += 1
                print(f"  {p.name[:52]:52s} 迁移={st['migrated']:4d} "
                      f"（历史取回 {st['from_history']:3d}）已迁={st['already']:4d} "
                      f"空={st['empty']:3d} 不可恢复={st['unrecoverable']:2d} "
                      f"未决={st['unresolved']:2d}")
            for u in st["unrecoverable_ids"][:3]:
                print(f"      ℹ️ 不可恢复 {u['id']} / {u['field']} = {u['value']!r}")
            for u in st["unresolved_ids"][:3]:
                print(f"      ⚠️ 未决 {u['id']} / {u['field']} = {u['value']!r}")

    print("\n合计："
          f"文件 {tot['files']}（改动 {tot['files_changed']}）｜"
          f"迁移 {tot['migrated']}｜历史取回 {tot['from_history']}｜"
          f"清掉明文 {tot['cleared_plaintext']}｜已迁 {tot['already']}｜"
          f"空值 {tot['empty']}｜不可恢复 {tot['unrecoverable']}｜未决 {tot['unresolved']}")
    if tot["unresolved"]:
        print("⚠️ 有未决字段 —— 既无明文也无历史来源，需人工补。")
        return 2
    if tot["unrecoverable"]:
        print("ℹ️ 「不可恢复」= 历史上就已被文本遮蔽、回溯到底无明文。原样保留"
              "（该格不含明文，不违反红线），但**没有哈希可复核**，引用时须注明。")
    return 0


if __name__ == "__main__":
    sys.exit(main())
