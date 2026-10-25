#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""已入库 CTF flag 明文 → 遮蔽（事故 #20 的清理执行器）。

背景
----
`scripts/secret_guard.py` 的明文 flag 门禁实测：**已入库文件含明文 flag 1876 条**
（263 个文件），其中前缀 `d0g3` 的那条（正文已遮蔽，真值见
`scripts/plaintext_flag_baseline.json`）正是 commit a87b812「清除 PUBLIC 仓 7 条真题真
flag」以为清掉过的那条 —— 实际没清干净。本仓是 **PUBLIC**，答案明文入库即泄露。

为什么必须分类，不能全量替换
------------------------------
实测消费链（一刀切会破坏生产代码/测试）：
  A 类 可安全遮蔽：`data/ctf_benchmark/heldout_evidence/*.json`、`benchmark.json`、
     `coverage_report.json`、`docs/archive/**` —— 纯证据/报告，无代码读取其内容。
  B 类 需评估：`data/ctf_benchmark/xhlj_legacy/**` —— 被 `internal/ctfplatform/
     presolve_python.go` 调 `runner.py` 遍历求解，改动会影响生产链路，**默认排除**。
  C 类 永不改：`*_test.go` / `*_test.py` / `testdata/` / `internal/**` —— 测试夹具
     里的 `flag{...}` 是构造值不是真答案，改了测试就红。
  ⚠️ `build_real_benchmark.py` 属 A 类但**特殊**：它用明文当真值构建 benchmark，
     遮蔽后生成器失去真值。故单独列为 `--include-generators` 才处理，
     且处理时会把真值写进本地真值文件（见下）。

真值保全（不硬删）
------------------
每条被遮蔽的 flag：先算 `sha256`，连同 `文件:行` 写入
`data/flag_truth.local.json`（**默认已在 .gitignore**，不入库）。
遮蔽形态沿用 `build_cross_bench.sanitize_text` 的既有约定 `前缀{****}` ——
它被 secret_guard 的 FLAG_PLACEHOLDER_RE 判为占位，不会重新触发门禁。
判据与 secret_guard 共用同一 `FLAG_CAND_RE`（纪律：修复器必须与判红门禁同判据）。

用法（**默认 dry-run，不写盘**）
--------------------------------
  python scripts/redact_plaintext_flags.py                      # 预演
  python scripts/redact_plaintext_flags.py --json               # 机器可读
  python scripts/redact_plaintext_flags.py --apply              # 落盘（会改已跟踪文件）
  python scripts/redact_plaintext_flags.py --apply --include-generators
  python scripts/redact_plaintext_flags.py --apply --update-gitignore

退出码：0 = 无异常（dry-run 恒 0）；1 = 参数/环境错；2 = apply 后复检仍未清零。
"""

from __future__ import annotations

import argparse
import hashlib
import json
import os
import re
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))
import secret_guard as sg  # noqa: E402  复用同一判据，绝不另起一套

ROOT = Path(__file__).resolve().parent.parent

# 永不改：测试夹具 + 生产代码（改动风险 >> 泄露收益）
EXCLUDE_RE = re.compile(
    r"_test\.go$|_test\.py$|/testdata/|/tests?/|^internal/|^cmd/|\.example", re.I)
# ⚠️ 真值库/生产资产：被判定器**按 flag 明文**读取，遮蔽 = 评测全崩。
#    `benchmark.json` 被 build_real_benchmark / judge_* / gen_* 消费，
#    `coverage_report.json` 被 judge.py / run_all_benchmarks.py / miss_attribution_test.go 消费，
#    `xhlj_legacy/**` 被 internal/ctfplatform/presolve_python.go 调 runner.py 遍历求解。
#    要清理它们必须**先改判据为 sha256 比对**，属另一项工程 —— 默认排除。
RISKY_RE = re.compile(
    r"benchmark\.json|coverage_report|real_coverage_report|xhlj_legacy|"
    r"questions_real|questions_external", re.I)
# 默认只处理**零代码消费**的证据/归档面（实测无人读取其内容）
#
# 2026-10-25 扩面：`CTF-Agent_融合/ctf_agent/heldout_evidence/` 是同一批证据的
# 另一份拷贝（50 个 json / 801 条，占全仓 1/3），此前漏在覆盖面外——理由已核过：
#   - 消费方只有 `_kpi_canonical.py`（取 KPI 数字，读 `summary` 与 `*_verdict`）
#     与 3 个测试（读 `leak_provenance_*` 的 id/verdict），**无一处读 flag 明文**
#   - `sample_candidates`（_baseline_naive.py 产出）仅作人读样例，命中判定
#     早在 `hit_any = expected in shas` 里由 sha256 完成
#   - `with_answers`/`no_answers` 被 `_leak_provenance.py:218` 读，但它只是把
#     明文抄进 leak 报告——遮蔽后抄进去的是 `前缀{****}`，泄漏证明力由 sha256 承担
DEFAULT_INCLUDE = (
    "data/ctf_benchmark/heldout_evidence/",
    "CTF-Agent_融合/ctf_agent/heldout_evidence/",
    "docs/archive/",
)

# 逐文件白名单：纯文档/台账，正文里的真题 flag 只为叙述，遮蔽后论述仍成立
# （`REAL_SOLVES_LEDGER.md` 的条目本身就并列写了 sha256，遮蔽是**无损**的）
DOC_INCLUDE = (
    "CTF-Agent_融合/协同任务总账-TOP0.md",
    "CTF-Agent_融合/ctf_agent/REAL_SOLVES_LEDGER.md",
)
# 生成器：含真值逻辑，需显式开关
GENERATOR_SUFFIX = ("build_real_benchmark.py",)

TRUTH_FILE = ROOT / "data" / "flag_truth.local.json"
GITIGNORE_LINE = "data/flag_truth.local.json"
REDACTED = "{****}"


def classify(rel: str, include_generators: bool) -> str:
    """返回 'act'（可遮蔽）/ 'skip'（排除）。"""
    if rel in DOC_INCLUDE:
        return "act"
    if EXCLUDE_RE.search(rel):
        return "skip"
    if RISKY_RE.search(rel):
        return "skip"
    if rel.endswith(GENERATOR_SUFFIX):
        return "act" if include_generators else "skip"
    return "act" if rel.startswith(DEFAULT_INCLUDE) else "skip"


def scan(root: Path, include_generators: bool):
    """返回 (待处理文件列表, 跳过的文件数)；每项是 dict(file, n, samples)。"""
    tracked = sg._git_tracked(str(root)) or set()
    acts, skipped = [], 0
    for dirpath, dirnames, filenames in os.walk(root):
        dirnames[:] = [d for d in dirnames if d not in sg.SKIP_DIRS]
        for fn in filenames:
            ext = os.path.splitext(fn)[1].lower()
            if ext in sg.SKIP_FILE_SUFFIX:
                continue
            if ext and ext not in sg.TEXT_EXT and fn not in (".env", "Dockerfile"):
                continue
            p = Path(dirpath) / fn
            rel = os.path.relpath(p, root).replace("\\", "/")
            if rel not in tracked:
                continue  # 未入库副本不处理（不进 PUBLIC 仓）
            if p.stat().st_size > sg.MAX_FILE_BYTES:
                continue
            try:
                text = p.read_text(encoding="utf-8")
            except Exception:
                continue
            # 统计口径必须与 redact_text / secret_guard 完全一致
            # （占位符豁免 + 可打印性过滤），否则会出现"预报 899 实改 896"。
            n = sum(1 for m in sg.FLAG_CAND_RE.finditer(text)
                    if not sg.FLAG_PLACEHOLDER_RE.search(m.group(0))
                    and sg._flag_is_printable(m.group(0)))
            if not n:
                continue
            if classify(rel, include_generators) == "skip":
                skipped += 1
                continue
            acts.append({"path": p, "rel": rel, "n": n})
    return acts, skipped


def redact_text(text: str, rel: str, truth: list[dict]) -> tuple[str, int]:
    """把明文 flag 替换为 `前缀{****}`，真值 sha256 记入 truth。

    ⚠️ 全文口径（与 secret_guard.scan_plaintext_flags 完全一致）：逐行 splitlines
    会漏掉含 \\x85 / \\u2028 等 Unicode 行边界的 flag（实测漏 3 条），且会与
    门禁统计口径对不上（899 vs 896）。行号用 count("\\n") 现算，精度不变。
    """
    changed = 0

    def _sub(m: "re.Match[str]") -> str:
        nonlocal changed
        raw = m.group(0)
        if sg.FLAG_PLACEHOLDER_RE.search(raw):
            return raw
        if not sg._flag_is_printable(raw):
            return raw  # 二进制噪声，不是答案
        changed += 1
        truth.append({
            "file": rel,
            "line": text.count("\n", 0, m.start()) + 1,
            "sha256": hashlib.sha256(raw.encode("utf-8")).hexdigest(),
            "len": len(raw),
        })
        return m.group(1) + REDACTED

    return sg.FLAG_CAND_RE.sub(_sub, text), changed


# ── JSON 真值字段级清理（对齐 external_westlake 既有规范：只存 flag_sha256）──
# 判据链早已按 sha256 比对（judge.py:527 / judge_crc32.py），明文字段纯属冗余。
# external_westlake/benchmark.json 的 problem 已无 flag 字段 —— 本模式就是把它补齐。
TRUTH_KEYS = ("flag", "presolve_flag", "real_flag", "answer")
SHA_KEY = "flag_sha256"
# 2026-10-25 实锤：`with_answers` / `no_answers` 不在 TRUTH_KEYS 里，于是够不到
# 「删字段 + 留 sha256」的字段级通道，只能被**文本通道**打成 `前缀{****}` ——
# 结果 heldout_evidence 里 1821 处遮蔽**一个哈希都没随文件落盘**（哈希只在本地
# gitignore 的真值库里），仓库内的 `with_answers_verdict: TRUE` 变成不可复核的断言。
# 证据不可复核 = 没有证据。故把这两个字段纳入，并用自己的 `_sha256` 键配对；
# 它们与 with_answers/no_answers 一一对应，下游只多一个字段，不改语义。
SELF_HASH_FIELDS = {
    "with_answers": "with_answers_sha256",
    "no_answers": "no_answers_sha256",
}
# 题面/叙述字段：绝不触碰（清掉会毁题，且里面的 flag 形态多为密文而非答案）
PROSE_KEYS = frozenset({
    "description", "title", "notes", "note", "writeup", "content",
    "hint", "body", "text", "story", "summary", "provenance",
})


def _looks_like_flag(s: str) -> bool:
    for m in sg.FLAG_CAND_RE.finditer(s):
        raw = m.group(0)
        if sg.FLAG_PLACEHOLDER_RE.search(raw):
            continue
        if not sg._flag_is_printable(raw):
            continue
        return True
    return False


def redact_json_obj(node, rel: str, truth: list, stats: dict) -> None:
    """递归删明文字段。

    两条通道，区别在「哈希从哪来」：

    - `TRUTH_KEYS`（flag/presolve_flag/...）：哈希必须**已在同对象里**（判据链
      本来就是按 sha256 比对，明文字段是冗余）。缺整定哈希就跳过 —— fail-closed，
      绝不制造「真值丢失」。
    - `SELF_HASH_FIELDS`（with_answers/no_answers）：明文当场就能算出哈希，
      由本函数自己写 `<field>_sha256`，不依赖别处先备好。缺哈希不再是跳过理由。
    """
    if isinstance(node, dict):
        for k in list(node.keys()):
            if k in PROSE_KEYS:
                continue  # 题面字段，跳过（含 description 内的密文 flag）
            v = node.get(k)
            if isinstance(v, str) and _looks_like_flag(v):
                h = hashlib.sha256(v.encode("utf-8")).hexdigest()
                if k in SELF_HASH_FIELDS:
                    sha_key = SELF_HASH_FIELDS[k]
                    node[sha_key] = node.get(sha_key) or h
                    truth.append({"file": rel, "field": k, "sha256": h, "len": len(v)})
                    # 置 null 而非 del：与 `migrate_heldout_answers_to_sha256.py`
                    # 的产物形态保持一致（字段在、明文无），消费方 `r.get()` 等价。
                    node[k] = None
                    stats["cleared"] += 1
                    continue
                if k in TRUTH_KEYS:
                    if node.get(SHA_KEY):
                        truth.append({"file": rel, "field": k, "sha256": h, "len": len(v)})
                        del node[k]
                        stats["cleared"] += 1
                    else:
                        stats["skipped_no_sha"] += 1  # 无 sha256 兜底 → 不动
                    continue
            redact_json_obj(v, rel, truth, stats)
    elif isinstance(node, list):
        for x in node:
            redact_json_obj(x, rel, truth, stats)


def run_json_fields(target: Path, apply: bool, as_json: bool) -> int:
    stats = {"cleared": 0, "skipped_no_sha": 0, "files_changed": 0, "files": 0}
    truth: list = []
    files = sorted(p for p in target.rglob("*.json") if p.is_file())
    tracked = sg._git_tracked(str(ROOT)) or set()
    for p in files:
        rel = os.path.relpath(str(p), str(ROOT)).replace("\\", "/")
        if rel not in tracked:
            continue  # 未入库副本不处理（不构成 PUBLIC 泄露）
        try:
            doc = json.loads(p.read_text(encoding="utf-8"))
        except Exception:
            continue
        before = stats["cleared"]
        redact_json_obj(doc, rel, truth, stats)
        stats["files"] += 1
        if stats["cleared"] > before:
            stats["files_changed"] += 1
            if apply:
                p.write_text(json.dumps(doc, ensure_ascii=False, indent=2) + "\n",
                             encoding="utf-8")
    out = {
        "mode": "apply" if apply else "dry-run",
        "scanned_files": stats["files"],
        "files_to_change": stats["files_changed"],
        "fields_cleared": stats["cleared"],
        "skipped_no_sha256": stats["skipped_no_sha"],
        "truth_entries": len(truth),
    }
    if as_json:
        print(json.dumps(out, ensure_ascii=False, indent=1))
    else:
        print(f"== JSON 真值字段清理（{'已写盘' if apply else '预演'}）==")
        print(f"  扫描 {stats['files']} 个已入库 JSON，将删 {stats['cleared']} 个明文字段"
              f"（涉及 {stats['files_changed']} 个文件）")
        print(f"  无 flag_sha256 兜底而跳过（fail-closed）: {stats['skipped_no_sha']}")
    if apply and truth:
        _append_truth(truth)
    return 0


def _append_truth(rows: list) -> None:
    """真值 sha256 追加到 gitignore 的本地文件，绝不入仓。"""
    cur = []
    if TRUTH_FILE.is_file():
        try:
            cur = json.loads(TRUTH_FILE.read_text(encoding="utf-8"))
        except Exception:
            cur = []
    if not isinstance(cur, list):
        cur = []
    cur.extend(rows)
    TRUTH_FILE.parent.mkdir(parents=True, exist_ok=True)
    TRUTH_FILE.write_text(json.dumps(cur, ensure_ascii=False, indent=1),
                          encoding="utf-8")
    print(f"✅ 真值 sha256 已追加 {len(rows)} 条 → {TRUTH_FILE}（已 gitignore）")


def main() -> int:
    ap = argparse.ArgumentParser(description="已入库 CTF flag 明文遮蔽（默认 dry-run）")
    ap.add_argument("--apply", action="store_true", help="真正写盘（默认只预演）")
    ap.add_argument("--json-fields", metavar="DIR",
                    help="JSON 字段级清理：删除与 flag_sha256 并存的明文字段"
                         "（对齐 external_westlake 规范），题面字段豁免")
    ap.add_argument("--include-generators", action="store_true",
                    help="连 build_real_benchmark.py 等生成器一起处理")
    ap.add_argument("--update-gitignore", action="store_true",
                    help="把真值文件加入 .gitignore（防止真值被提交）")
    ap.add_argument("--json", action="store_true", help="机器可读输出")
    args = ap.parse_args()

    if args.json_fields:
        t = Path(args.json_fields)
        if not t.is_dir():
            print(f"❌ 目录不存在: {t}")
            return 2
        return run_json_fields(t, args.apply, args.json)

    acts, skipped = scan(ROOT, args.include_generators)
    total = sum(a["n"] for a in acts)

    if args.update_gitignore:
        gi = ROOT / ".gitignore"
        cur = gi.read_text(encoding="utf-8") if gi.is_file() else ""
        if GITIGNORE_LINE not in cur:
            gi.write_text(cur.rstrip("\n") + f"\n{GITIGNORE_LINE}\n", encoding="utf-8")
            print(f"✅ .gitignore 已加入 {GITIGNORE_LINE}")

    if not args.apply:
        summary = {
            "mode": "dry-run",
            "files_to_redact": len(acts),
            "hits_to_redact": total,
            "files_skipped": skipped,
            "truth_file": str(TRUTH_FILE),
            "top": [{"file": a["rel"], "n": a["n"]}
                    for a in sorted(acts, key=lambda x: -x["n"])[:10]],
        }
        if args.json:
            print(json.dumps(summary, ensure_ascii=False, indent=1))
        else:
            print("== 预演（未写盘）==")
            print(f"  将遮蔽 {total} 条明文 flag，涉及 {len(acts)} 个已入库文件")
            print(f"  按规则跳过 {skipped} 个文件（测试夹具 / 生产代码 / 生成器）")
            print("  top 10：")
            for a in sorted(acts, key=lambda x: -x["n"])[:10]:
                print(f"    {a['n']:5d}  {a['rel']}")
            print("\n  落盘执行：python scripts/redact_plaintext_flags.py --apply"
                  + (" --include-generators" if args.include_generators else ""))
        return 0

    # ---- apply ----
    truth: list[dict] = []
    done = 0
    for a in acts:
        try:
            text = a["path"].read_text(encoding="utf-8")
            new, n = redact_text(text, a["rel"], truth)
            if n:
                a["path"].write_text(new, encoding="utf-8")
                done += n
        except Exception as e:
            print(f"⚠️  跳过 {a['rel']}: {e}", file=sys.stderr)

    TRUTH_FILE.parent.mkdir(parents=True, exist_ok=True)
    # 合并而非覆盖：分多批清理（证据面 → 文档面 → 生成器）时，后一批不能把前一批
    # 的 sha256 抹掉——真值一旦丢，被遮蔽的答案就永久不可复原了。
    prev: list = []
    if TRUTH_FILE.is_file():
        try:
            old = json.loads(TRUTH_FILE.read_text(encoding="utf-8"))
            prev = old.get("items", []) if isinstance(old, dict) else list(old)
        except Exception:
            prev = []
    seen = {(i.get("file"), i.get("line"), i.get("sha256")) for i in prev if isinstance(i, dict)}
    for row in truth:
        k = (row.get("file"), row.get("line"), row.get("sha256"))
        if k not in seen:
            seen.add(k)
            prev.append(row)
    truth = prev
    TRUTH_FILE.write_text(json.dumps({
        "_why": "被遮蔽的 CTF flag 明文真值（sha256 + 位置）。本文件不入库。",
        "count": len(truth),
        "items": truth,
    }, ensure_ascii=False, indent=1), encoding="utf-8")

    print(f"✅ 已遮蔽 {done} 条明文 flag（{len(acts)} 个文件）")
    print(f"   真值 sha256 已保全到 {TRUTH_FILE}（{len(truth)} 条，确认已 gitignore）")

    # 复检：只断言**本次负责的 SAFE 面**清零。
    # 全仓断言必然残留（跳过的真值库/测试夹具仍在）→ 那是假红，不能这么判。
    hits, _ = sg.scan_plaintext_flags(str(ROOT), sg._git_tracked(str(ROOT)))
    safe_left = [h for h in hits
                 if h["tracked"] and classify(h["file"], args.include_generators) == "act"]
    all_left = [h for h in hits if h["tracked"]]
    print(f"   复检：SAFE 面残留 {len(safe_left)} 条；全仓已入库残留 {len(all_left)} 条"
          f"（清理前 1876 条基线，残留集中在真值库/测试夹具）")
    if safe_left:
        for h in safe_left[:10]:
            print(f"     仍有：{h['file']}:{h['line']}")
        return 2
    return 0


if __name__ == "__main__":
    sys.exit(main())
