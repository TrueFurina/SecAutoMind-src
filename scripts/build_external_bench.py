#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""把 A 库 `data/questions_external`（Google CTF 2021–2025 等外部真题）搬成 B 可跑的**对照尺**。

与 `build_cross_bench.py`（A 库西湖论剑真题 88 题）的关系：**并列的两把外部尺，互不替代**。

│ 尺            | 来源                    | 载荷      | 用途                              |
|---------------|-------------------------|-----------|-----------------------------------|
| cross-bench   | 西湖论剑真题 88 题       | 12/88     | 题型迁移决策（§2.2 阈值）          |
| external-bench| Google CTF 2021–2025 40 题 | **38/40** | **证伪「自产集高分 = 解题能力」**   |

为什么必须再立这一把尺（2026-10-17，规划 §2.2 的遗留盲区）
--------------------------------------------------------
B 对外最漂亮的数字是**自产集 70/72 = 97.2%**，但自产集是**按求解器能力造的**（开卷考试）。
项目已在 `docs/quant_effect.md` 明令「禁止把自产集当作赛题能力对外表述」——
然而此前**缺少一把「外部 + 载荷齐全」的对照尺**来实证这条禁令：

  · cross-bench 的 1/88 可被辩解为「A 侧 76 题附件缺失，是数据问题不是能力问题」；
  · Google CTF 这套**载荷齐全 38/40**，该辩解不成立——同一套求解器在完整外部真题上的
    水位，就是「自产集高分是否等于能力」的干净对照。

故本尺的第一用途**不是刷分**，而是给「自产集不得作能力证据」这条声明提供机验支撑；
数字无论好看难看都如实记录（§2.2 纪律：先定阈后看数，不为转绿改阈值）。

定位（同 cross-bench，不得越界）
  - 产物落在 `data/questions_external_bench/`（独立目录），
    **不进** `data/ctf_benchmark/` —— 后者是 B 的 KPI 基准，混进去会污染对外数字。
  - **不是 KPI**：命中数不得写进对外材料当战果；对外仍只用真求解器口径。

诚实约束（写死在产物里，防止后人口径漂移）
  - flag 一律沿用 A 的 `flag` 字段（sha256 真值），命中判定用 sha256 比对。
  - 🔴 交付红线：本仓 PUBLIC，禁止 flag 明文入库。附件逐文件扫描
    「候选 flag 串 sha256 == 本题 flag_sha256」，命中者只留本地、进 `.gitignore`，
    并在 JSON 逐文件登记 `git_excluded` + 原因。
  - 判据是 **sha256 相等**，不是"看着像 flag"：题目自带参数/样本不属答案形态，不得误伤。
  - 载荷不全的题（如 `ext_gctf2024_otp` 287 个附件只落地 1 个）标
    `payload_complete=false`，由门禁禁止其进入任何对外汇总（防"缺载荷恒 miss"做假分母）。

用法：
    python scripts/build_external_bench.py --src <A库>/data/questions_external
    python scripts/build_external_bench.py --src <...> --check     # 只校验不写盘
"""
from __future__ import annotations

import argparse
import glob
import hashlib
import json
import os
import re
import shutil
import sys
from collections import Counter

OUT_DIR = os.path.join("data", "questions_external_bench")
OUT_FILE = os.path.join(OUT_DIR, "external_bench.json")
REPORT = os.path.join(OUT_DIR, "external_bench_source_stats.json")
ATT_DIR = os.path.join(OUT_DIR, "attachments")

SAFE_ID_RE = re.compile(r"[^0-9A-Za-z._-]+")

# 题面/附件里任何「前缀{内容}」形态的候选（用于 flag 明文遮蔽与附件答案扫描）。
FLAG_CAND_RE = re.compile(r"([A-Za-z0-9_]{2,})\{[^}\n]{4,80}\}")

# 文件名形如 flag.* —— 与 build_cross_bench.py 同口径：场上有答案文件也是题型设计，
# 但"剔除答案形态"口径必须跳过它，否则测的是"抄答案"而非解题。
# ⚠️ 只影响 answer_key_shape（剔除口径），**不等于**含 flag 明文：
# 实测 Google CTF 2025 的 bpfbox/numerology 附件里 flag.txt 内容是占位符 `CTF{flag}`，
# 与本题 flag_sha256 不相等 ⇒ 按题目输入入库（不进 git 排除集），但仍按答案形态剔除。
ANSWER_KEY_RE = re.compile(r"^flag(\.[A-Za-z0-9_-]+)?$", re.IGNORECASE)

# 附件扫描上限：只扫前 256KB（文本型挑战文件足够；二进制大文件按可打印率跳过）。
ATT_SCAN_MAX = 256 * 1024


def is_sha256(s: str) -> bool:
    return isinstance(s, str) and len(s) == 64 and all(c in "0123456789abcdefABCDEF" for c in s)


def source_descriptor(src: str) -> str:
    """A 库目录的公开表述：只保留 ctf_agent 起的相对路径，不暴露本机绝对结构。"""
    parts = os.path.abspath(src).replace("\\", "/").rstrip("/").split("/")
    if "ctf_agent" in parts:
        i = len(parts) - 1 - parts[::-1].index("ctf_agent")
        return "/".join(parts[i:])
    return os.path.basename(src.rstrip("/\\")) or "questions_external"


def safe_id(qid: str) -> str:
    return SAFE_ID_RE.sub("_", qid) or "unknown"


def sanitize_text(text: str, flag_sha256: str) -> str:
    """把题面里**与本题 flag_sha256 逐字相等**的 flag 明文遮蔽为 `前缀{****}`。

    与 build_cross_bench.py 同源同判据（sha256 相等，不靠"看着像"），
    避免重跑生成器 = 二次泄密（见 2026-10-15 P0 事件 commit a87b812）。
    """
    if not text or not flag_sha256:
        return text

    def _sub(m: "re.Match[str]") -> str:
        cand = m.group(0)
        if hashlib.sha256(cand.encode("utf-8")).hexdigest() == flag_sha256:
            return m.group(1) + "{****}"
        return cand

    return FLAG_CAND_RE.sub(_sub, text)


def attachment_holds_flag(path: str, flag_sha256: str) -> bool:
    """附件是否含本题 flag 明文（判据：候选串 sha256 == flag_sha256）。

    只读前 ATT_SCAN_MAX 字节，且对不可打印字节占比过高的文件直接判否
    （二进制里逐字节扫候选串既慢又易误报；真 flag 明文不会以二进制形态给出）。
    """
    if not flag_sha256:
        return False
    try:
        with open(path, "rb") as fh:
            raw = fh.read(ATT_SCAN_MAX)
    except OSError:
        return False
    if not raw:
        return False
    printable = sum(1 for b in raw if 9 <= b <= 13 or 32 <= b <= 126)
    if printable / len(raw) < 0.6:
        return False
    text = raw.decode("utf-8", "ignore")
    for m in FLAG_CAND_RE.finditer(text):
        if hashlib.sha256(m.group(0).encode("utf-8")).hexdigest() == flag_sha256:
            return True
    return False


def norm_rel(a: str) -> str:
    """A 库附件路径既有 `/` 也有 `\\`（Windows 导出），统一成仓库根相对路径。"""
    return os.path.normpath(a.replace("\\", "/"))


def load_source(src: str):
    """读取 A 库外部真题，返回 (题目列表, 载荷齐全题数, 载荷缺失题数, A 库根)。"""
    files = sorted(glob.glob(os.path.join(src, "**", "*.json"), recursive=True))
    base = os.path.dirname(os.path.dirname(os.path.abspath(src)))  # ctf_agent 根
    probs, full, partial = [], 0, 0
    for f in files:
        try:
            with open(f, encoding="utf-8") as fh:
                d = json.load(fh)
        except Exception as e:  # noqa: BLE001
            print(f"  [WARN] 跳过无法解析的 {f}: {e}", file=sys.stderr)
            continue
        qid = str(d.get("id") or os.path.splitext(os.path.basename(f))[0])
        # 外部题集的真值字段名是 flag_sha256（与 A 库真题集的 flag 字段不同名），
        # 两者都可能是 sha256 串，故两个名字都认，避免"换了字段名就整集被跳过"。
        flag = (d.get("flag_sha256") or d.get("flag") or "").lower()
        if not is_sha256(flag):
            # 非 sha256 的 flag 不是外部真值，按铁律不计入本题
            print(f"  [SKIP] {qid}: flag 非 sha256 真值，不纳入", file=sys.stderr)
            continue
        atts = d.get("attachments") or []
        existing = [a for a in atts if os.path.isfile(os.path.join(base, norm_rel(a)))]
        payload_complete = bool(atts) and len(existing) == len(atts)
        if payload_complete:
            full += 1
        else:
            partial += 1
        probs.append({
            "id": qid,
            "category": d.get("category") or "misc",
            "sub": d.get("category") or "misc",
            "description": sanitize_text(d.get("description") or "", flag),
            "title": sanitize_text(d.get("title") or "", flag),
            "flag_sha256": flag,
            "difficulty": d.get("difficulty") or "",
            # 外部来源留痕（合规：Apache-2.0 等授权须可溯源到 source_repo）
            "external_source": d.get("external_source") or "",
            "source_repo": d.get("source_repo") or "",
            "license": d.get("license") or "",
            "provenance": d.get("provenance") or "real_past_ctf",
            "attachment_declared": len(atts),
            "attachment_present": len(existing),
            "payload_complete": payload_complete,
            "attachment_available": bool(existing),
            "attachment_files": [],
        })
    return probs, full, partial, base


def copy_attachments_for(p: dict, src_json: str, base: str) -> int:
    dest_dir = os.path.join(ATT_DIR, safe_id(p["id"]))
    os.makedirs(dest_dir, exist_ok=True)
    with open(src_json, encoding="utf-8") as fh:
        d = json.load(fh)
    n = 0
    for a in d.get("attachments") or []:
        full_path = os.path.join(base, norm_rel(a))
        if not os.path.isfile(full_path):
            continue
        name = os.path.basename(norm_rel(a))
        dest = os.path.join(dest_dir, name)
        shutil.copyfile(full_path, dest)
        holds_flag = attachment_holds_flag(dest, p["flag_sha256"])
        answer_shape = holds_flag or bool(ANSWER_KEY_RE.match(name))
        entry = {
            "name": name,
            "size": os.path.getsize(dest),
            "answer_key_shape": answer_shape,
            "git_excluded": holds_flag,
            "exclude_reason": "附件内含本题 flag 明文（sha256 相等）" if holds_flag else "",
        }
        if holds_flag:
            print(f"  🔴 [P0] {p['id']}/{name} 含 flag 明文 → 只留本地，已登记 git 排除",
                  file=sys.stderr)
        p["attachment_files"].append(entry)
        n += 1
    return n


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--src", required=True, help="A 库 data/questions_external 目录")
    ap.add_argument("--check", action="store_true", help="只校验不写盘")
    args = ap.parse_args()

    if not os.path.isdir(args.src):
        print(f"[FAIL] 源目录不存在: {args.src}", file=sys.stderr)
        return 1

    probs, full, partial, base = load_source(args.src)
    if not probs:
        print("[FAIL] 未读到任何题目", file=sys.stderr)
        return 1

    files_by_id = {}
    for f in sorted(glob.glob(os.path.join(args.src, "**", "*.json"), recursive=True)):
        try:
            with open(f, encoding="utf-8") as fh:
                d = json.load(fh)
        except Exception:  # noqa: BLE001
            continue
        files_by_id.setdefault(str(d.get("id") or os.path.splitext(os.path.basename(f))[0]), f)

    if not args.check and os.path.isdir(ATT_DIR):
        shutil.rmtree(ATT_DIR)  # 先清后建，保证幂等（无上一轮残留）

    att_files_total = 0
    att_flag_files = 0
    for p in probs:
        src_json = files_by_id.get(p["id"])
        if not src_json or not p["attachment_available"]:
            continue
        if not args.check:
            att_files_total += copy_attachments_for(p, src_json, base)
        att_flag_files += sum(1 for x in p["attachment_files"] if x["git_excluded"])

    att_git_excluded = sum(
        1 for p in probs for af in p["attachment_files"] if af.get("git_excluded"))
    if not args.check:
        os.makedirs(ATT_DIR, exist_ok=True)
        lines = [
            "# 由 scripts/build_external_bench.py 自动生成，请勿手改。",
            "# 含 flag 明文（sha256 与本题 flag 相等）的附件按交付红线只保留在本地，",
            "# 不进入 PUBLIC 仓库；CI 检出不含这些文件，「含答案口径」在 CI 上自动降级。",
        ]
        for p in probs:
            for af in p["attachment_files"]:
                if af.get("git_excluded"):
                    lines.append(f"{safe_id(p['id'])}/{af['name']}")
        with open(os.path.join(ATT_DIR, ".gitignore"), "w", encoding="utf-8", newline="\n") as fh:
            fh.write("\n".join(lines) + "\n")

    cats = Counter(p["category"] for p in probs)
    srcs = Counter(p["external_source"] or "unknown" for p in probs)
    doc = {
        "version": "v1",
        "created": "2026-10-17",
        "purpose": ("外部真题对照尺：用「载荷齐全的外部真题」证伪「自产集高分 = 解题能力」，"
                    "不用于对外 KPI。"),
        "source": {
            "repo": "西湖论剑 CTF-Agent (A 库)",
            "path": source_descriptor(args.src),
            "note": "仅作尺；不并入 B 的 KPI 基准 data/ctf_benchmark/",
            "external_sources": dict(sorted(srcs.items())),
        },
        "honesty": {
            "input_modes": ["text-only", "attachment-subset"],
            "why": ("默认口径只喂 description（文本口径）；载荷齐全的题另有「有数据子集」口径。"
                    "两口径分别报告，互不冒充。"),
            "payload_complete": full,
            "payload_partial": partial,
            "attachment_files_copied": att_files_total,
            "attachment_flag_plaintext_files": att_flag_files,
            "attachment_files_git_excluded": att_git_excluded,
            "git_exclude_reason": "附件含本题 flag 明文（sha256 相等）→ 按 PUBLIC 仓交付红线只留本地",
            "flag_truth": "沿用 A 的 flag 字段(sha256)，命中判定用 sha256 比对",
            "not_a_kpi": "命中数不得写入对外材料当战果；对外只用真求解器口径",
        },
        "problems": {p["id"]: p for p in probs},
    }
    stats = {
        "total": len(probs),
        "by_category": dict(cats),
        "by_external_source": dict(sorted(srcs.items())),
        "payload_complete": full,
        "payload_partial": partial,
        "attachment_files_copied": att_files_total,
        "sha256_of_doc": hashlib.sha256(
            json.dumps(doc, sort_keys=True, ensure_ascii=False).encode("utf-8")
        ).hexdigest(),
    }

    print("=" * 62)
    print(f"  external-bench 基准构建  题数={len(probs)}")
    print("=" * 62)
    for k, v in sorted(cats.items()):
        print(f"    {k:<10} {v}")
    for k, v in sorted(srcs.items()):
        print(f"    来源 {k:<18} {v}")
    print(f"    载荷齐全  {full}    载荷缺失  {partial}")
    print(f"    复制附件文件  {att_files_total}"
          f"（其中含 flag 明文 {att_flag_files}；git 排除 {att_git_excluded}）")
    print("    🔴 本尺只作对照，命中数不得写入对外材料当战果")

    if args.check:
        print("[check] 未写盘")
        return 0

    os.makedirs(OUT_DIR, exist_ok=True)
    for path, payload in ((OUT_FILE, doc), (REPORT, stats)):
        with open(path, "w", encoding="utf-8", newline="\n") as fh:
            json.dump(payload, fh, ensure_ascii=False, indent=2)
    print(f"  已写入 {OUT_FILE}")
    print(f"  已写入 {REPORT}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
