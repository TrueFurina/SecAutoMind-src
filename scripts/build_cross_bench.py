#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""把西湖论剑（A 库）的 93 道真题搬成 SecAutoMind（B 库）可跑的同卷基准。

定位（规划 §2.2）：**仅作尺，不混入 B 题库刷数字**。
  - 产物落在 `data/questions_real_bench/`（独立目录），
    **不进** `data/ctf_benchmark/` —— 后者是 B 的 KPI 基准，混进去会污染对外数字。

诚实约束（写死在产物里，防止后人口径漂移）：
  - A 侧真题的挑战数据（附件）**大部分已缺失**；仅少数题的附件路径仍存在。
    故默认口径是**文本口径**（只喂 description），测出的是 B 的**下限**，不是能力上限。
  - 对附件仍在的题，本脚本把附件文件复制进 `attachments/<id>/` 并逐文件登记
    （名字/大小/是否答案形态），由 `TestCrossBench_AttachmentSubset` 跑
    「有数据子集」。两个口径**分别报告、互不冒充**：
      · 含 `flag.*` 答案形态附件的命中——按真实赛制计入（附件当场给答案也是题型设计）；
      · 同时给出剔除答案形态附件后的数字——衡量真实解题能力。
  - flag 一律沿用 A 的 `flag` 字段（sha256 真值），B 侧命中判定同样用 sha256 比对，
    符合"无外部真值不计入战果"的铁律。
  - A 库路径只写 `ctf_agent` 起的相对描述，**不写本机绝对路径**（公开仓库不暴露本机结构）。
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

OUT_DIR = os.path.join("data", "questions_real_bench")
OUT_FILE = os.path.join(OUT_DIR, "cross_bench.json")
REPORT = os.path.join(OUT_DIR, "cross_bench_source_stats.json")
ATT_DIR = os.path.join(OUT_DIR, "attachments")

# 附件文件名形如 flag.* / flag.*（含被截断的 flag.tx）—— 场上有答案文件也是题型设计，
# 但基准必须能单独剔除它来报告"真实解题能力"，故登记形态而非静默计入。
ANSWER_KEY_RE = re.compile(r"^flag\.", re.IGNORECASE)
SAFE_ID_RE = re.compile(r"[^0-9A-Za-z._-]+")

# 🔴 交付红线：本仓库是 PUBLIC 仓，禁止 flag 明文入库。以下文件含答案真值
#（整文件即答案 / 源码注释内 flag 真值 / 二进制内嵌答案），只复制到本地供
# 「含答案口径」跑分，经 attachments/.gitignore 排除出 git；并在 cross_bench.json
# 逐文件登记 git_excluded + 原因——杜绝"清单声明了但 CI 检出没有"的静默不一致。
# 「答案形态」的判据 = **含 flag 明文 / 内嵌答案**（与
# internal/ctfplatform/answer_key_git_gate_test.go::flagPlaintextRe 同源）。
# ⚠️ 裸数字/参数是「题目输入」，**不属答案形态**，不得登记在此（该注释原文即如此规定）。
GIT_EXCLUDED_ATTACHMENTS = {
    ("real_misc_longjian2024_smallsword3", "flag.txt"): "整文件即 flag 明文",
    ("real_crypto_anxun2020_aes", "flag.txt"): "整文件即 flag 明文",
    ("real_web_gongye_web2", "index.php"): "源码注释内含 flag 真值",
    ("real_reverse_upx", "helloupx11"): "二进制内嵌答案 flag 明文",
    # 2026-10-16 **撤销登记**：("10733", "task.py") 曾在 2026-10-15 P0 事件后按
    # 「实例真值 = 答案材料」的从严口径登记在此。该口径经复核被证伪：
    #   ① 文件里 flag 是 `b'******'` **遮蔽态**，全文只有加密脚本 + hint/c/n 实例参数
    #      （即**题目输入**），不含任何 flag 串（grep + sha256 双重确认）；
    #   ② 与同批已入库的 ezrsa/exciting_inverse/simplelegendre/filterrandom 附件同类
    #      （它们同样带实例参数，登记 answer_key_shape=false）；
    #   ③ 本仓门禁注释原文即规定"裸数字/参数形态（那些是题目输入）"不算答案。
    # 故改按题目输入入库，使「有数据子集」口径在 CI 侧可复现（原排除令该题在 CI 不可评价，
    # 且 local/CI 数字分叉）。红线未变：真正含 flag 的 4 个文件仍在上方排除集内。
}

# 从 A 库 git 历史（而非工作树）找回的附件：生成器额外登记 sha256 + 来源标注，
# 使「重跑生成器」与已提交产物逐字一致（否则 sha256/recovered_from 会被静默抹掉）。
# 2026-10-16：原登记项 ("10733","task.py") 已撤销——该文件改按题目输入入库后，
# 生成器直接从 A 库工作树正常复制（A 库副本与本仓 sha256 一致 328d8244…），
# 不再需要"找回"通道。表保留为空以维持门禁 C5（生成器契约 ↔ 产物 recovered_from）。
RECOVERED_ATTACHMENTS = {}

# 题面中性化覆盖表：A 库个别题目的 description 抄了 writeup 的**解法走查**
# （非答案明文，故 sanitize_text 的 sha256 判据抓不到；但它把解答步骤写进了题面，
# 削弱该题作为能力证据的独立性）。此表把这类题面替换为与同批一致的**中性题面**。
# 判据：覆盖后题面不得含解法步骤，且生成器重跑与产物逐字一致（门禁 C10 钉死）。
DESCRIPTION_OVERRIDES = {
    "10733": (
        "附件 task.py 是加密脚本（文件末尾给出本实例的 hint、c、n）。"
        "解密还原明文 flag。"
    ),
}


def is_sha256(s: str) -> bool:
    return isinstance(s, str) and len(s) == 64 and all(c in "0123456789abcdefABCDEF" for c in s)


def source_descriptor(src: str) -> str:
    """A 库目录的公开表述：只保留 ctf_agent 起的相对路径，不暴露本机绝对结构。"""
    parts = os.path.abspath(src).replace("\\", "/").rstrip("/").split("/")
    if "ctf_agent" in parts:
        i = len(parts) - 1 - parts[::-1].index("ctf_agent")
        return "/".join(parts[i:])
    return os.path.basename(src.rstrip("/\\")) or "questions_real"


def safe_id(qid: str) -> str:
    return SAFE_ID_RE.sub("_", qid) or "unknown"


# 题面里任何「前缀{内容}」形态的候选（用于 flag 明文遮蔽）。
FLAG_CAND_RE = re.compile(r"([A-Za-z0-9_]{2,})\{[^}\n]{4,80}\}")


def sanitize_text(text: str, flag_sha256: str) -> str:
    """把题面里**与本题 flag_sha256 逐字相等**的 flag 明文遮蔽为 `前缀{****}`。

    为什么必须做：A 库部分题目的 description 直接抄了 writeup 里的真 flag，
    直接搬进本 PUBLIC 仓就是答案明文入库，会把 2026-10-15 的 P0 清理
    （commit a87b812「清除 PUBLIC 仓 7 条真题真 flag」）重新破防。
    实测：`d0g3{71b2…}` / `flag{i_am_not_right…}` 的 sha256 与本题 flag_sha256 相等，
    正是被清掉的明文——生成器不遮蔽就等于"重跑一次 = 再泄一次"。

    判据是 **sha256 相等**，不是"看着像 flag"：CRC32/LCG 等题面里的已知明文是
    合法输入（见 docs/cross_bench_report.md 关于 A 层判据的教训），不得误伤。
    """
    if not text or not flag_sha256:
        return text

    def _sub(m: "re.Match[str]") -> str:
        cand = m.group(0)
        if hashlib.sha256(cand.encode("utf-8")).hexdigest() == flag_sha256:
            return m.group(1) + "{****}"
        return cand

    return FLAG_CAND_RE.sub(_sub, text)


def load_source(src: str):
    """读取 A 库真题，返回 (题目列表, 附件可用题数, 附件缺失题数, A 库根目录)。"""
    files = sorted(glob.glob(os.path.join(src, "**", "*.json"), recursive=True))
    base = os.path.dirname(os.path.dirname(os.path.abspath(src)))  # ctf_agent 根
    probs, att_ok, att_missing = [], 0, 0
    for f in files:
        try:
            with open(f, encoding="utf-8") as fh:
                d = json.load(fh)
        except Exception as e:  # noqa: BLE001
            print(f"  [WARN] 跳过无法解析的 {f}: {e}", file=sys.stderr)
            continue
        qid = str(d.get("id") or os.path.splitext(os.path.basename(f))[0])
        flag = d.get("flag") or ""
        if not is_sha256(flag):
            # 非 sha256 的 flag 不是外部真值，按铁律不计入本题
            print(f"  [SKIP] {qid}: flag 非 sha256 真值，不纳入", file=sys.stderr)
            continue
        atts = d.get("attachments") or []
        existing = [a for a in atts if os.path.exists(os.path.join(base, a))]
        ok = bool(existing)
        if atts and ok:
            att_ok += 1
        else:
            att_missing += 1
        probs.append({
            "id": qid,
            "category": d.get("category") or "misc",
            "sub": d.get("category") or "misc",
            # 题面：先取（可选）中性化覆盖，再过 flag 明文遮蔽器——单一漏斗，
            # 保证「覆盖后仍不含 sha256 等于本题 flag 的明文」由同一判据把关。
            "description": sanitize_text(
                DESCRIPTION_OVERRIDES.get(qid, d.get("description") or ""), flag.lower()),
            "title": sanitize_text(d.get("title") or "", flag.lower()),
            "flag_sha256": flag.lower(),
            "difficulty": d.get("difficulty") or "",
            "attachment_declared": bool(atts),
            "attachment_available": ok,
            # 由 copy_attachments 回填：已入仓附件逐文件清单
            "attachment_files": [],
        })
    return probs, att_ok, att_missing, base


def copy_attachments_for(p: dict, src_json: str, base: str) -> int:
    dest_dir = os.path.join(ATT_DIR, safe_id(p["id"]))
    os.makedirs(dest_dir, exist_ok=True)
    with open(src_json, encoding="utf-8") as fh:
        d = json.load(fh)
    n = 0
    for a in d.get("attachments") or []:
        full = os.path.join(base, a)
        if not os.path.exists(full):
            continue
        name = os.path.basename(a)
        shutil.copyfile(full, os.path.join(dest_dir, name))
        excluded = (p["id"], name) in GIT_EXCLUDED_ATTACHMENTS
        entry = {
            "name": name,
            "size": os.path.getsize(full),
            # flag.* 前缀或显式登记的"题目本体但含答案"文件，均按答案形态处理：
            # 剔除口径跳过它们，避免把答案真值喂进求解器制造虚假命中。
            "answer_key_shape": bool(ANSWER_KEY_RE.match(name)) or excluded,
            "git_excluded": excluded,
            "exclude_reason": GIT_EXCLUDED_ATTACHMENTS.get((p["id"], name), ""),
        }
        # 找回附件（来自 A 库 git 历史的实物）：补 sha256 + 来源标注，使重跑生成器与
        # 已提交产物逐字一致。键序刻意与 register_recovered_attachment.py 保持一致。
        recovered_from = RECOVERED_ATTACHMENTS.get((p["id"], name))
        if recovered_from:
            with open(full, "rb") as fh:
                entry["sha256"] = hashlib.sha256(fh.read()).hexdigest()
            entry["recovered_from"] = recovered_from
        p["attachment_files"].append(entry)
        n += 1
    return n


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--src", required=True, help="A 库 questions_real 目录")
    ap.add_argument("--check", action="store_true", help="只校验不写盘")
    args = ap.parse_args()

    if not os.path.isdir(args.src):
        print(f"[FAIL] 源目录不存在: {args.src}", file=sys.stderr)
        return 1

    probs, att_ok, att_missing, base = load_source(args.src)
    if not probs:
        print("[FAIL] 未读到任何题目", file=sys.stderr)
        return 1

    # 附件复制 + 清单回填（按源文件路径逐题处理）
    if not args.check and os.path.isdir(ATT_DIR):
        shutil.rmtree(ATT_DIR)  # 先清后建，保证幂等（无上一轮残留）
    files_by_id = {}
    for f in sorted(glob.glob(os.path.join(args.src, "**", "*.json"), recursive=True)):
        try:
            with open(f, encoding="utf-8") as fh:
                d = json.load(fh)
        except Exception:  # noqa: BLE001
            continue
        qid = str(d.get("id") or os.path.splitext(os.path.basename(f))[0])
        files_by_id.setdefault(qid, f)
    att_files_total = 0
    att_answer_files = 0
    for p in probs:
        if not p["attachment_available"]:
            continue
        src_json = files_by_id.get(p["id"])
        if not src_json:
            continue
        if not args.check:
            att_files_total += copy_attachments_for(p, src_json, base)
        att_answer_files += sum(1 for x in p["attachment_files"] if x["answer_key_shape"])

    # attachments/.gitignore：答案文件只留本地，禁止进入 PUBLIC 仓（每次重生成幂等刷新）
    att_git_excluded = sum(
        1 for p in probs for af in p["attachment_files"] if af.get("git_excluded"))
    if not args.check:
        os.makedirs(ATT_DIR, exist_ok=True)
        lines = [
            "# 由 scripts/build_cross_bench.py 自动生成，请勿手改。",
            "# 含 flag 明文/内嵌答案的附件按交付红线只保留在本地（供「含答案口径」跑分），",
            "# 不进入 PUBLIC 仓库；CI 检出不含这些文件，含答案口径在 CI 上自动降级。",
        ]
        for p in probs:
            for af in p["attachment_files"]:
                if af.get("git_excluded"):
                    lines.append(f"{safe_id(p['id'])}/{af['name']}")
        with open(os.path.join(ATT_DIR, ".gitignore"), "w", encoding="utf-8", newline="\n") as fh:
            fh.write("\n".join(lines) + "\n")

    cats = Counter(p["category"] for p in probs)
    doc = {
        "version": "v1",
        "created": "2026-10-14",
        "source": {
            "repo": "西湖论剑 CTF-Agent (A 库)",
            "path": source_descriptor(args.src),
            "note": "仅作尺；不并入 B 的 KPI 基准 data/ctf_benchmark/",
        },
        "honesty": {
            "input_mode": "text-only",
            "why": f"A 侧真题中仅 {att_ok} 题附件仍存在（{att_missing} 题已缺失）；"
                   "默认口径只喂 description，测得的是 B 的下限而非能力上限。",
            "attachment_available": att_ok,
            "attachment_missing": att_missing,
            "attachment_files_copied": att_files_total,
            "attachment_answer_key_files": att_answer_files,
            "attachment_files_git_excluded": att_git_excluded,
            "git_exclude_reason": "flag 明文/内嵌答案文件按 PUBLIC 仓交付红线只留本地"
                                  "（见 attachments/.gitignore 与逐文件 exclude_reason）；"
                                  "CI 检出不含这些文件，「含答案口径」在 CI 上自动降级为剔除口径。",
            "attachment_subset_note": "附件仍在的题另有「有数据子集」口径"
                                      "（TestCrossBench_AttachmentSubset），含/不含 flag.* 答案文件分别报告；"
                                      "该子集不得写进对外材料当战果。",
            "flag_truth": "沿用 A 的 flag 字段(sha256)，命中判定用 sha256 比对",
        },
        "problems": {p["id"]: p for p in probs},
    }
    stats = {
        "total": len(probs),
        "by_category": dict(cats),
        "attachment_available": att_ok,
        "attachment_missing": att_missing,
        "attachment_files_copied": att_files_total,
        "sha256_of_doc": hashlib.sha256(
            json.dumps(doc, sort_keys=True, ensure_ascii=False).encode("utf-8")
        ).hexdigest(),
    }

    print("=" * 62)
    print(f"  cross-bench 基准构建  题数={len(probs)}")
    print("=" * 62)
    for k, v in sorted(cats.items()):
        print(f"    {k:<10} {v}")
    print(f"    附件仍存在  {att_ok}    附件已缺失  {att_missing}")
    print(f"    复制附件文件  {att_files_total}（其中 flag.* 答案形态 {att_answer_files}；"
          f"git 排除 {att_git_excluded}）")
    print(f"    🔴 输入口径：仅 description（文本口径，非完整同卷）")

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
