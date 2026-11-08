#!/usr/bin/env python3
"""题库完整性审计（2026-10-10 · 防"交付物悄悄腐烂"）。

为什么需要（真实事故链）
------------------------
2026-10-06 我把 87 道真题导出给 SecAutoMind 当"外部基准"，10-10 复核时发现：
  1. 其中 8 题的**唯一附件是 writeup 文本**，而该文本在 `_archive/` 清理时被删 →
     载荷消失，题目变成必然 0 分的坏题；
  2. 另 8 题的附件**就是答案键**（flag.txt 里存裸值）；
  3. 再 5 题没有可判定的真值。
→ 交付出去的"外部真题基准"实际只有 **10 题**能用于推理能力评测，其中未见题仅 1 题。

三类问题都不会自己报错：跑批时它们只是"解不出"，看起来像模型不行。
**必须有一道机器门禁在交付前把坏题挑出来。**

检查项（每题判定）
  payload_missing   声明了附件但磁盘上没有 → 必然 0 分
  answer_key_only   附件只有答案键形态、无真实载荷 → 坏题
  answer_leak       附件里能直接扫到真值 → 不能用于推理能力分母
  no_truth          无 flag_sha256 且 flag 非 sha256 占位 → 无法机器验真伪
  self_authored     自产训练题（不得计入"外部真题"口径）

用法
----
  python scripts/_audit_corpus_integrity.py --root data/questions_real [--json] [--strict]
  # --strict: 出现 broken 级问题即退出码 1（门禁模式）；默认只报告
"""
from __future__ import annotations

import argparse
import hashlib
import json
import os
import re
import subprocess
import sys
from collections import Counter
from datetime import datetime
from pathlib import Path

HEX64 = re.compile(r"^[0-9a-f]{64}$")
FLAG_RE = re.compile(rb"[A-Za-z0-9_]{1,20}\{[^}\s]{4,120}\}")
UUID_LIKE = re.compile(r"^[0-9a-fA-F]{8}-?[0-9a-fA-F]{4}-?[0-9a-fA-F]{4}-?[0-9a-fA-F]{4}-?[0-9a-fA-F]{12}$")
HEX32 = re.compile(r"^[0-9a-fA-F]{32}$")
KEY_NAMES = ("flag", "answer", "key", "pass", "secret")


def sha_hex(s: bytes) -> str:
    return hashlib.sha256(s).hexdigest()


def _matches(cand: bytes, truth: str) -> bool:
    """候选是否命中真值（全串 / 内文 / 裸值三种登记口径）。"""
    if not truth:
        return False
    if sha_hex(cand) == truth:
        return True
    m = re.search(rb"\{(.+)\}", cand, re.DOTALL)
    return bool(m) and sha_hex(m.group(1)) == truth


def vcs_ignored_paths(declared, bases) -> "set[str] | None":
    """批量判定：这些**声明路径**是否被 .gitignore 排除。返回 None = 无法判定。

    🔴 为什么需要（2026-11-08 实证：同一份代码在两台机器上给出两个"可用题"数）：
      `.gitignore:153-159` 有意排除 5 个**含真实答案**的附件（babysthird、
      4 个 flag/key 文件）。它们在作者机器上存在、在任何克隆/服务器上都不存在，
      于是 `questions_real` 的「可用题」是 9（本机）还是 7（服务器）取决于
      **谁手上留了答案副本**。基线只存计数、不存主机，跨机比较必然错一个方向：
      要么把正常机器判成「数据丢失 9→7」，要么在有副本的机器上永远看不到问题。

      判据换成「能否由仓库复现」：只要某题声明的附件命中 .gitignore，
      就**不问它在不在本机**，一律记 `payload_not_in_vcs`（broken）。
      这样无论文件在不在，两台机器的分类都相同 —— 主机无关是构造出来的，不是碰巧。

    bases：`check-ignore` 只按"相对当前目录"匹配，而题面里的声明路径没有统一的
      基准目录（相对仓库子目录 `ctf_agent/`、相对 `data/`、相对 CWD 三种都出现过）。
      所以对每个候选基准各查一遍再取并集。**不会产生假命中**：加了前缀的路径
      与规则里的路径不再逐段相等，`check-ignore` 自然不认。

    git 不可用 / 不在工作树 / 返回码异常 → 返回 None（fail-open 到"不知道"，
    由调用方决定怎么记；绝不返回空集冒充"一条都没被排除"）。
    """
    raw = sorted({normalize_declared_path(p) for p in declared if str(p or "").strip()})
    # `..` 开头的声明（如 `../_archive/...`）落在题库/仓库之外，check-ignore 会整批报错
    # （fatal: path is outside repository）—— 一条坏路径能把 93 条判定全废掉，故先剔掉。
    # ⚠️ 必须在 `lstrip("./")` **之前**判：`lstrip("./")` 会把 `../_archive/x` 削成
    # `_archive/x`，`..` 就消失了，过滤条件形同不存在（实测踩过）。
    paths = [p.lstrip("./") for p in raw if ".." not in p.split("/")]
    if not paths:
        return set()
    if isinstance(bases, (str, Path)):
        bases = [bases]
    payload = ("\0".join(paths) + "\0").encode("utf-8")
    found: "set[str]" = set()
    seen_cwd: "set[str]" = set()
    for b in bases:
        p = str(Path(b).resolve())
        if p in seen_cwd:
            continue
        seen_cwd.add(p)
        # 🔴 必须用 `-z` + 字节流：Windows 上 `input="\n".join(...)` 会被 subprocess 的
        # 文本模式转成 CRLF，git 于是收到 "a.py\r" —— 规则匹配失败并**静默**返回
        # "没被忽略"（实测：同两条路径单条查都命中，批量查只命中最后一条）。
        try:
            r = subprocess.run(["git", "-C", p, "check-ignore", "-z", "--stdin"],
                               input=payload, capture_output=True, timeout=120)
        except (OSError, subprocess.SubprocessError):
            return None
        # 0 = 有命中；1 = 一条都没命中（**不是错误**）；其它 = git 出错
        if r.returncode not in (0, 1):
            return None
        found |= {s.decode("utf-8", "replace")
                  for s in (r.stdout or b"").split(b"\0") if s}
    return found


def pool_is_tracked(root: Path) -> "bool | None":
    """该池目录下是否有文件被 git 跟踪。None = 无法判定。

    为什么需要这一层（2026-11-08 踩到）：`.gitignore` 里有 `data/*` 这种目录级规则，
    所以**一个整池都没入库**时，池里每个附件都会被 `check-ignore` 判成"被忽略"——
    于是 `payload_not_in_vcs` 会把整池题目打成 broken（实测 `questions_ext_A_20261001`
    坏题 0→1）。而「整池都不在仓库」与「题目在仓库、附件故意不入库」是两件事：
    前者由 `check_corpus_health.pool_in_vcs()` 按池处理，后者才是本题的判据。
    """
    try:
        top = subprocess.run(["git", "-C", str(root), "rev-parse", "--show-toplevel"],
                             capture_output=True, text=True, encoding="utf-8",
                             errors="replace", timeout=60)
        if top.returncode != 0 or not top.stdout.strip():
            return None
        top_p = Path(top.stdout.strip())
        try:
            rel = Path(os.path.relpath(Path(root).resolve(), top_p)).as_posix()
        except ValueError:  # 不同盘符
            return None
        r = subprocess.run(["git", "-C", str(top_p), "ls-files", "-z", "--", rel],
                           capture_output=True, timeout=120)
    except (OSError, subprocess.SubprocessError):
        return None
    if r.returncode != 0:
        return None
    return bool(r.stdout)


def normalize_declared_path(rel: str) -> str:
    """把题面声明的附件路径归一成 POSIX 分隔符（`\\` → `/`）。

    🔴 2026-11-08 实证（Linux 上 39/42 道外部题被判 payload_missing）：
      外部池的 `attachments` 是在 Windows 上生成的，写的是
      `data\\questions_external\\crypto\\ext_gctf2021_h1\\_attachments\\chall.py`。
      POSIX 的 `Path` **不把反斜杠当分隔符**，整串被当成一个 59 字符的文件名，
      于是 `base/rel`、`root/rel` 五个候选全落空 —— 附件明明在磁盘上（同样的
      221 个文件已入库），却被判"载荷缺失"。

    后果不是"多一条警告"：`check_corpus_health` 据此报
    「questions_external 可用题 39 → 0（-39）」与「坏题 3 → 42（+39）」，
    把一次**路径风格差异**读成 39 道题丢失；反向更糟 —— 若真丢题，读数与这条
    假告警长得一模一样，告警就失去分辨力。

    为什么不做数据迁移（把 221 个 json 里的反斜杠改掉）：
      Windows 的 `Path` 两种分隔符都认，改数据只是把同一个兼容性负担搬到数据侧，
      且会动 221 个已入库文件（大 diff、易冲突）。在**解析单点**归一，Windows/Linux
      两侧都通。同一做法已存在于 `_bench_adapter.py:196`（`decl.replace("\\\\","/")`），
      此前只有审计这一处漏了。
    """
    return str(rel or "").replace("\\", "/")


def _resolve_attachment(rel: str, fp: Path, root: Path,
                        att_root: "Path | None" = None) -> "Path | None":
    """解析单个附件声明路径 → 磁盘实际文件/目录；找不到返回 None。

    解析候选序（单一事实源，`missing_attachments` 与 `audit_question` 共用，
    避免「两处各写一遍」的判定漂移）：
      base=CWD(仓库根) → 绝对路径自身 → 题库根 → 仓库根 → base.parent

    🔴 2026-10-26 修正：judge 由 `is_file()` 改为 `exists()`。
    原实现把**目录形态的附件**误判为缺失——`ext_gctf2022_enigma` 声明的 `enigma/`、
    `messages/` 是目录（前者 7 个源文件，后者含 may_12_2022/flag.ciphertext.txt 与
    flag.fernet.txt，即本题密文与密钥），却被 `missing_attachments` 报"缺 2 项"。
    目录同样是合法题面输入（如整包源码、多日期密文），故只判断"是否存在"。

    🔴 同日二次修正：单纯 `exists()` 会让**空目录**也算有效附件（实测确认），
    与 `attachment_available` 的"空壳附件"是同一类漏洞。故：
      文件 → 存在即可；目录 → 必须**内含至少一个文件**（递归非空）才算存在。
    这条判据仍不看内容质量（不含"文件是否够大/是否有用"），那属 `attachment_available`
    的内容有效性范畴，不在本函数职责内。
    """
    base = att_root or Path.cwd()
    rel = normalize_declared_path(rel)
    cands = [base / rel, Path(rel), root / rel, root.parent / rel, base.parent / rel]

    def _usable(c: Path) -> bool:
        if c.is_file():
            return True
        if c.is_dir():
            return any(p.is_file() for p in c.rglob("*"))
        return False

    return next((c for c in cands if _usable(c)), None)


def missing_attachments(q: dict, fp: Path, root: Path,
                        att_root: "Path | None" = None) -> "list[str]":
    """返回题面声明了、但磁盘上找不到的附件清单（**逐文件**，非「全缺才算」）。

    为什么必须逐文件（2026-10-14 实证）：能力分母 heldout_candidates=1 的
    `real_reverse_js` 声明 2 个附件、只缺 1 个（flag 源头 index.html，10-12 删除
    事件永久丢失）—— 按「全缺才算」判定它是健康的，而它结构上不可解。
    缺一个就足够让 0/N 被误读成「模型能力失败」。
    """
    return [str(rel) for rel in (q.get("attachments") or [])
            if _resolve_attachment(str(rel), fp, root, att_root) is None]


def audit_question(q: dict, fp: Path, root: Path, att_root: Path | None = None,
                   vcs_ignored: "set[str] | None" = None) -> dict:
    qid = str(q.get("id") or fp.stem)
    truth = str(q.get("flag_sha256") or "").strip().lower()
    flag_field = str(q.get("flag") or "").strip().lower()
    if not truth and HEX64.match(flag_field):
        truth = flag_field  # flag 字段本身是 sha256 占位
    issues, atts = [], list(q.get("attachments") or [])
    # 声明路径命中 .gitignore ⇒ 该题**不由仓库复现**（见 vcs_ignored_paths 的注释）。
    # 与"文件在不在本机"无关，故两台机器同判。
    not_in_vcs = sorted({str(a) for a in atts
                         if vcs_ignored
                         and normalize_declared_path(str(a)).lstrip("./") in vcs_ignored})
    if not_in_vcs:
        issues.append("payload_not_in_vcs")
    payload_on_disk, keyish, leak = 0, 0, False
    for rel in atts:
        # 多候选解析的历史坑（2026-10-12 real_reverse_vnctf_cm1：附件路径带
        # ctf_agent/ 前缀而 att_root 已是 ctf_agent）见 `_resolve_attachment` 注释。
        p = _resolve_attachment(str(rel), fp, root, att_root)
        if p is None:
            continue
        payload_on_disk += 1
        if not p.is_file():
            # 目录形态附件（2026-10-26）：计入载荷存在，但无单文件字节可扫
            # （密钥/泄露判定按文件粒度做，目录交由上游按需展开）
            # ⚠️ 已知边界：目录内部的明文答案**不会被本函数检出**。当前全库
            # 目录形态附件内实测 0 个 flag 形态串（2026-10-26 核验），故无实际漏检；
            # 若将来引入含答案的目录附件，需在此展开递归扫描。
            continue
        raw = p.read_bytes()
        if any(k in p.name.lower() for k in KEY_NAMES):
            txt = raw.decode("utf-8", errors="ignore").strip()
            if len(txt) <= 200 and (HEX32.match(txt) or UUID_LIKE.match(txt)
                                     or _matches(txt.encode(), truth)):
                keyish += 1
        if len(raw) <= 65536:
            for cand in FLAG_RE.findall(raw) + [raw.strip()]:
                if cand and _matches(cand, truth):
                    leak = True
                    break
    if atts and payload_on_disk == 0:
        issues.append("payload_missing")
    elif atts and keyish == payload_on_disk and keyish > 0:
        issues.append("answer_key_only")
    if leak:
        issues.append("answer_leak")
    if not truth:
        issues.append("no_truth")
    prov = str(q.get("provenance") or "").lower()
    if any(k in prov for k in ("self_authored_training", "self-authored", "自产")):
        issues.append("self_authored")
    level = ("broken" if {"payload_missing", "answer_key_only", "no_truth",
                          "payload_not_in_vcs"} & set(issues)
             else "leaky" if "answer_leak" in issues else "ok")
    return {"id": qid, "file": str(fp), "level": level, "issues": issues,
            "attachments": len(atts), "payload_on_disk": payload_on_disk,
            "payload_not_in_vcs": not_in_vcs}


def _in_support_dir(fp: Path, root: Path) -> bool:
    """`_` 前缀目录（`_attachments/`、`_archive/` 等）里的是**支持文件**目录。

    注意：只用来决定「非题目形态的文件要不要跳过」，**不**用来整体排除目录 ——
    池里确实有题目定义放在 `_` 目录之外、清单放在 `_attachments/` 里；
    把整个 `_` 目录排掉会让 `total` 无故变小，而 `total` 变小正是「数据丢失」的判据
    （实测：整体排除会让 questions_external 42→39、questions_ext 37→34，
    凭空多出两条「题目池缩水」警告）。

    为什么这个函数存在（2026-11-08 实证）：`data/questions_real/_attachments/
    _hygiene_manifest.json` 是一个 JSON **数组**（清单，不是题目）。旧实现把池里
    所有 `*.json` 都当题目，于是 `audit_question()` 对 list 调 `.get()` 抛
    AttributeError → 整池审计崩溃 → 上游 `check_corpus_health.snapshot()` 的
    `except Exception: continue` 把它吞成「该池不在快照里」→ 门禁报
    **「questions_real: 池消失（曾有 93 题）」**。一条清单文件伪造了一场数据丢失。
    基线里 `questions_real.total = 93` 而磁盘上有 94 个 json，差的正是这一个。
    """
    rel = fp.relative_to(root)
    return any(part.startswith("_") for part in rel.parts[:-1])


def audit(root: Path, att_root: Path | None = None) -> dict:
    # 两趟：先把 (题目, 声明路径) 收齐，**一次** git check-ignore 批量判定，
    # 再逐题分级。为什么必须两趟：批量查是一次 subprocess，逐题查会是 93 次。
    # 行序与单趟实现完全一致（parse_error / not_question_object 也在队列里占位）。
    queue: list[tuple[Path, "dict | None", "dict | None"]] = []
    for fp in sorted(root.rglob("*.json")):
        try:
            q = json.loads(fp.read_text(encoding="utf-8"))
        except Exception as exc:  # noqa: BLE001
            queue.append((fp, None, {"id": fp.stem, "file": str(fp), "level": "broken",
                                     "issues": [f"parse_error:{exc}"], "attachments": 0,
                                     "payload_on_disk": 0}))
            continue
        if not isinstance(q, dict):
            if _in_support_dir(fp, root):
                # 支持目录里的清单/索引：不是题目，也不是坏题 —— 不计数
                continue
            # 非对象形态无法当题目判：记 broken（可见），绝不静默跳过——
            # 静默跳过会让 total 悄悄变小，而 total 变小正是「数据丢失」的判据。
            queue.append((fp, None, {"id": fp.stem, "file": str(fp), "level": "broken",
                                     "issues": [f"not_question_object:{type(q).__name__}"],
                                     "attachments": 0, "payload_on_disk": 0}))
            continue
        queue.append((fp, q, None))

    declared = [str(a) for _fp, q, _r in queue if q for a in (q.get("attachments") or [])]
    # 池本身不在版本库 ⇒ 整池都是"被忽略"，这属于池级问题（pool_in_vcs 负责），
    # 不能下沉成"每题附件不在库"，否则整池题目会凭空转 broken。
    pool_tracked = pool_is_tracked(root)
    # 两个候选基准：调用方给的附件根（与 _resolve_attachment 同基准）、仓库子目录
    # `ctf_agent/`（= root.parent.parent，标准布局）。
    # ⚠️ **不能**把 `root.parent`（`data/` 目录）也加进来：声明路径 `data/questions_real/...`
    # 相对 `data/` 会变成 `data/data/questions_real/...`，命中 `data/*` 规则 ⇒ 93 题全被
    # 判"被忽略"（实测踩过：questions_real broken 82→93）。基准多一个就全错。
    vcs_bases = [att_root or Path.cwd(), root.parent.parent]
    vcs_ignored = vcs_ignored_paths(declared, vcs_bases) if pool_tracked else None

    rows = []
    for fp, q, pre in queue:
        rows.append(pre if pre is not None
                    else audit_question(q, fp, root, att_root, vcs_ignored=vcs_ignored))
    levels = Counter(r["level"] for r in rows)
    issue_counts = Counter(i.split(":")[0] for r in rows for i in r["issues"])
    usable = [r for r in rows if r["level"] == "ok"]
    return {"generated_at": datetime.now().strftime("%Y-%m-%dT%H:%M:%S"),
            "root": str(root), "total": len(rows),
            "by_level": dict(levels), "by_issue": dict(issue_counts),
            "usable_for_reasoning": len(usable),
            # None = 没能判定「哪些题不由仓库复现」；不是"没有"
            "vcs_check": ("pool_not_tracked" if pool_tracked is False
                          else "ok" if vcs_ignored is not None else "unavailable"),
            "broken_list": [r["id"] for r in rows if r["level"] == "broken"],
            "rows": rows}


def main() -> int:
    ap = argparse.ArgumentParser(description="题库完整性审计")
    ap.add_argument("--root", default="data/questions_real")
    ap.add_argument("--att-root", default=".",
                    help="附件相对路径的解析根（默认当前目录=仓库根）")
    ap.add_argument("--json", action="store_true")
    ap.add_argument("--strict", action="store_true", help="有 broken 题即退出码 1")
    args = ap.parse_args()
    root = Path(args.root)
    if not root.is_dir():
        print(f"[audit] 题库目录不存在: {root}")
        return 2
    rep = audit(root, Path(args.att_root))
    if args.json:
        print(json.dumps(rep, ensure_ascii=False, indent=1))
    else:
        print(f"[audit] {root}：共 {rep['total']} 题")
        print(f"  可用于推理评测(ok): {rep['usable_for_reasoning']}")
        print(f"  分层: {rep['by_level']}")
        print(f"  问题计数: {rep['by_issue']}")
        if rep["broken_list"]:
            print(f"  ❌ 坏题 {len(rep['broken_list'])} 道（前 12）:")
            for qid in rep["broken_list"][:12]:
                print("     -", qid)
    if args.strict and rep["by_level"].get("broken"):
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
