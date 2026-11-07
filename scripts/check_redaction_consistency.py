#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""脱敏一致性门禁 —— 「脱敏」与「判分口径」必须同源，且每一次脱敏都要入账。

为什么需要它（2026-11-04 实锤，不是假想）：
  `data/ctf_benchmark/benchmark.json` 的 15 题题面被改成 `flag{REDACTED_*}`，
  但 `scripts/arena_manifest.json` 仍拿**原 flag** 判分 → 这 15 题在
  `arena-regression-gate` 上被永久判成「退化」（stable=40 / regressed=15）。
  同一批脱敏（`real_benchmark.json` 的 4 题 `prompt_answer_redacted`）把
  `static` 命中从 20/55 压到 16/55，而 `docs/benchmark_baseline.json` 的地板
  仍是 20 → evidence / parity / quant 三个 job 同时红。
  两次都是**同一个机制**：为了不泄密而改语料，判据没有跟着改，也没有任何人
  把这件事记在一处，于是「红」被叫作「历史遗留」。

本门禁只做以下确定性判定，不猜、不测能力：
  R1 语料里每一处脱敏都必须在台账登记；台账外的**新增**脱敏直接红。
  R2 登记项必须声明脱敏字段（`prompt_answer_redacted_fields` 非空），
     说不清「脱了哪一段」的脱敏不接受。
  R3 若该题仍被判分消费（当前消费方：`scripts/arena_manifest.json`），
     题面已脱敏的题**不得再被要求给出答案**——必须显式标 `expect=not_attemptable`
     （不执行、不计入 stable/regressed）；标了就视为已同步（`status=synced`）。
     没标却仍指望答案 = 恒判退化，必红。
  R4 台账里登记、语料里已不存在的脱敏 → 台账悬空，红（避免台账变成装饰）。
  R5 同一题内既有脱敏串又有非脱敏形态的 `flag{...}` → 脱敏漏了，红（泄密）。
  R6 声明了 `baseline_impact` 的，`docs/benchmark_baseline.json` 的地板必须
     要么已改成 `to`，要么仍是 `from` 且该条为 `accepted_debt`——
     防止「改了口径却不重锁地板」这类静默漂移。
  R7 判分清单（arena_manifest）里**不得再出现明文 `flag`**（service 模式例外，且必须
     声明 `flag_from_env`）——只能存 `flag_sha256`。2026-11-04 实测：题面脱敏后，
     该清单仍以明文躺着全部 15 题答案，脱敏被答案表原样抵消。
  R8 台账必须**有人负责、有到期日、不能靠手改延期**（2026-11-04 用户拍板「负责人就是
     agent」后补）：owner 非空且不是 `unassigned`；expires 必填、合法、未过期，
     且不得超过 MAX_EXPIRY_DAYS 天（防止「填 2999 年 = 永不复查」）；
     若条目带 `renewals`，最后一条的 to 必须等于当前 expires，且须有 date/by/reason
     （防止手改 JSON 悄悄延期，续期只能走 `--renew --reason`）。
  R9 **全域答案明文**：R1~R7 只守 `data/ctf_benchmark/*.json` 与判分清单，但同一份答案
     还可能躺在测试夹具、归档文档、生成器里——读一眼就能抄。故扫描**入仓文本文件**，
     任何位置出现「sha256 与已知答案相符」的明文即红；确需保留的（如题目生成器必须
     知道明文才能出题）登记在 `redaction_exempt.json` 豁免表，豁免同样要 owner + 到期日
     （复用 R8 口径），命中消失后豁免变悬空 → 红。
  R10 **历史防线**：R9 只清 HEAD，而 git 历史里留着的明文照样 `git log -p` 能抄走，
     要擦还得改写历史（不可逆）。故从 HISTORY_SINCE 起，**任何新提交的新增行**都不许
     再把答案明文写进仓库；删除行不算（那是历史债，不是新债）。

退出码：0 = 一致（含已入账的债）｜1 = 存在违规｜2 = 用法/文件错误。
口径说明：本门禁**不**判断债务该不该还，只保证债务被看见、被记名、有期限。
债务未清偿期间相关 job 仍会红，这是设计意图：红是债的账单，不是绿。

用法：
  python scripts/check_redaction_consistency.py            # 检查（CI 入口）
  python scripts/check_redaction_consistency.py --update-ledger \\
      --owner agent [--expires YYYY-MM-DD]                 # 新增脱敏时同步台账
  python scripts/check_redaction_consistency.py --update-ledger --renew \\
      --owner agent --expires YYYY-MM-DD --reason "<为何延期>"   # 到期后续期（留痕）
  python scripts/check_redaction_consistency.py --root <目录>   # 供自测使用
"""

from __future__ import annotations

import argparse
import hashlib
import json
import os
import re
import subprocess
import sys
from datetime import date, timedelta
from pathlib import Path

CORPUS_DIR = "data/ctf_benchmark"
LEDGER_REL = "data/ctf_benchmark/redaction_ledger.json"
MANIFEST_REL = "scripts/arena_manifest.json"
BASELINE_REL = "docs/benchmark_baseline.json"

REDACTED_TOKEN = re.compile(r"flag\{REDACTED_[A-Za-z0-9_]+\}")
ANY_FLAG = re.compile(r"flag\{[^}]{3,}\}")
VALID_STATUS = {"synced", "accepted_debt"}
# 到期日上限：脱敏是「临时遮住」，不是「永久封存」。超过一年的到期日等同于没有到期日，
# 而「填个很久以后的日子」正是把记账动作做空的最省力方式，故由机器卡死。
MAX_EXPIRY_DAYS = 365
OWNER_PLACEHOLDERS = {"", "-", "unassigned", "tbd", "TODO", "todo"}

# R9 全域答案明文扫描用的面：入仓文本文件（CI 干净检出 = 入仓内容，天然排除他人 WIP）
EXEMPT_REL = "data/ctf_benchmark/redaction_exempt.json"
ANSWER_SHAPE = re.compile(r"[A-Za-z0-9_]{1,24}\{[^}\s]{1,160}\}")
ANSWER_SKIP_EXT = {".png", ".jpg", ".jpeg", ".gif", ".webp", ".ico", ".zip", ".gz",
                   ".7z", ".pdf", ".docx", ".xlsx", ".pptx", ".pyc", ".so", ".dll",
                   ".exe", ".bin", ".woff", ".woff2", ".ttf", ".mp4", ".wav",
                   ".sqlite", ".db"}
ANSWER_SKIP_DIRS = {".git", "node_modules", "__pycache__", ".venv", ".idea"}
MAX_SCAN_BYTES = 2 * 1024 * 1024

# R10 历史防线：从 HISTORY_SINCE 起，任何提交都不许**再次**把答案明文写进仓库。
# 理由是清除只对 HEAD 有效：一旦明文进了历史，`git log -p` 照样能抄走，
# 而且再想擦就得改写历史（不可逆）。
#
# 2026-11-07 起点从 6ea2c81 前移到 b2c9ba6（本轮「答案库 126→434 + 证据日志脱敏」）。
# 前移原因必须写清楚，否则前移就等于把历史红擦掉：6ea2c81 之后那 47 个提交里有
# 778 处新增明文，全部由「答案库扩容后新纳入的 306 条哈希」照出来——此前判据看不见，
# 不代表不存在。旧债没有消失，只是换了记录位置：
#   · `history_exposure.json`（R11）逐哈希记了曾进过历史的答案、命中数、首末提交；
#   · `plaintext_debt.json`（R12）记 HEAD 面剩下的 222 条，只减不增且带到期日。
# 所以 R10 现在管「新债」，旧债由 R11/R12 盯着。门禁输出会打印窗口内命中条数，
# 前移前必须先看到它是 0（或已另记账）。
HISTORY_SINCE = "b2c9ba6"
MAX_HISTORY_COMMITS = 200

# 起点前移必须留下账：上一段窗口（旧 SINCE..新 SINCE）里到底有多少处明文被「移出防线范围」。
# 这些数字写进 history_exposure.json 的 legacy 字段，门禁逐项核对——否则「移前起点」
# 就是一句无法验证的声明，等于把 778 处历史明文擦成 0 处红。
LEGACY_WINDOW = {
    "since_prev": "6ea2c81",
    "commits": 47,      # 旧起点到新起点之间的提交数
    "hits": 778,        # 该窗口内新增行里命中的答案明文处数（扩容答案库后照出）
}

# R11 历史暴露事实表：R10 只保证「从此零新增」，但**已经进过历史的答案**仍在
# （本轮全历史实测：665 提交 / 3269 处新增行命中 / 348 个答案字面，而远端仓库是
#  PUBLIC）——任何人 clone 后 `git log -p` 就能抄走。事实必须先记下来，否则
# 「已泄」与「未泄」只能靠口头，对外口径随时可以说反。
# 本表是**生成物**：`--update-exposure` 全历史流式扫描后写出，禁止手改。
# **只记哈希、不记字面**：事实表自己若带明文，就会变成新的明文载体（自测 T31 抓出）。
# 校验只做能离线判真的两项（不重扫历史，避免每次 CI 都跑几百 MB 的 `git log -p`）：
#   E1 哈希形状合法、ids 能对上、hits 为正、无重复登记；
#   E2 status 必须与「现在还是不是判分用的答案」一致：仍是 → exposed，已轮换 → rotated。
# 「漏记」由 R10 结构性拦住：从 HISTORY_SINCE 起新明文进不了历史，就不会多出未记的暴露。
EXPOSURE_REL = "data/ctf_benchmark/history_exposure.json"
EXPOSURE_STATUS = {"exposed", "rotated", "pending_corpus"}

# R12 明文债棘轮（2026-11-07）：题库从 3 个文件扩到 33 个、答案从 126 条涨到 434 条后，
# 放宽扫描面立刻照出 1064 处入仓明文——说明此前「命中 0」是**判据看不见**，不是真干净。
# 一次清完不现实（生成器/靶场/测试夹具需要用真值才能产出与断言），但可以把债冻住：
#   · 债表里的（文件, 答案哈希）＝已入账的旧债，允许存在；
#   · 不在债表里的一律判红（新增明文不行）；
#   · 债表整体有 owner + 到期日，过期即红（不许无限期挂着）；
#   · 债只能变小：条目消失不算错（那是还债），但重新出现要靠 `--update-debt` 记回来。
DEBT_REL = "data/ctf_benchmark/plaintext_debt.json"


def str_fields(obj, path=""):
    """递归取出 (json 路径, 字符串值)，用于定位脱敏字段。"""
    if isinstance(obj, dict):
        for k, v in obj.items():
            yield from str_fields(v, "%s/%s" % (path, k))
    elif isinstance(obj, list):
        for i, v in enumerate(obj):
            yield from str_fields(v, "%s[%d]" % (path, i))
    elif isinstance(obj, str):
        yield path, obj


def iter_problems(doc):
    """兼容 problems 为 dict 或 list 两种形态。"""
    probs = doc.get("problems") if isinstance(doc, dict) else None
    if isinstance(probs, dict):
        for k, v in probs.items():
            if isinstance(v, dict):
                yield str(k), v
    elif isinstance(probs, list):
        for p in probs:
            if isinstance(p, dict):
                name = p.get("id") or p.get("name") or p.get("title") or "?"
                yield str(name), p


def scan_corpus(root: Path) -> list[dict]:
    """返回每道被脱敏题：文件、题名、脱敏字段、残留明文。"""
    out = []
    cdir = root / CORPUS_DIR
    if not cdir.is_dir():
        return out
    for f in sorted(cdir.glob("*.json")):
        try:
            doc = json.loads(f.read_text(encoding="utf-8", errors="ignore"))
        except json.JSONDecodeError:
            continue
        for name, prob in iter_problems(doc):
            fields = [p for p, s in str_fields(prob) if "REDACTED" in s]
            if not fields:
                continue
            residual = []
            for p, s in str_fields(prob):
                for m in ANY_FLAG.findall(s):
                    if not REDACTED_TOKEN.fullmatch(m):
                        residual.append(p)
                        break
            declared = [p for p in (prob.get("prompt_answer_redacted_fields") or [])]
            out.append({
                "file": str(f.relative_to(root)).replace("\\", "/"),
                "problem": name,
                "fields": sorted(set(fields)),
                "declared_fields": declared,
                "residual": sorted(set(residual)),
                "text": " ".join(s for _, s in str_fields(prob)),
            })
    return out


def load_json(p: Path, default):
    if not p.is_file():
        return default
    return json.loads(p.read_text(encoding="utf-8"))


def collect_answer_hashes(root: Path, include_untracked: bool = False) -> dict:
    """已知答案哈希 → [来源标识]。口径与判分同源：sha256(整串候选)。

    2026-11-07 改：原先只读 arena_manifest + real_benchmark + benchmark 三处，
    而题库已扩到 33 个 problem 文件 / 432 条哈希（私有题库 v1/v2、纯 LLM 两版、
    ycb 静态题…）。判据写死三个文件名，等于新题库的答案**不被任何明文扫描保护**——
    这是「语料往前走了、判据原地不动」的又一次复发（R9 上线时同款），
    所以改成按目录自动发现：凡是 `problems` 里带 flag_sha256 的都算真值源。
    """
    known: dict[str, list[str]] = {}
    manifest = load_json(root / MANIFEST_REL, [])
    cases = manifest if isinstance(manifest, list) else (manifest.get("cases") or [])
    for c in cases:
        if isinstance(c, dict) and c.get("flag_sha256"):
            known.setdefault(str(c["flag_sha256"]).strip().lower(), []).append(
                "arena:%s" % c.get("name"))
    corpus_dir = root / CORPUS_DIR
    if not corpus_dir.is_dir():
        return known
    # 判据只认**入仓**的题库文件：未跟踪的题库是并行会话在途 WIP，CI 干净检出里没有它。
    # 实测（2026-11-07，CI job 128351584627）：本地从磁盘读全部 *.json 得到 434 条哈希，
    # CI 只有 414 条 → 同一份历史暴露表在两处得出**相反的 status**（17 条被判「谎报 exposed」）。
    # 判据读的是开发机的草稿目录，而不是仓库内容，就不可能和 CI 一致。
    corpus_files = None
    if _git_out(root, "rev-parse", "--git-dir") is not None and not include_untracked:
        corpus_files = _tracked_json(root, CORPUS_DIR)
    paths = ([corpus_dir / n for n in corpus_files] if corpus_files is not None
             else sorted(corpus_dir.glob("*.json")))
    for p in sorted(paths):
        if not p.is_file():
            continue
        try:
            doc = load_json(p, {})
        except (ValueError, UnicodeDecodeError):
            continue
        for name, prob in iter_problems(doc):
            if not isinstance(prob, dict):
                continue
            # flag_sha256_inner 是「内层 flag」口径（ycb 静态题），与主 flag 同等看待：
            # 内层答案照样能被抄，判分也照样用它。
            for key in ("flag_sha256", "flag_sha256_inner"):
                h = str(prob.get(key) or "").strip().lower()
                if h:
                    known.setdefault(h, []).append(
                        "%s/%s#%s" % (CORPUS_DIR, p.name, name))
    return known


def _tracked_json(root: Path, subdir: str) -> list[str] | None:
    """列出 subdir 下**已入仓**的 .json 文件名；git 不可用时返回 None（调用方回退 glob）。"""
    try:
        out = subprocess.run(["git", "ls-files", "-z", "--", subdir], cwd=str(root),
                             capture_output=True, text=True, encoding="utf-8")
    except OSError:
        return None
    if out.returncode != 0:
        return None
    names = []
    prefix = subdir.rstrip("/") + "/"
    for rel in out.stdout.split("\0"):
        if not rel.startswith(prefix) or not rel.lower().endswith(".json"):
            continue
        rest = rel[len(prefix):]
        if "/" in rest:      # 只取目录顶层，与 glob("*.json") 同口径
            continue
        names.append(rest)
    return names


def _scan_files(root: Path) -> list[str]:
    """扫描面：git 仓库取入仓文件；非仓库（自测夹具）退回全目录遍历。"""
    try:
        out = subprocess.run(["git", "ls-files", "-z"], cwd=str(root),
                             capture_output=True, text=True, encoding="utf-8")
    except OSError:
        out = None
    if out is not None and out.returncode == 0:
        return [p for p in out.stdout.split("\0") if p.strip()]
    files = []
    for dirpath, dirnames, filenames in os.walk(root):
        dirnames[:] = [d for d in dirnames if d not in ANSWER_SKIP_DIRS]
        for fn in filenames:
            files.append(str(Path(dirpath, fn).relative_to(root)))
    return files


def scan_answer_plaintext(root: Path, known: dict) -> tuple[list[tuple[str, str, list[str]]], int]:
    """返回 (命中列表, 被跳过的超限文件数)。跳过数要显式报出，不许静默放过。"""
    hits = []
    skipped = 0
    for rel in _scan_files(root):
        if os.path.splitext(rel)[1].lower() in ANSWER_SKIP_EXT:
            continue
        p = root / rel
        try:
            if p.stat().st_size > MAX_SCAN_BYTES:
                skipped += 1
                continue
            txt = p.read_text(encoding="utf-8", errors="ignore")
        except OSError:
            continue
        for m in ANSWER_SHAPE.finditer(txt):
            cand = m.group(0)
            if "REDACTED" in cand:
                continue
            h = hashlib.sha256(cand.encode("utf-8")).hexdigest()
            if h in known:
                hits.append((rel.replace("\\", "/"), cand, known[h]))
    return hits, skipped


def _git_out(root: Path, *args: str) -> str | None:
    """跑一条 git 命令，失败返回 None（调用方必须按 fail-closed 处理）。"""
    try:
        r = subprocess.run(["git", *args], cwd=str(root), capture_output=True,
                           text=True, encoding="utf-8", errors="ignore")
    except OSError:
        return None
    if r.returncode != 0:
        return None
    return r.stdout


def scan_patch_added(text: str, known: dict) -> list[tuple[str, str, str, list[str]]]:
    """从 `git log -p` 文本里只看**新增行**（`+`，不是 `+++`）。

    删除行不算新增泄密（它是历史债，不是新债）；只看 `+` 才能做到
    「从某提交起零新增」，否则每一笔清污提交都会被自己判红。
    返回 [(commit, 文件, 字面, 对应)]。
    """
    hits: list[tuple[str, str, str, list[str]]] = []
    commit = "?"
    path = "?"
    in_msg = False
    for raw in text.splitlines():
        if raw.startswith("commit ") and len(raw) > 8:
            parts = raw.split()
            if len(parts) >= 2:
                commit = parts[1][:8]
            in_msg = True
            continue
        if raw.startswith("diff --git "):
            in_msg = False
            frag = raw[len("diff --git "):]
            idx = frag.find(" b/")
            path = frag[idx + 3:].strip() if idx >= 0 else frag.strip()
            continue
        if in_msg:
            # 提交信息正文（`git log` 里以 4 空格缩进；Author/Date 顶格）。
            # 为什么要扫它：公开仓上 commit message 和 diff 一样会被 `git log`
            # 原样打印出去——有人把答案写进 message，换个地方就照样泄密。
            if not raw.startswith("    "):
                continue
            where = "提交信息"
        else:
            if not raw.startswith("+") or raw.startswith("+++"):
                continue
            where = path
        for m in ANSWER_SHAPE.finditer(raw):
            cand = m.group(0)
            if "REDACTED" in cand:
                continue
            h = hashlib.sha256(cand.encode("utf-8")).hexdigest()
            if h in known:
                hits.append((commit, where, cand, known[h]))
    return hits


def check(root: Path) -> tuple[int, list[str]]:
    lines: list[str] = []
    fails: list[str] = []

    corpus = scan_corpus(root)
    ledger_path = root / LEDGER_REL
    ledger = load_json(ledger_path, {"schema": 1, "entries": []})
    entries = ledger.get("entries") or []
    manifest = load_json(root / MANIFEST_REL, [])
    baseline = load_json(root / BASELINE_REL, {"suites": {}})

    man_by_name = {}
    if isinstance(manifest, list):
        for c in manifest:
            if isinstance(c, dict) and c.get("name"):
                man_by_name[c["name"]] = c
    elif isinstance(manifest, dict):
        for c in manifest.get("cases", []):
            if isinstance(c, dict) and c.get("name"):
                man_by_name[c["name"]] = c

    lines.append("=== 脱敏一致性门禁（脱敏 ↔ 判分口径 必须同源）===")
    lines.append("  语料：%s/*.json —— 脱敏题 %d 道" % (CORPUS_DIR, len(corpus)))
    lines.append("  台账：%s —— 登记 %d 条" % (LEDGER_REL, len(entries)))

    # R7 答案表泄密（先查，因为它比「口径不一致」更严重）
    for c in man_by_name.values():
        if "flag" not in c:
            continue
        if c.get("mode") == "service" and c.get("flag_from_env"):
            continue
        fails.append("R7 答案表泄密：arena_manifest 条目 %r 仍是明文 flag"
                     "（local 模式只能存 flag_sha256）" % c.get("name"))
    sha_cases = sum(1 for c in man_by_name.values() if c.get("flag_sha256"))
    exc_cases = sum(1 for c in man_by_name.values()
                    if str(c.get("expect") or "") == "not_attemptable")
    lines.append("  判分清单：%d 条 —— 哈希判分 %d ｜ 声明不可判 %d ｜ 明文答案 %d"
                 % (len(man_by_name), sha_cases, exc_cases,
                    len([c for c in man_by_name.values() if "flag" in c])))

    entry_by_key = {(e.get("file"), e.get("problem")): e for e in entries}
    current_keys = {(c["file"], c["problem"]) for c in corpus}
    ledger_keys = set(entry_by_key)

    # R1 新增未登记 / R4 台账悬空
    for key in sorted(current_keys - ledger_keys):
        fails.append("R1 未登记的新增脱敏：%s :: %s（脱敏必须入账；用 --update-ledger 同步）" % key)
    for key in sorted(ledger_keys - current_keys):
        fails.append("R4 台账悬空：%s :: %s（语料里已无该脱敏，须同步删除）" % key)

    debt, synced = [], []
    for c in corpus:
        key = (c["file"], c["problem"])
        e = entry_by_key.get(key)
        if not e:
            continue
        # R2 声明字段
        if not c["declared_fields"]:
            fails.append("R2 未声明脱敏字段：%s :: %s（缺 prompt_answer_redacted_fields）" % key)
        # R5 残留明文
        if c["residual"]:
            fails.append("R5 脱敏不彻底：%s :: %s 仍有非脱敏 flag 形态（字段 %s）"
                         % (key[0], key[1], ",".join(c["residual"])))
        # R3 判分消费方一致性：题面脱敏后，判分不得再要求这题给出答案
        consumer = man_by_name.get(c["problem"])
        judge_synced = True
        if consumer:
            judge_synced = str(consumer.get("expect") or "") == "not_attemptable"
        status = e.get("status")
        if status not in VALID_STATUS:
            fails.append("R3 状态非法：%s :: %s status=%r（须为 synced / accepted_debt）"
                         % (key[0], key[1], status))
            continue
        if judge_synced and status != "synced":
            fails.append("R3 口径已同步却登记为债务：%s :: %s（须改 status=synced）" % key)
        if (not judge_synced) and status != "accepted_debt":
            fails.append("R3 题面已脱敏但判分仍要求答案：%s :: %s"
                         "（arena_manifest 须标 expect=not_attemptable；否则该题恒判退化）" % key)
        if status == "accepted_debt":
            exp = e.get("expires")
            if exp:
                try:
                    if date.fromisoformat(exp) < date.today():
                        fails.append("R3 债务到期：%s :: %s expires=%s（到期必须收口）"
                                     % (key[0], key[1], exp))
                except ValueError:
                    fails.append("R3 expires 非法日期：%s :: %s %r" % (key[0], key[1], exp))
            debt.append((c["file"], c["problem"], e.get("owner") or "-", exp or "-",
                         "arena_manifest" if not judge_synced else "-"))
        else:
            synced.append(key)
        # R6 地板联动
        bi = e.get("baseline_impact")
        if isinstance(bi, dict) and bi.get("suite"):
            suites = baseline.get("suites") or {}
            # 基线在 7a5c2b9 把单列 min_hit 拆成 min_real_hit / max_flag_scan；
            # 这里两个键都认（优先新的），否则 R6 会在改名后静默读不到地板。
            suite_cfg = suites.get(bi["suite"]) or {}
            cur = suite_cfg.get("min_real_hit", suite_cfg.get("min_hit"))
            frm, to = bi.get("from"), bi.get("to")
            if cur == to:
                pass
            elif cur == frm and status == "accepted_debt":
                pass  # 已入账的债：地板暂留旧值是被记账的，不是静默漂移
            else:
                fails.append("R6 地板未联动：suite=%s min_hit=%r（应=%r；如仍为 %r 须登记为债务）"
                             % (bi["suite"], cur, to, frm))

    # R8 记账三件套：有人负责 / 有到期日 / 延期只能留痕地做
    horizon = date.today() + timedelta(days=MAX_EXPIRY_DAYS)
    for key in sorted(current_keys & ledger_keys):
        e = entry_by_key[key]
        owner = str(e.get("owner") or "").strip()
        if owner in OWNER_PLACEHOLDERS:
            fails.append("R8 无人负责：%s :: %s owner=%r（脱敏必须点名责任人；"
                         "本项目由 agent 负责，填 agent 或 agent:<会话>）" % (key[0], key[1], owner))
        exp_raw = e.get("expires")
        exp = str(exp_raw or "").strip()
        if not exp:
            fails.append("R8 无到期日：%s :: %s（expires 空 = 永不复查，等于没记账）"
                         % (key[0], key[1]))
        else:
            try:
                exp_d = date.fromisoformat(exp)
            except ValueError:
                fails.append("R8 expires 非法日期：%s :: %s %r（须 YYYY-MM-DD）"
                             % (key[0], key[1], exp_raw))
            else:
                if exp_d < date.today():
                    fails.append("R8 已过期未续：%s :: %s expires=%s（到期必须复核；"
                                 "续期用 --renew --expires --reason 留痕）" % (key[0], key[1], exp))
                elif exp_d > horizon:
                    fails.append("R8 到期日过远：%s :: %s expires=%s（超过 %d 天上限，"
                                 "等于把记账做空）" % (key[0], key[1], exp, MAX_EXPIRY_DAYS))
        renewals = e.get("renewals")
        if renewals:
            if not isinstance(renewals, list):
                fails.append("R8 renewals 非法：%s :: %s 须为数组" % (key[0], key[1]))
            else:
                last = renewals[-1] if isinstance(renewals[-1], dict) else {}
                missing = [k for k in ("date", "by", "to", "reason")
                           if not str(last.get(k) or "").strip()]
                if missing:
                    fails.append("R8 续期缺留痕：%s :: %s 最后一条 renewals 缺 %s"
                                 % (key[0], key[1], ",".join(missing)))
                elif str(last.get("to")).strip() != exp:
                    fails.append("R8 手改过期日：%s :: %s expires=%s 与最后一条续期 to=%s 不符"
                                 "（续期只能走 --renew，不许手改 JSON）"
                                 % (key[0], key[1], exp, last.get("to")))

    # R9 全域答案明文：入仓文件里任何「可被直接抄走」的答案
    known = collect_answer_hashes(root)
    exempt_doc = load_json(root / EXEMPT_REL, {"schema": 1, "entries": []})
    exempt_entries = [e for e in (exempt_doc.get("entries") or []) if isinstance(e, dict)]
    ex_by_file = {str(e.get("file") or "").replace("\\", "/"): e for e in exempt_entries}
    hits, skipped_large = scan_answer_plaintext(root, known)
    used_exempt: set[str] = set()
    debt_doc = load_json(root / DEBT_REL, None)
    debt_entries = []
    debt_owner = ""
    debt_expires = ""
    if isinstance(debt_doc, dict):
        debt_entries = [e for e in (debt_doc.get("entries") or []) if isinstance(e, dict)]
        debt_owner = str(debt_doc.get("owner") or "").strip()
        debt_expires = str(debt_doc.get("expires") or "").strip()
    debt_keys = {(str(e.get("file") or "").replace("\\", "/"),
                  str(e.get("flag_sha256") or "").strip().lower()) for e in debt_entries}
    hit_keys: set[tuple[str, str]] = set()
    for rel, cand, ids in hits:
        e = ex_by_file.get(rel)
        if e:
            used_exempt.add(rel)
            lines.append("    [EXEMPT] %s ｜ %s ｜ %s" % (rel, cand, ",".join(ids)[:80]))
            continue
        h = hashlib.sha256(cand.encode("utf-8")).hexdigest()
        key = (rel, h)
        hit_keys.add(key)
        if key in debt_keys:
            continue  # 已入账旧债：允许存在，但到期必须清
        fails.append("R9 入仓明文答案：%s ｜ %s ｜ 对应 %s"
                     "（判分只用哈希，明文在入仓文件里等于把答案白送；"
                     "确需保留的登记到 %s 并写明理由与到期日；"
                     "旧债请用 --update-debt 记账，不许在扫描面上动手脚）"
                     % (rel, cand, ",".join(sorted(set(ids))), EXEMPT_REL))
    if debt_doc is None:
        if hit_keys:
            fails.append("R12 缺明文债基线 %s（`--update-debt` 生成：把已知旧债一次性记账，"
                         "之后只许减少）" % DEBT_REL)
        else:
            lines.append("  明文债棘轮：无债表且入仓明文 0 处（无债可记）")
    else:
        if debt_owner in OWNER_PLACEHOLDERS:
            fails.append("R12 债表无人负责：owner=%r" % debt_owner)
        try:
            d_exp = date.fromisoformat(debt_expires)
        except ValueError:
            fails.append("R12 债表到期日非法或缺失：%r" % debt_expires)
        else:
            if d_exp < date.today():
                fails.append("R12 明文债已过期：expires=%s（到期必须闭环，不许续着挂）"
                             % debt_expires)
            elif d_exp > horizon:
                fails.append("R12 债表到期日过远：expires=%s（超过 %d 天）"
                             % (debt_expires, MAX_EXPIRY_DAYS))
        lines.append("  明文债棘轮：登记 %d 条 ｜ 仍命中 %d 条 ｜ 已消债 %d 条"
                     "（只减不增；不在债表里的明文一律红）"
                     % (len(debt_keys), len(debt_keys & hit_keys),
                        len(debt_keys - hit_keys)))
        # 分类核查：一锅账会掩盖「哪些真该清」。文档类必须为 0；未知类别直接红。
        by_kind: dict[str, int] = {}
        for e in debt_entries:
            k = str(e.get("kind") or "").strip()
            rel = str(e.get("file") or "").replace("\\", "/")
            if k not in DEBT_KINDS:
                fails.append("R12 明文债缺分类：%s kind=%r（必须写明它属于哪一类，"
                             "否则「还留着」和「该清」混成一锅账）" % (rel, k))
                continue
            by_kind[k] = by_kind.get(k, 0) + 1
            if k == "doc_prose":
                fails.append("R12 文档里还有答案明文：%s（叙事/赛报/日志没有「必须持有真值」"
                             "的理由；用 scripts/redact_answer_plaintext.py --apply 换成人可读、"
                             "机不可抄的 <REDACTED:sha256=…>，不许记成债）" % rel)
        for k, n in sorted(by_kind.items(), key=lambda kv: -kv[1]):
            lines.append("    [KIND] %-24s %3d 条 ｜ %s" % (k, n, DEBT_KINDS[k][0]))
    lines.append("  全域明文扫描：已知答案哈希 %d 条 ｜ 命中 %d 处 ｜ 豁免 %d 处 ｜ 超大文件跳过 %d 个（>%dKB 未解码，属已知盲区）"
                 % (len(known), len(hits), len(used_exempt), skipped_large,
                    MAX_SCAN_BYTES // 1024))
    horizon_ex = horizon  # 与 R8 同一个 365 天上限
    for e in exempt_entries:
        rel = str(e.get("file") or "").replace("\\", "/")
        owner = str(e.get("owner") or "").strip()
        if owner in OWNER_PLACEHOLDERS:
            fails.append("R9 豁免无人负责：%s owner=%r" % (rel, owner))
        if not str(e.get("reason") or "").strip():
            fails.append("R9 豁免无理由：%s（必须写明为何这份明文必须留在仓库里）" % rel)
        exp = str(e.get("expires") or "").strip()
        if not exp:
            fails.append("R9 豁免无到期日：%s" % rel)
        else:
            try:
                exp_d = date.fromisoformat(exp)
            except ValueError:
                fails.append("R9 豁免 expires 非法：%s %r" % (rel, exp))
            else:
                if exp_d < date.today():
                    fails.append("R9 豁免已过期：%s expires=%s（到期必须复核）" % (rel, exp))
                elif exp_d > horizon_ex:
                    fails.append("R9 豁免到期日过远：%s expires=%s（超过 %d 天）"
                                 % (rel, exp, MAX_EXPIRY_DAYS))
        if rel not in used_exempt:
            fails.append("R9 豁免悬空：%s（该文件已无答案明文命中，须删除豁免）" % rel)

    # R10 历史防线：清干净之后的新提交，不许再把答案明文写回来
    if _git_out(root, "rev-parse", "--git-dir") is None:
        lines.append("  历史新增行扫描：非 git 环境（自测夹具/源码包副本），跳过 R10")
    else:
        revs = _git_out(root, "rev-list", "%s..HEAD" % HISTORY_SINCE)
        if revs is None:
            fails.append("R10 无法解析起始提交 %s（历史扫描面为空即不可信，fail-closed）"
                         % HISTORY_SINCE)
        else:
            rev_list = revs.split()
            if len(rev_list) > MAX_HISTORY_COMMITS:
                fails.append("R10 待扫提交过多：%s..HEAD 有 %d 个（上限 %d）——"
                             "请把 HISTORY_SINCE 前移到已确认干净的提交，再继续累计"
                             % (HISTORY_SINCE, len(rev_list), MAX_HISTORY_COMMITS))
            patch = _git_out(root, "log", "-p", "-U0", "--no-color", "--no-merges",
                             "%s..HEAD" % HISTORY_SINCE) or ""
            hist_hits = scan_patch_added(patch, known)
            lines.append("  历史新增行扫描：%s..HEAD 共 %d 个提交 ｜ 新增行里命中 %d 处"
                         % (HISTORY_SINCE, len(rev_list), len(hist_hits)))
            for commit, path, cand, ids in hist_hits:
                fails.append("R10 历史新增明文：commit %s ｜ %s ｜ %s ｜ 对应 %s"
                             "（清除只对 HEAD 有效：进了历史就能 git log -p 抄走，"
                             "且擦掉要改写历史；请在提交前就清掉）"
                             % (commit, path, cand, ",".join(sorted(set(ids)))[:80]))

    # R11 历史暴露事实表（生成物；这里只做离线可判真的诚信校验）
    # 非 git 环境没有历史可扫，不适用本条（自测夹具/源码包副本走这条分支）。
    exp_doc = load_json(root / EXPOSURE_REL, None)
    if _git_out(root, "rev-parse", "--git-dir") is None:
        lines.append("  R11 历史暴露事实表：非 git 环境，不适用")
    elif exp_doc is None:
        fails.append("R11 缺历史暴露事实表 %s（`--update-exposure` 生成；"
                     "已进过历史的答案必须被记下来，不许只靠口头承认）" % EXPOSURE_REL)
    else:
        exp_entries = exp_doc.get("entries") or []
        owner_ = str(exp_doc.get("owner") or "").strip()
        if owner_ in OWNER_PLACEHOLDERS:
            fails.append("R11 事实表无人负责：owner=%r" % owner_)
        live = set(known)  # 现役（判分正在用）答案哈希
        seen: set[str] = set()
        exposed_n = rotated_n = pending_n = 0
        for e in exp_entries:
            sha = str(e.get("flag_sha256") or "").strip().lower()
            if not sha:
                fails.append("R11 事实表条目缺 flag_sha256：%r" % (e,))
                continue
            if len(sha) != 64:
                fails.append("R11 事实表哈希非法：%r" % sha)
                continue
            if sha in seen:
                fails.append("R11 事实表重复登记：%s…" % sha[:12])
            seen.add(sha)
            if int(e.get("hits") or 0) <= 0:
                fails.append("R11 事实表 hits 非正：%s…" % sha[:12])
            ids = e.get("ids") or []
            if not isinstance(ids, list) or not ids:
                fails.append("R11 事实表缺对应题目：%s…" % sha[:12])
            st = str(e.get("status") or "").strip()
            if st not in EXPOSURE_STATUS:
                fails.append("R11 状态非法：%s… status=%r" % (sha[:12], st))
            elif st == "exposed":
                exposed_n += 1
                if sha not in live:
                    fails.append("R11 状态与事实不符：%s… 标 exposed，但它已不在现役答案里"
                                 "（轮换过就该改成 rotated）" % sha[:12])
            elif st == "rotated":
                rotated_n += 1
                if sha in live:
                    fails.append("R11 状态与事实不符：%s… 标 rotated，但它仍是现役判定答案"
                                 "（轮换没做完就标 rotated，等于宣布已解决）" % sha[:12])
            elif st == "pending_corpus":
                pending_n += 1
                if sha in live:
                    fails.append("R11 状态过期：%s… 标 pending_corpus（题库未入仓），"
                                 "但它现在已是入仓题库的现役答案——语料入库了就得重生成" % sha[:12])
        if len(exp_entries) == 0 and known:
            fails.append("R11 事实表为空但答案库非空：全历史至少应有 exposure，"
                         "空表通常意味着扫描根本没跑（生成物只由 --update-exposure 产出）")
        if str(exp_doc.get("since") or "").strip() != HISTORY_SINCE:
            fails.append("R11 起点与事实表脱钩：事实表 since=%r 但 HISTORY_SINCE=%r"
                         "（移动历史防线起点，必须在事实表里留下同一次账）"
                         % (exp_doc.get("since"), HISTORY_SINCE))
        legacy = exp_doc.get("legacy") if isinstance(exp_doc.get("legacy"), dict) else {}
        if int(legacy.get("hits") or 0) <= 0:
            fails.append("R11 前移起点没留下账：legacy.hits=%r（被移出防线范围的历史明文"
                         "必须计数，否则等于把历史红擦成 0）" % (legacy.get("hits"),))
        lines.append("  R11 历史暴露事实表：%d 条（exposed %d ｜ rotated %d ｜ pending_corpus %d）"
                     "｜ 防线起点 %s，移出防线范围的 %s..%s 有 %d 提交 / %d 处明文，已入表"
                     % (len(exp_entries), exposed_n, rotated_n, pending_n, HISTORY_SINCE,
                        legacy.get("since_prev") or LEGACY_WINDOW["since_prev"],
                        HISTORY_SINCE, int(legacy.get("commits") or 0),
                        int(legacy.get("hits") or 0)))

    if debt:
        lines.append("  判分口径对账：已同步 %d ｜ 未同步但已入账 %d" % (len(synced), len(debt)))
        for d in debt:
            file_, prob_, owner_, exp_, consumer_ = d
            lines.append("    [DEBT] %s :: %s ｜ 未同步消费方=%s ｜ owner=%s ｜ expires=%s"
                         % (file_, prob_, consumer_, owner_, exp_))
    else:
        lines.append("  判分口径对账：已同步 %d ｜ 未同步 0" % len(synced))

    for f in fails:
        if f:
            lines.append("  [FAIL] %s" % f)
    if fails:
        lines.append("结论：FAIL —— %d 项（脱敏与判分口径不同源，或脱敏未入账）" % len([x for x in fails if x]))
        return 1, lines
    if debt:
        lines.append("结论：PASS —— 差异全部入账（债务期相关 job 仍会红：红是账单，不是绿）")
    else:
        lines.append("结论：PASS —— 脱敏与判分口径一致")
    return 0, lines


def update_ledger(root: Path, owner: str, expires: str,
                  renew: bool = False, reason: str = "") -> int:
    """按当前语料同步台账。

    2026-11-04 补两条口径（否则「记账」可以留空，等于没记）：
      · expires 缺省不再写空，而是机器算出 today + MAX_EXPIRY_DAYS；
      · 续期只能显式 `renew=True` + `--reason`：覆盖 expires 的同时把
        {date, by, from, to, reason} 追加进 `renewals`，手改 JSON 会被 R8 抓出来。
    """
    path = root / LEDGER_REL
    ledger = load_json(path, {"schema": 1, "note": "", "entries": []})
    old = {(e.get("file"), e.get("problem")): e for e in ledger.get("entries") or []}
    corpus = scan_corpus(root)
    manifest = load_json(root / MANIFEST_REL, [])
    man = {c["name"]: c for c in manifest if isinstance(c, dict) and c.get("name")} \
        if isinstance(manifest, list) else {}
    default_exp = expires or (date.today() + timedelta(days=MAX_EXPIRY_DAYS)).isoformat()
    entries = []
    for c in corpus:
        key = (c["file"], c["problem"])
        prev = old.get(key) or {}
        consumer = man.get(c["problem"])
        judge_synced = True
        if consumer:
            judge_synced = str(consumer.get("expect") or "") == "not_attemptable"
        prev_exp = str(prev.get("expires") or "").strip()
        # 占位符不算「有人负责」：旧账里的 unassigned/空 可以被本次点名覆盖，
        # 但已有具名 owner 一律保留（旧账的记名不许被后一次同步静默改写）。
        prev_owner = str(prev.get("owner") or "").strip()
        owner_val = prev_owner if prev_owner not in OWNER_PLACEHOLDERS else owner
        item = {
            "file": c["file"],
            "problem": c["problem"],
            "redacted_fields": c["declared_fields"] or c["fields"],
            "judge_synced": judge_synced,
            # 判分已同步 → synced；否则保留旧状态（旧账不可被静默洗白）或登记为债务
            "status": "synced" if judge_synced else (prev.get("status") or "accepted_debt"),
            "owner": owner_val,
            "expires": default_exp if renew or not prev_exp else prev_exp,
            "reason": prev.get("reason") or "",
            "baseline_impact": prev.get("baseline_impact"),
            "renewals": list(prev.get("renewals") or []),
        }
        if renew and prev_exp and prev_exp != item["expires"]:
            item["renewals"].append({
                "date": date.today().isoformat(),
                "by": item["owner"] or owner,
                "from": prev_exp,
                "to": item["expires"],
                "reason": reason,
            })
        if not judge_synced and item["status"] == "synced":
            item["status"] = "accepted_debt"
        entries.append(item)
    entries.sort(key=lambda e: (e["file"], e["problem"]))
    ledger["entries"] = entries
    ledger.setdefault("schema", 1)
    path.write_text(json.dumps(ledger, ensure_ascii=False, indent=2) + "\n", encoding="utf-8")
    print("台账已同步：%d 条 → %s（expires 缺省=%s%s）"
          % (len(entries), path, default_exp, "，已续期并留痕" if renew else ""))
    return 0


def debt_kind(rel: str) -> str:
    """给每处明文债分类，因为「一锅 205 条」会掩盖两类完全不同的东西。

    ① doc_prose：叙事/赛报/计划/日志里的答案 —— 这类**没有必须持有真值的理由**，
       只是没清。清掉之后（2026-11-07：37 条 → 0）应当永久为 0，再出现就是新泄漏。
    ② target_artifact：靶场/生成器 —— 题目要能被解，真值就必须在题目里，
       删掉等于把题改成不可解。属结构性，但仍是「谁能读到 repo 谁就能抄」的风险面。
    ③ test_fixture：测试要断言「解出的就是这个值」，字面在断言里。
    ④ external_public_question：公开真题题库，答案本身是公开信息，
       但仍让该题变成「可抄」，会污染解出率。
    ⑤ source_literal：源码里写死的答案（如 presolve 的已知题对照表）。
    """
    p = rel.replace("\\", "/")
    if (p.startswith("docs/") or "/docs/" in p or "deliverables/" in p or
            p.startswith("plans/") or "/plans/" in p or "evidence/" in p or
            p.endswith(".log") or p.endswith(".jsonl") or p.endswith(".md")):
        if not p.endswith(".json") or "evidence/" in p:
            return "doc_prose"
    name = p.rsplit("/", 1)[-1]
    if "/tests/" in p or name.startswith("test_") or name.endswith("_test.py") \
            or name.endswith("_test.go"):
        return "test_fixture"
    if "live_target/" in p or name.startswith("gen_") or name.startswith("_gen_") \
            or name.startswith("judge_") or "crypto_attack_params" in p:
        return "target_artifact"
    if "questions_real/" in p or "questions_external/" in p:
        return "external_public_question"
    return "source_literal"


DEBT_KINDS = {
    "doc_prose": ("叙事/赛报/计划/日志", "必须为 0：这些地方没有『题要可解才需要真值』的理由"),
    "target_artifact": ("靶场 / 生成器", "题目要能被解，真值必须在题目里；删掉等于把题改成不可解"),
    "test_fixture": ("测试 / 夹具", "断言要写『解出的就是这个值』，真值在断言字面里"),
    "external_public_question": ("公开真题题库", "答案本身公开，但仍会让该题变可抄，污染解出率"),
    "source_literal": ("源码写死", "如 presolve 已知题对照表；可逐步改成按哈希比对"),
}


def update_debt(root: Path, owner: str, expires: str) -> int:
    """按当前扫描结果重写明文债表（R12）。只许在**减少**后重写，增项要人工解释。"""
    known = collect_answer_hashes(root)
    hits, skipped = scan_answer_plaintext(root, known)
    exempt_doc = load_json(root / EXEMPT_REL, {"schema": 1, "entries": []})
    ex_files = {str(e.get("file") or "").replace("\\", "/")
                for e in (exempt_doc.get("entries") or []) if isinstance(e, dict)}
    rows: dict[tuple[str, str], dict] = {}
    for rel, cand, ids in hits:
        if rel in ex_files:
            continue
        h = hashlib.sha256(cand.encode("utf-8")).hexdigest()
        row = rows.setdefault((rel, h), {"file": rel, "kind": debt_kind(rel),
                                         "flag_sha256": h, "ids": sorted(set(ids)),
                                         "hits": 0})
        row["hits"] += 1
    old = load_json(root / DEBT_REL, {})
    old_keys = {(str(e.get("file") or ""), str(e.get("flag_sha256") or ""))
                for e in (old.get("entries") or []) if isinstance(e, dict)}
    gained = sorted(k for k in rows if k not in old_keys)
    entries = sorted(rows.values(), key=lambda e: (-e["hits"], e["file"]))
    doc = {
        "schema": 1,
        "generated_by": "scripts/check_redaction_consistency.py --update-debt",
        "owner": owner,
        "expires": expires,
        "note": ("明文债棘轮：这些（文件,答案哈希）是入仓明文的**已记账旧债**，允许存在但只许减少。"
                 "不在本表里的明文一律判红。每条带 kind 说明它属于哪一类："
                 "doc_prose 必须为 0（叙事里不该有答案）；target_artifact / test_fixture "
                 "是结构性真值；external_public_question / source_literal 应逐步改成按哈希比对。"),
        "head": (_git_out(root, "rev-parse", "--short", "HEAD") or "").strip(),
        "total_hits": sum(e["hits"] for e in entries),
        "raw_hits": len(hits),
        "entries": entries,
    }
    p = root / DEBT_REL
    p.parent.mkdir(parents=True, exist_ok=True)
    p.write_text(json.dumps(doc, ensure_ascii=False, indent=2) + "\n", encoding="utf-8")
    print("明文债表已重写：%d 条（%d 处）｜ 相对上一版新增 %d 条 ｜ 超大文件跳过 %d"
          % (len(entries), doc["total_hits"], len(gained), skipped))
    if gained:
        print("新增条目（这些是**新债**，不是已达成的基线，须解释来源）：")
        for f, h in gained[:20]:
            print("  %s ｜ %s" % (f, rows[(f, h)]["literal"]))
    return 0


def update_exposure(root: Path, owner: str) -> int:
    """全历史扫描，生成 `history_exposure.json`（R11）。

    为什么用流式读而不 `subprocess.run(capture_output=True)`：本仓 600+ 提交的
    `git log -p` 文本是几百 MB 级，一次性读进内存会直接把门禁自己 OOM ——
    一个因为爱吃内存而时灵时不灵的门禁，比没有门禁更糟。
    """
    known = collect_answer_hashes(root)
    # 磁盘上（含未入仓的在途题库）也算一遍：用来区分「已轮换」与「题库还没入仓」。
    # 不这样做就只能二选一，而未入仓题库里的真值答案既没轮换、也不该被记成 rotated。
    known_disk = collect_answer_hashes(root, include_untracked=True)
    if _git_out(root, "rev-parse", "--git-dir") is None:
        print("非 git 环境：无法扫描历史，拒绝生成（fail-closed）")
        return 2
    proc = subprocess.Popen(["git", "log", "-p", "-U0", "--no-color", "--no-merges",
                             "--reverse", "HEAD"],
                            cwd=str(root), stdout=subprocess.PIPE,
                            text=True, encoding="utf-8", errors="ignore")
    agg: dict[str, dict] = {}
    n_commits = 0
    cur = "?"
    last_path = "?"
    in_msg = False
    assert proc.stdout is not None
    for raw in proc.stdout:
        if raw.startswith("commit ") and len(raw) > 8:
            n_commits += 1
            cur = raw.split()[1][:8]
            in_msg = True
            continue
        if raw.startswith("diff --git "):
            in_msg = False
            frag = raw[len("diff --git "):]
            idx = frag.find(" b/")
            last_path = frag[idx + 3:].strip() if idx >= 0 else frag.strip()
            continue
        if in_msg:
            if not raw.startswith("    "):
                continue
            where = "commit-message"
        else:
            if not raw.startswith("+") or raw.startswith("+++"):
                continue
            where = last_path
        for m in ANSWER_SHAPE.finditer(raw):
            cand = m.group(0)
            if "REDACTED" in cand:
                continue
            h = hashlib.sha256(cand.encode("utf-8")).hexdigest()
            # 匹配用「入仓 ∪ 磁盘」的并集：否则在途题库里的真值答案在历史里扫不到，
            # 事实表会把它们凭空漏掉（record 的完整性比「只看入仓」更要紧）。
            src = known.get(h) or known_disk.get(h)
            if not src:
                continue
            a = agg.setdefault(h, {"literal": cand, "flag_sha256": h,
                                   "ids": list(src), "hits": 0,
                                   "first_commit": cur, "last_commit": cur,
                                   "places": []})
            a["hits"] += 1
            a["last_commit"] = cur
            if where not in a["places"]:
                a["places"].append(where)
    proc.wait()
    if proc.returncode != 0:
        print("git log 读取失败 rc=%d，拒绝写出不完整的暴露表（fail-closed）"
              % proc.returncode)
        return 2

    entries = []
    for h, a in agg.items():
        entries.append({
            # 只记哈希，不记字面：事实表本身若带明文，就会变成新的明文载体
            "flag_sha256": h,
            "ids": a["ids"],
            "ids": a["ids"],
            # exposed = 仍是入仓题库里的现役判分答案；
            # rotated = 已不在任何题库里（换过值）；
            # pending_corpus = 答案只在**未入仓**的在途题库里，本仓还不判它——
            #   既不能叫 exposed（本仓没有这题），也不能叫 rotated（值没换过）。
            "status": ("exposed" if h in known
                       else "pending_corpus" if h in known_disk
                       else "rotated"),
            "hits": a["hits"],
            "first_commit": a["first_commit"],
            "last_commit": a["last_commit"],
            "places": a["places"][:12],
        })
    entries.sort(key=lambda e: (-e["hits"], e["flag_sha256"]))
    doc = {
        "schema": 1,
        "generated_by": "scripts/check_redaction_consistency.py --update-exposure",
        "owner": owner,
        "note": ("本表是生成物，禁手改。语义：这些答案的明文**曾经**进过 git 历史。"
                 "status=exposed 表示它仍是现役判分答案（泄密成立，须轮换或明确接受）；"
                 "status=rotated 表示答案已换新值，旧值仅作历史记录。"
                 "仓库若为 PUBLIC，任何人 git log -p 都能取到 exposed 条目。"),
        "head": (_git_out(root, "rev-parse", "--short", "HEAD") or "").strip(),
        "since": HISTORY_SINCE,
        # 起点前移的账：被移出防线范围的那一段有多少明文/提交（不许「无损前移」）
        "legacy": dict(LEGACY_WINDOW),
        "commits_scanned": n_commits,
        "total_hits": sum(e["hits"] for e in entries),
        "entries": entries,
    }
    p = root / EXPOSURE_REL
    p.parent.mkdir(parents=True, exist_ok=True)
    p.write_text(json.dumps(doc, ensure_ascii=False, indent=2) + "\n", encoding="utf-8")
    print("历史暴露事实表已生成：%d 条字面 ｜ %d 处命中 ｜ %d 个提交 → %s"
          % (len(entries), doc["total_hits"], n_commits, p))
    return 0


def main(argv=None) -> int:
    ap = argparse.ArgumentParser(description="脱敏一致性门禁")
    ap.add_argument("--root", default=".", help="仓库根目录（自测用）")
    ap.add_argument("--update-ledger", action="store_true", help="按当前语料同步台账")
    ap.add_argument("--owner", default="agent",
                    help="--update-ledger 时写入的责任人（本项目由 agent 负责；"
                         "留空/占位符会被 R8 判红）")
    ap.add_argument("--expires", default="",
                    help="到期日 YYYY-MM-DD；缺省 = 今天 + %d 天" % MAX_EXPIRY_DAYS)
    ap.add_argument("--renew", action="store_true",
                    help="续期：覆盖 expires 并把 date/by/from/to/reason 追加进 renewals")
    ap.add_argument("--reason", default="", help="续期理由（--renew 时必填）")
    ap.add_argument("--update-exposure", action="store_true",
                    help="全历史扫描，重写历史暴露事实表（R11 生成物）")
    ap.add_argument("--update-debt", action="store_true",
                    help="按当前扫描重写明文债表（R12；只许减少）")
    args = ap.parse_args(argv)
    if args.expires:
        try:
            exp_d = date.fromisoformat(args.expires)
        except ValueError:
            print("[ERROR] --expires 非法日期：%r（须 YYYY-MM-DD）" % args.expires)
            return 2
        if exp_d > date.today() + timedelta(days=MAX_EXPIRY_DAYS):
            print("[ERROR] --expires 超过 %d 天上限：%s（填太远等于没有到期日）"
                  % (MAX_EXPIRY_DAYS, args.expires))
            return 2
    if args.renew and not args.reason.strip():
        print("[ERROR] --renew 必须带 --reason（续期要留谁在何时为何延期）")
        return 2
    root = Path(args.root)
    if not (root / CORPUS_DIR).is_dir():
        print("[ERROR] 找不到语料目录：%s" % (root / CORPUS_DIR))
        return 2
    if args.update_exposure:
        return update_exposure(root, args.owner)
    if args.update_debt:
        return update_debt(root, args.owner,
                           args.expires or (date.today() + timedelta(days=MAX_EXPIRY_DAYS)).isoformat())
    if args.update_ledger:
        return update_ledger(root, args.owner, args.expires,
                             renew=args.renew, reason=args.reason.strip())
    code, lines = check(root)
    for ln in lines:
        print(ln)
    return code


if __name__ == "__main__":
    sys.exit(main())
