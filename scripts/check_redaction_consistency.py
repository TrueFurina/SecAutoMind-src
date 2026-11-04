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


def collect_answer_hashes(root: Path) -> dict:
    """已知答案哈希 → [来源标识]。口径与判分同源：sha256(整串候选)。"""
    known: dict[str, list[str]] = {}
    manifest = load_json(root / MANIFEST_REL, [])
    cases = manifest if isinstance(manifest, list) else (manifest.get("cases") or [])
    for c in cases:
        if isinstance(c, dict) and c.get("flag_sha256"):
            known.setdefault(str(c["flag_sha256"]).strip().lower(), []).append(
                "arena:%s" % c.get("name"))
    for rel in ("data/ctf_benchmark/real_benchmark.json",
                "data/ctf_benchmark/benchmark.json"):
        for name, prob in iter_problems(load_json(root / rel, {})):
            if isinstance(prob, dict) and prob.get("flag_sha256"):
                known.setdefault(str(prob["flag_sha256"]).strip().lower(), []).append(
                    "%s#%s" % (rel, name))
    return known


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


def scan_answer_plaintext(root: Path, known: dict) -> list[tuple[str, str, list[str]]]:
    hits = []
    for rel in _scan_files(root):
        if os.path.splitext(rel)[1].lower() in ANSWER_SKIP_EXT:
            continue
        p = root / rel
        try:
            if p.stat().st_size > MAX_SCAN_BYTES:
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
            cur = (suites.get(bi["suite"]) or {}).get("min_hit")
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
    hits = scan_answer_plaintext(root, known)
    used_exempt: set[str] = set()
    for rel, cand, ids in hits:
        e = ex_by_file.get(rel)
        if e:
            used_exempt.add(rel)
            lines.append("    [EXEMPT] %s ｜ %s ｜ %s" % (rel, cand, ",".join(ids)[:80]))
        else:
            fails.append("R9 入仓明文答案：%s ｜ %s ｜ 对应 %s"
                         "（判分只用哈希，明文在入仓文件里等于把答案白送；"
                         "确需保留的登记到 %s）"
                         % (rel, cand, ",".join(sorted(set(ids))), EXEMPT_REL))
    lines.append("  全域明文扫描：已知答案哈希 %d 条 ｜ 命中 %d 处 ｜ 豁免 %d 处"
                 % (len(known), len(hits), len(used_exempt)))
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
    if args.update_ledger:
        return update_ledger(root, args.owner, args.expires,
                             renew=args.renew, reason=args.reason.strip())
    code, lines = check(root)
    for ln in lines:
        print(ln)
    return code


if __name__ == "__main__":
    sys.exit(main())
