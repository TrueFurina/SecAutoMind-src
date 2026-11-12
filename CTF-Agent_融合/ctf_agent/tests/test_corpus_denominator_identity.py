"""语料分母的恒等式：台账里"已验证"的题与"素材还在盘"的题之间的关系。

为什么需要这条测试：`coverage_of_corpus = offline_verified / real_corpus` 这个数被当成
能力覆盖率在对外引用，但真实含义是「具备验证条件的题全部验证通过」。那个含义依赖两条
隐含事实：① 台账里标了已验证的题必然有素材；② 有素材但没进台账的题各有不计入的理由。
这两条只要有一条不成立，15% 这个数就会被误读。

本测试不锁数字，锁关系：
  - 交集条数 == currently_reproducible()（"已验证且素材还在"）
  - 台账独有 == LOST_PAYLOAD 中仍缺失的题（素材丢了但台账还记着）
  - 台账条数 == count_offline_verified()
这样语料变化（补了素材、加了题）不会让测试误红，但关系一旦被破坏就立刻红。
"""

import json
import re
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from scripts import _audit_corpus_integrity as aci  # noqa: E402
from scripts import _merge_gate as mg  # noqa: E402

QUESTIONS_REAL = Path(__file__).resolve().parents[1] / "data" / "questions_real"

# 题块标题形如 "### 1. real_crypto_specialcurve2 【A类·完整攻击链】"
# 或 "### 3. 10733（CRYPTO-02 【A类·完整攻击链】 · ...）"——id 后面可能紧跟中文括号注释，
# 所以必须按「序号 + id」这个前缀锚定，不能用 split 取词。
_TITLE_ID_RE = re.compile(r"^###\s+\d+\.\s+([A-Za-z0-9_]+)")


def _ledger_verified_ids() -> set:
    """台账里计入 offline_verified 的题块 id（与 count_offline_verified 同一判据）。"""
    ids = set()
    cur = ""
    with open(mg.LEDGER, encoding="utf-8") as f:
        for line in f:
            if line.startswith("### "):
                cur = line.strip()
            if ("- **状态**" in line and "✅ offline_verified" in line
                    and mg._classify_entry(cur) in ("A", "B")):
                m = _TITLE_ID_RE.match(cur)
                if m:
                    ids.add(m.group(1))
    return ids


def _on_disk_ids() -> set:
    """素材在盘或无需附件的题 id。"""
    rep = _audit()
    out = set()
    for r in rep["rows"]:
        issues = [i.split(":")[0] for i in r["issues"]]
        if "payload_missing" not in issues:
            out.add(r["id"])
    return out


def test_ledger_count_matches_machine_counter():
    """台账题块数与 count_offline_verified() 必须一致，否则 id 解析与计数口径已分家。"""
    ids = _ledger_verified_ids()
    assert len(ids) == mg.count_offline_verified(), (
        f"台账解析出 {len(ids)} 个 id，但 count_offline_verified() 返回 "
        f"{mg.count_offline_verified()}——两者口径已分家，先修解析再谈关系"
    )


def test_intersection_equals_currently_reproducible():
    """「已验证」∩「素材还在」的条数，必须等于 currently_reproducible()。

    currently_reproducible 由 14 - LOST_PAYLOAD 仍缺失数 算出，是个减法。
    本测试用另一条路径（扫台账 + 扫磁盘）独立算同一个量，两条路径必须相等——
    否则那个减法就只是算术，不是事实。
    """
    inter = _ledger_verified_ids() & _on_disk_ids()
    assert len(inter) == mg.currently_reproducible(), (
        f"交集 {len(inter)} 道，但 currently_reproducible()={mg.currently_reproducible()}；"
        f"差集：{sorted(inter ^ _ledger_verified_ids())}"
    )


def test_ledger_only_entries_are_exactly_the_lost_payload():
    """台账有、素材没有的题，必须恰好是 LOST_PAYLOAD 里仍缺失的那几道。

    这条最容易漂：如果哪天补回了某道丢的素材，它就从「台账独有」变成「交集」，
    此时 LOST_PAYLOAD 是否该缩小就成了必须回答的问题。测试会立刻红，逼着去回答。
    """
    ledger_only = _ledger_verified_ids() - _on_disk_ids()
    lost_still_missing = {qid for qid in mg.LOST_PAYLOAD
                          if mg._question_payload_missing(qid)}
    assert ledger_only == lost_still_missing, (
        "台账独有集合与 LOST_PAYLOAD 仍缺失集合不一致：\n"
        f"  台账独有但不在 LOST_PAYLOAD：{sorted(ledger_only - lost_still_missing)}\n"
        f"  LOST_PAYLOAD 仍有缺失但台账没记：{sorted(lost_still_missing - ledger_only)}"
    )


def test_on_disk_superset_of_intersection_and_disjointness_holds():
    """两个集合必须都是「交集 + 各自独有」，即没有任何 id 落在两侧都不存在的状态。"""
    ledger = _ledger_verified_ids()
    on_disk = _on_disk_ids()
    inter = ledger & on_disk
    assert inter | (ledger - on_disk) == ledger
    assert inter | (on_disk - ledger) == on_disk
    assert not (ledger - on_disk) & (on_disk - ledger)


# ---------------------------------------------------------------- 空壳附件

_TINY_PAYLOAD_BYTES = 100

_AUDIT_CACHE = None
_BYTES_CACHE = {}


def _audit() -> dict:
    """扫一次题库，整模块复用。aci.audit 要遍历 93 道题，逐用例重扫会把 5 条用例拖到 8 秒。"""
    global _AUDIT_CACHE
    if _AUDIT_CACHE is None:
        _AUDIT_CACHE = aci.audit(QUESTIONS_REAL)
    return _AUDIT_CACHE


def _payload_bytes(qid: str) -> int:
    """该题声明附件在盘上的总字节（目录递归求和）。"""
    if qid in _BYTES_CACHE:
        return _BYTES_CACHE[qid]
    rep = _audit()
    row = next(r for r in rep["rows"] if r["id"] == qid)
    jf = Path(row["file"]).resolve()
    q = json.loads(jf.read_text(encoding="utf-8"))
    total = 0
    for rel in (q.get("attachments") or []):
        fp = aci._resolve_attachment(str(rel), jf, QUESTIONS_REAL)
        if fp is None:
            continue
        p = Path(fp)
        if p.is_file():
            total += p.stat().st_size
        elif p.is_dir():
            total += sum(s.stat().st_size for s in p.rglob("*") if s.is_file())
    _BYTES_CACHE[qid] = total
    return total


def test_tiny_payload_is_always_explained():
    """声明了附件、但盘上那份不到 100 字节的题，必须带着「这份不是素材」的标记。

    payload_missing 只看「在不在」，不看「是不是真素材」（_resolve_attachment:195
    自述这是设计边界）。实测被这条边界漏过的是 real_crypto_anxun2020_aes（32 字节）
    与 real_misc_longjian2024_smallsword3（45 字节）——那 32/45 字节就是一条 flag，
    题目本体从来没在库里。它们恰好也是仅有的 2 道 answer_key_only+answer_leak。

    本测试不写死 id：只要将来任何一道题被塞进一个不足 100 字节的「附件」却没标
    answer_key_only/answer_leak，就立刻红——否则它会静默混进「有素材」的分母。
    """
    rep = _audit()
    offenders = []
    for r in rep["rows"]:
        issues = [i.split(":")[0] for i in r["issues"]]
        if "payload_missing" in issues:
            continue  # 缺附件的不在此列
        q = json.loads(Path(r["file"]).read_text(encoding="utf-8"))
        if not (q.get("attachments") or []):
            continue  # 纯题面题不声明附件，不在此列
        if _payload_bytes(r["id"]) >= _TINY_PAYLOAD_BYTES:
            continue
        if not {"answer_key_only", "answer_leak"} & set(issues):
            offenders.append((r["id"], _payload_bytes(r["id"]), issues))

    assert not offenders, (
        "以下题声明了附件但盘上那份不足 100 字节，却没标 answer_key_only / answer_leak——"
        f"它们会被静默算进「有素材」：{offenders}"
    )

