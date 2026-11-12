"""「答案在附件」人工登记清单的回归测试（含变异）。

**为什么这些用例必须存在**
--------------------------
`real_web_gongye_web2` 的答案写在 `index.php` 里，而该文件因含明文答案被 `.gitignore`
排除。旧判据只靠「读附件内容扫 flag 串」，于是：本机文件在盘 → 命中 → 正确排除；
干净检出文件不在 → 扫不到 → 题反被放行。2026-11-12 实测本机 5 / 检出 6 的漂移即由此而来。

把结论登记成独立真值后，排除判决与盘上文件无关。但**清单本身也会失效**——文件被删、
entries 被清空、键名写错，任何一种都会让它静默退回旧行为。所以必须有反例：
清单必须在自己被破坏时变红，否则「数字恰好稳定」会永久掩盖失效。

方向一（正例）：登记过的 id 被识别；未登记的 id 不被识别。
方向二（反例）：
  - 把 entries 清空 → 识别必须变成 False（证明判据读的是清单内容，不是硬编码）；
  - 清单文件不存在 → 必须显式告警并降级为 False（不许静默通过）；
  - 把 `_has_plaintext_flag_in_source` 桩成 False（模拟干净检出读不到附件）→
    该题仍必须被排除，且理由必须是 `declared-answer-in-attachment`
    （证明清单独立于盘上文件生效，而不是靠内容扫描兜底）。

只读 id / 理由字符串，不读任何明文 flag。
"""
from __future__ import annotations

import json

import pytest

from scripts import benchmark_heldout as bh


def _reset_cache(monkeypatch, path=None) -> None:
    """重置清单缓存；path 非空时把清单指向该路径（用于变异）。"""
    monkeypatch.setattr(bh, "_ANSWER_KEY_DECLARED_CACHE", None)
    if path is not None:
        monkeypatch.setattr(bh, "ANSWER_KEY_IN_ATTACHMENT_MANIFEST", path)


def test_declared_entry_is_recognized(monkeypatch):
    _reset_cache(monkeypatch)
    assert bh._is_declared_answer_key_in_attachment("real_web_gongye_web2") is True


def test_unlisted_id_is_not_recognized(monkeypatch):
    _reset_cache(monkeypatch)
    assert bh._is_declared_answer_key_in_attachment("real_crypto_dnui_keyboard") is False


def test_shipped_manifest_is_loadable_and_has_the_entry():
    """出厂清单必须可解析、schema 正确、条目带证据字段（禁止凭印象登记）。"""
    data = json.loads(bh.ANSWER_KEY_IN_ATTACHMENT_MANIFEST.read_text(encoding="utf-8"))
    assert data.get("schema") == "answer_key_in_attachment/v1"
    entries = data.get("entries") or {}
    assert "real_web_gongye_web2" in entries
    entry = entries["real_web_gongye_web2"]
    for key in ("attachment", "evidence", "how_verified", "excluded_reason_code"):
        assert entry.get(key), f"条目缺 {key}，不允许无证据登记"
    assert entry["excluded_reason_code"] == "source-leaked-flag(declared-answer-in-attachment)"


def test_emptied_manifest_turns_recognition_off(tmp_path, monkeypatch):
    """变异：entries 清空 → 识别必须变 False（证明读的是清单内容，不是硬编码结论）。"""
    p = tmp_path / "ak.json"
    p.write_text(json.dumps({"schema": "answer_key_in_attachment/v1", "entries": {}}),
                 encoding="utf-8")
    _reset_cache(monkeypatch, p)
    assert bh._is_declared_answer_key_in_attachment("real_web_gongye_web2") is False


def test_missing_manifest_degrades_loudly(tmp_path, monkeypatch, capsys):
    """变异：清单文件不存在 → 必须向 stderr 告警并降级为 False，不许静默通过。"""
    _reset_cache(monkeypatch, tmp_path / "does_not_exist.json")
    assert bh._is_declared_answer_key_in_attachment("real_web_gongye_web2") is False
    err = capsys.readouterr().err
    assert "不可用" in err and "显式降级" in err


def test_declared_entry_is_excluded_even_without_content_scan(monkeypatch):
    """核心用例：模拟干净检出（附件不在盘、内容扫描失效）→ 该题仍必须被排除。

    这是清单存在的唯一理由。若此用例不成立，说明清单并没有真正解耦盘上文件。
    """
    _reset_cache(monkeypatch)
    monkeypatch.setattr(bh, "_has_plaintext_flag_in_source", lambda q, qpath: False)
    cands, recs = bh.select_candidates(external_dir=bh.QUESTIONS_EXTERNAL)
    ids = [c["id"] for c in cands]
    assert "real_web_gongye_web2" not in ids, "清单命中却仍进了候选池"
    rec = next(r for r in recs if r["id"] == "real_web_gongye_web2")
    assert rec["declared_answer_in_attachment"] is True
    assert rec["excluded"] == "source-leaked-flag(declared-answer-in-attachment)"


def test_entry_is_excluded_on_disk_too(monkeypatch):
    """本机（附件在盘）也必须是排除态——两条判据结果一致，只是理由不同。"""
    _reset_cache(monkeypatch)
    cands, recs = bh.select_candidates(external_dir=bh.QUESTIONS_EXTERNAL)
    ids = [c["id"] for c in cands]
    assert "real_web_gongye_web2" not in ids
    rec = next(r for r in recs if r["id"] == "real_web_gongye_web2")
    assert rec["excluded"].startswith("source-leaked-flag")


def _corroborate(entries: dict) -> tuple[list, list, list]:
    """对清单条目逐条做动态复核，返回 (被证实, 被跳过, 未获证实)。

    「被跳过」= 附件不在盘，无法用内容扫描证实（正是需要清单的情形）。
    「未获证实」= 附件在盘但扫描没命中，说明清单条目可能记错。
    """
    checked, skipped, failed = [], [], []
    for qid, entry in entries.items():
        hits = list(bh.QUESTIONS_REAL.rglob(f"{qid}.json"))
        if not hits:
            failed.append(f"{qid}: 找不到题面，清单条目无法复核")
            continue
        qpath = hits[0]
        q = json.loads(qpath.read_text(encoding="utf-8"))
        if entry.get("attachment") not in (q.get("attachments") or []):
            failed.append(
                f"{qid}: 清单声明的 attachment 不在题面 attachments 里"
                f"（{entry.get('attachment')}）"
            )
            continue
        if bh._resolve_attachment(q, qpath, entry["attachment"]) is None:
            skipped.append(qid)
            continue
        if bh._has_plaintext_flag_in_source(q, qpath) is not True:
            failed.append(f"{qid}: 附件在盘但动态扫描未证实「答案在附件」——清单可能记错")
            continue
        checked.append(qid)
    return checked, skipped, failed


def test_every_declared_entry_is_independently_corroborated_when_on_disk():
    """清单不得撒谎：登记过的题，只要附件在盘，就必须同时被动态扫描独立证实。

    为什么要这条：清单是人工维护的，人工就可能记错——把一道正常题误登成「答案在附件」，
    排除掉它等于凭空缩小能力分母，而任何自动化检查都不会报警（因为清单就是它读的真值）。
    所以必须有一条用例，用**另一个判据**（读附件内容比 sha256）去复核清单里的每一个条目。

    附件不在盘的条目跳过——那种情形本来就无法用动态判据证实，也正是需要清单的原因。
    """
    data = json.loads(bh.ANSWER_KEY_IN_ATTACHMENT_MANIFEST.read_text(encoding="utf-8"))
    entries = data.get("entries") or {}
    assert entries, "清单为空时本用例失去意义"
    checked, skipped, failed = _corroborate(entries)
    assert not failed, "清单里有条目通不过独立复核：" + "; ".join(failed)
    assert checked, f"没有任何条目被动态证实（全部跳过：{skipped}），用例形同虚设"


def test_corroboration_catches_a_wrongly_declared_entry():
    """变异：往清单塞一道附件在盘、但内容并不含答案的题，复核必须把它抓出来。

    选 real_reverse_js 作变异体：它的 coso.js 就在盘上（_resolve_attachment 会成功），
    但 reverse 类被 _has_plaintext_flag_in_source 的类别闸放行（返回 False）。
    所以这正是「误登一道正常题」的真实形态——若复核逻辑失灵，它会静默通过。
    """
    _, _, failed = _corroborate({
        "real_reverse_js": {"attachment": "data/questions_real/_attachments/reverse/"
                                          "real_reverse_js/coso.js"}
    })
    assert failed, "变异未生效：误登的正常题竟然通过了复核，说明用例是摆设"
    assert "未证实" in failed[0]


