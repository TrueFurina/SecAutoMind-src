# -*- coding: utf-8 -*-
"""`real_corpus` 分母的回归锁：审计台账不得被数成题目。

背景（2026-11-12 实证）：`data/questions_real/_audit/*.json` 是审计台账（顶层键是
`batch` / `run_at` / `result` / `per_question` 等），但同样是 **dict**。旧的
`_counts_toward_corpus` 只判 `isinstance(payload, dict)` ⇒ 8 份台账被数成 8 道题，
`real_corpus` 从真值 93 虚高到 101（本地）/ 98（服务器，台账未全量同步），
`coverage_of_corpus` 被压到 15.1% → 14.3%。

这与 2026-11-08 的 `_hygiene_manifest.json`（数组被数成题）是**同一类错、反方向**：
一次是"非题被计入"，一次是"非题被计入"。判据从"是不是 dict"收紧到"符合题目字段契约"
（`category` + `flag_pattern`，93/93 真题具备、8/8 台账不具备）。

本测试双向锁住：
1. 现实数据：所有 `_audit/*.json` 必须**不**计入；所有题目必须以**真值总数**计入；
2. 变异数据：台账形状的 dict 必须不计、题目形状的 dict 必须计（证明判据真的在起作用，
   而不是因为"当前题库恰好长这样"）。
"""

from __future__ import annotations

import json
from pathlib import Path

import pytest

from scripts._kpi_canonical import QUESTIONS_REAL, _counts_toward_corpus, count_real_corpus


def _json_files(root: Path) -> list[Path]:
    return sorted(p for p in root.rglob("*.json") if p.is_file())


def test_audit_ledgers_are_not_counted() -> None:
    """现实数据：`_audit/` 下每份台账都必须被判为"不是题"。"""
    audit_dir = QUESTIONS_REAL / "_audit"
    if not audit_dir.is_dir():
        pytest.skip("无 _audit 目录（题库精简版检出）")
    ledgers = _json_files(audit_dir)
    assert ledgers, "_audit 目录里应有台账；空则本用例失去意义"
    counted = [str(p.name) for p in ledgers if _counts_toward_corpus(p)]
    assert counted == [], f"台账被数成题目：{counted}"


def test_questions_are_all_counted_and_total_matches() -> None:
    """现实数据：每道真题都计入，且逐文件计数与 count_real_corpus() 一致。"""
    questions = [p for p in _json_files(QUESTIONS_REAL) if "_audit" not in p.relative_to(QUESTIONS_REAL).parts]
    per_file = [p for p in questions
                if p.name != "_hygiene_manifest.json" and _counts_toward_corpus(p)]
    assert len(per_file) == count_real_corpus(), (
        f"逐文件谓词计数 {len(per_file)} ≠ count_real_corpus() {count_real_corpus()}"
    )
    # 真题必须全部计入（真值下限：不允许因判据收紧而漏题）
    assert len(per_file) >= 90, f"计入题数异常偏少：{len(per_file)}（判据可能误伤真题）"


def test_ledger_shaped_dict_is_rejected(tmp_path: Path) -> None:
    """变异数据：台账形状（无 category/flag_pattern）的 dict 不计入。"""
    p = tmp_path / "ledger_shaped.json"
    p.write_text(json.dumps({
        "batch": "ext47",
        "run_at": "2026-11-11",
        "result": {"runs": 47, "solved": 9},
        "per_question": {"q1": {"status": "failed"}},
    }, ensure_ascii=False), encoding="utf-8")
    assert _counts_toward_corpus(p) is False, "台账形状的 dict 被数成了题目"


def test_question_shaped_dict_is_counted(tmp_path: Path) -> None:
    """变异数据：题目形状的 dict 必须计入（判据不能误伤真题）。"""
    p = tmp_path / "question_shaped.json"
    p.write_text(json.dumps({
        "id": "crypto-999",
        "category": "crypto",
        "title": "t",
        "flag_pattern": "flag{...}",
        "attachments": [],
    }, ensure_ascii=False), encoding="utf-8")
    assert _counts_toward_corpus(p) is True, "题目形状的 dict 未被计入"


def test_unreadable_json_still_counted(tmp_path: Path) -> None:
    """读不出/解析失败的文件保留计数（分母偏大而非偏小，避免抬高覆盖率）。"""
    p = tmp_path / "broken.json"
    p.write_text("{not json", encoding="utf-8")
    assert _counts_toward_corpus(p) is True
