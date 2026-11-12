"""`scripts/recompute_clean_rate.py` 的回归测试（含双向变异）。

**为什么这些用例必须存在**
--------------------------
能力口径 `clean_rate = 4/34 = 0.1176` 依赖两个"剔除名单"和四个派生数。如果判据失效，
台账仍然会显示 4/34 —— 因为台账是人写进去的，它不会自己报错。所以每一条判据都要有
反例：判据必须在自己被破坏时变红，否则"当前数据恰好长这样"会永久掩盖失效。

方向一（正例必计）：真实仓库数据 → 34 / 4 / 0.1176 且与台账逐项一致。
方向二（反例必不计/必报错）：
  - 台账被篡改（分母改 36）→ 校验必须失败；
  - MANIFEST 结构从 dict 变 list → 必须 fail-closed，不许静默当 0 条；
  - 剔除名单里混进池外 id → 必须拒绝（否则 `runs - |名单|` 减掉没跑过的题）；
  - 同名但字节不同 → 不许判成重复（证明判据认字节，不认文件名）。

只读 id / 文件名 / 哈希，不读任何明文 flag。
"""
from __future__ import annotations

import json
from pathlib import Path

import pytest

from scripts import recompute_clean_rate as rcr


def _ledger() -> dict:
    return rcr._load_json(rcr.DEFAULT_LEDGER)


def _kpi() -> dict:
    return rcr._load_json(rcr.DEFAULT_KPI)


def _manifest() -> dict:
    return rcr._load_json(rcr.DEFAULT_MANIFEST)


def _compute(ledger=None, kpi=None, manifest=None,
             dup_source=None, real_dir=None) -> dict:
    return rcr.recompute(
        ledger or _ledger(),
        kpi or _kpi(),
        manifest or _manifest(),
        dup_source or rcr.DEFAULT_DUP_SOURCE,
        real_dir or rcr.DEFAULT_REAL_DIR,
    )


# ── 方向一：真实数据必须复算出台账的数 ──────────────────────────────

def test_live_repo_recomputes_and_matches_ledger():
    ledger = _ledger()
    computed = _compute(ledger=ledger)
    checks = rcr.verify(ledger, computed)
    bad = [c for c in checks if not c["ok"]]
    assert not bad, f"与台账不一致: {bad}"
    assert computed["pool_size"] == computed["runs"] == 47
    assert computed["solved"] == 9


def test_anchor_clean_rate_is_4_over_34():
    """锚点：对外的 11.8% 就是这个式子。改了台账又没改这里，说明有人动过口径。"""
    computed = _compute()
    assert computed["clean_denominator"] == 34
    assert computed["clean_solved"] == 4
    assert computed["clean_rate"] == 0.1176
    assert computed["clean_failed"] == 30


def test_polluted_ids_are_derived_from_manifest_not_handpicked():
    """11 道污染必须是 MANIFEST 的 answer_in_repo 集合，不是手挑的 11 个字符串。"""
    manifest = _manifest()
    derived = rcr.compute_polluted(manifest)
    ledger_polluted = set(_ledger()["pool_contamination"]["polluted_ids"])
    assert len(derived) == 11
    assert derived == ledger_polluted


def test_duplicate_ids_are_derived_from_byte_hash():
    """2 道重复必须是 sha256 撞上的，不是按文件名猜的。"""
    derived = rcr.compute_duplicates(rcr.DEFAULT_DUP_SOURCE, rcr.DEFAULT_REAL_DIR)
    ledger_dups = set(_ledger()["pool_contamination"]["duplicate_real_ids"])
    assert len(derived) == 2
    assert derived == ledger_dups


def test_drop_lists_are_inside_the_pool():
    """剔除名单必须落在池内，否则分母减法失真。"""
    computed = _compute()
    pool = rcr.pool_ids_from_kpi(_kpi())
    assert set(computed["polluted"]) <= pool
    assert set(computed["duplicates"]) <= pool
    assert computed["clean_denominator"] == \
        computed["pool_size"] - len(computed["polluted"]) - len(computed["duplicates"])


# ── 方向二：判据被破坏时必须变红 ───────────────────────────────────

def test_tampered_denominator_is_caught():
    ledger = _ledger()
    ledger["result"]["clean_denominator"] = 36          # 注入错值（36 是去污染未去重复）
    computed = _compute()
    checks = rcr.verify(ledger, computed)
    failed = [c for c in checks if not c["ok"]]
    assert [c["name"] for c in failed] == ["clean_denominator"]


def test_tampered_rate_is_caught():
    ledger = _ledger()
    ledger["result"]["clean_rate"] = 0.1915             # 注入过程值冒充 clean_rate
    checks = rcr.verify(ledger, _compute())
    failed = [c for c in checks if not c["ok"]]
    assert "clean_rate" in [c["name"] for c in failed]


def test_manifest_dropped_shape_change_fails_closed():
    """dropped 从 dict 变 list 时必须报错，不许静默返回空集。

    真实事故：2026-11-12 按 list 遍历 dict，`isinstance(x, dict)` 对字符串键恒 False，
    得出"answer_in_repo 命中 0 条"，差点把 11 道污染当成不存在。
    """
    with pytest.raises(rcr.CannotRun, match="dict"):
        rcr.compute_polluted({"dropped": ["a", "b"]})


def test_out_of_pool_drop_id_is_refused():
    """MANIFEST 里多出一条不在池内的 answer_in_repo → 必须拒绝而非静默相减。"""
    manifest = _manifest()
    manifest = json.loads(json.dumps(manifest))         # 深拷贝，不动原文件
    manifest["dropped"]["ghost_not_in_pool"] = rcr.POLLUTED_REASON
    with pytest.raises(rcr.CannotRun, match="不在池内"):
        _compute(manifest=manifest)


def test_non_reason_value_is_not_counted_as_polluted():
    """只有 failed_selection:answer_in_repo 算污染；别的原因不算。"""
    derived = rcr.compute_polluted({
        "dropped": {
            "a": "failed_selection:answer_in_repo",
            "b": "failed_selection:attachment_missing",
            "c": "failed_selection:too_short",
        }
    })
    assert derived == {"a"}


def test_same_name_different_bytes_is_not_duplicate(tmp_path: Path):
    """同名但内容不同 ≠ 重复。判据认字节，不认文件名。"""
    dup_src = tmp_path / "dup"
    real = tmp_path / "real"
    dup_src.mkdir()
    real.mkdir()
    (real / "q1.json").write_text('{"id":"q1"}', encoding="utf-8")
    (dup_src / "q1.json").write_text('{"id":"q1","difficulty":"hard"}', encoding="utf-8")
    assert rcr.compute_duplicates(dup_src, real) == set()


def test_same_bytes_different_name_is_duplicate(tmp_path: Path):
    """字节完全相同但文件名不同，仍是重复（这是本判据要抓的形态）。

    返回的 id 取 `json.id` 优先、文件名兜底——文件可能被改名，题的身份在 id 里。
    """
    dup_src = tmp_path / "dup"
    real = tmp_path / "real"
    dup_src.mkdir()
    real.mkdir()
    payload = '{"id":"orig","category":"crypto","flag_pattern":"flag\\\\{.*\\\\}"}'
    (real / "orig.json").write_text(payload, encoding="utf-8")
    (dup_src / "copy_of_orig.json").write_text(payload, encoding="utf-8")
    assert rcr.compute_duplicates(dup_src, real) == {"orig"}


def test_missing_ledger_raises_cannot_run(tmp_path: Path):
    with pytest.raises(rcr.CannotRun, match="缺文件"):
        rcr._load_json(tmp_path / "nope.json")


def test_missing_dup_source_raises_cannot_run(tmp_path: Path):
    with pytest.raises(rcr.CannotRun, match="缺目录"):
        rcr.compute_duplicates(tmp_path / "nope", rcr.DEFAULT_REAL_DIR)


def test_kpi_without_ext47_group_fails_closed():
    with pytest.raises(rcr.CannotRun, match="groups.ext47"):
        rcr.pool_ids_from_kpi({"groups": {"other": {"files": ["x.log"]}}})


def test_solved_id_outside_pool_fails_closed():
    """台账 solved_ids 里混进池外题 → 分子会虚高，必须拒绝。"""
    ledger = _ledger()
    ledger = json.loads(json.dumps(ledger))
    ledger["result"]["solved_ids"].append("ghost_outside_pool")
    with pytest.raises(rcr.CannotRun, match="不在池内"):
        _compute(ledger=ledger)


# ── 库内恒等式：kpi 台账足以独立验证 "47 跑 / 9 解出" ──────────────

def test_kpi_metrics_match_ledger_without_logs():
    """不依赖 /tmp/q47 也能验：kpi 台账的 runs/solved 与台账 result 一致。"""
    computed = _compute()
    metrics = rcr.metrics_from_kpi(_kpi())
    assert metrics["runs"] == computed["runs"] == 47
    assert metrics["solved"] == computed["solved"] == 9
    assert metrics["runs"] - metrics["solved"] == metrics["fail_count"] == 38


def test_fails_and_solved_partition_the_pool():
    """kpi 的 fails ∪ 台账 solved_ids 必须恰好等于池，且不相交。"""
    kpi = _kpi()
    ledger = _ledger()
    pool = rcr.pool_ids_from_kpi(kpi)
    fail_ids = rcr.metrics_from_kpi(kpi)["fail_ids"]
    solved = {str(x) for x in ledger["result"]["solved_ids"]}
    assert fail_ids.isdisjoint(solved)
    assert fail_ids | solved == pool


def test_solved_also_in_fails_is_refused():
    """同一题既算解出又算失败 → 口径冲突，必须拒绝。"""
    kpi = _kpi()
    kpi = json.loads(json.dumps(kpi))
    ledger = _ledger()
    fail_id = kpi["groups"]["ext47"]["fails"][0]["id"]
    ledger = json.loads(json.dumps(ledger))
    ledger["result"]["solved_ids"].append(fail_id)   # 制造重叠
    with pytest.raises(rcr.CannotRun, match="既在 solved_ids 又在 kpi fails"):
        _compute(ledger=ledger, kpi=kpi)


def test_uncovered_question_is_refused():
    """从 solved_ids 删掉一条 → 该题既不 solved 也不 fails，台账漏题，必须拒绝。"""
    ledger = _ledger()
    ledger = json.loads(json.dumps(ledger))
    ledger["result"]["solved_ids"].pop()
    with pytest.raises(rcr.CannotRun, match="未覆盖池内"):
        _compute(ledger=ledger)


# ── 分池归因：30 道干净桶失败分别是什么，也要机算 ──────────────

def test_pool_attribution_matches_declared_buckets(tmp_path=None):
    """三桶分布必须与 failure_attribution_by_pool 逐类一致，而不是手写的数字。"""
    ledger = _ledger()
    computed = _compute(ledger=ledger)
    checks = rcr.verify(ledger, computed)
    names = [c["name"] for c in checks if not c["ok"]]
    assert not names, f"有检查未通过: {names}"

    buckets = computed["pool_attribution"]["buckets"]
    assert buckets["clean"]["solved"] == 4
    assert buckets["clean"]["failed"] == 30
    assert buckets["polluted"]["failed"] == 7
    assert buckets["duplicate_real"]["failed"] == 1
    assert sum(b["failed"] for b in buckets.values()) == 38
    # extract_fail 全部落在 polluted 桶 —— 这是"干净桶 0 个 extract_fail"的机算依据
    assert buckets["clean"]["by_category"].get("extract_fail", 0) == 0
    assert buckets["polluted"]["by_category"]["extract_fail"] == 2


def test_failed_question_without_err_is_refused():
    """未解出但 err 为空 → 归因不完整，必须拒绝而不是静默算进 failed。"""
    ledger = _ledger()
    ledger = json.loads(json.dumps(ledger))
    for row in ledger["per_question"]:
        if row["solved"] is False:
            row["err"] = None
            break
    with pytest.raises(rcr.CannotRun, match="err 为空"):
        rcr.compute_pool_attribution(
            ledger,
            set(ledger["pool_contamination"]["polluted_ids"]),
            set(ledger["pool_contamination"]["duplicate_real_ids"]),
        )


def test_bucket_misattribution_is_detected():
    """把一道 clean 题错划进 polluted → 分池分布对不上，_dict_cmp 必须红。

    这一条守的是"分池判据"本身：如果归属搞错，34/30 这些数字会整体错位。
    """
    ledger = _ledger()
    computed = _compute(ledger=ledger)
    declared = json.loads(json.dumps(ledger["failure_attribution_by_pool"]))
    # 人为制造错位：把 clean 桶的一个类别数量改错
    declared["clean"]["by_category"]["tool_failure"] += 1
    cmp = rcr._dict_cmp("分池", computed["pool_attribution"]["buckets"], declared)
    assert not cmp["ok"]
    assert not cmp["detail"]["clean"]["by_category_ok"]
