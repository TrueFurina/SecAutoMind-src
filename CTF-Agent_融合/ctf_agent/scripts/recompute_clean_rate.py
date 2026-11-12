#!/usr/bin/env python
"""复算 47 道外部池的 clean_rate（4/34 = 0.1176），并 fail-closed 校验台账。

**为什么需要**（不是再算一遍，是让数字可被别人验）
--------------------------------------------------
clean_rate 是当前唯一对外的能力口径。它依赖两个"人工剔除"动作：

  ① 11 道 `answer_in_repo` —— 答案就躺在本仓里（writeup / exploit / 同题源码），
     解出来不证明能力，必须从分母剔除；
  ② 2 道与 `data/questions_real` 字节级重复 —— 同一道题在真题库里已经跑过，
     在外池再跑一次是白给。

如果这两份名单是手挑的、34 和 4 是手写进台账的，那这个数字**不可复算**：
任何人拿到仓库都只能选择相信台账。本脚本把三个源全部机算，再与台账逐项比对，
不一致即失败 —— 这样"11.8%"才是一个可以被别人重算的数，而不是一句自证。

**三个源**（都在库内，不依赖 /tmp）
----------------------------------
  1. 池与词汇：`data/questions_real/_audit/kpi_ext47_20261111.json`
     `groups.ext47.files`（47 个日志文件名）→ 池内 id 集合。该文件由
     `scripts/_kpi_from_logs.py` 从跑批日志机算落盘，`log_dir` 记为 `/tmp/q47`。
  2. 污染名单：`benchmarks/external_unseen/MANIFEST.json` 的 `dropped`
     —— 键是题 id、值是丢弃原因；只取 `failed_selection:answer_in_repo`。
  3. 重复名单：`data/questions_ext_L2_pure_reasoning` 下每个 json 的 sha256
     与 `data/questions_real` 递归下所有 json 比对，同哈希即重复。

**口径边界**
------------
- 只读 id、文件名与文件哈希，**不读任何明文 flag**（防泄露只防自己）。
- `47 runs / 9 solved` 取台账 `result.runs` 与 `result.solved_ids`（当时机算落盘）。
  日志丢了不影响本脚本；给了 `--log-dir` 才额外用 `_kpi_from_logs.py` 复算一次。
- 本脚本证明的是"34 和 4 这两个数由哪些源推出、与台账是否一致"，
  **不证明**"47 道题本身选得好不好"——那是选题口径，不在本脚本范围。

退出码：0 全部一致 / 1 有不一致 / 2 无法执行（缺文件或结构变了）
"""
from __future__ import annotations

import argparse
import hashlib
import json
import subprocess
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent

DEFAULT_LEDGER = ROOT / "data/questions_real/_audit/ext47_20261111.json"
DEFAULT_KPI = ROOT / "data/questions_real/_audit/kpi_ext47_20261111.json"
DEFAULT_MANIFEST = ROOT / "benchmarks/external_unseen/MANIFEST.json"
DEFAULT_DUP_SOURCE = ROOT / "data/questions_ext_L2_pure_reasoning"
DEFAULT_REAL_DIR = ROOT / "data/questions_real"

# MANIFEST.dropped 里"答案在本仓"这个原因的取值前缀。写成常量而非散在判断里，
# 是因为它是本脚本唯一的语义契约：MANIFEST 改了措辞，这里必须同步，否则会静默少剔。
POLLUTED_REASON = "failed_selection:answer_in_repo"


class CannotRun(Exception):
    """无法判定（缺文件 / 结构变了）——对应退出码 2，不是"不一致"。"""


def _load_json(path: Path) -> dict:
    if not Path(path).is_file():
        raise CannotRun(f"缺文件: {path}")
    try:
        payload = json.loads(Path(path).read_text(encoding="utf-8"))
    except (OSError, ValueError) as exc:
        raise CannotRun(f"解析失败: {path}: {exc}") from exc
    if not isinstance(payload, dict):
        raise CannotRun(f"顶层不是对象: {path}")
    return payload


def pool_ids_from_kpi(kpi: dict) -> set[str]:
    """从 kpi 台账的 ext47 分组取池内 id（日志文件名去 .log）。"""
    groups = kpi.get("groups")
    if not isinstance(groups, dict) or "ext47" not in groups:
        raise CannotRun("kpi 台账里没有 groups.ext47（分组名变了，判据需重写）")
    files = groups["ext47"].get("files")
    if not isinstance(files, list) or not files:
        raise CannotRun("groups.ext47.files 为空或不是列表")
    return {Path(str(f)).stem for f in files}


def metrics_from_kpi(kpi: dict) -> dict:
    """从 kpi 台账取 runs / solved / 失败 id 集合。

    这一层让 "9" 和 "哪 9 道" 都能在库内验证，不必依赖服务器上的跑批日志：
    kpi 台账是 `_kpi_from_logs.py` 从 47 份日志机算落盘的，`fails` 即未解出的题。
    于是 `runs - solved == len(fails)` 与 `fails ∪ solved == 池` 都是纯库内恒等式。
    """
    groups = kpi.get("groups")
    if not isinstance(groups, dict) or "ext47" not in groups:
        raise CannotRun("kpi 台账里没有 groups.ext47（分组名变了，判据需重写）")
    ext = groups["ext47"]
    runs, solved = ext.get("runs"), ext.get("solved")
    if not isinstance(runs, int) or not isinstance(solved, int):
        raise CannotRun(f"groups.ext47.runs/solved 不是整数: {runs!r} / {solved!r}")
    fails = ext.get("fails")
    if not isinstance(fails, list):
        raise CannotRun("groups.ext47.fails 不是列表")

    fail_ids: set[str] = set()
    for f in fails:
        if not isinstance(f, dict):
            continue
        qid = f.get("id") or Path(str(f.get("file", ""))).stem
        if qid:
            fail_ids.add(str(qid))
    return {"runs": runs, "solved": solved,
            "fail_ids": fail_ids, "fail_count": len(fails)}



def compute_polluted(manifest: dict) -> set[str]:
    """从 MANIFEST.dropped 机算"答案在本仓"的题 id。

    注意 dropped 是 **dict**（键=id，值=原因字符串），不是 list。
    2026-11-12 实测踩过：按 list 遍历时 `isinstance(x, dict)` 对字符串键恒 False，
    于是得出"answer_in_repo 命中 0 条"的错误结论。此处显式判 dict 并在结构变化时 fail-closed。
    """
    dropped = manifest.get("dropped")
    if dropped is None:
        return set()
    if not isinstance(dropped, dict):
        raise CannotRun(
            f"MANIFEST.dropped 是 {type(dropped).__name__} 而非 dict（结构变了，判据需重写）"
        )
    return {
        str(qid)
        for qid, reason in dropped.items()
        if isinstance(reason, str) and reason.startswith(POLLUTED_REASON)
    }


def compute_duplicates(dup_source: Path, real_dir: Path) -> set[str]:
    """字节级重复：外池文件的 sha256 在 questions_real 里也出现 ⇒ 该题记重复。

    比"同名文件"更严格——同名不同内容不算重复（那是两次不同的题）；
    比"同 id"更严格——id 可能被改名过。只认原始字节。
    返回的 id 取 `json.id` 优先、文件名 stem 兜底：文件可以被改名，题的身份在 id 里。
    """
    if not Path(dup_source).is_dir():
        raise CannotRun(f"缺目录: {dup_source}")
    if not Path(real_dir).is_dir():
        raise CannotRun(f"缺目录: {real_dir}")

    real_hashes: dict[str, Path] = {}
    for f in Path(real_dir).rglob("*.json"):
        try:
            real_hashes.setdefault(hashlib.sha256(f.read_bytes()).hexdigest(), f)
        except OSError:
            continue

    hits: set[str] = set()
    for f in Path(dup_source).rglob("*.json"):
        try:
            digest = hashlib.sha256(f.read_bytes()).hexdigest()
        except OSError:
            continue
        if digest not in real_hashes:
            continue
        qid = f.stem
        try:
            payload = json.loads(f.read_text(encoding="utf-8"))
            if isinstance(payload, dict) and payload.get("id"):
                qid = str(payload["id"])
        except (OSError, ValueError):
            pass  # 读不出就用文件名，不因单题解析失败丢掉整个判据
        hits.add(qid)
    return hits


def compute_pool_attribution(ledger: dict, polluted: set[str],
                             duplicates: set[str]) -> dict:
    """按 id 归属把池切成 clean / polluted / duplicate_real 三桶，机算每桶失败类别。

    为什么要在 clean_rate 脚本里做这件事：`clean_rate = 4/34` 只给出成功率，
    而 34 道里有 30 道失败 —— 对外交代时第一个被追问的就是"这 30 道分别败在哪"。
    台账 `failure_attribution_by_pool` 声称 clean=30（tool_failure 7 / no_candidate 6 /
    stuck_loop 5 / unresolved 5 / wrong_direction 4 / race_abandon 1 / timeout_330 1 /
    prefix_format_mismatch_recoverable 1），这里从 `per_question` 的 `err` 字段机算，
    逐桶逐类比对，防止分池数字是手写的。

    归属判据（与台账 note 一致）：id ∈ polluted_ids → polluted；
    id ∈ duplicate_real_ids → duplicate_real；其余 → clean。
    """
    if not isinstance(ledger.get("per_question"), list) or not ledger["per_question"]:
        raise CannotRun("台账缺 per_question（逐题记录）——分池归因需要它")

    buckets: dict[str, dict] = {
        "clean": {"solved": 0, "failed": 0, "by_category": {}},
        "polluted": {"solved": 0, "failed": 0, "by_category": {}},
        "duplicate_real": {"solved": 0, "failed": 0, "by_category": {}},
    }

    for row in ledger["per_question"]:
        if not isinstance(row, dict):
            raise CannotRun("per_question 里有非对象条目")
        qid = str(row.get("id") or "")
        if not qid:
            raise CannotRun("per_question 有条目缺 id")
        solved = row.get("solved")
        if not isinstance(solved, bool):
            raise CannotRun(f"per_question[{qid}].solved 不是布尔值: {solved!r}")

        name = ("polluted" if qid in polluted
                else "duplicate_real" if qid in duplicates
                else "clean")
        b = buckets[name]
        if solved:
            b["solved"] += 1
            continue

        b["failed"] += 1
        cat = row.get("err")
        if not isinstance(cat, str) or not cat:
            raise CannotRun(
                f"per_question[{qid}] 未解出但 err 为空 —— 归因不完整，不能当作已归因"
            )
        b["by_category"][cat] = b["by_category"].get(cat, 0) + 1

    totals = {"solved": 0, "failed": 0}
    for _name, b in buckets.items():
        b["by_category"] = dict(sorted(b["by_category"].items()))
        b["denominator_basis"] = b["solved"] + b["failed"]
        totals["solved"] += b["solved"]
        totals["failed"] += b["failed"]
    return {"buckets": buckets, "totals": totals}


def _dict_cmp(name: str, computed_val: dict, ledger_val) -> dict:
    """三桶分布比对：逐桶逐类，且要求类别键集合相同（多一类、少一类都算不一致）。"""
    if not isinstance(ledger_val, dict):
        return {"name": name, "computed": computed_val, "ledger": ledger_val,
                "ok": False, "reason": "台账缺该段或不是对象"}
    detail = {}
    ok = True
    for bucket, b in computed_val.items():
        declared = ledger_val.get(bucket)
        if not isinstance(declared, dict):
            detail[bucket] = {"ok": False, "reason": "台账缺该桶"}
            ok = False
            continue
        c_cat = b["by_category"]
        d_cat = declared.get("by_category")
        if not isinstance(d_cat, dict):
            detail[bucket] = {"ok": False, "reason": "台账缺 by_category"}
            ok = False
            continue
        # 台账里值为 0 的类别与本机算"不出现"等价，剔掉 0 再比，避免 0 与缺失的假差异
        same_cat = c_cat == {k: v for k, v in d_cat.items() if v}
        same_n = (b["solved"] == declared.get("solved")
                  and b["failed"] == declared.get("failed"))
        detail[bucket] = {"by_category_ok": same_cat, "counts_ok": same_n,
                          "computed_cat": c_cat, "ledger_cat": d_cat}
        ok = ok and same_cat and same_n
    return {"name": name, "computed": computed_val, "ledger": ledger_val,
            "ok": ok, "detail": detail}


def recompute(ledger: dict, kpi: dict, manifest: dict,
              dup_source: Path, real_dir: Path) -> dict:
    """机算分母/分子/成功率，并把每个中间量单独返回（便于逐项比对）。"""
    result = ledger.get("result")
    if not isinstance(result, dict):
        raise CannotRun("台账缺 result 段")
    runs = result.get("runs")
    if not isinstance(runs, int) or runs <= 0:
        raise CannotRun(f"result.runs 非法: {runs!r}")
    solved_ids = result.get("solved_ids")
    if not isinstance(solved_ids, list) or not solved_ids:
        raise CannotRun("result.solved_ids 为空或不是列表")

    pool = pool_ids_from_kpi(kpi)
    metrics = metrics_from_kpi(kpi)
    polluted = compute_polluted(manifest)
    duplicates = compute_duplicates(dup_source, real_dir)

    # 剔除名单必须落在池内。否则 runs - |名单| 会减掉没跑过的题，分母凭空变小。
    outside = (polluted | duplicates) - pool
    if outside:
        raise CannotRun(
            "剔除名单里有不在池内的题（分母减法会失真）: "
            + ", ".join(sorted(outside)[:6])
        )

    solved = {str(x) for x in solved_ids}
    solved_outside = solved - pool
    if solved_outside:
        raise CannotRun(
            "solved_ids 里有不在池内的题: " + ", ".join(sorted(solved_outside)[:6])
        )

    # 内部一致性：kpi 台账的 fails 与 result.solved_ids 必须恰好把池切成两半。
    # 这一条不依赖原始日志，所以是第三方开箱即可验的强约束：
    # 漏题（fails∪solved 小于池）、重叠（同一题既算解出又算失败）都会在这里暴露。
    uncovered = pool - solved - metrics["fail_ids"]
    if uncovered:
        raise CannotRun(
            "kpi 的 fails 与台账 solved_ids 未覆盖池内这些题（台账漏了或 kpi 少记）: "
            + ", ".join(sorted(uncovered)[:6])
        )
    overlap = solved & metrics["fail_ids"]
    if overlap:
        raise CannotRun(
            "同一题既在 solved_ids 又在 kpi fails 里（口径冲突）: "
            + ", ".join(sorted(overlap)[:6])
        )

    pool_attribution = compute_pool_attribution(ledger, polluted, duplicates)
    # 分池闭合：三桶 solved/failed 必须等于 9/38，且三桶之和 = 池
    if pool_attribution["totals"]["solved"] != len(solved):
        raise CannotRun(
            "分池 solved 合计 %d 与 solved_ids 条数 %d 不符"
            % (pool_attribution["totals"]["solved"], len(solved))
        )

    denom = len(pool) - len(polluted) - len(duplicates)
    clean_solved = len(solved) - len(solved & polluted) - len(solved & duplicates)
    rate = round(clean_solved / denom, 4) if denom else None

    return {
        "pool_size": len(pool),
        "runs": runs,
        "solved": len(solved),
        "kpi_runs": metrics["runs"],
        "kpi_solved": metrics["solved"],
        "kpi_fail_count": metrics["fail_count"],
        "polluted": sorted(polluted),
        "duplicates": sorted(duplicates),
        "solved_in_polluted": sorted(solved & polluted),
        "solved_in_duplicates": sorted(solved & duplicates),
        "clean_denominator": denom,
        "clean_solved": clean_solved,
        "clean_failed": denom - clean_solved,
        "clean_rate": rate,
        "pool_attribution": pool_attribution,
        "formula": {
            "denominator": f"{len(pool)} - {len(polluted)} - {len(duplicates)} = {denom}",
            "numerator": (f"{len(solved)} - {len(solved & polluted)} - "
                          f"{len(solved & duplicates)} = {clean_solved}"),
            "rate": f"{clean_solved}/{denom} = {rate}",
        },
    }


def verify(ledger: dict, computed: dict) -> list[dict]:
    """逐项比对台账，返回 checks（含 ok 标记）。"""
    result = ledger.get("result") or {}
    pc = ledger.get("pool_contamination") or {}

    def _set_cmp(name: str, computed_val, ledger_val) -> dict:
        return {
            "name": name,
            "computed": sorted(computed_val),
            "ledger": sorted(ledger_val or []),
            "ok": set(computed_val) == set(ledger_val or []),
        }

    def _num_cmp(name: str, computed_val, ledger_val) -> dict:
        return {
            "name": name,
            "computed": computed_val,
            "ledger": ledger_val,
            "ok": computed_val is not None and ledger_val is not None
                  and float(computed_val) == float(ledger_val),
        }

    return [
        _set_cmp("polluted_ids 由 MANIFEST answer_in_repo 机算",
                 computed["polluted"], pc.get("polluted_ids")),
        _set_cmp("duplicate_real_ids 由字节级 sha256 机算",
                 computed["duplicates"], pc.get("duplicate_real_ids")),
        _num_cmp("clean_denominator", computed["clean_denominator"],
                 result.get("clean_denominator")),
        _num_cmp("clean_solved", computed["clean_solved"], result.get("clean_solved")),
        _num_cmp("clean_rate", computed["clean_rate"], result.get("clean_rate")),
        _num_cmp("clean_failed", computed["clean_failed"], result.get("clean_failed")),
        _set_cmp("polluted_solved_ids 由 solved ∩ polluted 机算",
                 computed["solved_in_polluted"], pc.get("polluted_solved_ids")),
        _num_cmp("polluted_among_solved（数量与上一条一致）",
                 len(computed["solved_in_polluted"]), pc.get("polluted_among_solved")),
        _num_cmp("kpi 台账 runs 与 result 一致",
                 computed["kpi_runs"], computed["runs"]),
        _num_cmp("kpi 台账 solved 与 result 一致",
                 computed["kpi_solved"], computed["solved"]),
        _num_cmp("kpi 台账 runs - solved == 失败条数（库内恒等式）",
                 computed["kpi_runs"] - computed["kpi_solved"],
                 computed["kpi_fail_count"]),
        _dict_cmp("三桶分池失败分布 与 failure_attribution_by_pool 逐类一致",
                  computed["pool_attribution"]["buckets"],
                  ledger.get("failure_attribution_by_pool")),
    ]


def recompute_runs_from_logs(log_dir: Path) -> dict:
    """可选：从原始日志再算一次 runs/solved，用于验证台账 result 段没被改过。"""
    script = ROOT / "scripts/_kpi_from_logs.py"
    if not script.is_file():
        raise CannotRun(f"缺生成器: {script}")
    if not Path(log_dir).is_dir():
        raise CannotRun(f"缺日志目录: {log_dir}")
    proc = subprocess.run(
        [sys.executable, "-X", "utf8", str(script), "--log-dir", str(log_dir),
         "--group", "ext47=*.log", "--quiet"],
        cwd=str(ROOT), capture_output=True, text=True, timeout=300,
    )
    if proc.returncode != 0:
        raise CannotRun(f"_kpi_from_logs.py 失败 (rc={proc.returncode}): "
                        f"{(proc.stderr or proc.stdout or '').strip()[:200]}")
    try:
        payload = json.loads(proc.stdout)
    except ValueError as exc:
        raise CannotRun(f"日志机算输出不是 JSON: {exc}") from exc
    group = (payload.get("groups") or {}).get("ext47") or {}
    return {"runs": group.get("runs"), "solved": group.get("solved")}


def main() -> int:
    ap = argparse.ArgumentParser(
        description="复算 47 道外部池 clean_rate 并 fail-closed 校验台账")
    ap.add_argument("--ledger", default=str(DEFAULT_LEDGER))
    ap.add_argument("--kpi", default=str(DEFAULT_KPI))
    ap.add_argument("--manifest", default=str(DEFAULT_MANIFEST))
    ap.add_argument("--dup-source", default=str(DEFAULT_DUP_SOURCE))
    ap.add_argument("--real-dir", default=str(DEFAULT_REAL_DIR))
    ap.add_argument("--log-dir", default=None,
                    help="给了就额外从原始日志再算 runs/solved 并与台账比对")
    ap.add_argument("--json", action="store_true")
    args = ap.parse_args()

    try:
        ledger = _load_json(Path(args.ledger))
        kpi = _load_json(Path(args.kpi))
        manifest = _load_json(Path(args.manifest))
        computed = recompute(ledger, kpi, manifest,
                             Path(args.dup_source), Path(args.real_dir))
    except CannotRun as exc:
        payload = {"ok": False, "rc": 2, "reason": str(exc)}
        print(json.dumps(payload, ensure_ascii=False, indent=2) if args.json
              else f"无法判定（退出码 2）：{exc}")
        return 2

    checks = verify(ledger, computed)

    # 可选：日志再算一次 runs/solved
    log_check = None
    if args.log_dir:
        try:
            logged = recompute_runs_from_logs(Path(args.log_dir))
            log_check = {
                "name": "runs/solved 由原始日志机算",
                "computed": logged,
                "ledger": {"runs": computed["runs"], "solved": computed["solved"]},
                "ok": (logged["runs"] == computed["runs"]
                       and logged["solved"] == computed["solved"]),
            }
            checks.append(log_check)
        except CannotRun as exc:
            checks.append({"name": "runs/solved 由原始日志机算",
                           "computed": None, "ledger": None,
                           "ok": False, "reason": str(exc)})

    passed = all(c["ok"] for c in checks)
    payload = {
        "ok": passed,
        "rc": 0 if passed else 1,
        "ledger": str(Path(args.ledger).resolve()),
        "manifest": str(Path(args.manifest).resolve()),
        "computed": computed,
        "checks": checks,
    }

    if args.json:
        print(json.dumps(payload, ensure_ascii=False, indent=2))
    else:
        print(f"池 {computed['pool_size']} 道 / 跑 {computed['runs']} / 解出 {computed['solved']}")
        print(f"剔除：answer_in_repo {len(computed['polluted'])} 道，"
              f"字节级重复 {len(computed['duplicates'])} 道")
        for line in computed["formula"].values():
            print(f"  复算 {line}")
        print()
        for c in checks:
            mark = "✅" if c["ok"] else "❌"
            print(f"{mark} {c['name']}")
            if not c["ok"]:
                print(f"    computed={c['computed']!r}")
                print(f"    ledger  ={c['ledger']!r}")
                if c.get("reason"):
                    print(f"    reason  ={c['reason']}")
        print()
        print("复算校验：" + ("通过" if passed else "未通过"))
    return payload["rc"]


if __name__ == "__main__":
    sys.exit(main())
