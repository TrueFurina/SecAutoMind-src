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

    denom = len(pool) - len(polluted) - len(duplicates)
    clean_solved = len(solved) - len(solved & polluted) - len(solved & duplicates)
    rate = round(clean_solved / denom, 4) if denom else None

    return {
        "pool_size": len(pool),
        "runs": runs,
        "solved": len(solved),
        "polluted": sorted(polluted),
        "duplicates": sorted(duplicates),
        "solved_in_polluted": sorted(solved & polluted),
        "solved_in_duplicates": sorted(solved & duplicates),
        "clean_denominator": denom,
        "clean_solved": clean_solved,
        "clean_failed": denom - clean_solved,
        "clean_rate": rate,
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
        _num_cmp("polluted_among_solved（台账声明的解出污染数）",
                 len(computed["solved_in_polluted"]), pc.get("polluted_among_solved")),
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
