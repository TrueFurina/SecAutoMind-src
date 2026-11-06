#!/usr/bin/env python
# -*- coding: utf-8 -*-
"""私有题池「外部锚点」证明契约：堵死「题面自证即私有」的自证闭环。

背景（2026-11-06 评审 §17，第六个偏差，实锤可复现）
------------------------------------------------------------
`audit_pool_prior.classify()` 判 `private_proven` 的四条判据全部来自**题面字段**
（source / created_at / 无公开标识）。实测：把 `purellm_clean_benchmark_v2.json`
的 154 道题只改 id / name / description / pool / source / created_at，
**flag_sha256 一字不动**，即得::

    private_proven = 154/154
    capability_rate_publishable = True
    → claim_scope = capability_rate_candidate

题仍是那批公开题，只是套了「私有」壳。也就是说判据链最上层「这个数值能不能
叫能力率」完全由出题方自证决定 —— 与前面五个假绿同源：声明被当成证据。

契约（fail-closed，R0–R6 全过且覆盖全池才 anchored=True）
------------------------------------------------------------
  R0 注册表 `pool_sha256` == 当前池文件 sha256（防换池套用）
  R1 注册表存在、可解析，且**已在 git 历史中**（非本地草稿）
  R2 池内每题都有条目，且无多余条目
  R3 `problem_fingerprint` == sha256(description + "\\n" + flag_sha256) 重算值
  R4 `flag_sha256` 不与任何已知公开池（v1 / v2 / 草稿池）的真值重合
      —— 专门堵「把公开题套壳洗白」这条攻击路径
  R5 `first_commit` 是真实 commit（git cat-file -e），其**提交日期**（从 git 读，
      不信任自填）> PRIOR_CUTOFF，且 == 注册表登记的 first_commit_date
  R6 `declared_unreleased` 为 true（必要条件，非充分条件）

任何一条不满足 ⇒ anchored=False，该题不计私有。注册表缺失/解析失败/公开池
清单读不到 ⇒ 整体 fail-closed，绝不「猜一个绿」。

`run_capability_eval.claim_scope_for_pool()` 只在 anchored=True 时允许
`capability_rate_candidate`；否则即便题面自证全绿也强制降级。

用法：
  python scripts/audit_private_proof.py --selftest
  python scripts/audit_private_proof.py --check [--pool P] [--registry R]
  python scripts/audit_private_proof.py --verify
  python scripts/audit_private_proof.py --require-proof   # 未达成则 RC=2
"""
from __future__ import annotations

import argparse
import hashlib
import json
import os
import subprocess
import sys
from datetime import date, datetime

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
POOL = os.path.join(ROOT, "data", "ctf_benchmark", "purellm_clean_benchmark_v2.json")
REGISTRY = os.path.join(ROOT, "data", "ctf_benchmark", "private_pool_registry.json")
EVIDENCE = os.path.join(ROOT, "docs", "evidence", "capability_eval_20261105",
                        "private_proof_audit.json")
CONTRACT = "private-pool-proof/v1"

# 与 audit_pool_prior 保持一致；只有严格晚于此日期的首次提交才可能排除模型先验。
PRIOR_CUTOFF = date(2025, 1, 1)
# 只列**已入库**的公开池：CI checkout 拿不到被 .gitignore 忽略的本地草稿
# （purellm_full188.json 未入库），挂进去会让清单永远带一条假缺失。
PUBLIC_POOLS = (
    "data/ctf_benchmark/purellm_clean_benchmark.json",
    "data/ctf_benchmark/purellm_clean_benchmark_v2.json",
    "data/ctf_benchmark/real_benchmark.json",
    "data/questions_external_bench/external_bench.json",
)


def _sha256_file(path: str) -> str:
    h = hashlib.sha256()
    with open(path, "rb") as f:
        for chunk in iter(lambda: f.read(1 << 20), b""):
            h.update(chunk)
    return h.hexdigest()


def problem_fingerprint(problem: dict) -> str:
    """题目内容指纹：题面 + 真值哈希，不含任何明文答案。"""
    desc = str(problem.get("description", ""))
    flag = str(problem.get("flag_sha256", ""))
    return hashlib.sha256((desc + "\n" + flag).encode("utf-8")).hexdigest()


def _git(*args: str) -> tuple[int, str]:
    try:
        r = subprocess.run(["git", *args], cwd=ROOT, capture_output=True,
                           text=True, timeout=20)
        return r.returncode, (r.stdout or "").strip()
    except (OSError, subprocess.SubprocessError):
        return 1, ""


def _commit_date(sha: str) -> date | None:
    rc, out = _git("show", "-s", "--format=%cI", sha)
    if rc != 0 or not out:
        return None
    try:
        return datetime.fromisoformat(out.replace("Z", "+00:00")).date()
    except ValueError:
        return None


def _is_tracked(relpath: str) -> bool:
    rc, out = _git("log", "-1", "--format=%H", "--", relpath.replace("\\", "/"))
    return rc == 0 and bool(out)


def _public_truth_hashes() -> tuple[set[str], list[str]]:
    """已知公开池的真值集合；读不到任何一份都要显式留痕（fail-closed 判据）。"""
    hashes: set[str] = set()
    missing: list[str] = []
    for rel in PUBLIC_POOLS:
        p = os.path.join(ROOT, rel)
        if not os.path.isfile(p):
            missing.append(rel)
            continue
        try:
            d = json.load(open(p, encoding="utf-8"))
            probs = d.get("problems", d)
            items = probs.values() if isinstance(probs, dict) else probs
            for it in items:
                if isinstance(it, dict) and it.get("flag_sha256"):
                    hashes.add(str(it["flag_sha256"]).lower())
        except (OSError, ValueError, TypeError):
            missing.append(rel)
    return hashes, missing


def assess(pool_path: str = POOL, registry_path: str = REGISTRY,
           require_tracked: bool = True) -> dict:
    """重算私有性外部锚点结论。生产调用必须 require_tracked=True。

    `require_tracked=False` 仅供 --selftest 注入：合成注册表无法真的进 git 历史，
    但入库性由单独用例覆盖；生产路径不允许关闭该检查。
    """
    out = {
        "tool": "scripts/audit_private_proof.py::assess",
        "contract": CONTRACT,
        "pool_path": os.path.relpath(pool_path, ROOT).replace("\\", "/")
        if os.path.exists(pool_path) else pool_path,
        "registry_path": os.path.relpath(registry_path, ROOT).replace("\\", "/")
        if os.path.exists(registry_path) else registry_path,
        "pool_sha256": None,
        "registry_sha256": None,
        "anchored": False,
        "anchored_count": 0,
        "total": 0,
        "public_truth_hashes_loaded": 0,
        "public_pools_missing": [],
        "reasons": [],
        "per_problem_rejections": {},
        "prior_cutoff": PRIOR_CUTOFF.isoformat(),
    }
    if not os.path.isfile(pool_path):
        out["reasons"].append("pool_missing")
        return out
    out["pool_sha256"] = _sha256_file(pool_path)
    try:
        pool = json.load(open(pool_path, encoding="utf-8"))
        problems = pool.get("problems", pool)
        if isinstance(problems, list):
            problems = {p.get("id", str(i)): p for i, p in enumerate(problems)}
    except (OSError, ValueError, TypeError) as exc:
        out["reasons"].append("pool_unparsable:%s" % type(exc).__name__)
        return out
    if not isinstance(problems, dict) or not problems:
        out["reasons"].append("pool_empty_or_bad_shape")
        return out
    out["total"] = len(problems)

    # 公开真值清单健康度先算，避免「注册表缺失」短路让证据看起来像「公开池全读到」。
    pub_hashes, missing = _public_truth_hashes()
    out["public_truth_hashes_loaded"] = len(pub_hashes)
    out["public_pools_missing"] = missing
    if not pub_hashes:
        out["reasons"].append("no_public_pool_available: 无法排除洗白，fail-closed")
        return out

    if not os.path.isfile(registry_path):
        out["reasons"].append("no_registry: 私有性无外部锚点，题面自证一律不采信")
        return out
    out["registry_sha256"] = _sha256_file(registry_path)
    try:
        reg = json.load(open(registry_path, encoding="utf-8"))
    except (OSError, ValueError) as exc:
        out["reasons"].append("registry_unparsable:%s" % type(exc).__name__)
        return out
    if not isinstance(reg, dict) or reg.get("contract") != CONTRACT:
        out["reasons"].append("registry_contract_mismatch")
        return out
    if str(reg.get("pool_sha256", "")).lower() != out["pool_sha256"]:
        out["reasons"].append("registry_pool_sha256_mismatch")   # R0
        return out
    if require_tracked and not _is_tracked(
            os.path.relpath(registry_path, ROOT).replace("\\", "/")):
        out["reasons"].append("registry_not_in_git_history")       # R1
        return out
    entries = reg.get("entries")
    if not isinstance(entries, dict):
        out["reasons"].append("registry_entries_missing")
        return out

    # R2 覆盖性
    if set(entries) != set(problems):
        out["reasons"].append("registry_coverage_mismatch")
        return out

    good = 0
    for pid, prob in problems.items():
        bad: list[str] = []
        e = entries[pid]
        if not isinstance(e, dict):
            bad.append("entry_bad_shape")
        else:
            if str(e.get("problem_fingerprint", "")).lower() != problem_fingerprint(prob):
                bad.append("fingerprint_mismatch")                       # R3
            flag = str(prob.get("flag_sha256", "")).lower()
            if str(e.get("flag_sha256", "")).lower() != flag:
                bad.append("flag_sha256_mismatch")
            if flag in pub_hashes:
                bad.append("public_truth_reused")                        # R4
            sha = str(e.get("first_commit", ""))
            rc, _ = _git("cat-file", "-e", "%s^{commit}" % sha) if sha else (1, "")
            if rc != 0:
                bad.append("first_commit_not_real")                      # R5
            else:
                d = _commit_date(sha)
                if d is None or d <= PRIOR_CUTOFF:
                    bad.append("first_commit_not_post_cutoff")
                if str(e.get("first_commit_date", "")) != (d.isoformat() if d else ""):
                    bad.append("first_commit_date_not_from_git")
            if e.get("declared_unreleased") is not True:
                bad.append("unreleased_not_declared")                     # R6
        if bad:
            out["per_problem_rejections"][pid] = bad
        else:
            good += 1
    out["anchored_count"] = good
    out["anchored"] = (good == out["total"] > 0)
    if not out["anchored"]:
        out["reasons"].append("%d/%d 题未通过外部锚点校验" % (out["total"] - good, out["total"]))
    return out


def selftest() -> int:
    """变异验证：证明锚点可放行合规样例、可拒绝每一种伪造。"""
    import copy
    import tempfile

    work = os.path.join(ROOT, ".workbuddy", "tmp", "capability_eval")
    os.makedirs(work, exist_ok=True)
    pool_p = os.path.join(work, "_pproof_pool.json")
    reg_p = os.path.join(work, "_pproof_registry.json")

    # 真实锚点：当前 HEAD 及其真实提交日期（不由注册表自填）
    rc, head = _git("rev-parse", "HEAD")
    head_date = _commit_date(head) if rc == 0 else None
    if not head or not head_date:
        print("SKIP: 无法读取 git HEAD/日期（非 git 工作树）")
        return 2

    synthetic_flag = hashlib.sha256(b"synthetic-private-problem-20261106").hexdigest()
    prob = {"id": "pp_001", "description": "合成私有题：分析给定工件。",
            "pool": "private", "source": "internal-private",
            "created_at": "2026-11-06", "flag_sha256": synthetic_flag}
    pool = {"problems": {"pp_001": prob}}

    def entry(**kw):
        e = {"problem_fingerprint": problem_fingerprint(prob),
             "flag_sha256": synthetic_flag,
             "first_commit": head,
             "first_commit_date": head_date.isoformat(),
             "declared_unreleased": True}
        e.update(kw)
        return e

    def run(pool_obj, reg_obj, tracked=True, expect=True):
        json.dump(pool_obj, open(pool_p, "w", encoding="utf-8"))
        reg_obj = dict(reg_obj)
        reg_obj["pool_sha256"] = _sha256_file(pool_p)
        json.dump(reg_obj, open(reg_p, "w", encoding="utf-8"))
        r = assess(pool_p, reg_p, require_tracked=tracked)
        return r["anchored"], r["reasons"]

    def reg(entries=None, **kw):
        # 注意：空 dict 是合法的「缺题」变异，不能用 `or` 回填默认条目。
        d = {"contract": CONTRACT,
             "entries": {"pp_001": entry()} if entries is None else entries}
        d.update(kw)
        return d

    cases = []

    def case(name, got, want=True):
        cases.append((name, got, want, got == want))

    # 1 合规合成样例 ⇒ 分支可达（不是永远红灯）
    ok, _ = run(pool, reg(), tracked=False)
    case("合规合成注册表放行（分支可达）", ok, True)
    # 2 入库性：require_tracked=True 时未入库注册表必须拒绝
    ok, _ = run(pool, reg(), tracked=True)
    case("注册表未入库被拒（R1）", ok, False)
    # 3 伪造 commit
    ok, _ = run(pool, reg({"pp_001": entry(first_commit="deadbeef" * 5)}), tracked=False)
    case("伪造 first_commit 被拒（R5）", ok, False)
    # 4 伪造日期（与 git 不符）
    ok, _ = run(pool, reg({"pp_001": entry(first_commit_date="2026-01-01")}), tracked=False)
    case("自填日期与 git 不符被拒（R5）", ok, False)
    # 5 内容指纹漂移
    ok, _ = run(pool, reg({"pp_001": entry(problem_fingerprint="0" * 64)}), tracked=False)
    case("内容指纹漂移被拒（R3）", ok, False)
    # 6 未公开声明缺失
    ok, _ = run(pool, reg({"pp_001": entry(declared_unreleased=False)}), tracked=False)
    case("缺未公开声明被拒（R6）", ok, False)
    # 7 注册表缺题
    ok, _ = run(pool, reg({}), tracked=False)
    case("注册表缺题被拒（R2）", ok, False)
    # 8 注册表契约头不对
    ok, _ = run(pool, {"contract": "other/v9", "entries": {"pp_001": entry()}}, tracked=False)
    case("契约头不符被拒", ok, False)
    # 9 换池套用（R0）：注册表造好后池被替换
    json.dump(pool, open(pool_p, "w", encoding="utf-8"))
    json.dump(reg(entries={"pp_001": entry()}, pool_sha256=_sha256_file(pool_p)),
              open(reg_p, "w", encoding="utf-8"))
    other = {"problems": {"pp_001": dict(prob, description="另一份题面")}}
    json.dump(other, open(pool_p, "w", encoding="utf-8"))
    case("换池套用被拒（R0）", assess(pool_p, reg_p, require_tracked=False)["anchored"], False)
    # 10 注册表不存在 ⇒ fail-closed
    r = assess(pool_p, os.path.join(work, "_pproof_absent.json"), require_tracked=False)
    case("注册表缺失 fail-closed", r["anchored"], False)

    # 11 洗白攻击：拿真实公开题真值套「私有」壳 ⇒ R4 必须拒绝
    v2 = os.path.join(ROOT, "data", "ctf_benchmark", "purellm_clean_benchmark_v2.json")
    if os.path.isfile(v2):
        pub = json.load(open(v2, encoding="utf-8"))["problems"]
        pubid, pubprob = next(iter(pub.items()))
        attacked = {"problems": {"pp_001": {
            "id": "pp_001", "description": "分析给定工件并给出结论。",
            "pool": "private", "source": "internal-private",
            "created_at": "2026-11-06", "flag_sha256": pubprob["flag_sha256"]}}}
        attacked_entry = {"pp_001": {
            "problem_fingerprint": problem_fingerprint(attacked["problems"]["pp_001"]),
            "flag_sha256": pubprob["flag_sha256"], "first_commit": head,
            "first_commit_date": head_date.isoformat(), "declared_unreleased": True}}
        ok, _ = run(attacked, {"contract": CONTRACT, "entries": attacked_entry}, tracked=False)
        case("公开题真值套私有壳被拒（R4 洗白攻击）", ok, False)
        # 12 同一攻击在旧判据里确实能得 private_proven（证明洞存在，不是想象）
        sys.path.insert(0, os.path.join(ROOT, "scripts"))
        import audit_pool_prior
        kind = audit_pool_prior.classify("pp_001", attacked["problems"]["pp_001"])[0]
        case("题面自证伪造在旧判据里确实成立", kind, "private_proven")

    passed = sum(1 for *_, ok in cases if ok)
    for name, got, want, ok in cases:
        print("  [%s] %-42s got=%-18s want=%s" %
              ("OK" if ok else "FAIL", name, str(got)[:18], want))
    print("私有性外部锚点自测：%d/%d" % (passed, len(cases)))
    for p in (pool_p, reg_p):
        try:
            os.remove(p)
        except OSError:
            pass
    return 0 if passed == len(cases) else 1


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__.splitlines()[1])
    ap.add_argument("--pool", default=POOL)
    ap.add_argument("--registry", default=REGISTRY)
    ap.add_argument("--selftest", action="store_true")
    ap.add_argument("--check", action="store_true", help="重算结论并写证据 JSON")
    ap.add_argument("--verify", action="store_true", help="复核证据与当前重算一致")
    ap.add_argument("--require-proof", action="store_true", help="未达成时 RC=2")
    args = ap.parse_args()

    if args.selftest:
        return selftest()

    result = assess(args.pool, args.registry, require_tracked=True)
    if args.verify:
        if not os.path.isfile(EVIDENCE):
            print("FAIL: 证据文件不存在 %s" % EVIDENCE)
            return 1
        saved = json.load(open(EVIDENCE, encoding="utf-8"))
        # 只比结论性字段与「公开池清单健康度」。真值总数会随公开题库增补变化，
        # 但那不改变 anchored 结论；把它排除可避免环境差异造成假红。
        keys = ("pool_sha256", "registry_sha256", "anchored", "anchored_count",
                "total", "public_pools_missing")
        bad = [k for k in keys if saved.get(k) != result.get(k)]
        print("证据一致性：%s%s" % ("PASS" if not bad else "FAIL",
                                   "" if not bad else " 差异字段=%s" % bad))
        return 0 if not bad else 1

    print("私有性外部锚点：anchored=%s (%d/%d)" %
          (result["anchored"], result["anchored_count"], result["total"]))
    print("理由：%s" % ("; ".join(result["reasons"]) or "R0–R6 全过"))
    if args.check:
        os.makedirs(os.path.dirname(EVIDENCE), exist_ok=True)
        json.dump(result, open(EVIDENCE, "w", encoding="utf-8"),
                  ensure_ascii=False, indent=2, sort_keys=True)
        print("证据已写：%s" % os.path.relpath(EVIDENCE, ROOT))
    if args.require_proof and not result["anchored"]:
        print("FAIL: 未达成私有性外部锚点，禁止发布能力率")
        return 2
    return 0


if __name__ == "__main__":
    sys.exit(main())
