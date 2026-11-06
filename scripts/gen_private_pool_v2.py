#!/usr/bin/env python
# -*- coding: utf-8 -*-
"""自造私有题池 v2：v1 的 10 题原样复用 + 新增 30 题 = 40 题。

## 为什么要扩（承接 2026-11-07 的读数）

v1 十题在 agentic 路径拿到 10/10，这恰恰说明**题池饱和**：读数没有区分度，
无法回答「难到哪一步会掉」。扩到 40 题的三个目的：

1. **梯度**：easy/medium/hard 各约 1/3，让命中率落在 (0,1) 区间内才有信息量；
2. **算术/算法多样性**：v1 全是低算术题，v2 新增 Wiener / Fermat / Håstad /
   BSGS / MT19937 克隆 / XTEA / RC4 / JWT-HS256 / Pollard rho …；
3. **可比对**：v1 的 10 题**逐字保留**（description 与 flag_sha256 与已提交的
   `private_benchmark_v1.json` 完全一致），因此 v2 跑批里这 10 题构成天然对照组。
   任何"换池洗白"（悄悄改旧题）都会被 selftest 的 R-parent 检查判红。

## 硬约束（与 v1 相同，一条不放松）

- 材料 100% 内嵌 description，零附件依赖；
- flag 明文不落盘：由种子 `secautomind/private-pool/v2` 的 sha256 派生；
- 每题 solver **只读 description** 求解，生成时逐题断言
  `sha256(solve(desc)) == flag_sha256`；
- 覆盖 fail-closed：池内题数 != 生成器题数即判红（不把"少扫到"当"没问题"）。

用法：
    python scripts/gen_private_pool_v2.py                     # 写池 + manifest
    python scripts/gen_private_pool_v2.py --verify <pool.json>
    python scripts/gen_private_pool_v2.py --selftest           # 变异验证
    python scripts/gen_private_pool_v2.py --registry <out> --commit <sha>
退出码：0 全通过 / 1 有题不可解或口径不符 / 2 用法错误。
"""
from __future__ import annotations

import argparse
import hashlib
import json
import os
import sys

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

import gen_private_pool_v1 as v1                      # noqa: E402
import private_pool_v2_builders as b2                # noqa: E402

ROOT = v1.ROOT
V1_POOL = os.path.join(ROOT, "data", "ctf_benchmark",
                       "private_benchmark_v1.json")
POOL_OUT = os.path.join(ROOT, "data", "ctf_benchmark",
                        "private_benchmark_v2.json")
MANIFEST_OUT = os.path.join(ROOT, "data", "ctf_benchmark",
                            "private_benchmark_v2.manifest.json")

ALL_BUILDERS = list(v1.BUILDERS) + list(b2.NEW_BUILDERS)
FLAG_RE = v1.FLAG_RE
_sha = v1._sha


def _sha256_file(path: str) -> str:
    h = hashlib.sha256()
    with open(path, "rb") as fh:
        for chunk in iter(lambda: fh.read(1 << 20), b""):
            h.update(chunk)
    return h.hexdigest()


def _check_leak(pid: str, desc: str, plain: str) -> None:
    """题面不得包含答案。抽成独立函数，好让 selftest 测的是真逻辑。"""
    if plain in desc:
        raise AssertionError("%s: plaintext flag leaked into statement" % pid)
    inner = plain[5:-1]
    if inner and inner in desc:
        raise AssertionError("%s: inner answer leaked into statement" % pid)


def build_all() -> tuple[dict, list[dict]]:
    problems, audit = {}, []
    for pid, cat, diff, fn, note in ALL_BUILDERS:
        if pid in problems:
            raise AssertionError("duplicate problem id: %s" % pid)
        desc, plain, solve = fn()
        got = solve(desc)
        if got != plain:
            raise AssertionError("%s: solver mismatch (%r != %r)" % (pid, got, plain))
        if not FLAG_RE.fullmatch(plain):
            raise AssertionError("%s: flag form invalid: %r" % (pid, plain))
        _check_leak(pid, desc, plain)
        problems[pid] = {
            "id": pid,
            "name": pid,
            "category": cat,
            "difficulty": diff,
            "description": desc,
            "flag_sha256": _sha(plain),
            "pool": "private_selfauthored",
            "source": "self-authored / private internal benchmark (unreleased)",
            "created_at": "2026-11-07",
        }
        audit.append({"id": pid, "category": cat, "difficulty": diff,
                      "design_note": note, "statement_chars": len(desc)})
    return problems, audit


def build_pool(v1_pool_path: str = V1_POOL) -> dict:
    problems, audit = build_all()
    v1_pids = [pid for pid, _c, _d, _f, _n in v1.BUILDERS]
    parent = {}
    if os.path.isfile(v1_pool_path):
        try:
            parent = json.load(open(v1_pool_path, encoding="utf-8"))
        except Exception:
            parent = {}
    v1_sha = _sha256_file(v1_pool_path) if os.path.isfile(v1_pool_path) else ""
    by_diff = {}
    for row in audit:
        by_diff[row["difficulty"]] = by_diff.get(row["difficulty"], 0) + 1
    return {
        "benchmark": "private_pool_v2",
        "denominator": len(problems),
        "problems": problems,
        "provenance": {
            "note": ("%d 道本项目原创私有题，材料 100%% 内嵌题面（零附件依赖），"
                     "flag 明文不由任何文件保存（种子 sha256 派生），"
                     "生成时逐题机验「仅凭题面可解」。其中 %d 道与 v1 池逐字相同，"
                     "构成跨池对照组。" % (len(problems), len(v1_pids))),
            "generated_by": "scripts/gen_private_pool_v2.py",
            "created_at": "2026-11-07",
            "parent_pool": os.path.relpath(v1_pool_path, ROOT).replace("\\", "/"),
            "parent_pool_sha256": v1_sha,
            "parent_problem_ids": v1_pids,
            "parent_problem_count": len(v1_pids),
            "attachment_dependency": "none",
            "difficulty_mix": by_diff,
            "known_limitations": [
                "自造题只证明「链路可解 + 系统能解出结构完整的题」，"
                "不能外推为对公开赛题未见过题目的泛化能力",
                "题目难度由出题方设定，非赛题分布抽样，不构成难度校准",
                "v1 十题与 v2 新增三十题不是同分布：v2 刻意加大算术与算法深度",
            ],
            "audit": audit,
        },
    }


def verify_pool(path: str, builders=None) -> int:
    """复验：池内每题的 solver 只读 description 能否复现登记的 flag_sha256。

    覆盖 fail-closed：池内题数必须等于生成器题数，少一道就判红 ——
    「少扫到」不等于「没问题」（第七个假绿：命名绕过已修，这里是同一类）。
    """
    builders = builders or ALL_BUILDERS
    d = json.load(open(path, encoding="utf-8"))
    probs = d.get("problems", {})
    if not probs:
        print("FAIL 池为空：不可解性无从验证（fail-closed）")
        return 1
    fails = 0
    if len(probs) != len(builders):
        print("FAIL 池内 %d 题，生成器定义 %d 题 —— 覆盖不全，判红"
              % (len(probs), len(builders)))
        fails += 1
    fnmap = {pid: fn for pid, _c, _dd, fn, _n in builders}
    for pid, p in probs.items():
        if pid not in fnmap:
            print("FAIL %-38s 池内存在生成器未定义的题" % pid)
            fails += 1
            continue
        desc = p.get("description", "")
        try:
            _d, _plain, solve = fnmap[pid]()
        except Exception as exc:
            print("FAIL %-38s 构建失败: %s" % (pid, exc))
            fails += 1
            continue
        try:
            got = solve(desc)
        except Exception as exc:
            print("FAIL %-38s solver 无法从题面求解: %s: %s"
                  % (pid, type(exc).__name__, exc))
            fails += 1
            continue
        ok = _sha(got) == str(p.get("flag_sha256", "")).lower()
        print("%s %-38s chars=%-5d %s"
              % ("PASS" if ok else "FAIL", pid, len(desc),
                 "题面可解" if ok else "solver 输出与登记哈希不符"))
        fails += 0 if ok else 1
    print("可解性复验：%d/%d 通过" % (len(probs) - fails, len(probs)))
    return 0 if fails == 0 else 1


def _parent_subset_identical(pool: dict) -> tuple[bool, str]:
    """R-parent：v2 里的 v1 十题必须与已提交 v1 池逐字一致（防换池洗白）。"""
    if not os.path.isfile(V1_POOL):
        return False, "父池不存在：%s" % os.path.relpath(V1_POOL, ROOT)
    parent = json.load(open(V1_POOL, encoding="utf-8")).get("problems", {})
    mine = pool.get("problems", {})
    diffs = []
    for pid in [x for x, _c, _d, _f, _n in v1.BUILDERS]:
        if pid not in parent:
            diffs.append("%s 不在父池" % pid)
            continue
        if pid not in mine:
            diffs.append("%s 不在 v2 池" % pid)
            continue
        if parent[pid].get("description") != mine[pid].get("description"):
            diffs.append("%s 题面被改" % pid)
        if str(parent[pid].get("flag_sha256")) != str(mine[pid].get("flag_sha256")):
            diffs.append("%s 答案哈希被改" % pid)
    if diffs:
        return False, "; ".join(diffs[:5])
    return True, "v1 十题题面与答案哈希逐字一致"


def selftest() -> int:
    """变异验证：坏题、少题、改旧题、泄题都必须判红。"""
    cases = []
    pool = build_pool()
    n = len(pool["problems"])
    cases.append(("40 题全部可解（生成期逐题机验）", n == len(ALL_BUILDERS), True))

    ok, why = _parent_subset_identical(pool)
    cases.append(("v1 十题与父池逐字一致（防换池洗白）", ok, True))

    # 变异：改掉父池某题的答案哈希 → R-parent 必须红
    import copy
    bad = copy.deepcopy(pool)
    first = [x for x, _c, _d, _f, _n in v1.BUILDERS][0]
    bad["problems"][first]["flag_sha256"] = "0" * 64
    old = json.load(open(V1_POOL, encoding="utf-8")) if os.path.isfile(V1_POOL) else None
    ok2, _w = _parent_subset_identical(bad)
    cases.append(("改旧题答案哈希被检出", ok2, False))
    assert old is not None or not os.path.isfile(V1_POOL)

    # 变异：篡改某新题题面（改一个密文字符）→ solver 必须给不出原 flag
    pid = "pp_v2_29_licence_xor_table"
    d1 = dict(pool["problems"][pid])
    d1["description"] = d1["description"].replace("table bytes are:", "table bytes are: 00", 1)
    _dd, _pp, solve = b2.build_p29()
    mut_ok = True
    try:
        got = solve(d1["description"])
        mut_ok = (_sha(got) == d1["flag_sha256"])
    except Exception:
        mut_ok = False
    cases.append(("题面被篡改后不再可解出原答案", mut_ok, False))

    # 变异：把明文塞进题面 → _check_leak 必须拒绝
    leaked = True
    try:
        _check_leak("x", "hint: " + _pp, _pp)
    except AssertionError:
        leaked = False
    cases.append(("明文泄题被 _check_leak 拦住", leaked, False))

    # fail-closed：空池
    import tempfile
    tmp = tempfile.mkdtemp(prefix="pp2_selftest_")
    empty = os.path.join(tmp, "empty.json")
    json.dump({"problems": {}}, open(empty, "w", encoding="utf-8"))
    cases.append(("空池复验 fail-closed", verify_pool(empty) == 1, True))

    # fail-closed：少一题（覆盖不全）必须红
    short = copy.deepcopy(pool)
    short["problems"].pop(pid)
    sp = os.path.join(tmp, "short.json")
    json.dump(short, open(sp, "w", encoding="utf-8"), ensure_ascii=False)
    cases.append(("池内少一题（覆盖不全）判红", verify_pool(sp) == 1, True))

    # 变异：登记哈希被换 → 复验红
    tam = copy.deepcopy(pool)
    tam["problems"][pid]["flag_sha256"] = "0" * 64
    tp = os.path.join(tmp, "tampered.json")
    json.dump(tam, open(tp, "w", encoding="utf-8"), ensure_ascii=False)
    cases.append(("登记哈希被篡改后复验判红", verify_pool(tp) == 1, True))

    passed = 0
    for label, got, want in cases:
        good = got == want
        passed += int(good)
        print("  %s %-44s got=%s want=%s" % ("PASS" if good else "FAIL", label, got, want))
    print("生成器自测：%d/%d" % (passed, len(cases)))
    return 0 if passed == len(cases) else 1


def build_manifest(pool_path: str, pool: dict) -> dict:
    return {
        "tool": "scripts/gen_private_pool_v2.py",
        "out": os.path.relpath(pool_path, ROOT).replace("\\", "/"),
        "out_sha256": _sha256_file(pool_path),
        "total": len(pool["problems"]),
        "parent_pool": pool["provenance"]["parent_pool"],
        "parent_pool_sha256": pool["provenance"]["parent_pool_sha256"],
        "parent_problem_count": pool["provenance"]["parent_problem_count"],
        "attachment_dependency": "none",
        "difficulty_mix": pool["provenance"]["difficulty_mix"],
        "solvability_verified_by": (
            "scripts/gen_private_pool_v2.py --verify（逐题只读 description 重跑 solver）"),
        "note": pool["provenance"]["note"],
        "known_limitations": pool["provenance"]["known_limitations"],
    }


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--out", default=POOL_OUT)
    ap.add_argument("--manifest", default=MANIFEST_OUT)
    ap.add_argument("--verify", default=None)
    ap.add_argument("--selftest", action="store_true")
    ap.add_argument("--registry", default=None)
    ap.add_argument("--commit", default=None)
    ap.add_argument("--pool-for-registry", default=POOL_OUT)
    args = ap.parse_args()

    if args.selftest:
        return selftest()
    if args.registry:
        if not args.commit:
            raise SystemExit("--registry 必须配 --commit（日期与存在性都要从 git 读）")
        reg = v1.build_registry(args.pool_for_registry, args.commit)
        os.makedirs(os.path.dirname(args.registry), exist_ok=True)
        with open(args.registry, "w", encoding="utf-8", newline="\n") as fh:
            json.dump(reg, fh, ensure_ascii=False, indent=1, sort_keys=True)
            fh.write("\n")
        print("写出注册表 %s（%d 题，commit=%s）"
              % (os.path.relpath(args.registry, ROOT), len(reg["entries"]),
                 args.commit[:12]))
        print("pool_sha256 = %s" % reg["pool_sha256"])
        return 0
    if args.verify:
        return verify_pool(args.verify)

    pool = build_pool()
    os.makedirs(os.path.dirname(args.out), exist_ok=True)
    with open(args.out, "w", encoding="utf-8", newline="\n") as fh:
        json.dump(pool, fh, ensure_ascii=False, indent=1, sort_keys=True)
        fh.write("\n")
    mf = build_manifest(args.out, pool)
    with open(args.manifest, "w", encoding="utf-8", newline="\n") as fh:
        json.dump(mf, fh, ensure_ascii=False, indent=1, sort_keys=True)
        fh.write("\n")
    print("写出 %s（%d 题，难度分布 %s）"
          % (os.path.relpath(args.out, ROOT), mf["total"], mf["difficulty_mix"]))
    print("写出 %s（sha256=%s）"
          % (os.path.relpath(args.manifest, ROOT), mf["out_sha256"][:16]))
    return verify_pool(args.out)


if __name__ == "__main__":
    sys.exit(main())
