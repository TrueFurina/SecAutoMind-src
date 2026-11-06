#!/usr/bin/env python
# -*- coding: utf-8 -*-
"""能力评测证据面统一门禁：把「写了却没锁进 CI」的断言入口一次接齐。

背景（2026-11-06 第九个偏差）：上一轮只把 4 份 verdict 的一致性接进 CI，
再复核 ci.yml 与脚本调用关系后发现同一形态的洞还铺在整个证据面：

* 判据本体 `check_pure_llm_caliber.py --selftest`（19/19）在 ci.yml **0 命中**。
  `run_capability_eval.pipeline_selftest()` 里调用的 `selftest()` 是它自己的
  函数；该文件只被 import 了两个常量 ⇒ 判据变异验证从没在 CI 跑过。
* `audit_scoring_variant_gap.py --selftest`（7/7）同样 0 命中。
* 能力评测链共 11 条断言入口，此前 ci.yml 只接了 1 条
  （`audit_private_proof.py --verify`）；判据自测、v1/v2 题源、题面自曝、
  v1/v2 manifest、v2 池构建自测全是本机跑过、CI 不跑。
* v2 题源证据可用现成 `--verify --pool/--out` 参数化复核，但从未有人这么跑。
* `scoring_variant_gap_v1/v2.json` 没有 verify（原始 result 不入 git，CI 无法
  重算），只能做内部自洽 + 与 verdict 的交叉一致性。

本脚本**不新增判据、不改任何现有断言脚本**，只做三件事：

1. 统一转发 12 条现成断言入口（subprocess，任一非 0 ⇒ 红）；
2. 交叉一致性：verdict ↔ gap 证据、verdict ↔ 题源证据池指纹、gap 证据内部自洽、
   IP 直连证据字段、入库结果的 sha256 命中必须被 verdict 归因；
3. 必需证据文件完整性（缺一即红，防「删件让门禁恒绿」）。

第 11 轮补充两项（同一形态，不新开脚本）：
* `prove_airgap_ip_direct.py --check`：断网闸 IP 直连证据（基线有外网 → 开闸
  EPERM errno=1 → AF_UNIX 未误伤），从原始 stdout 重算，纯本地不联网。
* **第十个偏差**：`ctf_stepfun_orchestrator.py` 的 `summary.coverage = solved/total`
  完全由 sha256 命中算，判据链是可选旁路 —— 直接读 result.json 就能拿到一个
  看起来像能力率的数（历史 `purellm_full176.result.json` 的 0.0057 正是题面抄写）。
  因此要求：入库结果里任何 `solved=True` 的题，必须被某份 verdict 的 rows 归因；
  否则判红。注意这只锁「入库结果」，未入库本机文件不在扫描范围（见证据文档）。

  python scripts/verify_capability_evidence.py --check
  python scripts/verify_capability_evidence.py --selftest   # 变异攻击自证会变红

前置已实测：模拟 CI checkout 缺少 `.workbuddy/tmp/rev_leak.out` 时 7 个断言
入口仍全部 RC=0，故接线不会造成 CI 恒红。本门禁只证明证据没被改坏，
**不证明任何能力**；能力证据仍为空。
"""
from __future__ import annotations

import argparse
import glob
import json
import os
import re
import shutil
import subprocess
import sys
import tempfile

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
EV = os.path.join(ROOT, "docs", "evidence", "capability_eval_20261105")
POOL_V1 = "data/ctf_benchmark/purellm_clean_benchmark.json"
POOL_V2 = "data/ctf_benchmark/purellm_clean_benchmark_v2.json"
PRIOR_V2 = "docs/evidence/capability_eval_20261105/pool_prior_audit_v2.json"

MIN_VERDICTS = 4

# 必需证据文件：缺一即红。防止「删掉一份证据让不一致消失」造成空洞绿。
REQUIRED = [
    "evidence_smoke3.json", "path_proof.json",
    "pool_prior_audit.json", "pool_prior_audit_v2.json",
    "private_proof_audit.json",
    "scoring_variant_gap_v1.json", "scoring_variant_gap_v2.json",
    "smoke3.result.json", "writeup_answer_audit.json",
    "airgap_ip_direct_proof_20261106.json",
]

# 全量 verdict → 判分假阴性证据的绑定契约。smoke* 是 3 题子集，不与全量
# gap 证据比对；新增全量 verdict 未登记 ⇒ fail-closed 报红。
GAP_BINDINGS = {
    "verdict_full160.json": "scoring_variant_gap_v1.json",
    "verdict_full154_v2.json": "scoring_variant_gap_v2.json",
}

# 现成断言入口。此前 ci.yml 只接了最后一条（且是单独一个 step）。
EXTERNAL_GATES = [
    ("判据本体变异验证 19/19", ["scripts/check_pure_llm_caliber.py", "--selftest"]),
    ("判分假阴性变异验证 7/7", ["scripts/audit_scoring_variant_gap.py", "--selftest"]),
    ("题源先验变异验证 9/9", ["scripts/audit_pool_prior.py", "--selftest"]),
    ("题面自曝变异验证 7/7", ["scripts/audit_writeup_answer.py", "--selftest"]),
    ("v2 池构建变异验证 7/7", ["scripts/build_clean_benchmark_v2.py", "--selftest"]),
    ("v1 题源先验证据", ["scripts/audit_pool_prior.py", "--verify"]),
    ("v2 题源先验证据（参数化）",
     ["scripts/audit_pool_prior.py", "--verify", "--pool", POOL_V2, "--out", PRIOR_V2]),
    ("题面自曝答案审计证据", ["scripts/audit_writeup_answer.py", "--verify"]),
    ("v1 干净池 manifest", ["scripts/build_clean_benchmark.py", "--verify"]),
    ("v2 干净池 manifest", ["scripts/build_clean_benchmark_v2.py", "--verify"]),
    ("私有性外部锚点证据", ["scripts/audit_private_proof.py", "--verify"]),
    ("断网闸 IP 直连证据（原始输出重算）",
     ["scripts/prove_airgap_ip_direct.py", "--check"]),
]


def _load(path):
    with open(path, encoding="utf-8") as f:
        return json.load(f)


def cross_check(ev_dir=EV, verdict_paths=None):
    """交叉一致性 + 完整性。返回问题描述列表（空 = 通过）。

    ev_dir / verdict_paths 可注入，供自测用合成副本做变异验证。
    """
    if verdict_paths is None:
        verdict_paths = sorted(glob.glob(os.path.join(ev_dir, "verdict_*.json")))
    errs = []
    for n in REQUIRED:
        if not os.path.isfile(os.path.join(ev_dir, n)):
            errs.append("缺必需证据文件：%s" % n)
    if len(verdict_paths) < MIN_VERDICTS:
        errs.append("verdict 仅 %d 份 < 下限 %d（防删件）"
                    % (len(verdict_paths), MIN_VERDICTS))
    if errs:
        return errs

    # gap 证据内部自洽（原始 result 不入 git，无法重算，只能验自洽 + 交叉）。
    gap_counts = {}
    for n in ("scoring_variant_gap_v1.json", "scoring_variant_gap_v2.json"):
        g = _load(os.path.join(ev_dir, n))
        c = g.get("false_negative_count")
        ids, hits = g.get("false_negative_ids", []), g.get("hits", [])
        if not isinstance(c, int) or c != len(ids) or c != len(hits):
            errs.append("%s：false_negative_count=%r 与 ids(%d)/hits(%d) 不自洽"
                        % (n, c, len(ids), len(hits)))
        if not re.fullmatch(r"[0-9a-f]{64}", str(g.get("result_sha256") or "")):
            errs.append("%s：result_sha256 不是合法指纹" % n)
        gap_counts[n] = c

    priors = {
        "v1": _load(os.path.join(ev_dir, "pool_prior_audit.json")).get("pool_sha256"),
        "v2": _load(os.path.join(ev_dir, "pool_prior_audit_v2.json")).get("pool_sha256"),
    }

    for vp in verdict_paths:
        name = os.path.basename(vp)
        v = _load(vp)
        cs = v.get("claim_scope") or {}
        pool = cs.get("pool_path") or ""
        key = "v2" if "v2" in pool else "v1"
        if cs.get("pool_sha256") != priors[key]:
            errs.append("%s：claim_scope.pool_sha256 与 %s 题源证据不一致" % (name, key))
        if "smoke" in name:
            continue
        bound = GAP_BINDINGS.get(name)
        if not bound:
            errs.append("%s：全量 verdict 未登记 gap 证据绑定（fail-closed）" % name)
            continue
        got = (v.get("scoring_variant_gap") or {}).get("false_negative_count")
        if got != gap_counts.get(bound):
            errs.append("%s：gap=%r 与 %s 的 %r 不一致"
                        % (name, got, bound, gap_counts.get(bound)))
        g = _load(os.path.join(ev_dir, bound))
        if g.get("rows") != v.get("total"):
            errs.append("%s：gap 证据 rows=%r != verdict total=%r"
                        % (bound, g.get("rows"), v.get("total")))

    # 第十个偏差：入库结果里的 sha256 命中必须被 verdict 归因。否则
    # summary.coverage 会作为「看起来像能力率」的数被直接消费。
    covered = {}
    for vp in verdict_paths:
        for row in (_load(vp).get("rows") or []):
            covered[str(row.get("id", ""))] = row.get("verdict")
    for rp in sorted(glob.glob(os.path.join(ev_dir, "*.result.json"))):
        r = _load(rp)
        for d in (r.get("details") or []):
            if isinstance(d, dict) and d.get("solved"):
                pid = str(d.get("id", ""))
                if pid not in covered:
                    errs.append("%s：sha256 命中题 %s 未被任何 verdict 归因"
                                "（summary.coverage 会成为伪能力率）"
                                % (os.path.basename(rp), pid))

    # IP 直连证据字段级最低校验；从原始 stdout 重算由外部入口 --check 完成。
    p = _load(os.path.join(ev_dir, "airgap_ip_direct_proof_20261106.json"))
    if p.get("verdict") != "PROVEN" or any(
            p.get(k) is not True for k in
            ("baseline_egress_proven", "ip_direct_blocked", "af_unix_ok", "udp_blocked")):
        errs.append("IP 直连证据字段不成立（verdict/基线外网/EPERM/AF_UNIX/UDP）")
    return errs


def check():
    errs = cross_check()
    bad = 0
    print("=== 1/2 证据集完整性 + 交叉一致性 ===")
    for e in errs:
        print("  · %s" % e)
    print("  %s（%d 条异常）" % ("FAIL" if errs else "PASS", len(errs)))
    if errs:
        bad += 1
    print("=== 2/2 现成断言入口统一接线（%d 条）===" % len(EXTERNAL_GATES))
    for label, argv in EXTERNAL_GATES:
        r = subprocess.run([sys.executable] + argv, cwd=ROOT,
                            capture_output=True, text=True)
        out = (r.stdout or r.stderr).strip().splitlines()
        tail = out[-1][:78] if out else ""
        ok = r.returncode == 0
        print("  [%s] %-30s rc=%d  %s"
              % ("OK" if ok else "FAIL", label, r.returncode, tail))
        if not ok:
            bad += 1
    print("能力评测证据面：%s" % ("PASS" if not bad else "FAIL"))
    return 0 if not bad else 1


def selftest():
    """变异攻击：证明交叉校验对改证/删件确实会变红，不是恒绿。"""
    verdict_files = sorted(glob.glob(os.path.join(EV, "verdict_*.json")))
    all_names = REQUIRED + [os.path.basename(p) for p in verdict_files]
    cases = []
    with tempfile.TemporaryDirectory() as td:
        ev = os.path.join(td, "ev")
        os.makedirs(ev)

        def restore():
            for n in all_names:
                shutil.copy(os.path.join(EV, n), os.path.join(ev, n))

        def probe(label, mutate, want_blocked):
            restore()
            mutate(ev)
            cur = sorted(glob.glob(os.path.join(ev, "verdict_*.json")))
            errs = cross_check(ev, cur)
            blocked = bool(errs)
            cases.append((label, blocked, want_blocked, errs))

        def edit(name, fn):
            def _m(d):
                p = os.path.join(d, name)
                doc = _load(p)
                fn(doc)
                with open(p, "w", encoding="utf-8") as f:
                    json.dump(doc, f, ensure_ascii=False, indent=2)
            return _m

        probe("原件：交叉校验通过（非永远红灯）", lambda d: None, False)
        probe("篡改 gap_v2 计数",
              edit("scoring_variant_gap_v2.json",
                   lambda d: d.__setitem__("false_negative_count", 5)), True)
        probe("篡改 verdict 的 gap 字段",
              edit("verdict_full154_v2.json",
                   lambda d: d["scoring_variant_gap"].__setitem__(
                       "false_negative_count", 9)), True)
        probe("篡改 v2 题源证据池指纹",
              edit("pool_prior_audit_v2.json",
                   lambda d: d.__setitem__("pool_sha256", "0" * 64)), True)
        probe("删除一份必需证据", lambda d: os.remove(
            os.path.join(d, "writeup_answer_audit.json")), True)
        probe("删除一份 verdict（证据集缩小）", lambda d: os.remove(
            os.path.join(d, "verdict_smoke3.json")), True)
        probe("结果里注入未被 verdict 归因的 sha256 命中",
              edit("smoke3.result.json", lambda d: (
                  d["summary"].__setitem__("solved", 1),
                  d["details"][0].__setitem__("solved", True),
                  d["details"][0].__setitem__("id", "zz_unattributed_hit"))), True)
        probe("篡改 IP 直连证据 ip_direct_blocked",
              edit("airgap_ip_direct_proof_20261106.json",
                   lambda d: d.__setitem__("ip_direct_blocked", False)), True)
        probe("删除 IP 直连证据", lambda d: os.remove(
            os.path.join(d, "airgap_ip_direct_proof_20261106.json")), True)

    passed = 0
    for label, blocked, want, errs in cases:
        good = blocked is want
        passed += 1 if good else 0
        print("  [%s] %-38s %s"
              % ("OK" if good else "FAIL", label,
                 "" if good else "blocked=%s errs=%s" % (blocked, errs[:2])))
    print("证据面变异自测：%d/%d" % (passed, len(cases)))
    return 0 if passed == len(cases) else 1


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__.splitlines()[1])
    ap.add_argument("--check", action="store_true", help="校验证据面（默认行为）")
    ap.add_argument("--selftest", action="store_true", help="变异攻击自测")
    args = ap.parse_args()
    if args.selftest:
        return selftest()
    return check()


if __name__ == "__main__":
    sys.exit(main())
