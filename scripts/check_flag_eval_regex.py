#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
门禁：flag 评测口径一致性检查（2026-10-28 建立）。

背景（真实事故）：
    基准 72 个 flag 全是小写 `flag{`，而 LLM 常输出大写 `FLAG{...}`。
    仓库里 10 个评测脚本有 9 个用小写-only 正则提取候选，且直接拿原文算 sha256，
    导致**模型答对却被判未命中**（morse_hello 实锤）。这是静默错误：不报错，只让数字偏低。

统一口径：`scripts/experiments/flag_util.py::flag_sha256_hit`
    —— 大小写不敏感提取 + 前缀归一 + 变体比对 + target 为空时 fail-closed。

本门禁检查两类违规：
    A. FLAG_RE 定义写成小写-only 且未标 IGNORECASE（提取不到大写候选）
    B. 文件同时用 FLAG_RE 提取与 hashlib.sha256 判定，却未引用统一口径
       （即使提取到了大写候选，直接比 sha 仍会漏判）

存量豁免走显式 allowlist（scripts/flag_eval_allowlist.json），必须写明原因与责任人；
    allowlist 是**挂账不是通过**——发布节点前必须清零，门禁会打印挂账数量。

为什么挂账必须自带"过期"机制（否则 allowlist 会退化成永久遮羞布：
门禁常绿，洞一个没补）：
    1. 每条挂账必须写 expires；过期自动升为违规 → BLOCK。
    2. renewals 上限 MAX_RENEWALS（默认 2）：续期不是无限续命。
    3. owner 为"待认领"超过 UNCLAIMED_GRACE_DAYS（默认 3 天）→ 也升为违规，
       逼出真正的责任人，而不是让债永远匿名。
    4. 缺 expires / renewals 字段 → 视为不合规挂账，直接 BLOCK（fail-closed）。

用法：
    python scripts/check_flag_eval_regex.py            # 人类可读
    python scripts/check_flag_eval_regex.py --json
    python scripts/check_flag_eval_regex.py --self-test  # 变异验证，证明门禁有效
    python scripts/check_flag_eval_regex.py --today 2026-12-01  # 注入日期（测试用）
"""
from __future__ import annotations

import argparse
import datetime as _dt
import json
import os
import re
import sys
import tempfile

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
SCRIPTS = os.path.join(ROOT, "scripts")
ALLOWLIST = os.path.join(SCRIPTS, "flag_eval_allowlist.json")

# 自身与统一口径模块不参与检查
SELF_EXEMPT = {
    os.path.join(SCRIPTS, "experiments", "flag_util.py"),
    os.path.join(SCRIPTS, "check_flag_eval_regex.py"),
}

# 非"答案判定"用途，命中即为误报（2026-10-28 基线核对时逐个人工确认）
NON_EVALUATOR_EXEMPT = {
    "scripts/count_stats.py":
        "统计脚本：_FLAG_BUILD 用于统计基准文件里的 flag 字面量，不做答案命中判定",
    "scripts/secret_guard.py":
        "密钥扫描脚本：FLAG_LIKE 用于发现疑似密钥文本，不做答案命中判定",
    "scripts/ycb_static_survey.py":
        "静态盘点脚本：FLAG_RE 用于收集 flag 形态 token，sha256_bytes 是给**文件**算哈希，"
        "不参与答案命中判定（2026-10-28 人工核对确认，属误报）",
}

FLAG_RE_DEF = re.compile(r"^([A-Za-z_][A-Za-z0-9_]*)\s*=\s*re\.compile\((.*)\)\s*$", re.M)
SHA_CMP = re.compile(r"hashlib\.sha256\(")
UNIFIED_MARKERS = ("flag_util", "flag_sha256_hit", "candidate_variants")


def _is_flag_pattern(body: str) -> bool:
    """正则体是否针对 flag{...} 形态。"""
    return bool(re.search(r"['\"]?.*flag", body, re.I)) and "{" in body


def _has_ignorecase(body: str) -> bool:
    return bool(re.search(r"re\.IGNORECASE|re\.I\b", body))


def _is_case_class(body: str) -> bool:
    """字符类写法 [Ff][Ll][Aa][Gg] 等价大小写不敏感。"""
    return bool(re.search(r"\[Ff\]\[Ll\]\[Aa\]\[Gg\]", body))


MAX_RENEWALS = 2
UNCLAIMED_GRACE_DAYS = 3
TODAY: _dt.date = _dt.date.today()


def _parse_date(s) -> _dt.date | None:
    if not s:
        return None
    try:
        return _dt.date.fromisoformat(str(s)[:10])
    except Exception:  # noqa: BLE001
        return None


def allowlist_health(entry: dict) -> list[str]:
    """检查一条挂账是否仍然'健康'。返回问题列表（空 = 仍可豁免）。

    fail-closed：字段缺失/不可解析一律算问题，不许静默放过。
    """
    issues: list[str] = []
    exp = _parse_date(entry.get("expires"))
    if exp is None:
        issues.append("缺 expires（挂账必须有到期日）")
    elif TODAY > exp:
        issues.append(f"已过期 expires={exp}（today={TODAY}）")

    ren = entry.get("renewals")
    if not isinstance(ren, int):
        issues.append("缺 renewals 计数（必须是整数）")
    elif ren > MAX_RENEWALS:
        issues.append(f"续期 {ren} 次 > 上限 {MAX_RENEWALS}")

    owner = (entry.get("owner") or "").strip()
    added = _parse_date(entry.get("added"))
    if "待认领" in owner:
        if added is None:
            issues.append("缺 added 日期，无法判定认领期限")
        elif (TODAY - added).days > UNCLAIMED_GRACE_DAYS:
            issues.append(f"挂账已 {(TODAY - added).days} 天仍为『待认领』"
                          f"（宽限 {UNCLAIMED_GRACE_DAYS} 天）")
    return issues


def load_allowlist() -> dict:
    """以仓库相对路径（正斜杠）为键，与扫描时算出的 rel 对齐。"""
    if not os.path.exists(ALLOWLIST):
        return {}
    try:
        d = json.load(open(ALLOWLIST, encoding="utf-8"))
        return {e["file"].replace(os.sep, "/").lstrip("./"): e
                for e in d.get("entries", [])}
    except Exception as e:  # noqa: BLE001
        # fail-closed：allowlist 读不出来就当没有，宁可报红
        print(f"[warn] allowlist 解析失败，按空处理: {e}", file=sys.stderr)
        return {}


def scan_file(path: str) -> list[dict]:
    v: list[dict] = []
    try:
        t = open(path, encoding="utf-8", errors="replace").read()
    except Exception as e:  # noqa: BLE001
        return [{"file": path, "kind": "unreadable", "detail": str(e)}]

    flag_defs = []
    for m in FLAG_RE_DEF.finditer(t):
        name, body = m.group(1), m.group(2)
        if not _is_flag_pattern(body):
            continue
        line = t[: m.start()].count("\n") + 1
        flag_defs.append((line, name, body))

    for line, name, body in flag_defs:
        if not (_has_ignorecase(body) or _is_case_class(body)):
            v.append({
                "file": path, "line": line, "kind": "A:lower-only-regex",
                "detail": f"{name} = re.compile({body[:60]}) 提取不到大写 FLAG{{...}}",
            })

    # B 类：既有 flag 提取又有 sha256 判定，却没走统一口径
    if flag_defs and SHA_CMP.search(t):
        if not any(mk in t for mk in UNIFIED_MARKERS):
            v.append({
                "file": path, "line": flag_defs[0][0], "kind": "B:no-normalization",
                "detail": "sha256 判定直接比原文候选，大写 FLAG{...} 必然漏判",
            })
    return v


def scan_all() -> tuple[list[dict], list[dict]]:
    allow = load_allowlist()
    violations, allowlisted = [], []
    for dirpath, _dirs, files in os.walk(SCRIPTS):
        for fn in files:
            if not fn.endswith(".py"):
                continue
            p = os.path.join(dirpath, fn)
            if p in SELF_EXEMPT:
                continue
            rel0 = os.path.relpath(p, ROOT).replace(os.sep, "/")
            if rel0 in NON_EVALUATOR_EXEMPT:
                continue
            for item in scan_file(p):
                rel = os.path.relpath(item["file"], ROOT).replace(os.sep, "/")
                item["rel"] = rel
                e = allow.get(rel)
                kinds = (e or {}).get("kinds", ["*"])
                prefix = item["kind"].split(":")[0]
                if e and ("*" in kinds or prefix in [k.split(":")[0] for k in kinds]):
                    issues = allowlist_health(e)
                    if issues:
                        # 挂账不健康 → 不再豁免，升为违规（防止 allowlist 变永久遮羞布）
                        item["kind"] = "C:allowlist-unhealthy"
                        item["detail"] = "; ".join(issues)
                        violations.append(item)
                    else:
                        item["allow_reason"] = e.get("reason", "")
                        item["allow_owner"] = e.get("owner", "")
                        item["allow_expires"] = e.get("expires", "")
                        allowlisted.append(item)
                else:
                    violations.append(item)
    return violations, allowlisted


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--json", action="store_true")
    ap.add_argument("--self-test", action="store_true")
    ap.add_argument("--today", help="注入日期 YYYY-MM-DD（测试/演练用）")
    a = ap.parse_args()

    global TODAY
    if a.today:
        d = _parse_date(a.today)
        if d is None:
            print(f"[error] --today 格式错误: {a.today}", file=sys.stderr)
            return 2
        TODAY = d

    if a.self_test:
        return self_test()

    violations, allowlisted = scan_all()

    if a.json:
        print(json.dumps({"violations": violations, "allowlisted": allowlisted,
                          "allowlist_size": len(allowlisted)},
                         ensure_ascii=False, indent=2))
    else:
        print("=== flag 评测口径门禁 ===")
        print(f"统一口径: scripts/experiments/flag_util.py::flag_sha256_hit")
        print()
        if violations:
            print(f"🔴 违规 {len(violations)} 处（必须修）:")
            for v in violations:
                print(f"   {v['rel']}:{v['line']}  [{v['kind']}]")
                print(f"      {v['detail']}")
        else:
            print("🟢 无未挂账违规")
        print()
        if allowlisted:
            print(f"🟡 挂账(allowlist) {len(allowlisted)} 处 —— 发布节点前必须清零:")
            seen = {}
            for v in allowlisted:
                seen.setdefault((v["rel"], v["allow_owner"]), []).append(v["kind"])
            for (rel, owner), kinds in sorted(seen.items()):
                print(f"   {rel}  owner={owner}  {sorted(set(kinds))}")
        print()
        print(f"结论: {'BLOCK' if violations else 'PASS'}"
              + (f"（另有 {len(allowlisted)} 处挂账）" if allowlisted else ""))

    return 1 if violations else 0


# ── 变异验证：证明门禁真的能抓到问题，而不是常绿 ──
def _exp_far() -> str:
    """自测里用的"远未来"到期日，保证不受真实日期影响。"""
    return (_dt.date.today() + _dt.timedelta(days=365)).isoformat()


def self_test() -> int:
    ok = True
    tmp = tempfile.mkdtemp(prefix="flag_gate_")
    scripts_tmp = os.path.join(tmp, "scripts")
    os.makedirs(scripts_tmp)

    global SCRIPTS, ROOT, ALLOWLIST, TODAY
    old = (SCRIPTS, ROOT, ALLOWLIST, TODAY)
    ROOT, SCRIPTS = tmp, scripts_tmp
    ALLOWLIST = os.path.join(scripts_tmp, "flag_eval_allowlist.json")
    TODAY = _dt.date(2026, 10, 28)

    try:
        # 1) 坏样本：小写-only 正则 + 直接 sha 判定
        bad = os.path.join(scripts_tmp, "bad.py")
        open(bad, "w", encoding="utf-8").write(
            'import re, hashlib\n'
            'FLAG_RE = re.compile(r"flag\\{[^{}]*\\}")\n'
            'def v(t, s):\n'
            '    for c in FLAG_RE.findall(t):\n'
            '        if hashlib.sha256(c.encode()).hexdigest() == s:\n'
            '            return True\n'
            '    return False\n')
        v, al = scan_all()
        got = {x["kind"] for x in v}
        ok &= ("A:lower-only-regex" in got and "B:no-normalization" in got and not al)
        print(f"[1] 坏样本应报 A+B -> 实得 {sorted(got)} allowlisted={len(al)}")

        # 2) 好样本：IGNORECASE + 引用统一口径
        good = os.path.join(scripts_tmp, "good.py")
        open(good, "w", encoding="utf-8").write(
            'import re\n'
            'from flag_util import flag_sha256_hit\n'
            'FLAG_RE = re.compile(r"flag\\{[^{}]*\\}", re.IGNORECASE)\n'
            'def v(t, s):\n'
            '    return flag_sha256_hit(t, s)\n')
        os.remove(bad)
        v, al = scan_all()
        ok &= (not v and not al)
        print(f"[2] 好样本应全绿 -> 违规={len(v)} 挂账={len(al)}")

        # 3) 变异：把好样本的 IGNORECASE 去掉，必须变红（证明门禁不是常绿）
        open(good, "w", encoding="utf-8").write(
            'import re\n'
            'from flag_util import flag_sha256_hit\n'
            'FLAG_RE = re.compile(r"flag\\{[^{}]*\\}")\n'
            'def v(t, s):\n'
            '    return flag_sha256_hit(t, s)\n')
        v, al = scan_all()
        kinds = {x["kind"] for x in v}
        ok &= ("A:lower-only-regex" in kinds)
        print(f"[3] 变异(去掉 IGNORECASE)应变红 -> 违规={sorted(kinds)}")

        # 4) allowlist 生效验证：坏样本挂账后不计入违规
        open(os.path.join(scripts_tmp, "bad2.py"), "w", encoding="utf-8").write(
            'import re, hashlib\n'
            'FLAG_RE = re.compile(r"flag\\{[^{}]*\\}")\n'
            'x = hashlib.sha256(b"a").hexdigest()\n')
        # 注意：挂账条自 2026-10-28 起必须带 expires/renewals/added，缺任一即 fail-closed 变红
        json.dump({"entries": [{"file": "scripts/bad2.py", "kinds": ["*"],
                                "reason": "测试挂账", "owner": "test",
                                "added": "2026-10-28",
                                "expires": _exp_far(),
                                "renewals": 0}]},
                  open(ALLOWLIST, "w", encoding="utf-8"))
        v, al = scan_all()
        bad2_in_viol = any("bad2.py" in x["rel"] for x in v)
        bad2_in_allow = any("bad2.py" in x["rel"] for x in al)
        ok &= (not bad2_in_viol and bad2_in_allow)
        print(f"[4] allowlist 挂账生效 -> 违规中={bad2_in_viol} 挂账中={bad2_in_allow}")

        # 5) fail-closed：allowlist 损坏时不得静默放过
        open(ALLOWLIST, "w", encoding="utf-8").write("{ broken json")
        v, al = scan_all()
        ok &= any("bad2.py" in x["rel"] for x in v)
        print(f"[5] allowlist 损坏应 fail-closed(回到违规) -> "
              f"{any('bad2.py' in x['rel'] for x in v)}")

        def write_allow(entry):
            json.dump({"entries": [entry]},
                      open(ALLOWLIST, "w", encoding="utf-8"))

        base = {"file": "scripts/bad2.py", "kinds": ["*"],
                "reason": "测试", "owner": "S1", "added": "2026-10-28",
                "expires": "2026-11-04", "renewals": 0}

        # 6) 未到期 -> 仍豁免
        write_allow(dict(base))
        v, al = scan_all()
        ok &= (not any("bad2.py" in x["rel"] for x in v)
               and any("bad2.py" in x["rel"] for x in al))
        print(f"[6] 未到期挂账应仍豁免 -> 违规={any('bad2.py' in x['rel'] for x in v)} "
              f"挂账={any('bad2.py' in x['rel'] for x in al)}")

        # 7) 变异：到期后必须变红（防止 allowlist 变永久遮羞布）
        TODAY = _dt.date(2026, 11, 5)
        write_allow(dict(base))
        v, al = scan_all()
        hit7 = any("bad2.py" in x["rel"] and x["kind"] == "C:allowlist-unhealthy"
                   for x in v)
        ok &= hit7
        print(f"[7] 变异(过期)应变红 -> {hit7}")

        # 8) 变异：续期超上限必须变红
        TODAY = _dt.date(2026, 10, 28)
        write_allow(dict(base, renewals=MAX_RENEWALS + 1))
        v, al = scan_all()
        hit8 = any("bad2.py" in x["rel"] and x["kind"] == "C:allowlist-unhealthy"
                   for x in v)
        ok &= hit8
        print(f"[8] 变异(续期>{MAX_RENEWALS}次)应变红 -> {hit8}")

        # 9) 变异：长期"待认领"超宽限期必须变红
        write_allow(dict(base, owner="待认领"))
        TODAY = _dt.date(2026, 11, 5)
        v, al = scan_all()
        hit9 = any("bad2.py" in x["rel"] and x["kind"] == "C:allowlist-unhealthy"
                   for x in v)
        ok &= hit9
        print(f"[9] 变异(待认领超{UNCLAIMED_GRACE_DAYS}天)应变红 -> {hit9}")

        # 10) 变异：缺 expires 字段 -> fail-closed 变红
        TODAY = _dt.date(2026, 10, 28)
        e10 = dict(base)
        e10.pop("expires")
        write_allow(e10)
        v, al = scan_all()
        hit10 = any("bad2.py" in x["rel"] and x["kind"] == "C:allowlist-unhealthy"
                    for x in v)
        ok &= hit10
        print(f"[10] 变异(缺 expires)应 fail-closed 变红 -> {hit10}")
    finally:
        SCRIPTS, ROOT, ALLOWLIST, TODAY = old

    print("\nSELFTEST:", "PASS" if ok else "FAIL")
    return 0 if ok else 1


if __name__ == "__main__":
    raise SystemExit(main())
