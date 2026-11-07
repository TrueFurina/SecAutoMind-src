#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""`check_redaction_consistency.py` 的回归自测：每条判据一个正例 + 一个变异反例。

为什么必须带变异：本仓教训反复出现「门禁写好但从没证明它会红」。
这里每条规则都用「注入缺陷 → 必须 exit 1」证明判定力，而不是只测正例。
"""

from __future__ import annotations

import json
import shutil
import sys
import tempfile
from datetime import date, timedelta
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))
import check_redaction_consistency as C  # noqa: E402

RESULTS: list[tuple[str, bool, str]] = []
# 夹具默认的「合规」记账值：R8 要求有人负责 + 到期日在 365 天内且未过期。
DEFAULT_OWNER = "agent"
DEFAULT_EXPIRES = (date.today() + timedelta(days=180)).isoformat()


def _write(root: Path, rel: str, obj) -> None:
    p = root / rel
    p.parent.mkdir(parents=True, exist_ok=True)
    p.write_text(json.dumps(obj, ensure_ascii=False, indent=2) + "\n", encoding="utf-8")


def make_repo(tmp: Path, *, declared: bool = True, residual: bool = False,
              status: str = "synced", expires: str | None = DEFAULT_EXPIRES,
              owner: str = DEFAULT_OWNER, renewals=None,
              baseline_min_hit: int = 20, baseline_impact=None,
              dangling_entry: bool = False, consumer: str = "synced",
              answer_leak: bool = False, exempt=None, debt=None,
              leak_path: str = "scripts/leaky_fixture.py") -> Path:
    """造一个最小仓库形态。

    consumer 四种形态：
      synced      —— 判分已标 expect=not_attemptable（不再要求答案）
      answer      —— 判分仍要求答案，但只存哈希（flag_sha256）
      plain       —— 判分仍要求答案，且以明文 flag 存（R7 泄密）
      service_env —— service 模式明文 flag + 声明 flag_from_env（R7 允许的例外）
    """
    desc = "flag{REDACTED_web_xss}"
    if residual:
        desc = "flag{REDACTED_web_xss} 另有 flag{leak_me}"
    prob = {"description": desc, "name": "web_xss"}
    if declared:
        prob["prompt_answer_redacted"] = True
        prob["prompt_answer_redacted_fields"] = ["description"]
    _write(tmp, "data/ctf_benchmark/benchmark.json",
           {"version": 1, "problems": {"web_xss": prob}})

    man = []
    if consumer == "synced":
        man = [{"name": "web_xss", "mode": "local", "cmd": "x",
                "expect": "not_attemptable",
                "not_attemptable_reason": "题面已脱敏，密文不在语料里"}]
    elif consumer == "answer":
        man = [{"name": "web_xss", "mode": "local", "cmd": "x",
                "flag_sha256": "0" * 64}]
    elif consumer == "plain":
        man = [{"name": "web_xss", "mode": "local", "cmd": "x", "flag": "flag{old_answer}"}]
    elif consumer == "service_env":
        man = [{"name": "web_xss", "mode": "service", "cmd": "x",
                "flag": "flag{svc}", "flag_from_env": True}]
    _write(tmp, "scripts/arena_manifest.json", man)
    # 基线形状与入仓一致（7a5c2b9 起 static 是 min_real_hit / max_flag_scan 双列）
    _write(tmp, "docs/benchmark_baseline.json",
           {"suites": {"static": {"total": 55, "min_real_hit": baseline_min_hit,
                                  "max_flag_scan": 0}}})
    entries = [{
        "file": "data/ctf_benchmark/benchmark.json",
        "problem": "web_xss",
        "redacted_fields": ["description"],
        "judge_synced": consumer == "synced",
        "status": status,
        "owner": owner,
        "expires": expires,
        "reason": "自测夹具",
        "baseline_impact": baseline_impact,
    }]
    if renewals is not None:
        entries[0]["renewals"] = renewals
    if dangling_entry:
        entries.append({
            "file": "data/ctf_benchmark/benchmark.json", "problem": "ghost",
            "redacted_fields": ["description"], "judge_synced": True,
            "status": "synced", "owner": "-", "expires": None, "reason": "悬空夹具",
            "baseline_impact": None,
        })
    _write(tmp, "data/ctf_benchmark/redaction_ledger.json", {"schema": 1, "entries": entries})
    # R9 夹具：在入仓位置放一条「可被直接抄走」的答案明文，并让题目真值指向它
    if answer_leak:
        import hashlib
        leak = "flag{fixture_leak_0001}"
        prob["flag_sha256"] = hashlib.sha256(leak.encode("utf-8")).hexdigest()
        _write(tmp, "data/ctf_benchmark/benchmark.json",
               {"version": 1, "problems": {"web_xss": prob}})
        leak_p = tmp / leak_path
        leak_p.parent.mkdir(parents=True, exist_ok=True)
        leak_p.write_text('# 夹具：答案明文躺在这里\nLEAK = "%s"\n' % leak, encoding="utf-8")
    if exempt is not None:
        _write(tmp, C.EXEMPT_REL, {"schema": 1, "entries": exempt})
    if debt is not None:
        _write(tmp, C.DEBT_REL, debt)
    return tmp


def run_case(title: str, expect: int, **kw) -> None:
    tmp = Path(tempfile.mkdtemp(prefix="rl_"))
    try:
        root = make_repo(tmp, **kw)
        code, lines = C.check(root)
        ok = code == expect
        detail = lines[-1] if lines else "(无输出)"
        if not ok:
            detail += " ｜ 失败项：" + " ; ".join(l for l in lines if "[FAIL]" in l)[:600]
        RESULTS.append((title, ok, detail))
    finally:
        shutil.rmtree(tmp, ignore_errors=True)


def _patch_case(title: str, *, expect_hits: int, added: str, removed: str,
                header_name: str = "", msg_body: str = "    fixture commit") -> None:
    """R10 的纯函数夹具：造一段 `git log -p` 文本，喂给 scan_patch_added。

    为什么不用真仓库：自测要能在任何环境毫秒级跑完，且要能精确控制
    「这行是 +（新增）还是 -（删除）」，真仓库反而难以构造这种反差。
    """
    import hashlib
    leak = "XXX{fixture_patch_leak}"
    known = {hashlib.sha256(leak.encode("utf-8")).hexdigest(): ["fixture#patch"]}
    patch = "\n".join([
        "commit 0123456789abcdef0123456789abcdef01234567",
        "Author: agent <agent@example>",
        msg_body,
        "",
        "diff --git a/%s b/%s" % (header_name or "scripts/x.py", header_name or "scripts/x.py"),
        "--- a/%s" % (header_name or "scripts/x.py"),
        "+++ b/%s" % (header_name or "scripts/x.py"),
        "@@ -1 +1 @@",
        ("-" + removed) if removed else "-old line",
        ("+" + added) if added else "+new line",
        "",
    ])
    hits = C.scan_patch_added(patch, known)
    ok = len(hits) == expect_hits
    RESULTS.append((title, ok,
                    "hits=%d（期望 %d）%s" % (len(hits), expect_hits,
                                             "" if ok else " ｜ %r" % (hits,))))


def _history_case(title: str, *, exposure=None, sinces: str = "self") -> None:
    """真仓库端到端：先提交一次带答案明文的文件，再提交把它删掉。

    结果：HEAD 上看什么都没有（R9 查不到），但历史里还在——这正是本项目
    真实发生过的事（答案进过测试夹具与归档文档，后来才清）。只有 R10 能抓。
    """
    import hashlib
    import subprocess

    leak = "flag{fixture_history_leak}"
    tmp = Path(tempfile.mkdtemp(prefix="rl_hist_"))
    try:
        make_repo(tmp, consumer="synced", status="synced")
        # 让题目真值指向这条明文，R10 才有「已知答案」可比对
        prob_path = tmp / "data/ctf_benchmark/benchmark.json"
        doc = json.loads(prob_path.read_text(encoding="utf-8"))
        doc["problems"]["web_xss"]["flag_sha256"] = hashlib.sha256(
            leak.encode("utf-8")).hexdigest()
        prob_path.write_text(json.dumps(doc, ensure_ascii=False, indent=2) + "\n",
                             encoding="utf-8")

        def git(*a):
            return subprocess.run(["git", *a], cwd=str(tmp), capture_output=True,
                                  text=True, encoding="utf-8")

        git("init", "-q")
        git("config", "user.email", "agent@example")
        git("config", "user.name", "agent")
        git("config", "commit.gpgsign", "false")
        git("add", "-A")
        git("commit", "-q", "-m", "clean baseline")
        base = git("rev-parse", "HEAD").stdout.strip()

        (tmp / "scripts" / "history_leak.py").write_text(
            '# 曾经把答案写在这里\nLEAK = "%s"\n' % leak, encoding="utf-8")
        git("add", "-A")
        git("commit", "-q", "-m", "leak slipped in")

        (tmp / "scripts" / "history_leak.py").unlink()
        git("add", "-A")
        git("commit", "-q", "-m", "clean it up")

        saved = C.HISTORY_SINCE
        C.HISTORY_SINCE = base[:8]
        if exposure is not None:
            # 夹具里用占位符填「题目真值哈希」与「起点 sha」，避免写死与本用例无关的值
            import copy
            exposure = copy.deepcopy(exposure)
            if str(exposure.get("since")) == "HEADSHORT":
                exposure["since"] = base[:8]
            for e in exposure.get("entries") or []:
                if e.get("flag_sha256") == "@LEAK@":
                    e["flag_sha256"] = hashlib.sha256(leak.encode("utf-8")).hexdigest()
            _write(tmp, C.EXPOSURE_REL, exposure)
        try:
            code, lines = C.check(tmp)
        finally:
            C.HISTORY_SINCE = saved
        joined = "\n".join(lines)
        r10_lines = [ln for ln in lines if "R10" in ln and "[FAIL]" in ln]
        r9_lines = [ln for ln in lines if "R9 入仓明文答案" in ln]
        r11_lines = [ln for ln in lines if "R11" in ln and "[FAIL]" in ln]
        if exposure is None:
            ok = (code == 1 and len(r10_lines) == 1 and not r9_lines)
            detail = "RC=%d ｜ R10 命中 %d ｜ R9 命中 %d ｜ %s" % (
                code, len(r10_lines), len(r9_lines),
                r10_lines[0].strip() if r10_lines else joined[-80:])
        else:
            # 同一夹具里历史确实有明文，R10 也会命中；这里只断言**目标不变量**确实把门禁判红
            ok = code == 1 and len(r11_lines) >= 1
            detail = "RC=%d ｜ R11 命中 %d ｜ 全部 FAIL：%s" % (
                code, len(r11_lines),
                " ; ".join(l.strip() for l in lines if "[FAIL]" in l)[:400])
        RESULTS.append((title, ok, detail))
    finally:
        shutil.rmtree(tmp, ignore_errors=True)


def _msg_case(title: str, *, expect_hits: int = 1,
              body: str = "    顺手把答案写进提交信息 XXX{fixture_patch_leak}") -> None:
    """R10 提交信息通道：message 与 diff 一样会被 git log 打印，不能只扫 `+` 行。"""
    _patch_case(title, expect_hits=expect_hits, added="", removed="", msg_body=body)


def main() -> int:
    # T1 正例：判分已标不可判，台账 synced
    run_case("T1 判分已标不可判 + synced → PASS", 0, consumer="synced", status="synced")
    # T2 正例：判分仍要求答案，但已登记为债务 → PASS（债被看见）
    run_case("T2 仍要求答案但登记为债务 → PASS", 0, consumer="answer", status="accepted_debt")
    # T3 变异：台账文件缺失 → 新增脱敏未登记必须红
    tmp = Path(tempfile.mkdtemp(prefix="rl_"))
    try:
        make_repo(tmp, consumer="synced")
        (tmp / C.LEDGER_REL).unlink()
        code, lines = C.check(tmp)
        RESULTS.append(("T3 没有台账 → 未登记的新增脱敏必须红", code == 1,
                        "RC=%d ｜ %s" % (code, lines[-1] if lines else "")))
    finally:
        shutil.rmtree(tmp, ignore_errors=True)
    # T4 变异：仍要求答案却写 synced（等于声称已同步）
    run_case("T4 仍要求答案却写 synced → FAIL", 1, consumer="answer", status="synced")
    # T5 变异：台账悬空
    run_case("T5 台账悬空 → FAIL", 1, dangling_entry=True, consumer="synced")
    # T6 变异：同一题残留非脱敏 flag 形态
    run_case("T6 残留明文 → FAIL", 1, residual=True, consumer="synced")
    # T7 变异：没声明脱敏字段
    run_case("T7 缺 prompt_answer_redacted_fields → FAIL", 1, declared=False, consumer="synced")
    # T8 变异：债务已过期
    run_case("T8 债务过期 → FAIL", 1, consumer="answer", status="accepted_debt",
             expires="2026-01-01")
    # T9 变异：声明了 baseline_impact 但地板既不是 from 也不是 to
    run_case("T9 地板未联动 → FAIL", 1, consumer="synced", status="synced",
             baseline_min_hit=99, baseline_impact={"suite": "static", "from": 20, "to": 16})
    # T10 正例：地板仍是 from 且登记为债务
    run_case("T10 地板暂留 from 但有债务登记 → PASS", 0,
             consumer="answer", status="accepted_debt", baseline_min_hit=20,
             baseline_impact={"suite": "static", "from": 20, "to": 16})
    # T11 变异：判分清单仍存明文答案（泄密）；判分口径本身也已同步
    run_case("T11 manifest 明文 flag → FAIL（答案表泄密）", 1,
             consumer="plain", status="synced")
    # T12 正例：service 模式明文 flag 且声明来自环境变量 → 不算泄密
    run_case("T12 service 模式 flag_from_env 例外 → PASS", 0,
             consumer="service_env", status="accepted_debt")
    # ---- R8 记账三件套（2026-11-04 补：负责人=agent / 有到期日 / 续期须留痕）----
    # T13 变异：owner 仍是占位符 unassigned（「没人负责」）
    run_case("T13 owner=unassigned → FAIL（无人负责）", 1, consumer="synced",
             status="synced", owner="unassigned")
    # T14 变异：expires 为空（「永不复查」）
    run_case("T14 expires 为空 → FAIL", 1, consumer="synced", status="synced",
             expires=None)
    # T15 变异：synced 条目也已过期（旧版只校验债务，synced 逃检）
    run_case("T15 synced 但已过期 → FAIL", 1, consumer="synced", status="synced",
             expires="2020-01-01")
    # T16 变异：到期日超过 365 天上限（「填个很久以后」= 把记账做空）
    run_case("T16 expires 超上限 → FAIL", 1, consumer="synced", status="synced",
             expires=(date.today() + timedelta(days=400)).isoformat())
    # T17 变异：手改 expires 却不留续期记录（renewals 最后一条 to 对不上）
    run_case("T17 手改过期日留痕不符 → FAIL", 1, consumer="synced", status="synced",
             expires=DEFAULT_EXPIRES,
             renewals=[{"date": "2026-01-01", "by": "agent",
                        "from": "2026-01-01", "to": "2027-01-01", "reason": "手改"}])
    # T18 正例：续期记录完整且与 expires 一致
    run_case("T18 续期留痕一致 → PASS", 0, consumer="synced", status="synced",
             expires=DEFAULT_EXPIRES,
             renewals=[{"date": date.today().isoformat(), "by": "agent",
                        "from": "2026-01-01", "to": DEFAULT_EXPIRES,
                        "reason": "复核后延期"}])
    # ---- R9 全域答案明文（2026-11-04 补：判分只用哈希，明文在任何入仓文件里都是白送）----
    # T19 变异：入仓文件里躺着可直接抄的答案明文
    run_case("T19 入仓文件含答案明文 → FAIL", 1, consumer="synced", status="synced",
             answer_leak=True)
    # T20 正例：同一命中，但该文件在豁免表里且豁免本身合规
    run_case("T20 明文中豁免且豁免合规 → PASS", 0, consumer="synced", status="synced",
             answer_leak=True,
             exempt=[{"file": "scripts/leaky_fixture.py", "reason": "生成器必须知道明文",
                      "owner": "agent", "expires": DEFAULT_EXPIRES}])
    # T21 变异：豁免表里挂着一条已无命中的条目（豁免变防腐堆）
    run_case("T21 豁免悬空 → FAIL", 1, consumer="synced", status="synced",
             exempt=[{"file": "scripts/leaky_fixture.py", "reason": "已无用",
                      "owner": "agent", "expires": DEFAULT_EXPIRES}])
    # T22 变异：豁免无人负责（等于开了个没有人管的洞）
    run_case("T22 豁免 owner=unassigned → FAIL", 1, consumer="synced", status="synced",
             answer_leak=True,
             exempt=[{"file": "scripts/leaky_fixture.py", "reason": "生成器必须知道明文",
                      "owner": "unassigned", "expires": DEFAULT_EXPIRES}])

    # ---- R10 历史防线（清干净只对 HEAD 有效；历史里的明文照样能 git log -p 抄走）----
    # T23 变异：新提交的新增行里带答案明文 → 命中（只看 + 行）
    _patch_case("T23 历史新增行含答案明文 → 命中", expect_hits=1,
                added='XXX{fixture_patch_leak}', removed="")
    # T24 反例：明摆着是被删掉的那一行（历史债），不算新债 → 不命中
    _patch_case("T24 删除行不算新增泄密 → 不命中", expect_hits=0,
                added="", removed="XXX{fixture_patch_leak}")
    # T25 反例：新增行里的 REDACTED 占位不算命中（否则脱敏本身会被判红）
    _patch_case("T25 新增行是 REDACTED 占位 → 不命中", expect_hits=0,
                added="XXX{REDACTED_placeholder}", removed="")
    # T26 变异：新增行里的答案被拆进 diff 头（+++ b/file）时不许误判成内容行
    _patch_case("T26 文件头 +++ 不算新增内容 → 不命中", expect_hits=0,
                added="", removed="", header_name="XXX{fixture_patch_leak}")
    # T35 语料已入库但事实表还标 pending_corpus → FAIL（状态过期，必须重生成）
    _history_case("T35 标 pending_corpus 但答案已入仓 → FAIL",
                  exposure={"schema": 1, "owner": "agent", "since": "HEADSHORT",
                            "legacy": {"hits": 1},
                            "entries": [{"flag_sha256": "@LEAK@", "ids": ["web_xss"],
                                         "status": "pending_corpus", "hits": 1}]})

    # T27 端到端：HEAD 干净、历史里有过明文 → 只有 R10 能抓到（证明「清 HEAD 不等于清干净」）
    _history_case("T27 HEAD 干净但历史含明文 → 只有 R10 抓得到")
    # T33 事实表起点与防线常量脱钩 → FAIL（移动起点必须同一次留账）
    _history_case("T33 事实表 since 与 HISTORY_SINCE 不一致 → FAIL",
                  exposure={"schema": 1, "owner": "agent", "since": "deadbeef",
                            "legacy": {"hits": 1},
                            "entries": [{"flag_sha256": "@LEAK@", "ids": ["web_xss"],
                                         "status": "exposed", "hits": 1}]})
    # T34 前移起点却不记旧债（legacy.hits=0）→ FAIL（等于把历史红擦成 0）
    _history_case("T34 前移起点但没留下旧债计数 → FAIL",
                  exposure={"schema": 1, "owner": "agent", "since": "HEADSHORT",
                            "legacy": {"hits": 0},
                            "entries": [{"flag_sha256": "@LEAK@", "ids": ["web_xss"],
                                         "status": "exposed", "hits": 1}]})
    # ---- R10 补：提交信息也是公开面（git log 原样打印 message）----
    _msg_case("T28 提交信息里带答案 → 命中")
    _msg_case("T29 提交信息里是 REDACTED 占位 → 不命中", expect_hits=0,
              body="    XXX{REDACTED_by_tool}")
    # ---- R12 明文债棘轮：旧债允许存在，新债一律红，过期即红 ----
    debt_leak = {"schema": 1, "owner": "agent", "expires": DEFAULT_EXPIRES, "entries": []}
    run_case("T30 明文不在债表 → FAIL（新增明文）", 1, consumer="synced",
             status="synced", answer_leak=True, debt=debt_leak)
    run_case("T31 同一处明文已入账债表 → PASS（只减不增）", 0, consumer="synced",
             status="synced", answer_leak=True,
             debt={"schema": 1, "owner": "agent", "expires": DEFAULT_EXPIRES,
                   "entries": [{"file": "scripts/leaky_fixture.py",
                                "kind": "source_literal",
                                "flag_sha256": __import__("hashlib").sha256(
                                    b"flag{fixture_leak_0001}").hexdigest()}]})
    # T36/T37 分类核查：账不能一锅记，否则「该清」和「必须留」混在一起互相掩护
    run_case("T36 文档类明文债 → FAIL（叙事里没理由持真值）", 1, consumer="synced",
             status="synced", answer_leak=True, leak_path="docs/leaky_note.md",
             debt={"schema": 1, "owner": "agent", "expires": DEFAULT_EXPIRES,
                   "entries": [{"file": "docs/leaky_note.md", "kind": "doc_prose",
                                "flag_sha256": __import__("hashlib").sha256(
                                    b"flag{fixture_leak_0001}").hexdigest()}]})
    run_case("T37 債条目缺分类 → FAIL（不写清它是什么，就没法判断该不该留）", 1,
             consumer="synced", status="synced", answer_leak=True,
             debt={"schema": 1, "owner": "agent", "expires": DEFAULT_EXPIRES,
                   "entries": [{"file": "scripts/leaky_fixture.py",
                                "flag_sha256": __import__("hashlib").sha256(
                                    b"flag{fixture_leak_0001}").hexdigest()}]})
    run_case("T32 明文债已过期 → FAIL（到期必须闭环）", 1, consumer="synced",
             status="synced", answer_leak=True,
             debt={"schema": 1, "owner": "agent", "expires": "2026-01-01", "entries": []})

    bad = 0
    for title, ok, detail in RESULTS:
        print("  [%s] %s" % ("PASS" if ok else "FAIL", title))
        if not ok:
            print("        %s" % detail)
            bad += 1
    total = len(RESULTS)
    print("\n结论：%s —— %d/%d 通过" % ("PASS" if bad == 0 else "FAIL", total - bad, total))
    return 0 if bad == 0 else 1


if __name__ == "__main__":
    sys.exit(main())
