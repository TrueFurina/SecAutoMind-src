#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""check_quant_effect 门禁回归测试 —— 防止「对外量化陈述机验」静默空转。

背景（2026-10-14 门禁 fail-closed 审计实锤，三种空洞绿形态）：
    M2. **全 slow**：每条声明都标 `耗时类: slow` → CI 默认 quick 模式选中 0 条，
        脚本打印「PASS —— 本次机验的 0 条量化陈述全部可复现」并 rc=0。
        零机验却报全绿，与 `_audit_llm_pool.py` 当年「池文件缺失 → 自动全真」同构。
    M3. **缺 command/pattern**：声明没给可机验的命令 → 旧版记 `[SKIP]` 且**不计入
        fails**，结论仍是 PASS，甚至谎报「1 条全部可复现」（实际 0 条被验）。
        违反验收第 8 条「对外量化陈述 100% 可指回」——不可机验就该红，不该静默。
    M1. **全 slow + 缺字段叠加**时，门禁彻底变成"什么都不做还报绿"的哑门禁。

本测试在临时仓库里构造上述输入，断言门禁**必须 rc=1**；
同时用 M4/M5 反向锁死「修完没变成恒红」：真实漂移要红、真实一致要绿。

第 3 段另锁「验证不得有副作用」（2026-10-14 实锤：门禁自己跑一次就把受版本管理的
data/ctf_benchmark/all_benchmarks_summary.json 覆盖一次，降级环境写进降级值并级联
判红基线门禁）：断言事前重定向生效、事后快照还原生效；并用变异（禁用还原）证明该
断言不是空洞的。

用法：
    python scripts/check_quant_effect_test.py
退出码：0 = 门禁健康；1 = 门禁已退化，必须修 scripts/check_quant_effect.py
"""
import os
import shutil
import subprocess
import sys
import tempfile

try:
    sys.stdout.reconfigure(encoding="utf-8")
except Exception:
    pass

HERE = os.path.dirname(os.path.abspath(__file__))
GATE = os.path.join(HERE, "check_quant_effect.py")

# 可机验的命令（ASCII 输出，规避 Windows 控制台编码差异）。
# ⚠️ 刻意**不用** `python -c "print(...)"`：Windows cmd.exe 对 `-c "..."` 的嵌套引号
# 解析与 POSIX sh 不同（`"%s" -c "print('...')"` 会被拆成无法识别的命令名），
# 曾让本测试的"一致场景"在 Windows 上假红。改用探针脚本文件，两侧通用。
CMD_OK = '"%s" probe_ok.py'
CMD_DRIFT = '"%s" probe_drift.py'
PAT = r"(\d+)/(\d+) = ([\d.]+)%"


def claim(cid, cmd, pat=PAT, expect="5/10 = 50.0%", cost="quick"):
    lines = ["- id: %s" % cid]
    if cmd is not None:
        lines.append("  command: %s" % cmd)
    if pat is not None:
        lines.append("  pattern: '%s'" % pat)
    lines.append("  耗时类: %s" % cost)
    lines.append("  期望: %s" % expect)
    return "\n".join(lines)


def doc_of(claims):
    return "# 量化效果\n\n```yaml\n" + "\n".join(claims) + "\n```\n"


def run_gate(doc_text, full=False):
    """在临时仓库里跑门禁，返回 (rc, 输出)。"""
    tmp = tempfile.mkdtemp(prefix="qe_gate_")
    try:
        root = os.path.join(tmp, "repo")
        os.makedirs(os.path.join(root, "scripts"))
        os.makedirs(os.path.join(root, "docs"))
        shutil.copyfile(GATE, os.path.join(root, "scripts", "check_quant_effect.py"))
        # 探针脚本：命令由门禁以 cwd=ROOT 执行，故放在仓库根
        with open(os.path.join(root, "probe_ok.py"), "w",
                  encoding="utf-8", newline="\n") as fh:
            fh.write('print("hits 5/10 = 50.0%")\n')
        with open(os.path.join(root, "probe_drift.py"), "w",
                  encoding="utf-8", newline="\n") as fh:
            fh.write('print("hits 3/10 = 30.0%")\n')
        with open(os.path.join(root, "docs", "quant_effect.md"), "w",
                  encoding="utf-8", newline="\n") as fh:
            fh.write(doc_text)
        args = [sys.executable, os.path.join(root, "scripts", "check_quant_effect.py")]
        if full:
            args.append("--full")
        p = subprocess.run(args, cwd=root, capture_output=True, text=True,
                           encoding="utf-8", errors="replace", timeout=300)
        return p.returncode, (p.stdout or "") + (p.stderr or "")
    finally:
        shutil.rmtree(tmp, ignore_errors=True)


# ── 验证副作用防线（2026-10-14 实锤：验证动作污染被验证的产物）──────────────
# 背景：docs/quant_effect.md 的 `benchmark_suite_green` 声明会跑
# data/ctf_benchmark/run_all_benchmarks.py，而后者此前**无条件就地写**
# all_benchmarks_summary.json（受版本管理、被证据包与基线门禁消费）。
# 于是「跑验证」=「改产物」：降级环境下写进降级值，并级联把
# check_benchmark_baseline_test.py 判红。
#
# 本段在临时仓库里放一个"会就地改写受保护产物"的探针命令，锁两件事：
#   ① 事前重定向：机验命令能拿到 CTF_AGENT_BENCH_SUMMARY_OUT 且指向仓库外临时目录；
#   ② 事后守卫：产物字节被改 → 必须自动还原 + 告警；且门禁不得因告警而误报 PASS 混淆。
# 变异验证：把还原函数改空 → 断言必须 FAIL（证明断言不是摆设）。

ISO_CMD = '"%s" probe_iso.py'
ISO_ORIGINAL = '{\n  "padding_oracle": {"total": 1, "hit": 1, "miss": 0}\n}\n'
# 探针：先就地改写受保护产物（模拟降级写入），把重定向值落盘（门禁不回显子进程
# stdout，只能借文件观测），再打印门禁期望的数字，使 claim 本身 PASS。
ISO_REDIRECT_DUMP = "_redirect_probe.txt"
ISO_PROBE = (
    'import json, os, pathlib\n'
    'pathlib.Path("' + ISO_REDIRECT_DUMP + '").write_text(\n'
    '    str(os.environ.get("CTF_AGENT_BENCH_SUMMARY_OUT", "<unset>")), encoding="utf-8")\n'
    'p = pathlib.Path("data/ctf_benchmark/all_benchmarks_summary.json")\n'
    'd = json.loads(p.read_text(encoding="utf-8"))\n'
    'd["padding_oracle"] = {"total": 1, "hit": 0, "miss": 1}\n'
    'p.write_text(json.dumps(d, ensure_ascii=False, indent=2) + "\\n", encoding="utf-8")\n'
    'print("hits 5/10 = 50.0%")\n'
)

MUT_NO_RESTORE_OLD = '    changed = []\n    for rel, blob in sorted(snap.items()):'
MUT_NO_RESTORE_NEW = '    return []\n    changed = []\n    for rel, blob in sorted(snap.items()):'


def run_gate_iso(doc_text, gate_transform=None, extra_args=()):
    """跑门禁并返回 (rc, 输出, 产物原始字节, 产物跑后字节, 探针观测到的重定向值)。"""
    tmp = tempfile.mkdtemp(prefix="qe_iso_")
    try:
        root = os.path.join(tmp, "repo")
        os.makedirs(os.path.join(root, "scripts"))
        os.makedirs(os.path.join(root, "docs"))
        bench = os.path.join(root, "data", "ctf_benchmark")
        os.makedirs(bench)
        src = open(GATE, encoding="utf-8").read()
        if gate_transform:
            src = gate_transform(src)
        with open(os.path.join(root, "scripts", "check_quant_effect.py"), "w",
                  encoding="utf-8", newline="\n") as fh:
            fh.write(src)
        with open(os.path.join(root, "probe_iso.py"), "w",
                  encoding="utf-8", newline="\n") as fh:
            fh.write(ISO_PROBE)
        with open(os.path.join(root, "docs", "quant_effect.md"), "w",
                  encoding="utf-8", newline="\n") as fh:
            fh.write(doc_text)
        art = os.path.join(bench, "all_benchmarks_summary.json")
        with open(art, "w", encoding="utf-8", newline="\n") as fh:
            fh.write(ISO_ORIGINAL)

        args = [sys.executable, os.path.join(root, "scripts", "check_quant_effect.py")]
        args.extend(extra_args)
        p = subprocess.run(args, cwd=root, capture_output=True, text=True,
                           encoding="utf-8", errors="replace", timeout=300)
        with open(art, "rb") as fh:
            after = fh.read()
        dump = os.path.join(root, ISO_REDIRECT_DUMP)
        redirect = ""
        if os.path.exists(dump):
            with open(dump, encoding="utf-8") as fh:
                redirect = fh.read().strip()
        return p.returncode, (p.stdout or "") + (p.stderr or ""), \
            ISO_ORIGINAL.encode("utf-8"), after, redirect
    finally:
        shutil.rmtree(tmp, ignore_errors=True)


def main():
    failures = []
    py = sys.executable

    print("=" * 62)
    print("check_quant_effect 门禁回归测试（空洞绿防线）")
    print("=" * 62)

    # ---- 空洞绿三形态：必须 rc=1 ----
    print("\n[1/3] 空洞绿必须变红（fail-closed）")

    cases_empty = [
        ("M2 全部声明标 slow（quick 模式机验 0 条）",
         doc_of([claim("only_slow", CMD_OK % py, cost="slow")]), False),
        ("M3 声明缺 command（不可机验却记 SKIP 报绿）",
         doc_of([claim("no_cmd", None)]), False),
        ("M3b 声明缺 pattern（同上）",
         doc_of([claim("no_pat", CMD_OK % py, pat=None)]), False),
        # M2b：--full 时 slow 会被选中，必须真的执行命令 —— 用会漂移的命令，
        # 断言 rc=1 且**不是**"机验 0 条"那种空转红，以此证明 slow 声明确实跑了。
        ("M2b --full 下 slow 声明必须真实执行命令",
         doc_of([claim("only_slow2", CMD_DRIFT % py, cost="slow")]), True),
    ]
    for label, doc, full in cases_empty[:3]:
        rc, out = run_gate(doc, full)
        ok = (rc == 1)
        print("  %s %s（期望 rc=1，实际 rc=%d）" % ("PASS" if ok else "FAIL", label, rc))
        if not ok:
            failures.append("%s：门禁未 fail-closed（rc=%d）\n    %s"
                            % (label, rc, out.strip().replace("\n", "\n    ")[:400]))

    # M2b：--full 时 slow 会被选中，此时应当真的去跑并因期望不符而红（不是空转红）
    rc, out = run_gate(cases_empty[3][1], full=True)
    ok_full = (rc == 1) and ("0 条" not in out)
    print("  %s --full 下 slow 被真实机验（期望 rc=1 且非空转，实际 rc=%d）"
          % ("PASS" if ok_full else "FAIL", rc))
    if not ok_full:
        failures.append("--full 下 slow 声明未真实机验（rc=%d）\n    %s"
                        % (rc, out.strip().replace("\n", "\n    ")[:400]))

    # ---- 反向变异：不能修成恒红 ----
    print("\n[2/3] 反向变异（门禁不得恒红 / 不得虚报）")

    rc, out = run_gate(doc_of([claim("drift", CMD_DRIFT % py)]))
    ok = (rc == 1)
    print("  %s M4 真实数字漂移必须红（期望 rc=1，实际 rc=%d）" % ("PASS" if ok else "FAIL", rc))
    if not ok:
        failures.append("真实漂移未被检出（rc=%d）——门禁已失效\n    %s"
                        % (rc, out.strip().replace("\n", "\n    ")[:400]))

    rc, out = run_gate(doc_of([claim("ok", CMD_OK % py)]))
    ok = (rc == 0) and ("本次机验的 1 条" in out)
    print("  %s M5 真实一致必须绿且计数真实（期望 rc=0 且报 1 条，实际 rc=%d）"
          % ("PASS" if ok else "FAIL", rc))
    if not ok:
        failures.append("一致场景未通过或计数虚报（rc=%d）\n    %s"
                        % (rc, out.strip().replace("\n", "\n    ")[:400]))

    # 混合场景：1 条真过 + 1 条缺 command → 必须红（缺字段不得被"1 条通过"掩盖）
    rc, out = run_gate(doc_of([claim("ok", CMD_OK % py),
                               claim("no_cmd", None)]))
    ok = (rc == 1)
    print("  %s M6 混合场景缺字段必须连坐红（期望 rc=1，实际 rc=%d）"
          % ("PASS" if ok else "FAIL", rc))
    if not ok:
        failures.append("混合场景下缺 command 的声明被静默放过（rc=%d）\n    %s"
                        % (rc, out.strip().replace("\n", "\n    ")[:400]))

    # ---- 验证副作用防线（重定向 + 快照还原）----
    print("\n[3/3] 验证不得有副作用（受版本管理产物保护）")

    rc, out, before, after, redirect = run_gate_iso(doc_of([claim("ok", ISO_CMD % py)]))
    restored = (after == before)
    warned = ("[WARN]" in out) and ("已自动还原" in out)
    # 重定向必须指向仓库外的临时目录（门禁自建的 qe_isolated_*），而非受管理路径
    redirected = (redirect not in ("", "<unset>")) and ("qe_isolated_" in redirect) \
        and ("data" + os.sep + "ctf_benchmark" not in redirect) \
        and ("data/ctf_benchmark" not in redirect)
    ok = (rc == 0) and restored and warned and redirected
    print("  %s ISO1 改写受保护产物 → 自动还原并告警（期望 rc=0/已还原/已告警/已重定向，"
          "实际 rc=%d 还原=%s 告警=%s 重定向=%s）"
          % ("PASS" if ok else "FAIL", rc, restored, warned, redirected))
    if not ok:
        failures.append("ISO1 验证副作用未被封住（rc=%d 还原=%s 告警=%s 重定向=%r）\n    %s"
                        % (rc, restored, warned, redirect,
                           out.strip().replace("\n", "\n    ")[:400]))

    rc, out, before, after, _ = run_gate_iso(doc_of([claim("ok", ISO_CMD % py)]),
                                             extra_args=("--strict-isolation",))
    ok = (rc == 1)
    print("  %s ISO2 --strict-isolation 下改写产物必须红（期望 rc=1，实际 rc=%d）"
          % ("PASS" if ok else "FAIL", rc))
    if not ok:
        failures.append("ISO2 --strict-isolation 未生效（rc=%d）\n    %s"
                        % (rc, out.strip().replace("\n", "\n    ")[:400]))

    # 变异：把还原函数改空 → ISO1 的核心断言必须变红（证明它不是摆设）
    def kill_restore(src):
        assert MUT_NO_RESTORE_OLD in src, "探针原文未找到，请同步本测试的变异常量"
        return src.replace(MUT_NO_RESTORE_OLD, MUT_NO_RESTORE_NEW, 1)

    rc, out, before, after, _ = run_gate_iso(doc_of([claim("ok", ISO_CMD % py)]),
                                             gate_transform=kill_restore)
    mutant_caught = (after != before)
    print("  %s M7 变异：禁用还原 → 产物确实留存被改内容（断言仍生效，实际 caught=%s）"
          % ("PASS" if mutant_caught else "FAIL", mutant_caught))
    if not mutant_caught:
        failures.append("M7 变异未被捕获 —— ISO1 的\"已还原\"断言是空洞的："
                        "把还原函数改空后产物仍与原文一致，说明断言没在真的比对内容")

    print("\n" + "=" * 62)
    if failures:
        print("[FAIL] 量化机验门禁已退化，必须修 scripts/check_quant_effect.py：")
        for f in failures:
            print("  - %s" % f)
        print("=" * 62)
        return 1
    print("[PASS] 量化机验门禁健康：3 类空洞绿全部 fail-closed，"
          "真实漂移仍检出，一致场景仍放行且计数真实，")
    print("       且验证动作不污染受版本管理产物（重定向 + 快照还原均生效）。")
    print("=" * 62)
    return 0


if __name__ == "__main__":
    sys.exit(main())
