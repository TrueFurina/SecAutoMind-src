#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""run_hitl_boundary 门禁回归测试 —— 防「声明了却没跑」静默算 PASS。

背景（2026-10-14 门禁审计 · 空洞绿，只读探针实证）：
  旧版判据只有 `ok = rc==0 and "FAIL" not in out`。而 `go test -run '^TestX$'`
  在**测试名对不上**（被改名 / 被删 / 包路径写错）时照样 exit 0，只输出
  `testing: warning: no tests to run` / `ok ... [no tests to run]`。
  探针实测：让 subprocess 返回该输出，5 个 machine 模式**全部 PASS**、rc=0 ——
  模式矩阵写着全绿，实际验证覆盖为 0。这正是 AGENTS.md 第八条
  「定义齐全 ≠ 接线」的同款形态：**声明了却不存在/不跑**。

修法（fail-closed）：从 `go test -v` 输出回读每个测试名的 `--- PASS/--- FAIL` 判定行；
  缺一个就把该模式判 FAIL。`--- SKIP` 不算验证（跳过 = 没测），同样计红。

本测试锁两半：
  · 回归：no tests to run / 部分缺失 / 真 FAIL / 全 SKIP / go 不在 PATH → 必须 rc=1；
  · 反向变异：全部测试名都有 PASS 行 → 必须 rc=0（防"改成恒红"）。

用法：
    python scripts/run_hitl_boundary_test.py
退出码：0 = 门禁健康；1 = 门禁已退化或仍能静默放行，必须修 scripts/run_hitl_boundary.py
"""
import contextlib
import importlib.util
import io
import os
import sys

try:
    sys.stdout.reconfigure(encoding="utf-8")
except Exception:
    pass

HERE = os.path.dirname(os.path.abspath(__file__))
GATE = os.path.join(HERE, "run_hitl_boundary.py")


def load_gate():
    spec = importlib.util.spec_from_file_location("hitl_under_test", GATE)
    m = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(m)
    return m


class FakeRun:
    """替身 subprocess.run：返回固定输出/退出码，或抛 FileNotFoundError。"""

    def __init__(self, stdout="", returncode=0, not_found=False):
        self.stdout, self.returncode, self.not_found = stdout, returncode, not_found

    def __call__(self, cmd, **kw):
        if self.not_found:
            raise FileNotFoundError("go")
        import subprocess
        return subprocess.CompletedProcess(cmd, self.returncode,
                                           stdout=self.stdout, stderr="")


def all_matrix_tests(rh):
    out = []
    for m in rh.MACHINE_MODES:
        for sp in m["specs"]:
            out.extend(sp["tests"])
    return out


def run_boundary(fake):
    """加载门禁、patch subprocess、跑 --check，返回 (rc, 输出)。"""
    rh = load_gate()
    rh.subprocess.run = fake
    argv, sys.argv = sys.argv, ["run_hitl_boundary.py", "--check"]
    buf = io.StringIO()
    try:
        with contextlib.redirect_stdout(buf):
            rc = rh.main()
        return rc, buf.getvalue()
    finally:
        sys.argv = argv


def main():
    failures = []
    print("=" * 66)
    print("run_hitl_boundary 门禁回归测试（空洞绿 / 恒红 / 回读判据）")
    print("=" * 66)

    rh0 = load_gate()
    all_tests = all_matrix_tests(rh0)
    pass_out = "\n".join("--- PASS: %s (0.00s)" % t for t in all_tests) + "\nok  \tpkg\t0.10s\n"

    # ---- 1. no tests to run 必须 FAIL（2026-10-14 封死的空洞绿）----
    print("\n[1/8] 全部测试都没真跑（no tests to run, rc=0）必须 FAIL")
    rc, out = run_boundary(FakeRun("testing: warning: no tests to run\n"
                                   "ok  \tpkg\t0.01s [no tests to run]\n"))
    ok = (rc == 1)
    print("  %s 返回 %s（期望 1）" % ("PASS" if ok else "FAIL", rc))
    if not ok:
        failures.append("no tests to run 却 PASS（rc=%s）——矩阵全绿但验证覆盖为 0" % rc)

    # ---- 2. 反向变异：全部测试名都有 PASS 行必须 PASS（防恒红）----
    print("\n[2/8] 全部测试真跑且 PASS 必须 PASS（反向变异：防恒红）")
    rc, out = run_boundary(FakeRun(pass_out))
    ok = (rc == 0)
    print("  %s 返回 %s（期望 0）" % ("PASS" if ok else "FAIL", rc))
    if not ok:
        failures.append("全 PASS 场景被判红（rc=%s）——门禁被修成恒红：%s" % (rc, out[-300:]))

    # ---- 3. 部分测试名缺失（改名/删除）必须 FAIL ----
    print("\n[3/8] 部分测试未真跑（第一个测试的判定行缺失）必须 FAIL")
    dropped = pass_out.splitlines(True)
    dropped = [l for l in dropped if not l.startswith("--- PASS: %s " % all_tests[0])]
    rc, out = run_boundary(FakeRun("".join(dropped)))
    ok = (rc == 1)
    print("  %s 返回 %s（期望 1）" % ("PASS" if ok else "FAIL", rc))
    if not ok:
        failures.append("测试名失效未被捕获（rc=%s）——改名即可让该模式静默失效" % rc)

    # ---- 4. 真 FAIL 必须 FAIL（既有判据未退化）----
    print("\n[4/8] 测试真 FAIL 必须 FAIL（既有判据未退化）")
    fail_out = pass_out.replace("--- PASS: %s (0.00s)" % all_tests[0],
                                "--- FAIL: %s (0.00s)" % all_tests[0])
    rc, out = run_boundary(FakeRun(fail_out))
    ok = (rc == 1)
    print("  %s 返回 %s（期望 1）" % ("PASS" if ok else "FAIL", rc))
    if not ok:
        failures.append("真 FAIL 未判红（rc=%s）" % rc)

    # ---- 5. 全 SKIP 必须 FAIL（跳过不算验证）----
    print("\n[5/8] 全部测试被 SKIP 必须 FAIL（跳过 ≠ 验证）")
    skip_out = "\n".join("--- SKIP: %s (0.00s)" % t for t in all_tests) + "\nok  \tpkg\t0.10s\n"
    rc, out = run_boundary(FakeRun(skip_out))
    ok = (rc == 1)
    print("  %s 返回 %s（期望 1）" % ("PASS" if ok else "FAIL", rc))
    if not ok:
        failures.append("全 SKIP 却 PASS（rc=%s）——跳过被当成验证充数" % rc)

    # ---- 6. go 不在 PATH（环境故障）必须 FAIL 且如实归因 ----
    print("\n[6/8] 找不到 go（环境故障）必须 FAIL 且输出如实归因")
    rc, out = run_boundary(FakeRun(not_found=True))
    ok = (rc == 1 and "环境故障" in out)
    print("  %s 返回 %s（期望 1 且含「环境故障」）" % ("PASS" if ok else "FAIL", rc))
    if not ok:
        failures.append("go 缺失未 fail-closed 或未归因环境（rc=%s）" % rc)

    # ---- 7. 回读判据：括号/时间后缀/子测试行不得误报 missing ----
    print("\n[7/8] 回读判据 · 主测试行 + 子测试行都算真跑（不得误报缺失）")
    rh = load_gate()
    out7 = ("=== RUN   TestX\n--- PASS: TestX (0.00s)\n"
            "    --- PASS: TestX/sub (0.00s)\n--- PASS: TestY (0.00s)\n")
    missing = rh.tests_actually_run(out7, ["TestX", "TestY"])
    ok = (missing == [])
    print("  %s missing=%s（期望 []）" % ("PASS" if ok else "FAIL", missing))
    if not ok:
        failures.append("主测试/子测试行解析有误，误报 missing=%s——会把真跑判成没跑" % missing)

    # ---- 8. 回读判据：FAIL 行也算"真跑"（不得与"没跑"混淆）----
    print("\n[8/8] 回读判据 · --- FAIL 行同样算真跑（只判红，不误报缺失）")
    rh = load_gate()
    missing = rh.tests_actually_run("--- FAIL: TestZ (0.00s)\n", ["TestZ"])
    ok = (missing == [])
    print("  %s missing=%s（期望 []）" % ("PASS" if ok else "FAIL", missing))
    if not ok:
        failures.append("FAIL 行被误判成没跑（missing=%s）——两类失败原因会互相掩盖" % missing)

    print("\n" + "=" * 66)
    if failures:
        print("FAIL —— %d 项不达标：" % len(failures))
        for f in failures:
            print("  - " + f)
        return 1
    print("PASS —— run_hitl_boundary 门禁 8/8 用例通过"
          "（零真跑 fail-closed + 恒红防护 + 回读判据两态）。")
    return 0


if __name__ == "__main__":
    sys.exit(main())
