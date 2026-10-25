"""selftest_all.py — ctf_sage 模板库聚合自测（master selftest）。

逐个模板跑 `--selftest`，汇总结果。纪律（AGENTS.md 1.2）：
  - 每个子进程输出落盘到临时文件，再统计——**不许用管道**（管道会吞退出码，
    本项目有 `cmd | tail; echo $?` 打印 tail 的 0 而门禁真实 rc=1 的实锤事故）。
  - 全部通过 rc=0；任一失败 rc=1 并列出失败模板与输出尾部。
  - 每模板有独立超时（默认 300s），超时即失败（不等僵尸）。

用法：
  python selftest_all.py                    # 用当前解释器
  python selftest_all.py --python /usr/bin/python3 --timeout 600
"""

from __future__ import annotations

import subprocess
import sys
import tempfile
from pathlib import Path

HERE = Path(__file__).resolve().parent

# (模板, 说明, 超时秒)。时间预算：合计应控制在分钟级（重活归服务器实验，不进自测）。
TEMPLATES = [
    ("t1_coppersmith.py", "Coppersmith 小根（7 用例，含 docstring 513bit 候选路径）", 300),
    ("t2_ecdsa_hnp.py", "ECDSA nonce 复用 + HNP 格（4 用例）", 300),
    ("t3_truncated_lfsr.py", "LFSR taps/状态恢复（6 用例）", 300),
    ("t4_boneh_durfee.py", "Boneh-Durfee 小私钥指数（6 用例，含 sympy 结式）", 600),
    ("t5_dlp_bsgs_ph.py", "DLP：Pohlig-Hellman + BSGS（19 用例，含重复素因子/多位剥离回归）", 300),
    ("t6_hastad_broadcast.py", "Håstad 广播攻击（4 用例）", 300),
]


def run_one(python: str, script: str, timeout: int, tmpdir: Path) -> tuple[bool, str, str]:
    """跑一个模板自测；返回 (passed, 输出尾部, 失败原因)。"""
    out_file = tmpdir / f"{script}.out.txt"
    with open(out_file, "w", encoding="utf-8") as fh:
        try:
            proc = subprocess.run(
                [python, "-u", script, "--selftest"],
                cwd=HERE, stdout=fh, stderr=subprocess.STDOUT, timeout=timeout,
            )
        except subprocess.TimeoutExpired:
            return False, "", f"超时（>{timeout}s）"
    text = out_file.read_text(encoding="utf-8", errors="replace")
    tail = "\n".join(text.strip().splitlines()[-6:])
    return proc.returncode == 0, tail, f"rc={proc.returncode}"


def main() -> None:
    args = list(sys.argv[1:])
    python = sys.executable
    if "--python" in args:
        python = args[args.index("--python") + 1]
        del args[args.index("--python"):args.index("--python") + 2]

    print(f"ctf_sage master selftest（解释器: {python}）")
    print(f"模板数: {len(TEMPLATES)}")
    print("-" * 72)

    results: list[tuple[str, bool, str, str]] = []
    with tempfile.TemporaryDirectory(prefix="ctf_sage_st_") as td:
        tmpdir = Path(td)
        for script, desc, timeout in TEMPLATES:
            path = HERE / script
            if not path.exists():
                results.append((script, False, "", f"文件不存在: {path}"))
                print(f"  [MISS] {script}: 文件不存在")
                continue
            ok, tail, why = run_one(python, script, timeout, tmpdir)
            results.append((script, ok, tail, why))
            mark = "PASS" if ok else "FAIL"
            print(f"  [{mark}] {script} — {desc}" + ("" if ok else f"（{why}）"))
            if not ok and tail:
                for line in tail.splitlines():
                    print(f"         | {line}")

    print("-" * 72)
    npass = sum(1 for _, ok, _, _ in results if ok)
    print(f"master selftest: {npass}/{len(results)}")
    if npass != len(results):
        print("失败模板: " + ", ".join(s for s, ok, _, _ in results if not ok))
        sys.exit(1)
    print("ALL PASS")
    sys.exit(0)


if __name__ == "__main__":
    main()
