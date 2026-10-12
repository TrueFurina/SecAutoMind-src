#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""冠军证据包门禁的**变异验证**（证明 `--check` 真能杀死漂移，而不是恒 PASS）。

为什么需要它（本仓已两次栽在"门禁失效"）：
  2026-09-08 旧 secret 正则漏配 → 门禁报 CLEAN；2026-09-13 省略号被无条件豁免 → 门禁放过真 key 片段。
  教训：**"测试全绿"不等于"测试有效"**。任何门禁都必须能被"故意注入错误"打红。

本脚本对 docs/evidence-package.json 依次注入 4 类变异，每次都要求 --check 返回 **非 0**：
  ① 规模数字漂移（caliber.ctf_solvers 改值）
  ② 基准命中数漂移（benchmark.base.execution.hit 改值）
  ③ golden 哈希漂移（golden.files_sha256 改值）
  ④ 门禁 RC 记录为非 0（模拟"把一次失败的门禁冻结进证据包"）
最后恢复原文，要求 --check 回到 **0**，并校验文件与备份**逐字节一致**（sha256）。

实战价值（首次运行即抓到本门禁自身的 2 个真 bug）：
  比对 golden 段与 gates 段时误复用了 benchmark 子字典 → 这两类漂移**完全不被检测**
  （门禁形同虚设）。若只跑一次"全绿"就收工，这个缺陷永远不会暴露。

安全性：所有写入都用 try/finally 包裹，任何异常都会先还原原文件再退出。
"""
import os
import sys
import json
import shutil
import hashlib
import subprocess

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
PKG = os.path.join(ROOT, "docs", "evidence-package.json")
BAK = PKG + ".mutation-bak"
CHECK = os.path.join(ROOT, "scripts", "build_championship_evidence.py")


def sha256(path):
    h = hashlib.sha256()
    with open(path, "rb") as fh:
        for chunk in iter(lambda: fh.read(1 << 20), b""):
            h.update(chunk)
    return h.hexdigest()


def run_check():
    r = subprocess.run([sys.executable, CHECK, "--check"], cwd=ROOT, shell=False,
                       capture_output=True, encoding="utf-8", errors="ignore", timeout=1800)
    return r.returncode, (r.stdout or "") + (r.stderr or "")


def mutate(mutator, loaded):
    """在 loaded（已解析的包）上原地变异，返回 (描述, 变异后 JSON 文本)。"""
    desc = mutator(loaded)
    text = json.dumps(loaded, ensure_ascii=False, indent=2, sort_keys=False) + "\n"
    return desc, text


def m_caliber(d):
    old = d["caliber"].get("ctf_solvers")
    d["caliber"]["ctf_solvers"] = (old or 0) + 7
    return "caliber.ctf_solvers %s -> %s" % (old, d["caliber"]["ctf_solvers"])


def m_benchmark(d):
    b = d["benchmark"]["base"]["execution"]
    old = b.get("hit")
    b["hit"] = 3 if old != 3 else 4
    return "benchmark.base.execution.hit %s -> %s" % (old, b["hit"])


def m_golden(d):
    files = d["golden"]["files_sha256"]
    key = sorted(files)[0] if files else None
    if not key:
        return None
    old = files[key]
    files[key] = "0" * 64
    return "golden.files_sha256[%s] %s -> %s" % (os.path.basename(key), (old or "")[:12], "0" * 12)


def m_gate_rc(d):
    """模拟"把一次失败的门禁冻结进证据包"。"""
    g = d.get("gates") or {}
    key = "secret_guard_rc"
    if key not in g:
        return None
    old = g[key]
    g[key] = 1
    return "gates.%s %s -> 1" % (key, old)


def main():
    if not os.path.isfile(PKG):
        print("✗ 证据包不存在：%s\n  先跑 `python scripts/build_championship_evidence.py`" % PKG)
        sys.exit(1)
    if not os.path.isfile(CHECK):
        print("✗ 缺失 %s" % CHECK)
        sys.exit(1)

    shutil.copy2(PKG, BAK)
    orig_hash = sha256(PKG)
    print("=" * 70)
    print("证据包门禁变异验证")
    print("=" * 70)
    print("  证据包 %s" % os.path.relpath(PKG, ROOT))
    print("  原始 sha256 %s" % orig_hash[:16])
    print()

    failures = []
    try:
        # ── 基线：原文必须 PASS ──────────────────────────────────────────────
        rc, out = run_check()
        print("  [基线] --check rc=%d  %s" % (rc, "PASS" if rc == 0 else "FAIL"))
        if rc != 0:
            failures.append("基线应为 0，实测 %d（门禁在正常情况下就不通过，无法判定变异有效性）" % rc)
            print(out[-1500:])
            raise SystemExit(1)

        # ── 逐个变异：--check 必须变红 ──────────────────────────────────────
        for name, mutator in (("规模数字漂移", m_caliber),
                              ("基准命中数漂移", m_benchmark),
                              ("golden 哈希漂移", m_golden),
                              ("门禁 RC 记录为非 0", m_gate_rc)):
            loaded = json.load(open(PKG, "r", encoding="utf-8"))
            info, text = mutate(mutator, loaded)
            if info is None:
                print("  [%s] 跳过（包内无可变异字段）" % name)
                continue
            with open(PKG, "w", encoding="utf-8", newline="\n") as fh:
                fh.write(text)
            rc, out = run_check()
            detected = rc != 0
            # 抽取 --check 报出的漂移行，证明是"被正确检出"而非别的原因失败
            drift_line = ""
            for line in out.splitlines():
                if line.strip().startswith("- ") and ("活值" in line or "包内" in line):
                    drift_line = line.strip()
                    break
            print("  [%s] %s" % (name, info))
            print("      --check rc=%d  %s" % (rc, "已捕获 ✓" if detected else "未捕获 ✗"))
            if drift_line:
                print("      检出: %s" % drift_line)
            if not detected:
                failures.append("%s 未被检出" % name)
            # 还原，准备下一个变异
            shutil.copy2(BAK, PKG)
    finally:
        shutil.copy2(BAK, PKG)
        os.remove(BAK)

    # ── 恢复后必须逐字节一致且 PASS ────────────────────────────────────────
    now_hash = sha256(PKG)
    restored = (now_hash == orig_hash)
    rc, out = run_check()
    print()
    print("  [恢复] sha256 %s（%s）" % (now_hash[:16], "与原始逐字节一致 ✓" if restored
                                        else "与原始不一致 ✗"))
    print("  [恢复] --check rc=%d  %s" % (rc, "PASS" if rc == 0 else "FAIL"))
    if not restored:
        failures.append("恢复后文件与原始不一致（sha256 不同）")
    if rc != 0:
        failures.append("恢复后 --check 仍为 %d（应为 0）" % rc)

    print()
    if failures:
        print("证据包门禁变异验证：FAIL")
        for f in failures:
            print("  ✗ %s" % f)
        sys.exit(1)
    print("证据包门禁变异验证：MUTATION_CHECK_PASS（4 类漂移全部被捕获，恢复后逐字节一致）")


if __name__ == "__main__":
    main()
