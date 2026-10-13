#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""_audit_truth_sources.py 的回归 + 变异验证（不依赖 pytest，纯 stdlib）。

为什么必须存在
--------------
ci.yml 的 truth-source-gate 注释曾写「测试已覆盖每个检查项的红/绿两态」，
但**仓库里根本没有这个测试文件**（2026-10-13 实查：全仓引用 `_audit_truth_sources`
的只有 ci.yml 与该脚本自身）——一条不实的自证声明。一个宣称"有变异验证"却无人
跑的门禁，和一个失效门禁同样危险：它给出的是假的安全感。
本文件把那条声明变成真的，并由 CI 每次 PR 实跑。

同时修复一处**装饰性门禁**：检查 #1（duplicate_id_within_file）此前不可达 ——
重复 id 在 `_problems_of` 的 dict 去重阶段就被静默合并，永远报 ✅。现改为在去重
之前按声明顺序扫描，list 形态可被抓住（见 T3）。

覆盖用例（每条都在独立 tempfile 夹具根上跑真实门禁子进程）：
    T1  合规 dict 形态（sha 合法 / id 唯一 / 无明文）           → exit 0
    T2  变异：flag_sha256 非 64 位十六进制                      → exit 1 且点名 truth_not_verifiable
    T3  变异：list 形态同 id 重复                               → exit 1 且点名 duplicate_id_within_file
    T4  变异：external_* 来源集出现明文 flag{...}               → exit 1 且点名 plaintext_answer_leak_external
    T5  自研集出现明文 flag（设计允许）                         → exit 0，且仅计入 hints（不误报红线）
    T6  变异：同一 id 跨文件真值不一致（真值源分裂）            → exit 1 且点名 truth_source_divergence
    T7  变异：external manifest 的 included_count 与实际不符    → exit 1 且点名 external_manifest_mismatch
    T8  变异：JSON 解析错误                                     → exit 1 且点名 truth_not_verifiable
    T9  fail-closed：--target 指向不存在目录                    → exit 2（绝不当"通过"）
    T10 --json 输出可解析且含 all_green 字段                    → true
    T11 真实仓库当前状态（回归基线，防夹具与真库脱节）          → exit 0

因果自变异（证明上面每个"红"确实由被改坏的那条判据产生，而非恰好为红）：
    M1  把 external 泄漏判据改成恒不报红 → T4 夹具必须**转绿**
    M2  把 duplicate 判据改成恒不报红   → T3 夹具必须**转绿**

用法：
    python scripts/_audit_truth_sources_test.py
    echo $?     # 0 = 全部通过
"""
import json
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
ROOT = os.path.dirname(HERE)
GATE = os.path.join(HERE, "_audit_truth_sources.py")

HEX = "a" * 64
HEX2 = "b" * 64

_results = []


def _write(root, relpath, content):
    path = os.path.join(root, relpath)
    os.makedirs(os.path.dirname(path), exist_ok=True)
    with open(path, "w", encoding="utf-8", newline="\n") as fh:
        fh.write(content)


def _write_json(root, relpath, obj):
    _write(root, relpath, json.dumps(obj, ensure_ascii=False))


def _run(gate, target, extra=None):
    proc = subprocess.run(
        [sys.executable, gate, "--target", target] + (extra or []),
        capture_output=True, text=True, encoding="utf-8", errors="replace",
    )
    return proc.returncode, (proc.stdout or "") + (proc.stderr or "")


def _mkroot():
    return tempfile.mkdtemp(prefix="truthsrc_")


def check(name, cond, detail=""):
    _results.append((name, bool(cond), detail))
    print("  %s %s%s" % ("PASS" if cond else "FAIL", name,
                         "" if cond else "  <- " + detail))


# ---------------------------------------------------------------- fixtures

def fx_compliant(root):
    _write_json(root, "data/ctf_benchmark/bench.json",
                {"problems": {"p1": {"id": "p1", "flag_sha256": HEX}}})


def fx_bad_sha(root):
    _write_json(root, "data/ctf_benchmark/bench.json",
                {"problems": {"p1": {"id": "p1", "flag_sha256": "zz"}}})


def fx_dup_list(root):
    _write_json(root, "data/ctf_benchmark/list.json",
                {"problems": [{"id": "dup", "flag_sha256": HEX},
                              {"id": "dup", "flag_sha256": HEX}]})


def fx_external_plaintext(root):
    _write_json(root, "data/ctf_benchmark/external_x/benchmark.json",
                {"problems": {"e1": {"id": "e1", "flag_sha256": HEX,
                                     "answer": "flag{leaked-supersecret}"}}})


def fx_selfbuilt_plaintext(root):
    _write_json(root, "data/ctf_benchmark/self.json",
                {"problems": {"s1": {"id": "s1", "flag_sha256": HEX,
                                     "source": "自研", "answer": "flag{ok_local}"}}})


def fx_divergence(root):
    _write_json(root, "data/ctf_benchmark/a.json",
                {"problems": {"p1": {"id": "p1", "flag_sha256": HEX}}})
    _write_json(root, "data/ctf_benchmark/b.json",
                {"problems": {"p1": {"id": "p1", "flag_sha256": HEX2}}})


def fx_manifest_mismatch(root):
    _write_json(root, "data/ctf_benchmark/external_y/benchmark.json",
                {"problems": {"y1": {"id": "y1", "flag_sha256": HEX},
                              "y2": {"id": "y2", "flag_sha256": HEX2}}})
    _write_json(root, "data/ctf_benchmark/external_y/export_manifest.json",
                {"included_count": 5})


def fx_parse_error(root):
    _write(root, "data/ctf_benchmark/broken.json", "{ not valid json ")


# ---------------------------------------------------------------- cases

def case_compliant():
    root = _mkroot()
    try:
        fx_compliant(root)
        rc, out = _run(GATE, root)
        check("T1 合规 → exit 0", rc == 0, "rc=%d\n%s" % (rc, out))
    finally:
        shutil.rmtree(root, ignore_errors=True)


def case_bad_sha():
    root = _mkroot()
    try:
        fx_bad_sha(root)
        rc, out = _run(GATE, root)
        check("T2 变异：非 64-hex sha → exit 1 且点名 truth_not_verifiable",
              rc == 1 and "❌ truth_not_verifiable" in out, "rc=%d\n%s" % (rc, out))
    finally:
        shutil.rmtree(root, ignore_errors=True)


def case_dup_list():
    """修前此判据不可达（重复被 dict 去重吞掉）；修后 list 形态必须能抓。"""
    root = _mkroot()
    try:
        fx_dup_list(root)
        rc, out = _run(GATE, root)
        check("T3 变异：list 形态同 id 重复 → exit 1 且点名 duplicate_id_within_file",
              rc == 1 and "❌ duplicate_id_within_file" in out, "rc=%d\n%s" % (rc, out))
    finally:
        shutil.rmtree(root, ignore_errors=True)


def case_external_plaintext():
    root = _mkroot()
    try:
        fx_external_plaintext(root)
        rc, out = _run(GATE, root)
        check("T4 变异：外部集明文答案 → exit 1 且点名 plaintext_answer_leak_external",
              rc == 1 and "❌ plaintext_answer_leak_external" in out,
              "rc=%d\n%s" % (rc, out))
    finally:
        shutil.rmtree(root, ignore_errors=True)


def case_selfbuilt_plaintext():
    root = _mkroot()
    try:
        fx_selfbuilt_plaintext(root)
        rc, out = _run(GATE, root, ["--json"])
        try:
            rep = json.loads(out)
            n = rep["hints"]["selfbuilt_plaintext_answers"]["count"]
            ok = (rc == 0 and n == 1)
        except Exception as exc:  # noqa: BLE001
            ok, n = False, "json_error %s" % exc
        check("T5 自研集明文 → exit 0 且 hints 计数=1（不误报红线）",
              ok, "rc=%d hints=%s\n%s" % (rc, n, out))
    finally:
        shutil.rmtree(root, ignore_errors=True)


def case_divergence():
    root = _mkroot()
    try:
        fx_divergence(root)
        rc, out = _run(GATE, root)
        check("T6 变异：真值源分裂 → exit 1 且点名 truth_source_divergence",
              rc == 1 and "❌ truth_source_divergence" in out, "rc=%d\n%s" % (rc, out))
    finally:
        shutil.rmtree(root, ignore_errors=True)


def case_manifest_mismatch():
    root = _mkroot()
    try:
        fx_manifest_mismatch(root)
        rc, out = _run(GATE, root)
        check("T7 变异：manifest 计数不符 → exit 1 且点名 external_manifest_mismatch",
              rc == 1 and "❌ external_manifest_mismatch" in out, "rc=%d\n%s" % (rc, out))
    finally:
        shutil.rmtree(root, ignore_errors=True)


def case_parse_error():
    root = _mkroot()
    try:
        fx_parse_error(root)
        rc, out = _run(GATE, root)
        check("T8 变异：JSON 解析错误 → exit 1 且点名 truth_not_verifiable",
              rc == 1 and "❌ truth_not_verifiable" in out, "rc=%d\n%s" % (rc, out))
    finally:
        shutil.rmtree(root, ignore_errors=True)


def case_missing_target():
    rc, out = _run(GATE, os.path.join(tempfile.gettempdir(), "truthsrc_does_not_exist_xyz"))
    check("T9 --target 不存在 → exit 2（fail-closed）", rc == 2, "rc=%d\n%s" % (rc, out))


def case_json_contract():
    root = _mkroot()
    try:
        fx_compliant(root)
        rc, out = _run(GATE, root, ["--json"])
        try:
            rep = json.loads(out)
            ok = (rc == 0 and rep.get("all_green") is True
                  and "checks" in rep and rep.get("problems_total") == 1)
        except Exception as exc:  # noqa: BLE001
            ok = False
            rep = "json_error %s" % exc
        check("T10 --json 可解析且 all_green=true", ok, "rc=%d rep=%s" % (rc, rep))
    finally:
        shutil.rmtree(root, ignore_errors=True)


def case_repo_baseline():
    rc, out = _run(GATE, ROOT)
    check("T11 真实仓库基线 → exit 0", rc == 0, "rc=%d\n%s" % (rc, out))


# ------------------------------------------------- 因果自变异（证明红例是因果的）

def _mutate_gate(replace_from, replace_to):
    """把门禁源码里某条判据改成恒不报红，返回改后的临时脚本路径与清理函数。"""
    with open(GATE, "r", encoding="utf-8") as fh:
        src = fh.read()
    if replace_from not in src:
        return None, (lambda: None), "未找到可变异片段: %s" % replace_from
    mutated = src.replace(replace_from, replace_to, 1)
    fd, path = tempfile.mkstemp(prefix="gate_mut_", suffix=".py")
    with os.fdopen(fd, "w", encoding="utf-8", newline="\n") as fh:
        fh.write(mutated)
    return path, (lambda: os.remove(path)), ""


def case_causal_external():
    path, cleanup, err = _mutate_gate(
        'failures["plaintext_answer_leak_external"].append(tag)',
        'pass  # mutated: 恒不报红')
    if path is None:
        check("M1 自变异：external 判据改坏 → T4 夹具转绿", False, err)
        return
    root = _mkroot()
    try:
        fx_external_plaintext(root)
        rc, out = _run(path, root)
        check("M1 自变异：external 判据改坏 → T4 夹具转绿（证明红例因果）",
              rc == 0, "rc=%d（期望 0）\n%s" % (rc, out))
    finally:
        cleanup()
        shutil.rmtree(root, ignore_errors=True)


def case_causal_duplicate():
    path, cleanup, err = _mutate_gate(
        'failures["duplicate_id_within_file"].append(f"{path.name}:{qid}")',
        'pass  # mutated: 恒不报红')
    if path is None:
        check("M2 自变异：duplicate 判据改坏 → T3 夹具转绿", False, err)
        return
    root = _mkroot()
    try:
        fx_dup_list(root)
        rc, out = _run(path, root)
        check("M2 自变异：duplicate 判据改坏 → T3 夹具转绿（证明红例因果）",
              rc == 0, "rc=%d（期望 0）\n%s" % (rc, out))
    finally:
        cleanup()
        shutil.rmtree(root, ignore_errors=True)


def main():
    print("=" * 66)
    print("_audit_truth_sources 回归 + 变异验证")
    print("=" * 66)
    case_compliant()
    case_bad_sha()
    case_dup_list()
    case_external_plaintext()
    case_selfbuilt_plaintext()
    case_divergence()
    case_manifest_mismatch()
    case_parse_error()
    case_missing_target()
    case_json_contract()
    case_repo_baseline()
    case_causal_external()
    case_causal_duplicate()

    failed = [n for n, ok, _ in _results if not ok]
    print("-" * 66)
    print("  合计 %d 用例，通过 %d，失败 %d" % (len(_results),
                                              len(_results) - len(failed), len(failed)))
    if failed:
        for n in failed:
            print("  [FAIL] %s" % n)
        return 1
    print("  [PASS] 门禁回归 + 变异验证全过")
    return 0


if __name__ == "__main__":
    sys.exit(main())
