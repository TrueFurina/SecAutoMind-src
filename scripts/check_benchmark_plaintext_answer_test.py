#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""``check_benchmark_plaintext_answer.py`` 的自测与变异用例。

项目铁律：门禁必须自证有判别力。本组用例专门证明判据**两端都灵**：

- 正向：干净基准 PASS、报数模式恒 rc=0
- 报红：已登记集超标、未登记集带明文、覆盖度不足
- **防误伤**（本门禁最关键的一组）：题面 flag 是"已知输入"而非答案时，
  sha256 与 flag_sha256 不等 ⇒ **不得**计入。初版扫描时 crc32 / lcg / ecdsa
  三集就是这样被我误判的，这三个用例锁死该行为。
"""
from __future__ import annotations

import hashlib
import json
import os
import shutil
import subprocess
import sys
import tempfile

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import check_benchmark_plaintext_answer as gate  # noqa: E402

HERE = os.path.dirname(os.path.abspath(__file__))
SCRIPT = os.path.join(HERE, "check_benchmark_plaintext_answer.py")

_pass = fail = 0


def case(name, ok, detail=""):
    global _pass, fail
    if ok:
        _pass += 1
        print("  ✅ %s" % name)
    else:
        fail += 1
        print("  ❌ %s  %s" % (name, detail))


def sha(s):
    return hashlib.sha256(s.encode("utf-8")).hexdigest()


def make_bench(tmp, fname, problems):
    d = os.path.join(tmp, "data", "ctf_benchmark")
    os.makedirs(d, exist_ok=True)
    with open(os.path.join(d, fname), "w", encoding="utf-8") as f:
        json.dump({"problems": problems}, f, ensure_ascii=False)
    return tmp


def fill(tmp, n_sets):
    """补足到若干集，避免覆盖度断言意外触发（隔离被测维度）。"""
    d = os.path.join(tmp, "data", "ctf_benchmark")
    os.makedirs(d, exist_ok=True)
    for i in range(n_sets):
        with open(os.path.join(d, "pad%d_benchmark.json" % i), "w", encoding="utf-8") as f:
            json.dump({"problems": {
                "p%d_%d" % (i, j): {"description": "正常题面，无明文", "flag_sha256": sha("x%d%d" % (i, j))}
                for j in range(10)
            }}, f, ensure_ascii=False)


print("=== check_benchmark_plaintext_answer 自测 ===")
print()

# ---- 判据单测：answer_is_in_statement ----
print("[判据单测]")

leak, plain = gate.answer_is_in_statement(
    {"description": "POST /login.php user=admin flag{ZZ_synthetic_sqli_probe_0001} UNION",
     "flag_sha256": sha("flag{ZZ_synthetic_sqli_probe_0001}")})
case("答案写在题面 → 判为漏水", leak and plain == "flag{ZZ_synthetic_sqli_probe_0001}", str(plain))

leak, _ = gate.answer_is_in_statement(
    {"description": "给定原文 flag{admin_forge}，伪造其 CRC32 碰撞",
     "flag_sha256": sha("flag{another_value}")})
case("flag 是已知输入（sha256 不等）→ 不判漏水【防误伤，关键】", not leak)

leak, _ = gate.answer_is_in_statement({"description": "flag{abc}", "flag_sha256": None})
case("无 flag_sha256 → 不判漏水（无法裁定，不误伤）", not leak)

# ---- 变异用例：门禁整体 ----
print()
print("[变异用例]")

# 1 干净基准（全部无题面即答案）
tmp = tempfile.mkdtemp()
try:
    fill(tmp, 22)
    res = gate.analyze(tmp)
    bad = gate.violations(res)
    case("干净基准 → 零违规（判据不恒红）", not bad, str(bad[:1]))
finally:
    shutil.rmtree(tmp, ignore_errors=True)

# 2 已登记集超标：构造 16 题（基线 15）
tmp = tempfile.mkdtemp()
try:
    probs = {}
    for i in range(16):
        flag = "flag{leak_%d}" % i
        probs["leak_%d" % i] = {"description": "题面直接给答案 " + flag,
                                "flag_sha256": sha(flag)}
    make_bench(tmp, "benchmark.json", probs)
    fill(tmp, 22)
    bad = gate.violations(gate.analyze(tmp))
    case("已登记集 16 > 基线 15 → 报红", any("benchmark.json" in b and "超标" not in b for b in bad)
         or any("benchmark.json" in b for b in bad), str(bad[:1]))
finally:
    shutil.rmtree(tmp, ignore_errors=True)

# 3 未登记集出现 1 题（基线按 0）
tmp = tempfile.mkdtemp()
try:
    flag = "flag{new_set_leak}"
    make_bench(tmp, "brand_new_benchmark.json",
               {"n1": {"description": "答案在题面 " + flag, "flag_sha256": sha(flag)}})
    fill(tmp, 22)
    bad = gate.violations(gate.analyze(tmp))
    case("未登记集带明文 → 报红（防新增集注水）",
         any("brand_new_benchmark.json" in b for b in bad), str(bad[:1]))
finally:
    shutil.rmtree(tmp, ignore_errors=True)

# 4 覆盖度不足（只扫 1 集 → 判据会恒真）
tmp = tempfile.mkdtemp()
try:
    make_bench(tmp, "only_benchmark.json", {"a": {"description": "干净", "flag_sha256": sha("a")}})
    bad = gate.violations(gate.analyze(tmp))
    case("覆盖度不足（1 集）→ 报红（fail-closed，防扫 0 全绿）",
         any("覆盖度" in b for b in bad), str(bad[:1]))
finally:
    shutil.rmtree(tmp, ignore_errors=True)

# 5 全集的 flag 都是输入 → 不得报红
tmp = tempfile.mkdtemp()
try:
    make_bench(tmp, "crc32_benchmark.json", {
        "c1": {"description": "给定 flag{admin_forge} 伪造 CRC32", "flag_sha256": sha("flag{real_answer_1}")},
        "c2": {"description": "给定 flag{firmware} 伪造 CRC32", "flag_sha256": sha("flag{real_answer_2}")},
    })
    fill(tmp, 22)
    res = gate.analyze(tmp)
    crc = [r for r in res if r["file"] == "crc32_benchmark.json"]
    bad = gate.violations(res)
    case("CRC32 式『明文是输入』→ 计数 0 且不报红【防误伤，关键】",
         crc and crc[0]["plaintext_answer"] == 0 and not any("crc32" in b for b in bad),
         str(crc[:1]) + " bad=" + str(bad[:1]))
finally:
    shutil.rmtree(tmp, ignore_errors=True)

# 6 混合：同集内既有真漏水又有输入型明文，只数真漏水
tmp = tempfile.mkdtemp()
try:
    real = "flag{real_leak}"
    make_bench(tmp, "mixed_benchmark.json", {
        "m1": {"description": "答案在题面 " + real, "flag_sha256": sha(real)},
        "m2": {"description": "输入型 flag{input_only}", "flag_sha256": sha("flag{other}")},
    })
    fill(tmp, 22)
    res = gate.analyze(tmp)
    mixed = [r for r in res if r["file"] == "mixed_benchmark.json"][0]
    case("混合集只数真漏水（1 而非 2）", mixed["plaintext_answer"] == 1, str(mixed))
finally:
    shutil.rmtree(tmp, ignore_errors=True)

# 7 报数模式恒 rc=0（确认 --check 才是判定入口）
rc = subprocess.call([sys.executable, SCRIPT],
                     stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
case("报数模式 rc=0（--check 才是判定入口）", rc == 0, "rc=%d" % rc)

# ---- 第二判据：题面自然语言自曝答案（2026-11-06 第四个假绿）----
# 该假绿的形态：真值登记为 sha256(裸内容)，题面写「writeup 明确给出 X」，
# 旧判据只扫 word{} token 且 candidate_variants 不去壳 ⇒ plaintext_answer=0。
# 这组用例锁死「新判据命中 + 防误伤 + 门禁对未登记池零容忍」三件事。
print()
print("[第二判据：题面自然语言自曝答案]")

synth = "ZZ_synthetic_bare_answer_0001"
bare_prob = {"description": "writeup 明确给出 %s。flag{端口}。" % synth,
             "flag_sha256": sha(synth)}
case("裸内容真值 + 自然语言自曝 → 命中（旧判据扫不到）",
     gate.self_disclosure_in_statement(bare_prob) is not None
     and not gate.answer_is_in_statement(bare_prob)[0])
case("证据不含明文答案（项目红线）",
     synth not in json.dumps(gate.self_disclosure_in_statement(bare_prob), ensure_ascii=False))
case("题面有同形词但真值不同 → 不命中【防误伤】",
     gate.self_disclosure_in_statement(
         {"description": "writeup 明确给出 %s。" % synth,
          "flag_sha256": sha("flag{totally_different_value}")}) is None)
case("无合法 flag_sha256 → 不裁定",
     gate.self_disclosure_in_statement(
         {"description": "writeup 明确给出 %s。" % synth, "flag_sha256": None}) is None)

tmp = tempfile.mkdtemp()
try:
    make_bench(tmp, "purellm_new_benchmark.json",
               {"n1": {"description": "writeup 明确给出 %s。flag{答案}。" % synth,
                       "flag_sha256": sha(synth)}})
    fill(tmp, 22)
    bad = gate.violations(gate.analyze(tmp))
    case("未登记能力池带自然语言自曝 → 门禁报红（零容忍）",
         any("purellm_new_benchmark.json" in b and "自曝" in b for b in bad), str(bad[:1]))
finally:
    shutil.rmtree(tmp, ignore_errors=True)

# 8 真实仓库当前状态：违规数应与登记基线一致（回归锁定）
# 2026-10-28：基线从 15/4 改为 0/0 —— 题干内嵌的答案已由
# `scripts/redact_prompt_answers.py` 脱敏（real 4 道 / benchmark 15 道）。
# 这里锁 0 是**收紧**而不是放宽：以后谁再往题面里塞答案，这门禁立刻红。
res = gate.analyze(gate.REPO_ROOT)
bad = gate.violations(res)
leaks = {r["file"]: r["plaintext_answer"] for r in res}
case("真实仓库：benchmark.json=0 / real_benchmark.json=0（题干已脱敏）",
     leaks.get("benchmark.json", 0) == 0 and leaks.get("real_benchmark.json", 0) == 0, str(leaks))
case("真实仓库：当前全部在基线内（登记契约成立）", not bad, str(bad[:1]))

print()
print("=== 通过 %d / 失败 %d ===" % (_pass, fail))
sys.exit(1 if fail else 0)
