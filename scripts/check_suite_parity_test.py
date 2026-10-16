#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""``check_suite_parity.py`` 的回归与**变异**用例。

项目铁律：门禁必须自证有判别力（AGENTS.md 第四条）。本组证明判据两端都灵：

- 正向控制：台账与汇总一致、wired 集两侧集合一致且非空 ⇒ **必须 0 违规**（防门禁恒红）
- 报红：台账漏登记 / 悬空条目 / id 有洞 / wired 缺判据（哑门禁）/
        Python 超前（注水）/ Go 超前（宣称不成立）/ 任一侧空集
- 解析器：真命中行收得进；MISS 行、汇总行、💧 注水行不得误收
- 覆盖度真值自证：读**真实** run_all_benchmarks.py 与 parity_registry.json，
  断言二者一致（防止有人加了集却忘了登记台账）

判据与主流程共用同一份纯函数（``parse_hits`` / ``coverage_violations`` /
``compare_suite`` / ``wired_spec_violations``），避免「自测过的是另一份判据」。
"""
from __future__ import annotations

import os
import sys

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import check_suite_parity as gate  # noqa: E402

_p = _f = 0


def case(name, ok, detail=""):
    global _p, _f
    if ok:
        _p += 1
        print("  ✅ %s" % name)
    else:
        _f += 1
        print("  ❌ %s  %s" % (name, detail))


def joined(vs):
    return "\n".join(vs)


print("=== 1) 正向控制：干净台账 + 一致集合 ⇒ 必须 0 违规（防恒红）===")
ids = {1, 2, 3}
case("台账覆盖汇总且 id 连续 → 0 违规",
     gate.coverage_violations(ids, ids) == [],
     joined(gate.coverage_violations(ids, ids)))
case("两侧集合一致且非空 → 0 违规",
     gate.compare_suite("x", {"a", "b"}, {"a", "b"}) == [],
     joined(gate.compare_suite("x", {"a", "b"}, {"a", "b"})))
case("wired 集带全判据 → 0 违规",
     gate.wired_spec_violations([{"id": 14, "key": "ecdsa", "parity": "wired",
                                  "wired_by": "scripts/check_suite_parity.py",
                                  "go_tests": ["T"], "python_hit_re": "p", "go_hit_re": "g"}]) == [],
     "本应为空")

print()
print("=== 2) 覆盖度自证报红（漏登记=零覆盖也可能显 PASS）===")
v = gate.coverage_violations({1, 2}, {1, 2, 3})
case("汇总有【3】台账没登记 → 报红且点名漏登记",
     any("漏登记" in x and "3" in x for x in v), joined(v))
v = gate.coverage_violations({1, 2, 3}, {1, 2})
case("台账登记了汇总外的集 → 报红『悬空条目』",
     any("悬空" in x and "3" in x for x in v), joined(v))
v = gate.coverage_violations({1, 2, 3}, set())
case("解析不出任何【N】（判据退化为恒真）→ 报红",
     any("自证失败" in x or "恒真" in x for x in v), joined(v))
v = gate.coverage_violations({1, 3}, {1, 3})
case("id 有洞（缺 2）→ 报红『拓扑漂移』",
     any("不连续" in x and "2" in x for x in v), joined(v))

print()
print("=== 3) 哑门禁报红：wired 却无判据 ===")
v = gate.wired_spec_violations([{"id": 14, "key": "ecdsa", "parity": "wired"}])
case("wired 集缺 go_tests/regex → 报红『哑门禁』",
     any("哑门禁" in x for x in v), joined(v))
v = gate.wired_spec_violations([{"id": 1, "key": "static", "parity": "wired",
                                 "wired_by": "scripts/check_benchmark_parity.py"}])
case("静态集（由独立脚本负责）不应被误判为哑门禁",
     v == [], joined(v))

print()
print("=== 4) 集合不一致报红（双向定性）===")
v = gate.compare_suite("x", {"a", "b"}, {"a"})
case("Python 超前 → 报红且定性『注水方向』",
     any("注水方向" in x and "b" in x for x in v), joined(v))
v = gate.compare_suite("x", {"a"}, {"a", "b"})
case("Go 超前 → 报红且定性『宣称不成立』",
     any("宣称不成立" in x and "b" in x for x in v), joined(v))

print()
print("=== 5) 空集 fail-closed（0 命中 ⇒ 无差异 ⇒ 恒绿）===")
v = gate.compare_suite("x", set(), {"a"})
case("Python 侧空 → 报红『空洞绿风险』",
     any("空洞绿风险" in x for x in v), joined(v))
v = gate.compare_suite("x", {"a"}, set())
case("Go 侧空 → 报红『空洞绿风险』（不许因两侧都空而判绿）",
     any("空洞绿风险" in x for x in v), joined(v))

print()
print("=== 6) 解析器：真命中行收得进，噪声行不得误收 ===")
py_out = "ecdsa_nonce_reuse_01   HIT\nECDSA nonce reuse 基准（Python 侧独立复刻）: 1/1\n"
case("Python 逐题命中行 → 收得进",
     gate.parse_hits(py_out, "^\\s*(\\S+)\\s+HIT\\b") == {"ecdsa_nonce_reuse_01"},
     str(gate.parse_hits(py_out, "^\\s*(\\S+)\\s+HIT\\b")))
py_out2 = "cbc_padding_oracle_basic HIT   (候选 1)\nfoo MISS\n"
case("padding_oracle 命中行收得进、MISS 行不得误收",
     gate.parse_hits(py_out2, "^\\s*(\\S+)\\s+HIT\\b") == {"cbc_padding_oracle_basic"},
     str(gate.parse_hits(py_out2, "^\\s*(\\S+)\\s+HIT\\b")))
go_out = ("    ecdsa_nonce_reuse_test.go:109: ✅ HIT  ecdsa_nonce_reuse_01\n"
          "    ecdsa_nonce_reuse_test.go:114: === ECDSA nonce 复用基准 (Go 侧): 1/1 ===\n")
case("Go 命中行收得进；汇总行不得误收",
     gate.parse_hits(go_out, "✅\\s+HIT\\s+(\\S+)") == {"ecdsa_nonce_reuse_01"},
     str(gate.parse_hits(go_out, "✅\\s+HIT\\s+(\\S+)")))
go_miss = "    padding_oracle_test.go:93: ❌ MISS cbc_padding_oracle_basic\n"
case("Go MISS 行不得被当成命中",
     gate.parse_hits(go_miss, "✅\\s+HIT\\s+(\\S+)") == set(),
     str(gate.parse_hits(go_miss, "✅\\s+HIT\\s+(\\S+)")))

print()
print("=== 7) 覆盖度真值自证：真实台账 vs 真实汇总必须一致 ===")
try:
    reg = gate.load_registry()
    reg_ids = {s["id"] for s in reg.get("suites", []) if isinstance(s.get("id"), int)}
    summ = gate.summary_ids()
    v = gate.coverage_violations(reg_ids, summ)
    case("真实 parity_registry.json 覆盖 run_all_benchmarks.py 全部【N】集",
         v == [], joined(v))
    case("真实台账 id 连续且非空", reg_ids == set(range(1, len(reg_ids) + 1)), str(sorted(reg_ids)))
except Exception as e:  # noqa: BLE001
    case("真实台账/汇总可读", False, repr(e))

print()
print("=" * 56)
print("结果：%d 通过 / %d 失败" % (_p, _f))
sys.exit(1 if _f else 0)
