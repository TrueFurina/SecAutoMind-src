#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""``check_benchmark_parity.py`` 的回归与**变异**用例。

项目铁律：门禁必须自证有判别力（AGENTS.md 第四条）。本组用例专门证明判据
**两端都灵**——既能报红每一种漂移，也不会对干净数据恒红：

- 正向控制：三路一致 ⇒ **必须 0 违规**（若这条红，说明门禁恒红，比没有门禁更坏）
- 报红（六向）：镜像超前 / 镜像滞后 / 注册表漏题 / 注册表多题 / 空集 / id 越界 / 地板退化
- 解析器：真命中行收得进、MISS 行与汇总行不得误收
- fail-closed：前置条件（基准/基线）缺失时，``--check`` 必须 BLOCK；报数模式不判定

判据与主流程共用同一份纯函数（``compare_hits`` / ``parse_go_hits``），
避免「自测过的是另一份判据」这种自欺。
"""
from __future__ import annotations

import os
import sys
import tempfile

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import check_benchmark_parity as gate  # noqa: E402

_pass = fail = 0


def case(name, ok, detail=""):
    global _pass, fail
    if ok:
        _pass += 1
        print("  ✅ %s" % name)
    else:
        fail += 1
        print("  ❌ %s  %s" % (name, detail))


BENCH = {"a", "b", "c", "d"}
BASE = {"a", "b", "c"}


def viol(shipped=BASE, registry=BASE, py=BASE, bench=None, floor=2):
    return gate.compare_hits(shipped, registry, py, bench if bench is not None else BENCH, floor)


def joined(vs):
    return "\n".join(vs)


print("=== 1) 正向控制：干净数据必须判绿（防门禁恒红）===")
v = viol()
case("三路完全一致 → 0 违规", v == [], "得到 %r" % (v,))
case("三路一致时不得出现任何『注水/滞后/漏题』字样",
     not any(k in joined(v) for k in ("注水", "滞后", "漏掉", "人工裁决")), joined(v))

print()
print("=== 2) 报红：Python 镜像超前（注水方向）===")
v = viol(py=BASE | {"d"})
case("镜像多解出一题 → 报红且定性为『注水方向』",
     any("注水方向" in x and "d" in x for x in v), joined(v))

print()
print("=== 3) 报红：Python 镜像滞后 ===")
v = viol(shipped=BASE | {"d"})
case("镜像少一题 → 报红且定性为『滞后』",
     any("滞后" in x and "d" in x for x in v), joined(v))

print()
print("=== 4) 报红：注册表路径漏掉生产能解的题（R ⊉ S）===")
v = viol(registry=BASE - {"c"})
case("注册表少一题 → 报红且定性为『漏掉』",
     any("漏掉" in x and "c" in x for x in v), joined(v))

print()
print("=== 5) 报红：注册表解出生产解不出的题（须人工裁决）===")
v = viol(registry=BASE | {"d"})
case("注册表多一题 → 报红且定性为『人工裁决』",
     any("人工裁决" in x for x in v), joined(v))

print()
print("=== 6) fail-closed：任一路为空必须报红（同型空洞绿）===")
for label, kw in (("shipped 空", dict(shipped=set())),
                  ("registry 空", dict(registry=set())),
                  ("python 空", dict(py=set()))):
    v = viol(**kw)
    case("%s → 报红且提及『空洞绿』" % label,
         any("空洞绿" in x for x in v), joined(v))

print()
print("=== 7) 报红：命中 id 越界（解析串味 / 基准被换）===")
v = viol(py=BASE | {"ghost_id"})
case("越界 id 计入 → 报红（此处 py 也含越界项）",
     any("不在 real_benchmark.json" in x for x in v), joined(v))
# 三路同时含越界 id：集合仍"一致"，但必须因越界而红 —— 证明一致性判据不是唯一防线
v = viol(shipped=BASE | {"ghost_id"}, registry=BASE | {"ghost_id"}, py=BASE | {"ghost_id"})
case("三路一致但都含越界 id → 仍须报红（一致性 ≠ 合法）",
     any("不在 real_benchmark.json" in x for x in v), joined(v))

print()
print("=== 8) 报红：低于基线地板（能力退化）===")
v = viol(shipped={"a", "b"}, registry={"a", "b"}, py={"a", "b"}, floor=3)
case("命中 2 < 地板 3 → 报红且提及『退化』",
     any("退化" in x for x in v), joined(v))
v = viol(shipped={"a", "b", "c"}, registry={"a", "b", "c"}, py={"a", "b", "c"}, floor=3)
case("命中 3 == 地板 3 → 不报地板违规（边界不恒真）",
     not any("退化" in x for x in v), joined(v))

print()
print("=== 9) 解析器：真命中行收得进、MISS/汇总行不得误收 ===")
sample = """
    presolve_benchmark_test.go:84: ✅ base64_triple_real engine=base64_multilayer
    presolve_benchmark_test.go:84: ✅ ehaxctf2025_morse engine=morse_decode
    presolve_benchmark_test.go:106: ❌ MISS some_unsolved_id
    presolve_benchmark_test.go:109: === 注册表路径 PresolveWithRegistry 真题覆盖率: 20/55 = 36.4% (MISS 35) ===
"""
got = gate.parse_go_hits(sample)
case("抽到 2 条命中且 id 正确",
     got == {"base64_triple_real", "ehaxctf2025_morse"}, "得到 %r" % (got,))
case("❌ MISS 行不被计入", "some_unsolved_id" not in got, "得到 %r" % (got,))
case("汇总覆盖率行不被误收（无 engine= 后缀）", len(got) == 2, "得到 %r" % (got,))
case("空输入 → 空集合（不炸）", gate.parse_go_hits("") == set())
case("None 输入 → 空集合（不炸）", gate.parse_go_hits(None) == set())

print()
print("=== 10) fail-closed：前置条件缺失时 --check 必须 BLOCK ===")


def run_main(argv):
    old = sys.argv
    sys.argv = ["check_benchmark_parity.py"] + argv
    try:
        return gate.main()
    finally:
        sys.argv = old


old_bench = gate.BENCH_PATH
try:
    gate.BENCH_PATH = os.path.join(tempfile.gettempdir(), "definitely_missing_bench_xyz.json")
    rc_check = run_main(["--check"])
    case("基准缺失 + --check → rc=1（fail-closed）", rc_check == 1, "rc=%r" % rc_check)
    rc_report = run_main([])
    case("基准缺失 + 报数模式 → rc=0（不判定）", rc_report == 0, "rc=%r" % rc_report)
finally:
    gate.BENCH_PATH = old_bench

print()
print("结果：%d 通过，%d 失败" % (_pass, fail))
sys.exit(1 if fail else 0)
