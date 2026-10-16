#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""check_cross_bench_manifest.py 的变异自测。

门禁只写测试不证明"真能失败"= 不实自证（AGENTS.md 第四条）。本测试把判据
`manifest_violations()` 直接喂**变异后的输入**，逐条断言必须报红；并含一条
**真实回归用例**：把生成器契约表里的 10733 摘掉（正是本次修的那个真 bug）→ 必红。

用法：python scripts/check_cross_bench_manifest_test.py
"""
from __future__ import annotations

import hashlib
import json
import os
import sys

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import check_cross_bench_manifest as M  # noqa: E402


def sha(s: str) -> str:
    return hashlib.sha256(s.encode("utf-8")).hexdigest()


def mkprob(pid, files, desc="", title="", flag_sha256=""):
    af = []
    for (name, excluded, ak, recovered) in files:
        e = {"name": name, "size": 1, "answer_key_shape": ak, "git_excluded": excluded}
        if recovered:
            e["recovered_from"] = "src"
        af.append(e)
    return {"id": pid, "description": desc, "title": title,
            "flag_sha256": flag_sha256, "attachment_files": af}


def base():
    doc = {"problems": {
        "p1": mkprob("p1", [("a.bin", True, True, False)], desc="普通题面"),
        "p2": mkprob("p2", [("b.py", False, False, False)], desc="另一题"),
    }}
    gi = ["p1/a.bin"]
    gen_ex = {"p1/a.bin"}
    gen_rec = set()
    pinned = {"p1/a.bin": "测试钉"}
    return doc, gi, gen_ex, gen_rec, pinned


CASES = []


def case(name, fn):
    CASES.append((name, fn))


def _run(doc, gi, gen_ex, gen_rec, pinned, min_problems=2):
    return M.manifest_violations(doc, gi, gen_ex, gen_rec, pinned, min_problems)


case("基线：合法输入 → 无违规", lambda: _run(*base()) == [])


def c1_short():
    doc, gi, ge, gr, pin = base()
    return any("C1 题数" in v for v in _run(doc, gi, ge, gr, pin, min_problems=3))


case("变异 C1：题数 < 基线 → 红", c1_short)


def c1_empty_att():
    doc, gi, ge, gr, pin = base()
    for p in doc["problems"].values():
        p["attachment_files"] = []
    return any("C1 附件清单为空" in v for v in _run(doc, [], set(), set(), {}))


case("变异 C1：附件清单为空（零覆盖）→ 红", c1_empty_att)


def c1_empty_excl():
    doc = {"problems": {"p1": mkprob("p1", [("a.bin", False, False, False)])}}
    return any("C1 git 排除集为空" in v for v in _run(doc, [], set(), set(), {}, 1))


case("变异 C1：排除集为空 → 红", c1_empty_excl)


def c2_missing():
    doc, gi, ge, gr, pin = base()
    return any("C2" in v for v in _run(doc, [], ge, gr, pin))


case("变异 C2：.gitignore 少一条 → 红", c2_missing)


def c2_extra():
    doc, gi, ge, gr, pin = base()
    return any("C2" in v for v in _run(doc, gi + ["p9/z"], ge, gr, pin))


case("变异 C2：.gitignore 多一条 → 红", c2_extra)


def c2_absent():
    doc, gi, ge, gr, pin = base()
    return any("C2" in v or "缺失" in v for v in _run(doc, None, ge, gr, pin))


case("变异 C2：.gitignore 缺失 → 红", c2_absent)


def c3_gen_forgot():
    """核心回归：生成器契约表漏了某个排除条目（本次真 bug 的形态）。"""
    doc, gi, ge, gr, pin = base()
    return any("C3" in v for v in _run(doc, gi, set(), gr, pin))


case("变异 C3：生成器漏登记排除条目（真 bug 形态）→ 红", c3_gen_forgot)


def c3_gen_extra():
    doc, gi, ge, gr, pin = base()
    return any("C3" in v for v in _run(doc, gi, ge | {"p9/z"}, gr, pin))


case("变异 C3：生成器多登记 → 红", c3_gen_extra)


def c4_ak_not_excluded():
    """答案形态文件没排除 → 会被 git 提交进 PUBLIC 仓。"""
    doc, gi, ge, gr, pin = base()
    doc["problems"]["p2"]["attachment_files"][0]["answer_key_shape"] = True
    return any("C4" in v for v in _run(doc, gi, ge, gr, pin))


case("变异 C4：答案形态但未排除 → 红", c4_ak_not_excluded)


def c5_recovered():
    doc, gi, ge, gr, pin = base()
    doc["problems"]["p1"]["attachment_files"][0]["recovered_from"] = "src"
    return any("C5" in v for v in _run(doc, gi, ge, gr, pin))


case("变异 C5：产物的 recovered_from 未在生成器登记 → 红", c5_recovered)


def c6_plaintext():
    """题面含真 flag（sha256 相等）→ 报红。"""
    flag = "flag{this_is_the_real_answer}"
    doc = {"problems": {
        "p1": mkprob("p1", [("a.bin", True, True, False)],
                     desc="由 writeup 可知真 flag 为 %s。" % flag,
                     flag_sha256=sha(flag)),
    }}
    return any("C6 题面即答案" in v for v in _run(doc, ["p1/a.bin"], {"p1/a.bin"}, set(), {"p1/a.bin": "x"}, 1))


case("变异 C6：题面含 flag 明文（sha256 命中）→ 红", c6_plaintext)


def c6_known_input_ok():
    """合法已知输入（sha256 不等）不得误伤。"""
    doc = {"problems": {
        "p1": mkprob("p1", [("a.bin", True, True, False)],
                     desc="给定已知明文 CRC32{deadbeef} 求碰撞。",
                     flag_sha256=sha("dasctf{something_else}")),
    }}
    return _run(doc, ["p1/a.bin"], {"p1/a.bin"}, set(), {"p1/a.bin": "x"}, 1) == []


case("反例 C6：题面里的已知输入（sha256 不等）不误伤 → 绿", c6_known_input_ok)


def c6_title():
    flag = "dasctf{title_leak_case}"
    doc = {"problems": {
        "p1": mkprob("p1", [("a.bin", True, True, False)],
                     title="真值 %s" % flag, flag_sha256=sha(flag)),
    }}
    return any("C6 题面即答案" in v for v in _run(doc, ["p1/a.bin"], {"p1/a.bin"}, set(), {"p1/a.bin": "x"}, 1))


case("变异 C6：泄漏藏在 title → 红", c6_title)


def c6_sanitizer_identity():
    """遮蔽器对已提交（已遮蔽）数据必须是恒等变换。"""
    flag = "d0g3{abcdef123456}"
    masked = "真 flag d0g3{****}。"
    doc = {"problems": {
        "p1": mkprob("p1", [("a.bin", True, True, False)],
                     desc=masked, flag_sha256=sha(flag)),
    }}
    good = _run(doc, ["p1/a.bin"], {"p1/a.bin"}, set(), {"p1/a.bin": "x"}, 1)
    doc["problems"]["p1"]["description"] = masked + " 另见 %s" % flag
    bad = _run(doc, ["p1/a.bin"], {"p1/a.bin"}, set(), {"p1/a.bin": "x"}, 1)
    return good == [] and len(bad) > 0


case("C6：已遮蔽题面恒等（绿）／未遮蔽（红）", c6_sanitizer_identity)


def c8_pin_broken():
    doc, gi, ge, gr, pin = base()
    ghost = dict(pin)
    ghost["p9/ghost.bin"] = "幽灵钉"
    return any("C8" in v for v in _run(doc, gi, ge, gr, ghost))


case("变异 C8：红线钉指向未排除文件 → 红", c8_pin_broken)


def c8_consistent_removal():
    """三方**一致地**把红线文件摘掉：C2/C3/C4 都不响，只有 C8 能拦住。"""
    doc = {"problems": {"p1": mkprob("p1", [("a.bin", False, False, False)])}}
    v = _run(doc, [], set(), set(), {"p1/a.bin": "红线"})
    return any("C8" in x for x in v)


case("变异 C8：一致地摘除红线文件（一致性判据拦不住）→ 红", c8_consistent_removal)


def real_regression():
    """真实回归：把生成器契约表里的 10733 摘掉（真 bug 形态）→ 必红。"""
    root = os.path.join(os.path.dirname(os.path.abspath(__file__)), "..")
    cb = os.path.join(root, "data", "questions_real_bench", "cross_bench.json")
    gi_path = os.path.join(root, "data", "questions_real_bench", "attachments", ".gitignore")
    if not os.path.exists(cb) or not os.path.exists(gi_path):
        print("   (跳过：真实产物不在本机)")
        return True
    with open(cb, encoding="utf-8") as fh:
        doc = json.load(fh)
    gi = [ln.strip() for ln in open(gi_path, encoding="utf-8").read().splitlines()
          if ln.strip() and not ln.startswith("#")]
    full_ex = {"%s/%s" % (pid, f["name"])
               for pid, p in doc["problems"].items()
               for f in (p.get("attachment_files") or []) if f.get("git_excluded")}
    ok = M.manifest_violations(doc, gi, full_ex,
                               {"10733/task.py"}, M.PINNED_REDLINE) == []
    broken = M.manifest_violations(doc, gi, full_ex - {"10733/task.py"},
                                   {"10733/task.py"}, M.PINNED_REDLINE)
    return ok and any("C3" in v for v in broken)


case("真实回归：生成器漏 10733（真 bug）→ 红；修好后 → 绿", real_regression)


def main() -> int:
    print("=" * 64)
    print("  check_cross_bench_manifest 变异自测（%d 例）" % len(CASES))
    print("=" * 64)
    failed = 0
    for name, fn in CASES:
        try:
            ok = bool(fn())
        except Exception as e:  # noqa: BLE001
            ok = False
            print("   ❌ %s —— 抛异常 %r" % (name, e))
            failed += 1
            continue
        print(("   ✅ " if ok else "   ❌ ") + name)
        if not ok:
            failed += 1
    if failed:
        print("🔴 %d/%d 例失败" % (failed, len(CASES)))
        return 1
    print("✅ %d/%d 例全部通过" % (len(CASES), len(CASES)))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
