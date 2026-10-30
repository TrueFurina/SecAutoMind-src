#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""race_triage_test.py —— race_triage.py 的回归测试。

判据（每条都必须能独立失败）：
  T1  「已答出66次，…当前分值482.54」→ (66, 482.54)
  T2  取不到解出数时返回 None，**不许静默当 0**（当成 0 会把它排到最前，正好反了）
  T3  三种输入形态（YCB 字典 / CTF² items / 裸列表）都能归一化
  T4  unsolved 口径：0 队解出的排最前
  T5  同解出数时，有直连靶机的排前（能立刻打）
  T6  static 口径：无靶机的排前（容器题排后）
  T7  解出数未知的排最后，且建议列标「解出数未知」而不是「优先」
  T8  Markdown 含全部列名与汇总行
  T9  变异验证：把排序反过来，T4 必须失败（证明 T4 不是恒绿）

用法：python scripts/race_triage_test.py     # 0=全过，1=有失败
"""
from __future__ import annotations

import sys

sys.path.insert(0, "scripts")
import race_triage as R  # noqa: E402

passed = 0
failed = 0


def ok(name: str) -> None:
    global passed
    passed += 1
    print(f"  [PASS] {name}")


def bad(name: str, detail: str = "") -> None:
    global failed
    failed += 1
    print(f"  [FAIL] {name}{('：' + detail) if detail else ''}")


# ── T1 ──────────────────────────────────────────────────────────────────────
n = R.parse_solved_count("已答出66次，初始分值500.0，当前分值482.54，解出分值482.0")
s = R.parse_current_score("已答出66次，初始分值500.0，当前分值482.54，解出分值482.0")
if (n, s) == (66, 482.54):
    ok("T1 解析「已答出66次 / 当前分值482.54」")
else:
    bad("T1 解析错误", f"got {(n, s)}")

# ── T2 ──────────────────────────────────────────────────────────────────────
if R.parse_solved_count("无法解析的文本") is None and R.parse_solved_count("") is None:
    ok("T2 取不到解出数返回 None（不静默当 0）")
else:
    bad("T2 解析失败时返回了数字", "会被误排到最前")

# ── T3 三种输入形态 ─────────────────────────────────────────────────────────
ycb = {"12061": {"code": "00000", "data": {
    "id": 12061, "name": "pdfchallenge",
    "score": "已答出0次，初始分值500.0，当前分值500.0，解出分值500.0",
    "hasSolved": False, "attachment": {"name": "a.zip"},
    "endpoints": [{"exposeIps": ["1.2.3.4:8080"], "status": "running"}]}}}
ctf2 = {"data": {"items": [
    {"id": "u1", "title": "GraphNexus", "category": "WEB", "score": 370.5,
     "solved_count": 178, "hasSolved": True}]}}
plain = [{"id": 7, "name": "Jammed", "points": 500, "solved": 84, "endpoints": []}]

a, b, c = R.normalize(ycb), R.normalize(ctf2), R.normalize(plain)
if (len(a), len(b), len(c)) == (1, 1, 1) and a[0]["title"] == "pdfchallenge" \
        and b[0]["title"] == "GraphNexus" and c[0]["title"] == "Jammed":
    ok("T3 三种输入形态均可归一化")
else:
    bad("T3 归一化失败", f"{len(a)}/{len(b)}/{len(c)}")

if a[0]["solved_count"] == 0 and a[0]["has_target"] and a[0]["addrs"] == ["1.2.3.4:8080"]:
    ok("T3b YCB 形态：解出数/直连靶机/地址都正确")
else:
    bad("T3b YCB 字段抽取错误", str(a[0]))

# ── T4 unsolved：0 队优先 ───────────────────────────────────────────────────
def mk(cid, solved, target=False, score=500.0, title=None):
    return {"id": cid, "title": title or f"t{cid}", "category": "X", "score": score,
            "solved_count": solved, "has_target": target,
            "addrs": ["1.1.1.1:1"] if target else [], "attachment": "",
            "solved_by_me": False}


sample = [mk("A", 178), mk("B", 0), mk("C", 66), mk("D", 1)]
order = [c["id"] for c in R.rank(sample, "unsolved")]
if order == ["B", "D", "C", "A"]:
    ok("T4 unsolved 口径：0 队解出的排最前")
else:
    bad("T4 排序错误", str(order))

# ── T5 同解出数：有直连靶机优先 ─────────────────────────────────────────────
tie = [mk("noT", 0, target=False), mk("hasT", 0, target=True)]
order = [c["id"] for c in R.rank(tie, "unsolved")]
if order == ["hasT", "noT"]:
    ok("T5 同解出数时，有直连靶机的排前")
else:
    bad("T5 并列排序错误", str(order))

# ── T6 static：无靶机优先 ───────────────────────────────────────────────────
st = [mk("hasT", 0, target=True), mk("noT", 5, target=False)]
order = [c["id"] for c in R.rank(st, "static")]
if order == ["noT", "hasT"]:
    ok("T6 static 口径：无靶机的排前（容器题排后）")
else:
    bad("T6 static 排序错误", str(order))

# ── T7 解出数未知：排最后且不标优先 ─────────────────────────────────────────
unk = [mk("unk", None), mk("zero", 0)]
order = [c["id"] for c in R.rank(unk, "unsolved")]
adv = R.advice(mk("unk", None))
if order == ["zero", "unk"] and adv == "解出数未知":
    ok("T7 解出数未知的排最后，且建议列不标「优先」")
else:
    bad("T7 未知解出数处理错误", f"order={order} advice={adv}")

# ── T8 Markdown 列名与汇总 ──────────────────────────────────────────────────
md = R.render_markdown(R.rank(sample, "unsolved"), "unsolved")
need = ["# 开赛分诊表", "| # | id | 题名 | 分类 | 当前分值 | 已解出 | 直连靶机 | 附件 | 建议 |",
        "0 队解出"]
if all(k in md for k in need):
    ok("T8 Markdown 含全部列名与汇总行")
else:
    bad("T8 Markdown 缺列", str([k for k in need if k not in md]))

# ── T9 变异验证：反序后 T4 必须失败 ─────────────────────────────────────────
mut = sorted(sample, key=R._sort_key("unsolved"), reverse=True)
if [c["id"] for c in mut] != ["B", "D", "C", "A"]:
    ok("T9 变异验证：反序排序会破坏 T4 断言（T4 非恒绿）")
else:
    bad("T9 变异未生效", "T4 可能是恒绿的")

# ── T12 靶机探活：关闭端口必须判死 ─────────────────────────────────────────
# 2026-10-31 演练暴露：题目 JSON 里 12061 标着 status=running，实际 HTTP 000 早死。
# 只看 JSON 会把人往死靶机上送。
if R.probe_target("127.0.0.1:1", timeout=0.5) is False:
    ok("T12 关闭端口探活 → False")
else:
    bad("T12 关闭端口被判活")

# ── T13 靶机探活：活着的端口必须判活（真起一个本地监听）────────────────────
import socket  # noqa: E402
import threading  # noqa: E402

_srv = socket.socket()
_srv.bind(("127.0.0.1", 0))
_srv.listen(1)
_live_port = _srv.getsockname()[1]
threading.Thread(target=lambda: _srv.accept(), daemon=True).start()
try:
    if R.probe_target("127.0.0.1:%d" % _live_port, timeout=1.0) is True:
        ok("T13 活跃端口探活 → True")
    else:
        bad("T13 活跃端口被判死")
finally:
    _srv.close()

# ── T14 死靶机在同解出数时排到活靶机之后 ───────────────────────────────────
dead = mk("dead", 0, target=True)
dead["target_alive"] = False
live = mk("live", 0, target=True)
live["target_alive"] = True
order = [c["id"] for c in R.rank([dead, live], "unsolved")]
if order == ["live", "dead"]:
    ok("T14 死靶机排到活靶机之后（不把人往死靶机上送）")
else:
    bad("T14 死靶机未被降权", str(order))

# ── T15 建议列必须明说「靶机死」 ───────────────────────────────────────────
if "靶机死" in R.advice(dead):
    ok("T15 建议列标明「靶机死·需重建」")
else:
    bad("T15 死靶机仍显示为可打", R.advice(dead))

# ── T16 汇总统计死靶机数 ───────────────────────────────────────────────────
if R.summary([dead, live, mk("static", 3)])["dead_target"] == 1:
    ok("T16 汇总统计靶机已死数量")
else:
    bad("T16 汇总未统计死靶机")

print("-" * 60)
if failed == 0:
    print(f"结论：PASS —— {passed} 项全过（含 1 项变异验证）")
    sys.exit(0)
print(f"结论：FAIL —— {failed} 项未过")
sys.exit(1)
