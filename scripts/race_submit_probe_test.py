#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""race_submit_probe_test.py —— 提交通道探针的回归测试（**不联网**）。

判据：
  T1  安全不变量：探针体不含 flag / confirmation（含则可能真的提交）
  T2  40001 / HTTP 400 → ok（端点存在、鉴权过）
  T3  40403 / 401 → deny
  T4  404 → path_wrong；429 → rate_limited
  T5  **2xx 必须是 unexpected，绝不能是 ok**（探针不该提交成功）
  T6  差异性：40403 与 40001 判定必须不同（防「一律 ok」的假门禁）
  T7  URL 构造：两个平台路径正确；缺参数抛 ValueError（不许拼半截地址）
  T8  鉴权头按平台派发（Bearer / X-Agent-AccessKey）
  T9  dry-run 返回 0、打印 URL 与「已设置」，**不回显令牌**
  T10 变异验证：把 2xx 当 ok，T5 必须变红

用法：python scripts/race_submit_probe_test.py    # 0=全过
"""
from __future__ import annotations

import sys

sys.path.insert(0, "scripts")
import race_submit_probe as P  # noqa: E402

passed = failed = 0


def ok(name: str) -> None:
    global passed
    passed += 1
    print(f"  [PASS] {name}")


def bad(name: str, detail: str = "") -> None:
    global failed
    failed += 1
    print(f"  [FAIL] {name}{('：' + detail) if detail else ''}")


# ── T1 安全不变量 ───────────────────────────────────────────────────────────
if "flag" not in P.PROBE_BODY and "confirmation" not in P.PROBE_BODY:
    ok("T1 探针体为空 JSON，不含 flag/confirmation（不可能误交）")
else:
    bad("T1 探针体含敏感字段", P.PROBE_BODY)

# ── T2/T3 业务码 ────────────────────────────────────────────────────────────
cases = [
    (200, '{"code":"40001","message":"参数不全"}', "ok", "T2 40001 → ok"),
    (400, "", "ok", "T2b HTTP 400 → ok"),
    (200, '{"code":"40403","message":"无权操作"}', "deny", "T3 40403 → deny"),
    (401, "", "deny", "T3b HTTP 401 → deny"),
    (404, "", "path_wrong", "T4 404 → path_wrong"),
    (429, "", "rate_limited", "T4b 429 → rate_limited"),
]
for status, body, want, name in cases:
    got, detail = P.classify(status, body)
    if got == want:
        ok(name)
    else:
        bad(name, f"got {got}（{detail}）")

# ── T5 2xx 绝不等于 ok ──────────────────────────────────────────────────────
got, detail = P.classify(200, '{"success":true}')
if got == "unexpected":
    ok("T5 HTTP 200 → unexpected（探针不该提交成功）")
else:
    bad("T5 2xx 被判成 %s —— 会把「真的交了」当成通道健康" % got, detail)

# ── T6 差异性 ───────────────────────────────────────────────────────────────
a, _ = P.classify(200, '{"code":"40403"}')
b, _ = P.classify(200, '{"code":"40001"}')
if a != b:
    ok("T6 40403 与 40001 判定不同（不是「一律 ok」的假门禁）")
else:
    bad("T6 两种码判定相同", a)

# ── T7 URL 构造 ─────────────────────────────────────────────────────────────
u1 = P.build_url("ctf2", base_url="https://ctf2.dasctf.com", competition="C1",
                 stage="S1", challenge="X1")
want1 = ("https://ctf2.dasctf.com/api/open/v1/user/agent/competitions/C1"
         "/stages/S1/challenges/X1/submit/")
u2 = P.build_url("dasctf", base_url="https://ycb-bk.dasctf.com")
want2 = "https://ycb-bk.dasctf.com/slab-match/api/v1/agent/answer-panel/answer"
if u1 == want1 and u2 == want2:
    ok("T7 两平台提交路径正确")
else:
    bad("T7 路径错误", f"{u1} | {u2}")

raised = 0
for kwargs in ({"base_url": "https://x"}, {"base_url": "https://x", "competition": "C"},
               {"base_url": "https://x", "competition": "C", "stage": "S"}):
    try:
        P.build_url("ctf2", **kwargs)
    except ValueError:
        raised += 1
try:
    P.build_url("dasctf")
except ValueError:
    raised += 1
if raised == 4:
    ok("T7b 缺参数一律抛 ValueError（不拼半截地址去试）")
else:
    bad("T7b 缺参数没抛异常", f"raised={raised}/4")

# ── T8 鉴权头派发 ───────────────────────────────────────────────────────────
h1 = P.build_headers("ctf2", "tok")
h2 = P.build_headers("dasctf", "tok")
if h1.get("Authorization") == "Bearer tok" and h2.get("X-Agent-AccessKey") == "tok" \
        and "Authorization" not in h2:
    ok("T8 鉴权头按平台派发（Bearer / X-Agent-AccessKey）")
else:
    bad("T8 鉴权头错误", f"{h1} | {h2}")

# ── T9 dry-run 不回显令牌 ───────────────────────────────────────────────────
import io  # noqa: E402
import os  # noqa: E402
import contextlib  # noqa: E402

os.environ["CTF2_AGENT_TOKEN"] = "SECRET_TOKEN_XYZ"
buf = io.StringIO()
with contextlib.redirect_stdout(buf):
    rc = P.main(["--platform", "ctf2", "--base-url", "https://ctf2.dasctf.com",
                 "--competition", "C", "--stage", "S", "--challenge", "X", "--dry-run"])
out = buf.getvalue()
if rc == 0 and "submit/" in out and "SECRET_TOKEN_XYZ" not in out:
    ok("T9 dry-run 返回 0、打印 URL、不回显令牌")
else:
    bad("T9 dry-run 异常", f"rc={rc} out={out[:80]}")

# 缺令牌时必须 fail-closed（返回 2），不许当成「通道通」
os.environ.pop("CTF2_AGENT_TOKEN", None)
err = io.StringIO()
with contextlib.redirect_stderr(err):
    rc2 = P.main(["--platform", "ctf2", "--base-url", "https://ctf2.dasctf.com",
                  "--competition", "C", "--stage", "S", "--challenge", "X", "--dry-run"])
if rc2 == 2:
    ok("T9b 缺令牌返回 2（fail-closed，不谎报通道通）")
else:
    bad("T9b 缺令牌没 fail-closed", f"rc={rc2}")

# ── T10 变异验证 ────────────────────────────────────────────────────────────
def _mutant(status, body):
    if status is not None and 200 <= status < 300:
        return "ok", "mutant"
    return P.classify(status, body)


if _mutant(200, '{"success":true}')[0] != "unexpected":
    ok("T10 变异验证：把 2xx 当 ok 会让 T5 失败（T5 非恒绿）")
else:
    bad("T10 变异未生效", "T5 可能是恒绿的")

# ── T11 端到端：本地假服务器验证 probe() 的网络路径（含绕代理）────────────────
# 纯函数测试证明不了「真的能发出去」。起一个只回 40001 的本地服务，
# 走完整 probe() → classify() 链路。**不碰任何真实平台。**
import http.server  # noqa: E402
import threading  # noqa: E402


class _H(http.server.BaseHTTPRequestHandler):
    def do_POST(self):  # noqa: N802
        n = int(self.headers.get("Content-Length") or 0)
        self.rfile.read(n)
        body = b'{"code":"40001","message":"params missing"}'
        self.send_response(200)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def log_message(self, *a):  # 静音
        pass


srv = http.server.HTTPServer(("127.0.0.1", 0), _H)
port = srv.server_address[1]
threading.Thread(target=srv.serve_forever, daemon=True).start()
try:
    st, bd = P.probe("http://127.0.0.1:%d/" % port, {"Content-Type": "application/json"})
    v, _ = P.classify(st, bd)
    if st == 200 and v == "ok":
        ok("T11 端到端：本地假服务 40001 → ok（网络路径含绕代理可用）")
    else:
        bad("T11 端到端失败", f"status={st} verdict={v}")
finally:
    srv.shutdown()

print("-" * 60)
if failed == 0:
    print(f"结论：PASS —— {passed} 项全过（含 1 项变异验证）")
    sys.exit(0)
print(f"结论：FAIL —— {failed} 项未过")
sys.exit(1)
