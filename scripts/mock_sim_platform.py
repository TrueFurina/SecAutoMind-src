#!/usr/bin/env python3
"""mock_sim_platform.py — 官方仿真平台的本地桩 (P0-1 降级链)。

目的：在拿到 Agent Key 之前 / CI 环境 / 断网演练中，
把 `Presolve → 平台 API → 提交 flag` 全链在本地跑通，
证明"拿到 Key 即通"。

端点真值对齐 internal/ctfplatform/dasctf.go（仅实现 mock 需要的形状）：
  前缀 /slab-match/api/v1/agent/
  match-info      GET  match/notice/match-info        -> {code,msg,data:{...}}
  overview        GET  answer-panel/overview          -> {code,msg,data:{...}}
  challenges      GET  ctf/exercise-list              -> {code,msg,data:[...]}
  detail          GET  ctf/exercise?exerciseId=...    -> {code,msg,data:{...,endpoints:[]}}
  build_env       POST ctf/build-exercise-env          -> {code,msg,data:{instance:"10.0.0.1:8080"}}
  recover_env     POST ctf/recover-exercise-env        -> {code,msg,data:{}}
  submit          POST answer-panel/answer             -> {code,msg,data:{isCorrect:true}}

纪律：
  成功判据与生产一致 —— 只认字符串 "00000"（不认 int 0，见 dasctf.go codeIsSuccess）。
  本脚本零第三方依赖（纯 stdlib），可直接进 CI。
"""
import argparse
import json
import threading
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from urllib.parse import urlparse, parse_qs

OK = "00000"          # 与真源 dasctf.py:562 / dasctf.go codeIsSuccess 对齐
PREFIX = "/slab-match/api/v1/agent/"
TOKEN_ENV = "MOCK_TOKEN"   # 设为空串表示不校验

CHALLENGES = [
    {"id": "1001", "name": "misc-1", "category": "misc",
     "description": "题目说明：解析附件还原 flag{mock_example_2026}",
     "attachments": [], "isNeedInit": False, "endpoints": []},
    {"id": "1002", "name": "pwn-instance", "category": "pwn",
     "description": "实例题示例", "attachments": [],
     "isNeedInit": True, "endpoints": ["tcp://10.0.0.1:9999"]},
]
DETAILS = {
    "1001": {**CHALLENGES[0]},
    "1002": {**CHALLENGES[1]},
}
CORRECT_FLAGS = {"1001": "flag{mock_example_2026}", "1002": "flag{mock_example_2026}"}


def _resp(code, msg, data):
    return {"code": code, "msg": msg, "data": data}


class MockHandler(BaseHTTPRequestHandler):
    server_version = "MockSimPlatform/1.0"
    auth_token = ""      # 空 = 不校验；非空则要求 Authorization/Token 头匹配

    def log_message(self, fmt, *args):  # 静默，保持 CI 输出干净
        pass

    def _authed(self):
        if not self.auth_token:
            return True
        got = (self.headers.get("Authorization") or self.headers.get("Token") or "").strip()
        # 允许 "Bearer xxx" / "xxx" 两种形态
        got = got[7:] if got.lower().startswith("bearer ") else got
        return got == self.auth_token

    def _deny_403(self):
        body = json.dumps(_resp("40403", "无权操作（mock：Agent Key 未开通/令牌不符）", None)).encode()
        self.send_response(403)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def _send_ok(self, data):
        body = json.dumps(_resp(OK, "success", data), ensure_ascii=False).encode()
        self.send_response(200)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def _read_json(self):
        n = int(self.headers.get("Content-Length") or 0)
        if n <= 0:
            return {}
        try:
            return json.loads(self.rfile.read(n) or b"{}")
        except Exception:
            return {}

    def do_GET(self):
        if not self._authed():
            return self._deny_403()
        u = urlparse(self.path)
        q = parse_qs(u.query)
        p = u.path
        if p == PREFIX + "match/notice/match-info":
            return self._send_ok({"match": "MOCK-MATCH", "status": "running", "utc": None})
        if p == PREFIX + "answer-panel/overview":
            return self._send_ok({"solved": 0, "total": len(CHALLENGES), "score": 0})
        if p == PREFIX + "ctf/exercise-list":
            return self._send_ok(CHALLENGES)
        if p == PREFIX + "ctf/exercise":
            cid = (q.get("exerciseId") or [""])[0]
            if cid in DETAILS:
                return self._send_ok(DETAILS[cid])
            return self._send_ok(None)
        if p == PREFIX + "match/notice/now-list":
            return self._send_ok([])
        return self._send_ok(None)

    def do_POST(self):
        if not self._authed():
            return self._deny_403()
        u = urlparse(self.path)
        body = self._read_json()
        p = u.path
        if p == PREFIX + "ctf/build-exercise-env":
            cid = str(body.get("exerciseId") or body.get("id") or "1001")
            return self._send_ok({"instance": "10.0.0.1:8080", "exerciseId": cid})
        if p == PREFIX + "ctf/recover-exercise-env":
            return self._send_ok({})
        if p == PREFIX + "answer-panel/answer":
            cid = str(body.get("exerciseId") or body.get("id") or "")
            flag = str(body.get("flag") or body.get("answer") or "")
            ok = CORRECT_FLAGS.get(cid) == flag.strip()
            return self._send_ok({"isCorrect": ok, "exerciseId": cid})
        return self._send_ok(None)


def serve(host="127.0.0.1", port=0, token=""):
    MockHandler.auth_token = token or ""
    srv = ThreadingHTTPServer((host, port), MockHandler)
    t = threading.Thread(target=srv.serve_forever, daemon=True)
    t.start()
    return srv


def main():
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument("--host", default="127.0.0.1")
    ap.add_argument("--port", type=int, default=0, help="0 = 随机端口")
    ap.add_argument("--token", default="", help="非空则校验 Authorization/Token 头")
    a = ap.parse_args()
    srv = serve(a.host, a.port, a.token)
    print("MOCK_SIM_PLATFORM_READY http://%s:%d" % (a.host, srv.server_address[1]), flush=True)
    try:
        srv.serve_forever()
    except KeyboardInterrupt:
        pass


if __name__ == "__main__":
    main()