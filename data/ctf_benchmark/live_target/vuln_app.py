#!/usr/bin/env python3
"""
本地漏洞靶机（纯 stdlib，无外部依赖）——用于执行基准集真实利用演示。

两个故意脆弱的端点，模拟真实 CTF Web 题：
  POST /login        SQL 注入登录绕过（' OR '1'='1 类 payload 触发 flag）
  GET  /ssti?name=   服务端模板注入（沙箱算术引擎，{{flag()}} 触发 flag）

仅用于本地基准测试，不对外暴露。
运行：python vuln_app.py [port]
"""
import sys
import json
from http.server import BaseHTTPRequestHandler, HTTPServer
from urllib.parse import urlparse, parse_qs

FLAG_SQLI = "flag{l1v3_sqli_byp4ss_rce_demo}"
FLAG_SSTI = "flag{l1v3_sst1_t3mplat3_1nj3ct10n}"


class Handler(BaseHTTPRequestHandler):
    def log_message(self, *a):
        pass  # 静默

    def _send(self, code, body: str):
        self.send_response(code)
        self.send_header("Content-Type", "text/html; charset=utf-8")
        self.end_headers()
        self.wfile.write(body.encode("utf-8"))

    def do_GET(self):
        u = urlparse(self.path)
        if u.path == "/ssti":
            qs = parse_qs(u.query)
            name = qs.get("name", [""])[0]
            self._send(200, render_ssti(name))
        else:
            self._send(404, "not found")

    def do_POST(self):
        u = urlparse(self.path)
        length = int(self.headers.get("Content-Length", 0))
        body = self.rfile.read(length).decode("utf-8", "ignore")
        qs = parse_qs(body)
        if u.path == "/login":
            user = qs.get("user", [""])[0]
            pwd = qs.get("pass", [""])[0]
            self._send(200, render_login(user, pwd))
        else:
            self._send(404, "not found")


def render_login(user: str, pwd: str) -> str:
    """脆弱登录：把输入拼进"SQL"做字符串包含判断（模拟 OR 绕过）。"""
    query = "SELECT * FROM users WHERE user='%s' AND pass='%s'" % (user, pwd)
    # 注入判定：若 user 中包含 OR 绕过片段，视为认证成功
    if "' OR '" in user or "admin' --" in user or "' OR '1'='1" in user or " OR 1=1" in user:
        return "Welcome admin! flag=%s<br>query=%s" % (FLAG_SQLI, query)
    return "Login failed<br>query=%s" % query


def render_ssti(name: str) -> str:
    """沙箱 SSTI 引擎：仅支持 {{a*b}} 算术与魔法 {{flag()}}。"""
    import re
    def repl(m):
        expr = m.group(1)
        if expr.strip() == "flag()":
            return FLAG_SSTI
        mm = re.fullmatch(r"\s*(\d+)\s*\*\s*(\d+)\s*", expr)
        if mm:
            return str(int(mm.group(1)) * int(mm.group(2)))
        return m.group(0)
    return re.sub(r"\{\{(.+?)\}\}", repl, name)


def main():
    port = int(sys.argv[1]) if len(sys.argv) > 1 else 18099
    srv = HTTPServer(("127.0.0.1", port), Handler)
    print("vuln_app listening on http://127.0.0.1:%d" % port)
    srv.serve_forever()


if __name__ == "__main__":
    main()
