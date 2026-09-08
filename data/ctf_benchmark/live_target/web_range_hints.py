#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
SecAutoMind 真题形态靶场（Hint Range）——复刻「静态集里打不中的 Web 题」的真实端点形态。

与 web_range.py 的区别（也是本靶场存在的理由）：
  web_range.py 的端点（/ssti /page /cmd /fetch /login）恰好落在引擎的硬编码
  探测列表里；而真实 CTF 的端点千奇百怪——/cmd.php、/index.php?page=、
  /profile?name=、/fetch.php?url=、/api/auth。本靶场刻意使用**不在硬编码列表里**
  的端点与参数名，只有「读题取线索 → 定向打」才能命中。

场景描述直接取自 data/ctf_benchmark/real_benchmark.json 里那 36 道打不中的真题
（如 buuctf_rce_basic「GET /cmd.php?ip=127.0.0.1;cat /flag」），不编造。

诚实铁律：
  1. flag 只在利用成功后返回，未利用成功绝不泄漏。
  2. 只监听 127.0.0.1。
  3. --dump-json 只输出 flag_sha256，不明文落答案。

用法： python web_range_hints.py [port] [--dump-json]
"""
import hashlib
import json
import re
import sys
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from urllib.parse import urlparse, parse_qs

SCENES = {
    # 真题: buuctf_rce_basic —— GET /cmd.php?ip=127.0.0.1;cat /flag
    "hint_cmdi": ("flag{h1nt_cmdd_1nj3ct_php}",
                  "GET /cmd.php?ip=127.0.0.1;cat /flag 命令注入读取 flag"),
    # 真题: buuctf_lfi_basic —— GET /index.php?page=../../../../etc/passwd
    "hint_lfi": ("flag{h1nt_lf1_1nd3x_php}",
                 "GET /index.php?page=../../../../etc/passwd 本地文件包含"),
    # 真题: buuctf_ssrf_basic —— GET /fetch?url=http://127.0.0.1:8080/admin
    "hint_ssrf": ("flag{h1nt_ssrf_f3tch_php}",
                  "GET /fetch.php?url=http://127.0.0.1:8080/internal/admin 服务端请求伪造"),
    # 真题: buuctf_sqli_basic —— POST /login user=admin' OR 1=1--&pass=x
    "hint_sqli": ("flag{h1nt_sql1_l0g1n_php}",
                  "POST /login.php user=admin' OR 1=1--&pass=x SQL 注入绕过登录"),
    # 真题: pico2025_echo_valley —— SSTI：输入 {{7*7}} 返回 49
    "hint_ssti": ("flag{h1nt_sst1_pr0f1l3}",
                  "SSTI 模板注入：输入 {{7*7}} 返回 49（参数名 name）"),
    # 真题: pico2024_no_sql_injection —— MongoDB 运算符注入
    "hint_nosql": ("flag{h1nt_n0sql_4uth_4p1}",
                   'MongoDB NoSQL 注入：{"user":{"$ne":""},"pass":{"$ne":""}} 打到 /api/auth'),
}

PORT = int(sys.argv[1]) if len(sys.argv) > 1 and sys.argv[1].isdigit() else 18099

FLAG_TXT = "flag{h1nt_lf1_1nd3x_php}"
PASSWD_TXT = "root:x:0:0:root:/root:/bin/bash\n"


def b64(s):
    import base64
    return base64.b64encode(s.encode()).decode()


class Range(BaseHTTPRequestHandler):
    # 重要：用 HTTP/1.0 + 读超时。Go net/http 与 urllib 都会复用/保持连接，
    # 若用 HTTP/1.1 且不设 timeout，服务线程会一直挂在 readline 上等下一个请求，
    # 几百个请求后靶场就不再应答（实测跑两轮即 alive=0，机验假失败）。
    protocol_version = "HTTP/1.0"
    timeout = 5

    def log_message(self, *a):
        pass

    def _send(self, code, body, ctype="text/html; charset=utf-8", extra=None):
        if isinstance(body, str):
            body = body.encode()
        self.send_response(code)
        self.send_header("Content-Type", ctype)
        self.send_header("Content-Length", str(len(body)))
        for k, v in (extra or {}).items():
            self.send_header(k, v)
        self.end_headers()
        self.wfile.write(body)

    def _q(self, name, default=""):
        qs = parse_qs(urlparse(self.path).query)
        return qs.get(name, [default])[0]

    def do_GET(self):
        p = urlparse(self.path).path
        if p == "/":
            return self._send(200, "<h1>Challenge Platform</h1><a href='/cmd.php'>ping</a>"
                                   " <a href='/profile'>profile</a> <a href='/index.php'>home</a>")
        if p == "/cmd.php":
            ip = self._q("ip")
            if re.search(r"[;&|`$]", ip):
                return self._send(200, f"<pre>PING {ip}\n{SCENES['hint_cmdi'][0]}</pre>")
            return self._send(200, f"<pre>PING {ip or '127.0.0.1'}</pre>")
        if p == "/index.php":
            page = self._q("page", "home")
            if "flag" in page:
                return self._send(200, f"<pre>{FLAG_TXT}</pre>")
            if "passwd" in page:
                return self._send(200, f"<pre>{PASSWD_TXT}</pre>")
            return self._send(200, f"<h1>Home</h1><p>page={page}</p>")
        if p == "/fetch.php":
            u = self._q("url")
            if "internal/admin" in u or "/admin" in u:
                return self._send(200, f"<pre>INTERNAL ADMIN PANEL\n{SCENES['hint_ssrf'][0]}</pre>")
            return self._send(200, f"<pre>fetched: {u}</pre>")
        if p == "/profile":
            name = self._q("name", "guest")
            if "{{" in name:
                if "flag()" in name or "config" in name or "popen" in name:
                    return self._send(200, f"<h1>Hello {SCENES['hint_ssti'][0]}</h1>")
                # 模拟模板执行：{{7*7}} -> 49
                expr = re.search(r"\{\{(.*?)\}\}", name)
                if expr:
                    try:
                        val = eval(expr.group(1), {"__builtins__": {}}, {})
                        return self._send(200, f"<h1>Hello {val}</h1>")
                    except Exception:
                        return self._send(200, "<h1>Hello </h1>")
            return self._send(200, f"<h1>Hello {name}</h1>")
        if p == "/internal/admin":
            return self._send(200, f"<pre>INTERNAL ADMIN PANEL\n{SCENES['hint_ssrf'][0]}</pre>")
        return self._send(404, "not found")

    def do_POST(self):
        p = urlparse(self.path).path
        length = int(self.headers.get("Content-Length") or 0)
        raw = self.rfile.read(length).decode("utf-8", "replace") if length else ""
        if p == "/login.php":
            form = dict(kv.split("=", 1) for kv in raw.split("&") if "=" in kv)
            from urllib.parse import unquote_plus
            form = {k: unquote_plus(v) for k, v in form.items()}
            vals = " ".join(form.values())
            if re.search(r"(?i)(or\s+1=1|'\s*or\s*'|or\s+'1'='1|--\s*$)", vals):
                return self._send(200, f"<h2>Welcome admin</h2><p>{SCENES['hint_sqli'][0]}</p>")
            return self._send(200, "<h2>Login failed</h2>")
        if p == "/api/auth":
            try:
                doc = json.loads(raw)
            except Exception:
                doc = {}
            if "$ne" in raw or "$gt" in raw or "$regex" in raw:
                return self._send(200, json.dumps({"ok": True, "flag": SCENES["hint_nosql"][0]}),
                                  "application/json")
            return self._send(200, json.dumps({"ok": False, "user": doc.get("user", "")}),
                              "application/json")
        return self._send(404, "not found")


if __name__ == "__main__":
    if "--dump-json" in sys.argv:
        doc = {
            "version": "web-hint-range-1.0",
            "note": "真题形态靶场：端点/参数名刻意不在引擎硬编码探测列表里，"
                    "只有『读题取线索 → 定向打』才能命中。description 取自 real_benchmark.json "
                    "里那批打不中的真题，只落 flag 的 SHA-256。",
            "problems": {
                k: {"flag_sha256": hashlib.sha256(v[0].encode()).hexdigest(),
                    "description": v[1]}
                for k, v in SCENES.items()
            },
        }
        print(json.dumps(doc, ensure_ascii=False, indent=2))
        sys.exit(0)
    srv = ThreadingHTTPServer(("127.0.0.1", PORT), Range)
    print(f"hint range listening on 127.0.0.1:{PORT}", flush=True)
    srv.serve_forever()
