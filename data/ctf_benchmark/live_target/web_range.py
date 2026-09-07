#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
SecAutoMind Web 靶场（Web Range）——复刻真实 CTF Web 题型的本地脆弱站点。

设计原则（诚实基准集铁律）：
  1. 每个场景对应一类**真实公开 CTF 真题**题型（见 SCENES 注释里的真题对照），
     不是凭空造的假题。
  2. flag 由靶场运行时真实产生（注入成功才返回），未利用成功**绝不会**泄漏。
  3. 仅监听 127.0.0.1，无任何外网依赖。

用法：  python web_range.py [port] [--dump-json]
        --dump-json 仅打印 flag_sha256 词典供基准集生成，不起服务。
"""
import base64
import hashlib
import json
import re
import sys
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from urllib.parse import urlparse, parse_qs

# ---------------------------------------------------------------------------
# 场景 -> flag（与真实题型一一对应；改动这里必须同步重生成 web_benchmark.json）
# ---------------------------------------------------------------------------
SCENES = {
    # 真题对照: picoCTF2024 intro-to-web / findme / not-my-fault —— 查看源码找隐藏注释
    "src_comment": "flag{html_c0mm3nt_h1dd3n}",
    # 真题对照: picoCTF2024 webdecode —— 源码里 base64 字符串解码
    "src_b64": "flag{s0urc3_b64_d3c0d3d}",
    # 真题对照: picoCTF2024 cookie / picoCTF2025 cookie-monster —— Cookie 里藏 flag
    "cookie_flag": "flag{c00k13_m0nst3r_v4lu3}",
    # 真题对照: picoCTF2024 irish-name / BUUCTF sqli-basic —— SQL 注入绕过登录
    "sqli_login": "flag{sql1_4uth_byp4ss}",
    # 真题对照: picoCTF2025 echo-valley / ssti_tpl_inject —— Jinja2 SSTI
    "ssti": "flag{sst1_t3mpl4t3_r3nd3r}",
    # 真题对照: BUUCTF lfi-basic —— 本地文件包含/路径遍历
    "lfi": "flag{lf1_p4th_tr4v3rs4l}",
    # 真题对照: BUUCTF ssrf-basic —— 服务端请求伪造访问内部端点
    "ssrf": "flag{ssrf_1nt3rn4l_4dm1n}",
    # 真题对照: picoCTF2025 handoff —— API 端点未授权访问/IDOR
    "api_idor": "flag{4pl_un4uth0r1z3d_4cc3ss}",
    # 真题对照: BUUCTF rce-basic —— 命令注入
    "cmdi": "flag{c0mm4nd_1nj3ct10n_rc3}",
    # 真题对照: picoCTF2024 no-sql-injection —— MongoDB 运算符注入
    "nosql": "flag{n0sql_0p3r4t0r_1nj3ct}",
}

PORT = int(sys.argv[1]) if len(sys.argv) > 1 and sys.argv[1].isdigit() else 18098

SQLI_PAYLOADS = [
    "admin' OR '1'='1", "admin' OR 1=1--", "' OR '1'='1' --",
    "admin'--", "' OR 1=1#", "admin' /*", "' or 'a'='a",
]

# 模拟的后台"数据库"
USER_ROW = {"admin": "s3cr3t-p4ssw0rd-7f3a"}


def b64(s: str) -> str:
    """标准 base64 编码（flag 在靶场里以 b64 形式泄漏，需解码才可见）。"""
    return base64.b64encode(s.encode()).decode()


def page(title: str, body: str) -> bytes:
    return (
        "<!DOCTYPE html><html><head><meta charset='utf-8'><title>%s</title></head>"
        "<body><h1>%s</h1>%s<hr><a href='/'>index</a></body></html>"
        % (title, title, body)
    ).encode("utf-8")


class Range(BaseHTTPRequestHandler):
    protocol_version = "HTTP/1.1"

    def log_message(self, *a):  # 静音
        pass

    # ---------------------------------------------------------------- helpers
    def _send(self, code, body, ctype="text/html; charset=utf-8", extra=None):
        self.send_response(code)
        self.send_header("Content-Type", ctype)
        self.send_header("Content-Length", str(len(body)))
        for k, v in (extra or {}).items():
            self.send_header(k, v)
        self.end_headers()
        self.wfile.write(body)

    def _q(self, key, default=""):
        return parse_qs(urlparse(self.path).query).get(key, [default])[0]

    def _json_body(self):
        n = int(self.headers.get("Content-Length") or 0)
        if not n:
            return {}
        try:
            return json.loads(self.rfile.read(n).decode("utf-8", "ignore"))
        except Exception:
            return {}

    # ------------------------------------------------------------------ GET
    def do_GET(self):
        path = urlparse(self.path).path
        route = {
            "/": self.r_index,
            "/source": self.r_source,
            "/b64": self.r_b64,
            "/cookie": self.r_cookie,
            "/ssti": self.r_ssti,
            "/page": self.r_lfi,
            "/fetch": self.r_ssrf,
            "/api/v1/secret": self.r_api,
            "/admin": self.r_admin,
            "/cmd": self.r_cmdi,
        }.get(path)
        if route:
            route()
        else:
            self._send(404, page("404", "<p>not found</p>"))

    # ----------------------------------------------------------------- POST
    def do_POST(self):
        path = urlparse(self.path).path
        length = int(self.headers.get("Content-Length") or 0)
        raw = self.rfile.read(length).decode("utf-8", "ignore") if length else ""
        if path == "/login":
            self.r_login(raw)
        elif path == "/nosql":
            self.r_nosql(raw)
        else:
            self._send(404, page("404", "<p>not found</p>"))

    # ---------------------------------------------------------------- scenes
    def r_index(self):
        links = "".join(
            "<li><a href='%s'>%s</a></li>" % (u, n)
            for n, u in [
                ("source", "/source"), ("b64", "/b64"), ("cookie", "/cookie"),
                ("login", "/login"), ("ssti", "/ssti"), ("page", "/page"),
                ("fetch", "/fetch"), ("api", "/api/v1/secret"), ("cmd", "/cmd"),
                ("nosql", "/nosql"),
            ]
        )
        self._send(200, page("Web Range", "<ul>%s</ul>" % links))

    def r_source(self):
        # 真题形态：flag 藏在 HTML 注释里
        self._send(200, page(
            "Intro",
            "<p>Welcome to my first webpage!</p>"
            "<!-- TODO: remove before prod. secret = %s -->"
            "<input type='hidden' name='debug' value='0'>"
            % SCENES["src_comment"],
        ))

    def r_b64(self):
        # 真题形态：源码里一段 base64，解码即 flag
        self._send(200, page(
            "Encoded",
            "<p>Here is some data:</p>"
            "<div id='data' style='display:none'>%s</div>"
            % b64(SCENES["src_b64"]),
        ))

    def r_cookie(self):
        # 真题形态：Set-Cookie 里 base64 编码的 flag
        self._send(200, page("Cookies", "<p>Cookie set. Enjoy.</p>"),
                   extra={"Set-Cookie": "secret=%s; Path=/" % b64(SCENES["cookie_flag"])})

    def r_login(self, raw=""):
        params = {}
        if raw:
            if raw.strip().startswith("{"):
                try:
                    params = json.loads(raw)
                except Exception:
                    params = {}
            else:
                params = {k: v[0] for k, v in parse_qs(raw).items()}
        user = str(params.get("user", self._q("user", "")))
        pwd = str(params.get("pass", params.get("password", self._q("pass", ""))))
        # 脆弱的拼接式"查询"
        injected = any(p in user for p in ["'", '"', " OR ", " or ", "--", "#"])
        if injected:
            self._send(200, page("Welcome admin",
                                 "<p>Logged in as <b>admin</b>.</p><p>%s</p>" % SCENES["sqli_login"]))
        elif user == "admin" and pwd == USER_ROW["admin"]:
            self._send(200, page("Welcome", "<p>Logged in. Nothing here.</p>"))
        else:
            self._send(401, page("Login", "<p>Invalid credentials.</p>"
                                          "<form method='post'><input name='user'><input name='pass'></form>"))

    def r_ssti(self):
        name = self._q("name", "guest")
        # 极简 Jinja2 语义模拟：支持 {{a*b}} 与 {{flag()}}
        m = re.findall(r"\{\{(.*?)\}\}", name)
        out = []
        for expr in m:
            e = expr.strip()
            if e == "flag()":
                out.append(SCENES["ssti"])
            elif re.fullmatch(r"\d+\s*\*\s*\d+", e):
                a, b = re.split(r"\s*\*\s*", e)
                out.append(str(int(a) * int(b)))
            elif re.fullmatch(r"\d+\s*\+\s*\d+", e):
                a, b = re.split(r"\s*\+\s*", e)
                out.append(str(int(a) + int(b)))
            else:
                out.append("")
        if out:
            self._send(200, page("Echo", "<p>Hello %s</p>" % "".join(out)))
        else:
            self._send(200, page("Echo", "<p>Hello %s</p>" % name))

    def r_lfi(self):
        f = self._q("file", "home.txt")
        # 路径遍历 / 直接读 flag 文件
        if "flag" in f or "../" in f or "etc/passwd" in f:
            body = "root:x:0:0:root:/root:/bin/bash\n" + SCENES["lfi"] + "\n"
            self._send(200, body.encode(), ctype="text/plain; charset=utf-8")
        else:
            self._send(200, b"Welcome to the home page.", ctype="text/plain; charset=utf-8")

    def r_ssrf(self):
        u = self._q("url", "")
        # 只有访问内部 /admin 才拿到 flag（外部不可达）
        if "/admin" in u and ("127.0.0.1" in u or "localhost" in u):
            self._send(200, page("Fetch result", "<pre>ADMIN PANEL: %s</pre>" % SCENES["ssrf"]))
        else:
            self._send(200, page("Fetch result", "<pre>could not fetch: %s</pre>" % u))

    def r_admin(self):
        # 直接访问会被"鉴权"拦截，只有经 SSRF 内部回环才可达（模拟内网边界）
        if self.headers.get("Host", "").startswith("127.0.0.1") and \
           self.headers.get("X-Internal") == "1":
            self._send(200, page("Admin", "<pre>%s</pre>" % SCENES["ssrf"]))
        else:
            self._send(403, page("Forbidden", "<p>external access denied</p>"))

    def r_api(self):
        # 未授权 API：无需任何凭据即返回敏感数据
        self._send(200, json.dumps(
            {"ok": True, "secret": SCENES["api_idor"], "note": "internal only"}
        ).encode(), ctype="application/json")

    def r_cmdi(self):
        ip = self._q("ip", "127.0.0.1")
        # 命令注入：分隔符存在即"执行"后续命令
        if any(sep in ip for sep in [";", "|", "&&", "$(", "`"]):
            body = "PING 127.0.0.1\n" + SCENES["cmdi"] + "\n"
            self._send(200, body.encode(), ctype="text/plain; charset=utf-8")
        else:
            self._send(200, b"PONG 127.0.0.1", ctype="text/plain; charset=utf-8")

    def r_nosql(self, raw=""):
        # 注意：do_POST 已消费过 body，这里必须复用传入的 raw，
        # 不可再调 _json_body()（会在已读完的 rfile 上阻塞到超时）。
        data = {}
        if raw:
            try:
                data = json.loads(raw)
            except Exception:
                data = {}
        s = json.dumps(data, ensure_ascii=False)
        # MongoDB 运算符注入 / 空对象绕过
        if "$ne" in s or "$gt" in s or "$regex" in s or s.strip() in ('{"": ""}', "{}"):
            self._send(200, json.dumps(
                {"ok": True, "user": "admin", "token": SCENES["nosql"]}
            ).encode(), ctype="application/json")
        else:
            self._send(401, json.dumps({"ok": False, "msg": "bad credentials"}).encode(),
                       ctype="application/json")


def dump_json():
    out = {"problems": {
        k: {"category": "web", "flag_sha256": hashlib.sha256(v.encode()).hexdigest()}
        for k, v in SCENES.items()
    }}
    print(json.dumps(out, ensure_ascii=False, indent=2))


if __name__ == "__main__":
    if "--dump-json" in sys.argv:
        dump_json()
        sys.exit(0)
    srv = ThreadingHTTPServer(("127.0.0.1", PORT), Range)
    srv.serve_forever()
