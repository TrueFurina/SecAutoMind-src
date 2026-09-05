#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
SecAutoMind 评测靶场 · 自建可复现三场景（零第三方依赖）

用途：为作品报告第四章「实测验证」提供**完全授权、可一键重建、可任意次重复**的靶场环境。

设计原则（对应赛题 XH-202609 评分要求）：
  - 可复现：单文件、零依赖、固定端口、固定真值，任何人可一键重建
  - 多场景：Web 综合 / API·云 / 主机服务，覆盖赛题"渗透测试、应急响应、漏洞挖掘"场景
  - 可判分：每场景自带 ground_truth，漏洞与指纹的"预期答案"明确，可自动计算准确率
  - 安全合规：仅监听 127.0.0.1；目录遍历限制在虚拟根目录内，不触碰真实系统文件

启动：
    python scripts/experiments/target_range.py            # 起全部三场景
    python scripts/experiments/target_range.py --only s1  # 只起 S1
    python scripts/experiments/target_range.py --truth    # 只打印真值清单（不启动）

场景与端口：
    S1 Web 综合靶场    http://127.0.0.1:8501
    S2 API/云场景靶场  http://127.0.0.1:8502
    S3 主机服务靶场    tcp://127.0.0.1:8503(SSH) 8504(FTP) 8505(Redis)
"""

from __future__ import annotations

import argparse
import json
import os
import socket
import threading
import time
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from urllib.parse import urlparse, parse_qs, unquote

HOST = "127.0.0.1"
PORT_S1 = 8501
PORT_S2 = 8502
PORT_S3_SSH, PORT_S3_FTP, PORT_S3_REDIS = 8503, 8504, 8505

# ── 虚拟文件系统根目录（目录遍历靶场的沙箱，绝不越界到真实系统）──
_SANDBOX = os.path.join(os.path.dirname(os.path.abspath(__file__)), "_range_data")
os.makedirs(os.path.join(_SANDBOX, "private"), exist_ok=True)
with open(os.path.join(_SANDBOX, "private", "db_credentials.txt"), "w", encoding="utf-8") as f:
    f.write("[db]\nhost=127.0.0.1\nuser=secautomind_demo\npassword=Demo_Only_Fake_Pass_123\n")
with open(os.path.join(_SANDBOX, "notes.txt"), "w", encoding="utf-8") as f:
    f.write("deployment notes: apache + php backend, admin console at /admin\n")


# ════════════════════════════════════════════════════════════════
# S1 · Web 综合靶场（弱口令 / SQLi / XSS / 目录遍历 / 敏感文件 / 指纹）
# ════════════════════════════════════════════════════════════════
LOGIN_PAGE = """<!DOCTYPE html><html><head><meta charset="utf-8"><title>SecAutoMind Demo Range - Login</title></head>
<body style="font-family:sans-serif;max-width:420px;margin:80px auto">
<h2>Demo Range :: Login</h2>
<form method="POST" action="/login">
  <p>User:<br><input name="username" style="width:100%"></p>
  <p>Pass:<br><input name="password" type="password" style="width:100%"></p>
  <p><input type="submit" value="Login"></p>
</form>
<p><a href="/search">site search</a> | <a href="/robots.txt">robots</a></p>
<hr><small>Powered by SecAutoMind Demo Range</small>
</body></html>"""

# 注意：页面内含 CSS 百分比（width:70%），用 % 格式化会把 "70%" 误判为格式符而抛
# ValueError，因此统一用占位符 + replace 注入。
SEARCH_PAGE = """<!DOCTYPE html><html><head><meta charset="utf-8"><title>Search</title></head>
<body style="font-family:sans-serif;max-width:600px;margin:60px auto">
<h2>Site Search</h2><form method="GET" action="/search">
<input name="q" style="width:70%"><input type="submit" value="Search"></form>
<div id="result">__RESULT__</div></body></html>"""

ADMIN_PAGE = """<!DOCTYPE html><html><head><meta charset="utf-8"><title>Admin Console</title></head>
<body style="font-family:sans-serif;max-width:600px;margin:60px auto">
<h2>Admin Console (demo)</h2><p>Backup archive: <a href="/backup.tar.gz">backup.tar.gz</a></p>
</body></html>"""

ROBOTS = "User-agent: *\nDisallow: /admin\nDisallow: /private\nDisallow: /.git\n"
GIT_CONFIG = '[core]\n\trepositoryformatversion = 0\n[remote "origin"]\n\turl = http://demo.local/range.git\n'


class S1Handler(BaseHTTPRequestHandler):
    protocol_version = "HTTP/1.1"
    # 抑制 Python 默认 Server 头，确保指纹真实（BaseHTTPRequestHandler 会在 send_response 里
    # 自动追加 Server/Date，若不禁掉会发出 "BaseHTTP/0.6 Python/x.y" 污染指纹识别实验）
    server_version = "Apache/2.4.41"
    sys_version = "(Ubuntu)"

    def log_message(self, *a):  # 静音访问日志，避免污染实验输出
        pass

    def _send(self, body: str, code: int = 200, ctype: str = "text/html; charset=utf-8",
              extra: dict | None = None):
        raw = body.encode("utf-8")
        self.send_response(code)
        self.send_header("Content-Type", ctype)
        self.send_header("Content-Length", str(len(raw)))
        # 指纹：故意泄露技术栈，供"环境识别准确率"判分
        self.send_header("X-Powered-By", "PHP/7.4.33")
        for k, v in (extra or {}).items():
            self.send_header(k, v)
        self.end_headers()
        self.wfile.write(raw)

    def do_GET(self):
        u = urlparse(self.path)
        p, q = u.path, parse_qs(u.query)

        if p in ("/", "/index.php", "/login.php"):
            return self._send(LOGIN_PAGE)
        if p == "/robots.txt":
            return self._send(ROBOTS, ctype="text/plain; charset=utf-8")
        if p == "/.git/config":
            return self._send(GIT_CONFIG, ctype="text/plain; charset=utf-8")
        if p == "/admin" or p == "/admin/":
            return self._send(ADMIN_PAGE)
        if p == "/search":
            term = q.get("q", [""])[0]
            # 反射型 XSS：原样回显，不做转义
            shown = f"You searched for: {term}" if term else ""
            return self._send(SEARCH_PAGE.replace("__RESULT__", shown))
        if p == "/file":
            # 目录遍历：限制在 _SANDBOX 内，绝不越界
            name = unquote(q.get("name", [""])[0])
            target = os.path.normpath(os.path.join(_SANDBOX, name))
            if not target.startswith(os.path.abspath(_SANDBOX)):
                return self._send("403 forbidden", 403, "text/plain; charset=utf-8")
            if os.path.isfile(target):
                with open(target, "r", encoding="utf-8", errors="replace") as f:
                    return self._send(f.read(), ctype="text/plain; charset=utf-8")
            return self._send("404 not found", 404, "text/plain; charset=utf-8")
        if p == "/backup.tar.gz":
            return self._send("not a real archive (demo)", 200, "application/octet-stream")
        return self._send("404 Not Found", 404, "text/plain; charset=utf-8")

    def do_POST(self):
        if urlparse(self.path).path == "/login":
            ln = int(self.headers.get("Content-Length") or 0)
            body = self.rfile.read(ln).decode("utf-8", "replace")
            f = parse_qs(body)
            user = f.get("username", [""])[0]
            pw = f.get("password", [""])[0]
            # 弱口令 + SQL 注入双入口（真值清单里两条都算预期漏洞）
            ok = (user == "admin" and pw == "admin") or ("' or '1'='1" in (user + pw).lower())
            if ok:
                return self._send("<h2>Welcome, admin</h2><p>flag_range_login_ok</p>",
                                  extra={"Set-Cookie": "session=demo_session_admin"})
            return self._send("<h2>Login failed</h2><a href='/'>back</a>")
        return self._send("404 Not Found", 404, "text/plain; charset=utf-8")


# ════════════════════════════════════════════════════════════════
# S2 · API / 云场景靶场（未授权接口 / JWT 弱密钥 / 信息泄露 / 指纹）
# ════════════════════════════════════════════════════════════════
import base64
import hmac
import hashlib


def _b64(d: bytes) -> str:
    return base64.urlsafe_b64encode(d).rstrip(b"=").decode()


def make_jwt(payload: dict, secret: str = "secret") -> str:
    head = _b64(json.dumps({"alg": "HS256", "typ": "JWT"}).encode())
    body = _b64(json.dumps(payload).encode())
    sig = _b64(hmac.new(secret.encode(), f"{head}.{body}".encode(), hashlib.sha256).digest())
    return f"{head}.{body}.{sig}"


API_ROOT = """{"service":"secautomind-demo-api","version":"1.0","endpoints":["/api/v1/users","/api/v1/debug","/metrics"]}"""


class S2Handler(BaseHTTPRequestHandler):
    protocol_version = "HTTP/1.1"
    # 同上：抑制 Python 默认 Server 头，避免指纹污染
    server_version = "nginx/1.18.0"
    sys_version = ""

    def log_message(self, *a):
        pass

    def _send(self, body: str, code: int = 200, ctype: str = "application/json; charset=utf-8",
              extra: dict | None = None):
        raw = body.encode("utf-8")
        self.send_response(code)
        self.send_header("Content-Type", ctype)
        self.send_header("Content-Length", str(len(raw)))
        # 指纹：nginx + .NET 后端特征
        self.send_header("X-AspNet-Version", "4.0.30319")
        for k, v in (extra or {}).items():
            self.send_header(k, v)
        self.end_headers()
        self.wfile.write(raw)

    def do_GET(self):
        p = urlparse(self.path).path
        if p == "/":
            return self._send(API_ROOT)
        if p == "/api/v1/users":
            # 未授权可访问（预期漏洞）
            return self._send(json.dumps({"users": [
                {"id": 1, "name": "alice", "role": "user"},
                {"id": 2, "name": "admin", "role": "admin", "email": "admin@demo.local"}]}))
        if p == "/api/v1/debug":
            # 信息泄露（预期漏洞）
            return self._send(json.dumps({"debug": True, "env": "demo",
                                          "db": "postgres://demo:fakepass@127.0.0.1:5432/demo",
                                          "secret_hint": "jwt signing key is weak"}))
        if p == "/metrics":
            return self._send("http_requests_total 1024\nprocess_resident_memory_bytes 52428800\n",
                              ctype="text/plain; charset=utf-8")
        if p == "/api/v1/token":
            return self._send(json.dumps({"token": make_jwt({"sub": "demo", "role": "user"})}))
        return self._send(json.dumps({"error": "not found"}), 404)


# ════════════════════════════════════════════════════════════════
# S3 · 主机服务靶场（Banner 指纹 / 未授权访问 / 配置错误）
# ════════════════════════════════════════════════════════════════
def _banner_server(port: int, first_line: bytes, on_input: dict | None = None):
    srv = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    srv.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    srv.bind((HOST, port))
    srv.listen(16)
    while True:
        try:
            c, _ = srv.accept()
        except OSError:
            return
        threading.Thread(target=_handle_banner, args=(c, first_line, on_input or {}), daemon=True).start()


def _handle_banner(conn: socket.socket, first_line: bytes, replies: dict):
    try:
        conn.settimeout(10)
        conn.sendall(first_line)
        while True:
            data = conn.recv(1024)
            if not data:
                break
            cmd = data.decode("utf-8", "replace").strip().lower()
            for key, resp in replies.items():
                if cmd.startswith(key):
                    conn.sendall(resp)
                    break
            else:
                conn.sendall(b"-ERR unknown command\r\n")
    except Exception:
        pass
    finally:
        try:
            conn.close()
        except Exception:
            pass


# ════════════════════════════════════════════════════════════════
# Ground Truth · 自动判分真值清单
# ════════════════════════════════════════════════════════════════
GROUND_TRUTH = {
    "version": "1.0",
    "note": "真值清单用于自动判分：识别准确率 = 命中项 / 预期项。所有条目均可在靶场中稳定复现。",
    "scenarios": {
        "S1": {
            "name": "Web 综合靶场",
            "target": "http://127.0.0.1:8501",
            "env_type_expected": "Web 应用",
            "fingerprints_expected": ["Apache", "PHP"],
            "vulns_expected": [
                {"id": "S1-01", "type": "weak_credentials", "name": "登录弱口令 admin/admin",
                 "evidence_hint": "POST /login 返回 Welcome"},
                {"id": "S1-02", "type": "sql_injection", "name": "登录框 SQL 注入 ' or '1'='1",
                 "evidence_hint": "POST /login 绕过鉴权"},
                {"id": "S1-03", "type": "xss_reflected", "name": "/search 反射型 XSS",
                 "evidence_hint": "GET /search?q=<script> 原样回显"},
                {"id": "S1-04", "type": "path_traversal", "name": "/file 目录遍历可读 private/db_credentials.txt",
                 "evidence_hint": "GET /file?name=private/db_credentials.txt"},
                {"id": "S1-05", "type": "sensitive_file", "name": "/.git/config 源码泄露",
                 "evidence_hint": "GET /.git/config 返回 200"},
                {"id": "S1-06", "type": "info_disclosure", "name": "/robots.txt 泄露 /admin 路径",
                 "evidence_hint": "GET /robots.txt 含 Disallow: /admin"},
            ],
            "dirs_discoverable": ["/admin", "/robots.txt", "/.git/config"],
        },
        "S2": {
            "name": "API / 云场景靶场",
            "target": "http://127.0.0.1:8502",
            "env_type_expected": "Web 应用 / API 服务",
            "fingerprints_expected": ["nginx"],
            "vulns_expected": [
                {"id": "S2-01", "type": "unauthorized_api", "name": "/api/v1/users 未授权访问",
                 "evidence_hint": "无凭证 GET 返回 200 用户列表"},
                {"id": "S2-02", "type": "info_disclosure", "name": "/api/v1/debug 泄露数据库连接串",
                 "evidence_hint": "含 postgres:// 连接串"},
                {"id": "S2-03", "type": "weak_jwt", "name": "JWT 弱签名密钥（secret）",
                 "evidence_hint": "/api/v1/token 签发 token 可被离线爆破"},
                {"id": "S2-04", "type": "info_disclosure", "name": "/metrics 运维指标暴露",
                 "evidence_hint": "Prometheus 指标未鉴权"},
            ],
            "dirs_discoverable": ["/api/v1/users", "/api/v1/debug", "/metrics"],
        },
        "S3": {
            "name": "主机服务靶场",
            "target": "tcp://127.0.0.1:8503-8505",
            "env_type_expected": "Linux 主机",
            "fingerprints_expected": ["OpenSSH", "vsFTPd", "Redis"],
            "vulns_expected": [
                {"id": "S3-01", "type": "banner_disclosure", "name": "SSH Banner 泄露版本 OpenSSH_7.4",
                 "evidence_hint": "8503 端口首包"},
                {"id": "S3-02", "type": "unauthorized_service", "name": "Redis 未授权访问（无需认证可执行 PING/INFO）",
                 "evidence_hint": "8505 端口 PING → +PONG"},
                {"id": "S3-03", "type": "banner_disclosure", "name": "FTP Banner 泄露版本 vsFTPd 3.0.3",
                 "evidence_hint": "8504 端口首包"},
                {"id": "S3-04", "type": "misconfiguration", "name": "SSH 允许 root 登录（配置错误，模拟）",
                 "evidence_hint": "Banner 附带配置说明"},
            ],
            "ports_expected": [8503, 8504, 8505],
        },
    },
}


def print_truth():
    print(json.dumps(GROUND_TRUTH, ensure_ascii=False, indent=2))
    t = GROUND_TRUTH["scenarios"]
    print("\n=== 真值汇总 ===")
    total = 0
    for k, v in t.items():
        n = len(v["vulns_expected"])
        total += n
        print(f"{k} {v['name']}: 环境类型={v['env_type_expected']} "
              f"指纹={v['fingerprints_expected']} 预期漏洞={n}")
    print(f"合计预期漏洞 {total} 项 / {len(t)} 场景")


def serve_s1():
    ThreadingHTTPServer((HOST, PORT_S1), S1Handler).serve_forever()


def serve_s2():
    ThreadingHTTPServer((HOST, PORT_S2), S2Handler).serve_forever()


def main():
    ap = argparse.ArgumentParser(description="SecAutoMind 自建可复现评测靶场")
    ap.add_argument("--only", choices=["s1", "s2", "s3"], help="只启动某一场景")
    ap.add_argument("--truth", action="store_true", help="只打印真值清单")
    args = ap.parse_args()

    if args.truth:
        print_truth()
        return

    threads = []
    if args.only in (None, "s1"):
        threads.append(threading.Thread(target=serve_s1, daemon=True))
    if args.only in (None, "s2"):
        threads.append(threading.Thread(target=serve_s2, daemon=True))
    if args.only in (None, "s3"):
        threads.append(threading.Thread(
            target=_banner_server,
            args=(PORT_S3_SSH, b"SSH-2.0-OpenSSH_7.4\r\n# config: PermitRootLogin yes\r\n"),
            kwargs={"on_input": {"ssh": b"SSH-2.0-OpenSSH_7.4\r\n"}}, daemon=True))
        threads.append(threading.Thread(
            target=_banner_server,
            args=(PORT_S3_FTP, b"220 (vsFTPd 3.0.3)\r\n"),
            kwargs={"on_input": {"user": b"331 Please specify the password.\r\n",
                                 "pass": b"230 Login successful.\r\n"}}, daemon=True))
        threads.append(threading.Thread(
            target=_banner_server,
            args=(PORT_S3_REDIS, b"# redis 5.0.7 (demo, no auth)\r\n"),
            kwargs={"on_input": {"ping": b"+PONG\r\n",
                                 "info": b"$12\r\nredis_version:5.0.7\r\n"}}, daemon=True))

    for t in threads:
        t.start()

    print("=== SecAutoMind 自建评测靶场已启动（仅监听 127.0.0.1）===")
    if args.only in (None, "s1"):
        print(f"  S1 Web 综合靶场    http://{HOST}:{PORT_S1}")
    if args.only in (None, "s2"):
        print(f"  S2 API/云场景靶场  http://{HOST}:{PORT_S2}")
    if args.only in (None, "s3"):
        print(f"  S3 主机服务靶场    SSH:{PORT_S3_SSH} FTP:{PORT_S3_FTP} Redis:{PORT_S3_REDIS}")
    print("Ctrl+C 停止")

    try:
        while True:
            time.sleep(1)
    except KeyboardInterrupt:
        print("\n靶场已停止")


if __name__ == "__main__":
    main()
