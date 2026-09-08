#!/usr/bin/env python3
"""SSRF → 内网 Redis RCE 链靶场 —— 复刻真实 CTF / 云环境三类 SSRF 考点。

flag 只有通过靶机 /fetch?url= 代理打内网才返回（攻击者无法从外网直接拿）：
  1. ssrf_redis   : 内网 mini Redis(127.0.0.1:6399) 未授权访问，flag 存键 backup:flag。
                    靶机 fetch 支持 gopher:// 协议 → 需管道化 RESP 命令 KEYS/GET。
  2. ssrf_cloud   : 模拟云 IMDS(169.254.169.254)，两跳拿角色凭证
                    /latest/meta-data/iam/security-credentials/ → /…/imds-role
                    Token 字段内嵌 flag。
  3. ssrf_internal: 仅监听回环的 admin 服务(127.0.0.1:6401/internal/flag)，
                    要求 X-Internal-Token 头 —— 只有靶机 fetch 代理转发时注入
                    （直接外网连 6401 无该头 → 403，防绕过）。

纯标准库实现。
用法: python ssrf_range.py [port] [--dump-json]
"""

import hashlib
import json
import socket
import socketserver
import sys
import threading
import time
import urllib.error
import urllib.parse
import urllib.request
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

PORT = int(sys.argv[1]) if len(sys.argv) > 1 and sys.argv[1].isdigit() else 18120
REDIS_PORT = 6399
INTERNAL_PORT = 6401
INTERNAL_TOKEN = "ssrf-proxy"

# ── 场景定义：(flag, 考点说明) ──
SCENES = {
    "ssrf_redis": ("flag{ssrf_g0pher_redis_unauth}",
                   "SSRF：靶机 /ssrf_redis/fetch?url= 存在服务端请求伪造，可发起任意协议请求。"
                   "内网 6379 段 Redis(127.0.0.1:6399) 未授权访问，flag 存在键 backup:flag。"),
    "ssrf_cloud": ("flag{ssrf_cl0ud_metadata_cred}",
                   "SSRF：靶机 /ssrf_cloud/fetch?url= 可访问云元数据服务 169.254.169.254。"
                   "先取 IAM 角色列表，再取 security-credentials/imds-role 的凭证。"),
    "ssrf_internal": ("flag{ssrf_l00pback_admin_svc}",
                      "SSRF：靶机 /ssrf_internal/fetch?url= 可访问内网。"
                      "内网 6401 端口存在仅监听回环的 admin 服务 /internal/flag。"),
}

REDIS_KEY = "backup:flag"


# ───────────────────────── mini Redis（RESP 协议） ─────────────────────────

class MiniRedisHandler(socketserver.BaseRequestHandler):
    """极简 Redis：RESP 数组 + 内联命令，支持 PING/AUTH/GET/SET/KEYS/INFO/CONFIG。"""

    DB = {REDIS_KEY: SCENES["ssrf_redis"][0], "role": "web-cache", "ver": "6.2-mini"}
    lock = threading.Lock()

    def handle(self):
        buf = b""
        while True:
            try:
                data = self.request.recv(4096)
            except OSError:
                return
            if not data:
                return
            buf += data
            while True:
                consumed, replies = self._parse(buf)
                if consumed == 0:
                    break
                buf = buf[consumed:]
                for r in replies:
                    try:
                        self.request.sendall(r)
                    except OSError:
                        return

    def _parse(self, buf):
        """解析一条命令，返回 (消耗字节数, [响应])。"""
        if not buf:
            return 0, []
        if buf[:1] == b"*":
            # RESP 数组
            line_end = buf.find(b"\r\n")
            if line_end < 0:
                return 0, []
            try:
                n = int(buf[1:line_end])
            except ValueError:
                return line_end + 2, [b"-ERR bad array\r\n"]
            pos = line_end + 2
            args = []
            for _ in range(n):
                if pos >= len(buf) or buf[pos:pos + 1] != b"$":
                    return pos or 1, [b"-ERR expected bulk\r\n"]
                le = buf.find(b"\r\n", pos)
                if le < 0:
                    return 0, []
                try:
                    blen = int(buf[pos + 1:le])
                except ValueError:
                    return le + 2, [b"-ERR bad bulk\r\n"]
                pos = le + 2
                if len(buf) < pos + blen + 2:
                    return 0, []  # 数据未到齐
                args.append(buf[pos:pos + blen])
                pos += blen + 2
            return pos, [self._exec([a.decode("utf-8", "replace") for a in args])]
        # 内联命令
        line_end = buf.find(b"\r\n")
        if line_end < 0:
            return 0, []
        line = buf[:line_end].decode("utf-8", "replace").strip()
        if not line:
            return line_end + 2, []
        return line_end + 2, [self._exec(line.split())]

    def _exec(self, args):
        if not args:
            return b"-ERR empty\r\n"
        cmd = args[0].upper()
        with self.lock:
            if cmd == "PING":
                return b"+PONG\r\n"
            if cmd == "AUTH":
                return b"+OK\r\n"
            if cmd == "SELECT":
                return b"+OK\r\n"
            if cmd == "GET":
                v = self.DB.get(args[1]) if len(args) > 1 else None
                if v is None:
                    return b"$-1\r\n"
                return b"$%d\r\n%s\r\n" % (len(v), v.encode())
            if cmd == "SET":
                if len(args) < 3:
                    return b"-ERR wrong number of arguments\r\n"
                self.DB[args[1]] = args[2]
                return b"+OK\r\n"
            if cmd == "KEYS":
                pat = args[1] if len(args) > 1 else "*"
                import fnmatch
                keys = [k for k in self.DB if fnmatch.fnmatch(k, pat)]
                out = b"*%d\r\n" % len(keys)
                for k in keys:
                    out += b"$%d\r\n%s\r\n" % (len(k), k.encode())
                return out
            if cmd == "INFO":
                body = ("# Server\r\nredis_version:6.2.6-mini\r\n"
                        "flag_hint:GET backup:flag\r\n").encode()
                return b"$%d\r\n%s\r\n" % (len(body), body)
            if cmd == "CONFIG":
                return b"*2\r\n$3\r\ndir\r\n$4\r\n/tmp\r\n"
            return b"-ERR unknown command '%s'\r\n" % args[0].encode()


def start_redis():
    import socketserver
    srv = socketserver.ThreadingTCPServer(("127.0.0.1", REDIS_PORT), MiniRedisHandler)
    srv.daemon_threads = True
    t = threading.Thread(target=srv.serve_forever, daemon=True)
    t.start()
    return srv


# ───────────────────────── 内网 admin 服务（回环监听 + token 校验） ─────────────────────────

class InternalHandler(BaseHTTPRequestHandler):
    protocol_version = "HTTP/1.0"
    timeout = 5

    def log_message(self, *a):
        pass

    def do_GET(self):
        if self.path.split("?")[0] == "/internal/flag":
            if self.headers.get("X-Internal-Token") != INTERNAL_TOKEN:
                # 防绕过：只有靶机 fetch 代理（内网可信段）才持有该头
                body = json.dumps({"error": "forbidden: internal only"}).encode()
                self.send_response(403)
            else:
                body = json.dumps({"service": "admin", "flag": SCENES["ssrf_internal"][0]}).encode()
                self.send_response(200)
            self.send_header("Content-Type", "application/json")
            self.send_header("Content-Length", str(len(body)))
            self.end_headers()
            self.wfile.write(body)
            return
        self.send_response(404)
        self.send_header("Content-Length", "0")
        self.end_headers()


def start_internal():
    srv = ThreadingHTTPServer(("127.0.0.1", INTERNAL_PORT), InternalHandler)
    srv.daemon_threads = True
    t = threading.Thread(target=srv.serve_forever, daemon=True)
    t.start()
    return srv


# ───────────────────────── 靶机主服务（含漏洞 fetch 端点） ─────────────────────────

def gopher_fetch(host, port, raw):
    """gopher 语义：发原始字节，回读响应。"""
    try:
        s = socket.create_connection((host, port), timeout=5)
        s.sendall(raw)
        time.sleep(0.3)
        chunks = []
        s.settimeout(1.0)
        try:
            while True:
                d = s.recv(65536)
                if not d:
                    break
                chunks.append(d)
        except socket.timeout:
            pass
        s.close()
        return b"".join(chunks).decode("utf-8", "replace")
    except Exception as e:
        return "gopher error: %s" % e


def proxy_http(url):
    """http 代理转发；内网目标自动注入内网 token（模拟代理位于可信段）。"""
    req = urllib.request.Request(url)
    req.add_header("User-Agent", "internal-proxy/1.0")
    pu = urllib.parse.urlparse(url)
    if pu.hostname in ("127.0.0.1", "localhost") and pu.port == INTERNAL_PORT:
        req.add_header("X-Internal-Token", INTERNAL_TOKEN)
    try:
        with urllib.request.urlopen(req, timeout=6) as r:
            return r.read().decode("utf-8", "replace")
    except urllib.error.HTTPError as e:
        try:
            return e.read().decode("utf-8", "replace")
        except Exception:
            return "http error: %s" % e.code
    except Exception as e:
        return "fetch error: %s" % e


IMDS_ROLE = "imds-role"


def imds_response(path):
    """模拟云 IMDS 响应。"""
    if path.rstrip("/") == "/latest/meta-data/iam/security-credentials":
        return IMDS_ROLE
    if path.rstrip("/").endswith("/" + IMDS_ROLE):
        return json.dumps({
            "Code": "Success",
            "AccessKeyId": "AKIAIOSFODNN7EXAMPLE",
            "SecretAccessKey": "wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY",
            "Token": SCENES["ssrf_cloud"][0],
            "Expiration": "2026-12-31T00:00:00Z",
        }, indent=2)
    return "not found"


class Range(BaseHTTPRequestHandler):
    protocol_version = "HTTP/1.0"
    timeout = 8

    def log_message(self, *a):
        pass

    def _send(self, code, body, ctype="text/plain; charset=utf-8"):
        raw = body.encode() if isinstance(body, str) else body
        self.send_response(code)
        self.send_header("Content-Type", ctype)
        self.send_header("Content-Length", str(len(raw)))
        self.end_headers()
        self.wfile.write(raw)

    def do_GET(self):
        path, _, qs = self.path.partition("?")
        parts = path.strip("/").split("/")

        if path == "/" or path == "/index.html":
            links = "".join(
                f'<li><a href="/{s}/fetch?url=http://127.0.0.1:6399/">{s}</a> — {d}</li>'
                for s, (_, d) in SCENES.items())
            return self._send(200, f"<html><body><h1>SSRF Range</h1><ul>{links}</ul></body></html>",
                              "text/html; charset=utf-8")

        if len(parts) >= 2 and parts[1] == "fetch" and parts[0] in SCENES:
            q = urllib.parse.parse_qs(qs)
            url = (q.get("url") or [""])[0]
            if not url:
                return self._send(400, "missing url param")
            pu = urllib.parse.urlparse(url)
            scheme = pu.scheme.lower()
            if scheme == "gopher":
                # gopher://host:port/_<urlencoded raw>
                raw = urllib.parse.unquote(pu.path.lstrip("/"))
                if raw.startswith("_"):
                    raw = raw[1:]
                return self._send(200, gopher_fetch(pu.hostname, pu.port or 70, raw.encode()))
            if scheme == "http":
                if pu.hostname == "169.254.169.254":
                    return self._send(200, imds_response(pu.path))
                return self._send(200, proxy_http(url))
            return self._send(400, "unsupported scheme: %s" % scheme)

        return self._send(404, "not found")


def main():
    if "--dump-json" in sys.argv:
        print(json.dumps(
            {"problems": {k: {"flag_sha256": hashlib.sha256(v[0].encode()).hexdigest(),
                              "description": v[1]} for k, v in SCENES.items()}},
            indent=2, ensure_ascii=False))
        sys.exit(0)
    start_redis()
    start_internal()
    srv = ThreadingHTTPServer(("127.0.0.1", PORT), Range)
    srv.serve_forever()


if __name__ == "__main__":
    main()
