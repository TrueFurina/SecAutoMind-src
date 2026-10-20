#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
judge_blind_oob.py —— Web 盲打 / OOB 外带攻击基准（Python 侧独立机验）。

纯标准库自建时间盲注靶机 + OOB 监听器 + OOB 靶机，对 blind_oob_benchmark.json
离线求解，命中以 SHA-256 比对（基准集只存哈希，不存明文密钥）。与 Go
TestBlindOOB* 双语言镜像，任一侧漂移立即暴露。

用法: python judge_blind_oob.py
"""

import hashlib
import json
import os
import re
import sys
import threading
import time
import urllib.parse
import urllib.request
from http.server import BaseHTTPRequestHandler, HTTPServer

HERE = os.path.dirname(os.path.abspath(__file__))
BENCH = os.path.join(HERE, "blind_oob_benchmark.json")

TIME_SECRET = "t1m3b1"
OOB_SECRET = "flag{o0b_3xfil_7k}"
CHARSET = "abcdefghijklmnopqrstuvwxyz0123456789_"
THRESHOLD = 0.12  # 秒，条件成立延迟 0.35s >> 阈值 >> 不成立 0.02s

CAPTURED = []  # OOB 监听器捕获的回调 RawQuery


def make_time_handler():
    class H(BaseHTTPRequestHandler):
        def do_GET(self):
            q = urllib.parse.parse_qs(urllib.parse.urlparse(self.path).query)
            pos = int(q.get("pos", ["-1"])[0])
            c = q.get("c", [""])[0]
            if 0 <= pos < len(TIME_SECRET) and len(c) == 1 and TIME_SECRET[pos] == c:
                time.sleep(0.35)  # 条件成立：显著延迟（拉大与不成立侧的间隙，抗抖动）
            else:
                time.sleep(0.02)  # 条件不成立：快速返回
            self.send_response(200)
            self.end_headers()
            self.wfile.write(b"ok")

        def log_message(self, *a):
            pass

    return H


def make_oob_target_handler():
    class H(BaseHTTPRequestHandler):
        def do_GET(self):
            q = urllib.parse.parse_qs(urllib.parse.urlparse(self.path).query)
            cb = q.get("cb", [""])[0]
            if cb:
                def call():
                    try:
                        urllib.request.urlopen(cb + OOB_SECRET, timeout=5).read()
                    except Exception:
                        pass

                threading.Thread(target=call, daemon=True).start()
            self.send_response(200)
            self.end_headers()
            self.wfile.write(b"ok")

        def log_message(self, *a):
            pass

    return H


def make_listener_handler():
    class H(BaseHTTPRequestHandler):
        def do_GET(self):
            CAPTURED.append(urllib.parse.urlparse(self.path).query)
            self.send_response(200)
            self.end_headers()
            self.wfile.write(b"ok")

        def log_message(self, *a):
            pass

    return H


def run_server(handler_cls):
    srv = HTTPServer(("127.0.0.1", 0), handler_cls)
    threading.Thread(target=srv.serve_forever, daemon=True).start()
    return srv, srv.server_address[1]


def time_oracle(time_port, cond, n=3):
    u = "http://127.0.0.1:%d/time?%s" % (time_port, cond)
    samples = []
    for _ in range(n):
        t0 = time.time()
        urllib.request.urlopen(u, timeout=5).read()
        samples.append(time.time() - t0)
    samples.sort()
    return samples[len(samples) // 2]  # 中位数：抗 OS 调度抖动（单次测量偶尔会把 0.35s 误测成 <阈值）


def time_blind_recover(time_port, n, charset, threshold, samples=3):
    out = ""
    for i in range(n):
        for c in charset:
            cond = urllib.parse.urlencode({"pos": i, "c": c})
            if time_oracle(time_port, cond, n=samples) >= threshold:
                out += c
                break
    return out


RE_FLAG = re.compile(r"flag\{[^}\x00-\x1f\x7f]{4,}\}")


def oob_extract(listener_port, oob_port):
    cb = "http://127.0.0.1:%d/?d=" % listener_port
    urllib.request.urlopen(
        "http://127.0.0.1:%d/oob?cb=%s" % (oob_port, urllib.parse.quote(cb, safe="")),
        timeout=5,
    ).read()
    deadline = time.time() + 2
    while time.time() < deadline:
        for raw in CAPTURED:
            m = RE_FLAG.search(urllib.parse.unquote(raw))
            if m:
                return m.group(0)
        time.sleep(0.05)
    return None


def main():
    if not os.path.exists(BENCH):
        print("缺少 blind_oob_benchmark.json（请先运行 gen_blind_oob.py）", file=sys.stderr)
        return 1
    time_srv, time_port = run_server(make_time_handler())
    oob_srv, oob_port = run_server(make_oob_target_handler())
    lis_srv, lis_port = run_server(make_listener_handler())
    try:
        doc = json.load(open(BENCH, encoding="utf-8"))["problems"]
        total = len(doc)
        hit = 0

        t_rec = time_blind_recover(time_port, len(TIME_SECRET), CHARSET, THRESHOLD, samples=3)
        t_ok = hashlib.sha256(t_rec.encode()).hexdigest() == doc["time_blind_basic"]["flag_sha256"]
        hit += 1 if t_ok else 0
        print("%-22s %s  (还原=%s)" % ("time_blind_basic", "HIT " if t_ok else "MISS", t_rec))

        o_rec = oob_extract(lis_port, oob_port)
        o_ok = bool(o_rec) and hashlib.sha256(o_rec.encode()).hexdigest() == doc["oob_exfil_basic"]["flag_sha256"]
        hit += 1 if o_ok else 0
        print("%-22s %s  (还原=%s)" % ("oob_exfil_basic", "HIT " if o_ok else "MISS", o_rec))

        print("Blind/OOB 基准（Python 侧独立复刻）: %d/%d" % (hit, total))
        return 0 if hit == total else 1
    finally:
        time_srv.shutdown()
        oob_srv.shutdown()
        lis_srv.shutdown()


if __name__ == "__main__":
    sys.exit(main())
