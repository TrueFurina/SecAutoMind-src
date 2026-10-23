#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
judge_crc64.py —— CRC64 线性性伪造 cookie 判定器（Python 侧）。

真题对照：CyberNova 2026 - Lazarus Phantom DB（crc_forgery_real 能力面）。
攻击链（复刻真实 bit-flip，非关键词匹配）：
  1. /login 拿 guest 块与 crc(guest)；
  2. Δ = guest ⊕ admin（16 字节同长度异或）；
  3. /oracle?data=Δ 学 crc(Δ)（多项式参数未知也成立：CRC 是 GF(2) 线性映射）；
  4. crc(admin) = crc(guest) ⊕ crc(Δ) → 提交 cookie → /admin 校验通过 → flag。
反注水：标准 crc64（ISO/ECMA）算不出自定义多项式；data 必须精确翻转成 admin 块才给 flag。

用法：  python judge_crc64.py [port]
"""
import hashlib
import json
import os
import subprocess
import sys
import tempfile
import time
import urllib.parse
import urllib.request
from http.client import HTTPConnection

HERE = os.path.dirname(os.path.abspath(__file__))
RANGE_PY = os.path.join(HERE, "live_target", "crc64_range.py")
BENCH = os.environ.get("CRC64_BENCH", os.path.join(HERE, "crc64_benchmark.json"))
PORT = int(os.environ.get("CRC64_PORT", "18097"))

GUEST_BLOCK = b"user=guest\x00\x00\x00\x00\x00\x00"
ADMIN_BLOCK = b"user=admin\x00\x00\x00\x00\x00\x00"
DELTA = bytes(a ^ b for a, b in zip(GUEST_BLOCK, ADMIN_BLOCK))


def get_json(url: str):
    try:
        with urllib.request.urlopen(url, timeout=5) as r:
            return json.loads(r.read().decode("utf-8", "ignore"))
    except Exception:
        return {}


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
    # range 的 stderr 落临时文件：靶场起不来时给出真实原因（CI 曾报「未就绪」
    # 却零线索——web_hints judge 同款默认端口 18097 已改 18098 消除碰撞，
    # 但可诊断性必须保留，否则下次还是盲猜）。
    errf = tempfile.TemporaryFile()
    proc = subprocess.Popen([sys.executable, RANGE_PY, str(PORT)],
                            stdout=subprocess.DEVNULL, stderr=errf)
    try:
        if not wait_ready(PORT):
            errf.seek(0)
            tail = errf.read().decode("utf-8", "ignore").strip()[-600:]
            print("靶场未就绪（range stderr 尾部：%s）" % (tail or "<空>"))
            return 1
        base = "http://127.0.0.1:%d" % PORT
        # 1. guest cookie
        login = get_json(base + "/login")
        guest_crc = int(login["crc"], 16)
        # 2. 学习 Δ 的 crc 贡献
        oracle = get_json(base + "/oracle?data=" + DELTA.hex())
        delta_crc = int(oracle["crc"], 16)
        # 3. 线性性：crc(admin) = crc(guest) ⊕ crc(Δ)
        admin_crc = guest_crc ^ delta_crc
        cookie = ADMIN_BLOCK.hex() + "." + "%016x" % admin_crc
        # 4. 提交伪造 cookie
        resp = get_json(base + "/admin?cookie=" + urllib.parse.quote(cookie))

        hits = 0
        total = len(bench)
        for scene, p in bench.items():
            if resp.get("ok") and resp.get("flag") and \
                    hashlib.sha256(resp["flag"].encode()).hexdigest() == p["flag_sha256"]:
                hits += 1
                print("✅ HIT  %-12s (crc_guest=%016x Δcrc=%016x crc_admin=%016x)"
                      % (scene, guest_crc, delta_crc, admin_crc))
            else:
                print("❌ MISS %-12s resp=%s" % (scene, json.dumps(resp, ensure_ascii=False)))
        print("=== [Python] CRC64 伪造命中率: %d/%d = %.1f%% ===" % (hits, total, 100 * hits / total))
        return 0 if hits == total else 1
    finally:
        proc.kill()
        errf.close()


if __name__ == "__main__":
    sys.exit(main())
