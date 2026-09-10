#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
judge_ecdsa.py —— ECDSA nonce 复用攻击基准（Python 侧独立机验）。

与 Go tryECDSANonceReuse 双语言镜像：解析描述中的 n/r/s1/s2/z1/z2（十进制），
离线还原 d = (s1*k - z1) * r^-1 mod n，k = (z1 - z2) * (s1 - s2)^-1 mod n，
校验 flag = flag{<hex(d)>} 的 SHA-256 是否与基准集一致。

命中以单独一行的 "HIT" 计；run_all_benchmarks.run_ecdsa 据此统计命中数，
再由 scripts/verify_evidence.py 的 MUST_FULL 门禁强制 ecdsa_nonce_reuse 全命中。

用法: python judge_ecdsa.py
"""
import hashlib
import json
import os
import re
import sys

N = 0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEBAAEDCE6AF48A03BBFD25E8CD0364141

RE = {
    "r": re.compile(r"(?i)\br\s*=\s*(\d+)"),
    "n": re.compile(r"(?i)\bn\s*=\s*(\d+)"),
    "s1": re.compile(r"(?i)\bs1\s*=\s*(\d+)"),
    "s2": re.compile(r"(?i)\bs2\s*=\s*(\d+)"),
    "z1": re.compile(r"(?i)\bz1\s*=\s*(\d+)"),
    "z2": re.compile(r"(?i)\bz2\s*=\s*(\d+)"),
}


def inv(x, m):
    return pow(x % m, -1, m)


def recover(text):
    vals = {}
    for key, rx in RE.items():
        m = rx.search(text)
        if not m:
            return None
        vals[key] = int(m.group(1))
    r, n, s1, s2, z1, z2 = (vals["r"], vals["n"], vals["s1"], vals["s2"], vals["z1"], vals["z2"])
    if r == 0 or n <= 0 or s1 == s2:
        return None
    sdiff = (s1 - s2) % n
    kinv = inv(sdiff, n)
    if kinv is None:
        return None
    k = (z1 - z2) * kinv % n
    rinv = inv(r, n)
    if rinv is None:
        return None
    d = (s1 * k - z1) * rinv % n
    if d == 0:
        return None
    return d


def main():
    here = os.path.dirname(os.path.abspath(__file__))
    bench = os.path.join(here, "ecdsa_benchmark.json")
    if not os.path.exists(bench):
        print("缺少 ecdsa_benchmark.json（请先运行 gen_ecdsa.py）", file=sys.stderr)
        return 1
    probs = json.load(open(bench, encoding="utf-8"))["problems"]
    hit = 0
    for pid in sorted(probs):
        d = recover(probs[pid]["description"])
        ok = False
        if d is not None:
            cand = "flag{" + format(d, "x") + "}"
            ok = hashlib.sha256(cand.encode()).hexdigest() == probs[pid]["flag_sha256"]
        hit += 1 if ok else 0
        print("%-22s %s" % (pid, "HIT" if ok else "MISS"))
    print("ECDSA nonce reuse 基准（Python 侧独立复刻）: %d/%d" % (hit, len(probs)))
    return 0 if hit == len(probs) else 1


if __name__ == "__main__":
    sys.exit(main())
