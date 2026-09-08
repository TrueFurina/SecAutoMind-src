#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
judge_padding_oracle.py —— CBC Padding Oracle 攻击基准（Python 侧独立机验）。

纯标准库 + pycryptodome 自行实现 padding oracle 攻击，对 padding_oracle_benchmark.json
离线求解，命中以 SHA-256 比对（基准集只存哈希，不存明文 flag）。与 Go
paddingOracleRecover / tryPaddingOracle 双语言镜像，任一侧漂移立即暴露。

用法: python judge_padding_oracle.py
"""

import hashlib
import json
import os
import re
import sys

from Crypto.Cipher import AES
from Crypto.Util.Padding import unpad

HERE = os.path.dirname(os.path.abspath(__file__))
BENCH = os.path.join(HERE, "padding_oracle_benchmark.json")

RE_FLAG = re.compile(r"flag\{[^}\x00-\x1f\x7f]{4,}\}|[A-Z][A-Z0-9]{2,15}\{[^}\x00-\x1f\x7f]{4,}\}")


def pkcs7_valid(padded, bs):
    if len(padded) == 0 or len(padded) % bs != 0:
        return False
    p = padded[-1]
    if p < 1 or p > bs:
        return False
    return all(b == p for b in padded[-p:])


def aes_cbc_decrypt(key, ct):
    iv, body = ct[:AES.block_size], ct[AES.block_size:]
    return AES.new(key, AES.MODE_CBC, iv).decrypt(body)


def local_oracle(key):
    def f(ct):
        if len(ct) < AES.block_size * 2 or len(ct) % AES.block_size != 0:
            return False
        return pkcs7_valid(aes_cbc_decrypt(key, ct), AES.block_size)
    return f


def padding_oracle_recover(oracle, iv, ct, bs):
    if oracle is None or len(ct) == 0 or len(ct) % bs != 0 or len(iv) != bs:
        return None
    full = iv + ct
    blocks = [full[i:i + bs] for i in range(0, len(full), bs)]
    if len(blocks) < 2:
        return None
    plain = b""
    for i in range(1, len(blocks)):
        target = blocks[i]
        real_prev = blocks[i - 1]
        I = bytearray(bs)
        for b in range(bs - 1, -1, -1):
            padval = bs - b
            prefix = bytearray(bs)
            for j in range(b + 1, bs):
                prefix[j] = I[j] ^ padval
            p1 = p2 = -1
            for g in range(256):
                prefix[b] = g
                probe = bytes(prefix) + target
                if not oracle(probe):
                    continue
                if b == bs - 1 and bs >= 2:
                    p2b = bytearray(prefix)
                    p2b[bs - 2] ^= 0xFF
                    if oracle(bytes(p2b) + target):
                        p1 = g
                    else:
                        p2 = g
                else:
                    p1 = g
            if p1 >= 0:
                g = p1
            elif p2 >= 0:
                g = p2
            else:
                return None
            I[b] = g ^ padval
        pblock = bytes(I[j] ^ real_prev[j] for j in range(bs))
        plain += pblock
    try:
        return unpad(plain, bs)
    except Exception:
        return plain


def solve(text):
    m_key = re.search(r"aes_key\s*=\s*([0-9a-fA-F]+)", text, re.IGNORECASE)
    m_ct = re.search(r"ciphertext\s*=\s*([0-9a-fA-F]+)", text, re.IGNORECASE)
    if not m_key or not m_ct:
        return []
    key = bytes.fromhex(m_key.group(1))
    raw = bytes.fromhex(m_ct.group(1))
    if len(raw) < AES.block_size * 2 or len(raw) % AES.block_size != 0:
        return []
    iv, ct = raw[:AES.block_size], raw[AES.block_size:]
    oracle = local_oracle(key)
    plain = padding_oracle_recover(oracle, iv, ct, AES.block_size)
    if plain is None:
        return []
    found = []
    for f in RE_FLAG.findall(plain.decode("latin-1")):
        if f not in found:
            found.append(f)
    if not found:
        found.append("PaddingOracle解密(hex): " + plain.hex())
    return found


def main():
    if not os.path.exists(BENCH):
        print("缺少 padding_oracle_benchmark.json（请先运行 gen_padding_oracle.py）", file=sys.stderr)
        return 1
    doc = json.load(open(BENCH, encoding="utf-8"))["problems"]
    hit = 0
    for pid in sorted(doc):
        desc = doc[pid]["description"]
        found = solve(desc)
        ok = any(hashlib.sha256(f.encode()).hexdigest() == doc[pid]["flag_sha256"] for f in found)
        hit += 1 if ok else 0
        print("%-22s %s  (候选 %d)" % (pid, "HIT " if ok else "MISS", len(found)))
    print("Padding Oracle 基准（Python 侧独立复刻）: %d/%d" % (hit, len(doc)))
    return 0 if hit == len(doc) else 1


if __name__ == "__main__":
    sys.exit(main())
