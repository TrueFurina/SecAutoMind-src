#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
生成 AES-GCM nonce 复用 双语言基准 (gcm_nonce_reuse_benchmark.json)。

确定性合成：固定一条 keystream（同 nonce → 同 CTR keystream，这是 nonce 复用的本质），
用 XOR 构造两条密文：
    ct1 = known_plaintext ⊕ ks
    ct2 = secret          ⊕ ks
flag_sha256 = sha256(secret)，绝不存明文 secret。
注：AES-GCM 复用 nonce 后，CTR 模式对两条消息共享同一条 keystream，故「XOR 固定
keystream」即为该漏洞的密码学等价模型，无需引入任何 AES 实现（依赖无关、可复现）。
"""
import hashlib
import json
import os

HERE = os.path.dirname(os.path.abspath(__file__))
OUT = os.path.join(HERE, "gcm_nonce_reuse_benchmark.json")

# 固定 keystream（长度须覆盖两端明文）
KS = (b"k3ystr3am-fixed-for-nonce-reuse-benchmark-0123456789" * 8)

CASES = [
    {
        "name": "gcm_nr_basic",
        "known": b"The quick brown fox jumps over the lazy dog. KNOWN_PREFIX_PADDING_BLOCK_01",
        "secret": b"flag{gcm_nonce_reuse_keystream_recovered_2026}",
        "note": "AES-GCM 同密钥同 nonce，两条密文共享 CTR keystream，由已知明文还原第二条明文",
    },
    {
        "name": "gcm_nr_long_secret",
        "known": b"POST /api/v1/decrypt HTTP/1.1\r\ncontent-type: application/json\r\n",
        "secret": b"flag{nonce_reuse_breaks_gcm_confidentiality_no_key_needed}",
        "note": "GCM nonce 复用：服务端对同一 nonce 加密了请求头(已知)与敏感 token(未知)",
    },
]


def _xor(a, b):
    n = min(len(a), len(b))
    return bytes(x ^ y for x, y in zip(a[:n], b[:n]))


def main():
    if len(KS) < max(max(len(c["known"]) for c in CASES),
                     max(len(c["secret"]) for c in CASES)):
        raise SystemExit("KS 太短")
    nonce = bytes(range(12))
    problems = {}
    for c in CASES:
        known = c["known"]
        secret = c["secret"]
        ct1 = _xor(known, KS[:len(known)])
        ct2 = _xor(secret, KS[:len(secret)])
        description = (
            "AES-GCM with REUSED nonce: the same 256-bit key and the same 96-bit nonce "
            "were used to encrypt two messages, so they share one CTR keystream.\n"
            "nonce=%s\n"
            "ct1=%s\n"
            "known_plaintext=%s\n"
            "ct2=%s\n"
            "Recover the second plaintext (the secret).\n"
            % (nonce.hex(), ct1.hex(), known.hex(), ct2.hex())
        )
        problems[c["name"]] = {
            "description": description,
            "flag_sha256": hashlib.sha256(secret).hexdigest(),
            "algo": "aes-gcm",
            "note": c["note"],
        }
    with open(OUT, "w", encoding="utf-8") as f:
        json.dump({"problems": problems}, f, ensure_ascii=False, indent=2)
    print("wrote %s (%d problems)" % (OUT, len(problems)))
    for n, p in problems.items():
        print("  %s -> flag_sha256=%s" % (n, p["flag_sha256"][:16]))


if __name__ == "__main__":
    main()
