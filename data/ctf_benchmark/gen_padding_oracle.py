#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
gen_padding_oracle.py —— 确定性合成 CBC Padding Oracle 攻击基准参数。

场景：一段明文经 AES-CBC 加密（PKCS#7 填充）。攻击者只有「oracle(ct)->bool」
（解密后末块填充是否合法），即可逐字节还原明文、取出其中的 flag。
本脚本固定 key/iv 与明文（含确定性 flag），加密后导出 ciphertext(IV||CT) 与
flag 的 SHA-256；与 Go tryPaddingOracle / Python judge_padding_oracle.py 双语言镜像。

用法: python gen_padding_oracle.py
"""
import hashlib
import json
import os

from Crypto.Cipher import AES
from Crypto.Util.Padding import pad

HERE = os.path.dirname(os.path.abspath(__file__))

# 固定 key / iv（确定性）
KEY = bytes.fromhex("2b7e151628aed2a6abf7158809cf4f3c")
IV = bytes.fromhex("000102030405060708090a0b0c0d0e0f")


def main():
    flag = "flag{3a9f1c7e8b2d4560aa11bb22cc33dd44}"
    plain = (
        "CBC padding oracle demo. The hidden credential is "
        + flag
        + ". Congrats on recovering it byte by byte."
    ).encode()

    padded = pad(plain, AES.block_size)
    ct = AES.new(KEY, AES.MODE_CBC, IV).encrypt(padded)

    # ciphertext = IV || CT
    blob = IV + ct
    flag_sha = hashlib.sha256(flag.encode()).hexdigest()

    description = (
        "CBC Padding Oracle attack. An oracle tells whether the CBC padding "
        "of a decrypted ciphertext is valid (PKCS#7).\n"
        "aes_key     = %s\n"
        "ciphertext  = %s\n"
        "Recover the plaintext; the flag is hidden inside it."
    ) % (KEY.hex(), blob.hex())

    bench = {
        "problems": {
            "cbc_padding_oracle_basic": {
                "description": description,
                "flag_sha256": flag_sha,
                "note": "CBC PKCS#7 padding oracle: recover plaintext byte-by-byte using only oracle's padding-validity bool (no key).",
            }
        }
    }
    out = os.path.join(HERE, "padding_oracle_benchmark.json")
    with open(out, "w", encoding="utf-8") as f:
        json.dump(bench, f, ensure_ascii=False, indent=2)
    print("生成基准: %s" % out)
    print("  flag       = %s" % flag)
    print("  flag_sha   = %s" % flag_sha)
    print("  ciphertext = %s" % blob.hex())
    print("  problems   = %d" % len(bench["problems"]))


if __name__ == "__main__":
    main()
