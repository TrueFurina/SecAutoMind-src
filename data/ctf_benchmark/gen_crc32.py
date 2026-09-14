#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
生成 crc32_benchmark.json（CRC32 伪造，仅存 flag_sha256，绝不存明文 flag）

每题：给定消息(hex) 与其 CRC32，要求追加恰好 4 字节使 CRC32 命中目标值。
flag = flag{<4 字节后缀的 8 位十六进制>}。

运行：python gen_crc32.py
"""
import hashlib
import json
import os
import sys

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from judge_crc32 import crc32_std, forge_suffix, solve_from_text  # noqa: E402

HERE = os.path.dirname(os.path.abspath(__file__))
BENCH = os.path.join(HERE, "crc32_benchmark.json")

CASES = [
    {
        "name": "crc32_admin_forge",
        "msg": b"user=alice&role=user&admin=0",
        "target": 0xDEADBEEF,
    },
    {
        "name": "crc32_firmware_patch",
        "msg": bytes.fromhex("7f454c46020101000000000000000000"),
        "target": 0xCAFEBABE,
    },
    {
        "name": "crc32_request_tamper",
        "msg": b"GET /admin HTTP/1.1\r\nHost: target",
        "target": 0x0BADF00D,
    },
]


def main():
    problems = {}
    for cs in CASES:
        name = cs["name"]
        msg = cs["msg"]
        target = cs["target"]
        x = forge_suffix(msg, target)
        assert x is not None, "forge failed for %s" % name
        assert crc32_std(msg + x) == target, "forge mismatch for %s" % name
        flag = "flag{%s}" % x.hex()
        desc = (
            "The integrity of a message is protected with a CRC32 checksum. "
            "CRC32 is a linear checksum, not a MAC, so a 4-byte suffix can be forged.\n"
            "message (hex) = %s\n"
            "crc32 = %08x\n"
            "target = %08x\n"
            "Append exactly 4 bytes to the message so that CRC32(message || suffix) equals "
            "the target.\nSubmit the 4 appended bytes as flag{<8 hex>}.\n"
            % (msg.hex(), crc32_std(msg), target)
        )
        got = solve_from_text(desc)
        assert got == [flag], "selfcheck failed for %s: got %r want %r" % (name, got, [flag])
        problems[name] = {
            "description": desc,
            "flag_sha256": hashlib.sha256(flag.encode()).hexdigest(),
        }

    with open(BENCH, 'w', encoding='utf-8') as f:
        json.dump({"problems": problems}, f, ensure_ascii=False, indent=2)
    print("wrote %d problems -> %s" % (len(problems), os.path.basename(BENCH)))
    for name in problems:
        print("  -", name)


if __name__ == '__main__':
    main()
