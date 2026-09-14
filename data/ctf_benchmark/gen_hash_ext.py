#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
生成 Hash Length Extension 双语言基准 (hash_ext_benchmark.json)。

确定性合成：固定 secret / known_data / extra，计算 known_hash = H(secret||known_data)，
再用与 judge 一致的 length_extend 求出 forged_mac，flag_sha256 = sha256(forged_mac)。
仅存 SHA-256，绝不存明文 flag。
"""
import hashlib
import json
import os

from judge_hash_ext import length_extend

HERE = os.path.dirname(os.path.abspath(__file__))
OUT = os.path.join(HERE, 'hash_ext_benchmark.json')

CASES = [
    {
        'name': 'hle_md5_basic',
        'algo': 'md5',
        'secret': b'flag{l3ngth_ext_m4d5_w1ns}',
        'known_data': b'user=guest',
        'extra': b';role=admin',
        'note': 'MD5(secret||data) 长度扩展，secret 未知，伪造含 role=admin 的 MAC',
    },
    {
        'name': 'hle_sha1_basic',
        'algo': 'sha1',
        'secret': b'flag{l3ngth_ext_sh4_w1ns}',
        'known_data': b'role=user',
        'extra': b'&admin=1',
        'note': 'SHA1(secret||data) 长度扩展，伪造含 admin=1 的 MAC',
    },
]


def main():
    problems = {}
    for c in CASES:
        algo = c['algo']
        secret = c['secret']
        known = c['known_data']
        extra = c['extra']
        known_hash = (hashlib.sha1(secret + known) if algo == 'sha1'
                      else hashlib.md5(secret + known)).hexdigest()
        forged, forged_mac = length_extend(algo, known_hash, known, extra, len(secret))
        description = (
            'This endpoint validates requests with MAC = %s(secret || data) where secret is '
            'unknown. Perform a length extension attack to append data without knowing the secret.\n'
            'known_hash=%s\n'
            'known_message=%s\n'
            'append=%s\n'
            'secret_length=%d\n'
            % (algo, known_hash, known.decode(), extra.decode(), len(secret))
        )
        problems[c['name']] = {
            'description': description,
            'flag_sha256': hashlib.sha256(forged_mac.encode()).hexdigest(),
            'algo': algo,
            'note': c['note'],
        }
    with open(OUT, 'w', encoding='utf-8') as f:
        json.dump({'problems': problems}, f, ensure_ascii=False, indent=2)
    print('wrote %s (%d problems)' % (OUT, len(problems)))
    for n, p in problems.items():
        print('  %s -> flag_sha256=%s' % (n, p['flag_sha256'][:16]))


if __name__ == '__main__':
    main()
