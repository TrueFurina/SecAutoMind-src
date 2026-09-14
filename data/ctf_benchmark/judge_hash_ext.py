#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
Hash Length Extension 攻击 · 双语言镜像 (Python 侧, 纯标准库)

与 Go 侧 internal/ctfplatform/hash_ext_attack.go 独立实现、互相印证：
- 手动实现 MD5 / SHA1 Merkle–Damgård 单块压缩续算（不依赖任何第三方库）
- 从已知 MAC = H(secret||known_data) 伪造 H(secret||known_data||glue1||extra)
- 全基准集中只存 flag_sha256，绝不存明文

运行：
    python judge_hash_ext.py                 # 校验 hash_ext_benchmark.json
    python judge_hash_ext.py --selfcheck    # 与标准库 hashlib 交叉验证实现正确性
"""
import argparse
import hashlib
import json
import os
import re
import struct
import sys

HERE = os.path.dirname(os.path.abspath(__file__))
BENCH = os.path.join(HERE, "hash_ext_benchmark.json")


# ───────────────────────── MD5 / SHA1 手动压缩 ─────────────────────────

def _rotl32(x, s):
    s &= 31
    return ((x << s) | (x >> (32 - s))) & 0xFFFFFFFF


_MD5_K = [
    0xd76aa478, 0xe8c7b756, 0x242070db, 0xc1bdceee, 0xf57c0faf, 0x4787c62a, 0xa8304613, 0xfd469501,
    0x698098d8, 0x8b44f7af, 0xffff5bb1, 0x895cd7be, 0x6b901122, 0xfd987193, 0xa679438e, 0x49b40821,
    0xf61e2562, 0xc040b340, 0x265e5a51, 0xe9b6c7aa, 0xd62f105d, 0x02441453, 0xd8a1e681, 0xe7d3fbc8,
    0x21e1cde6, 0xc33707d6, 0xf4d50d87, 0x455a14ed, 0xa9e3e905, 0xfcefa3f8, 0x676f02d9, 0x8d2a4c8a,
    0xfffa3942, 0x8771f681, 0x6d9d6122, 0xfde5380c, 0xa4beea44, 0x4bdecfa9, 0xf6bb4b60, 0xbebfbc70,
    0x289b7ec6, 0xeaa127fa, 0xd4ef3085, 0x04881d05, 0xd9d4d039, 0xe6db99e5, 0x1fa27cf8, 0xc4ac5665,
    0xf4292244, 0x432aff97, 0xab9423a7, 0xfc93a039, 0x655b59c3, 0x8f0ccc92, 0xffeff47d, 0x85845dd1,
    0x6fa87e4f, 0xfe2ce6e0, 0xa3014314, 0x4e0811a1, 0xf7537e82, 0xbd3af235, 0x2ad7d2bb, 0xeb86d391,
]
_MD5_S = ([7, 12, 17, 22] * 4) + ([5, 9, 14, 20] * 4) + ([4, 11, 16, 23] * 4) + ([6, 10, 15, 21] * 4)
_MD5_IV = [0x67452301, 0xefcdab89, 0x98badcfe, 0x10325476]
_SHA1_IV = [0x67452301, 0xEFCDAB89, 0x98BADCFE, 0x10325476, 0xC3D2E1F0]
_SHA1_K = [0x5A827999, 0x6ED9EBA1, 0x8F1BBCDC, 0xCA62C1D6]


def _md5_compress(state, block):
    a, b, c, d = state
    x = list(struct.unpack('<16I', block))
    for i in range(64):
        if i < 16:
            f = (b & c) | ((~b & 0xFFFFFFFF) & d)
            g = i
        elif i < 32:
            f = (b & d) | (c & (~d & 0xFFFFFFFF))
            g = (5 * i + 1) % 16
        elif i < 48:
            f = b ^ c ^ d
            g = (3 * i + 5) % 16
        else:
            f = c ^ (b | (~d & 0xFFFFFFFF))
            g = (7 * i) % 16
        f = (f + a + _MD5_K[i] + x[g]) & 0xFFFFFFFF
        a, b, c, d = d, (b + _rotl32(f, _MD5_S[i])) & 0xFFFFFFFF, b, c
    return [(v + s) & 0xFFFFFFFF for v, s in zip([a, b, c, d], state)]


def _sha1_compress(state, block):
    w = list(struct.unpack('>16I', block))
    for i in range(16, 80):
        w.append(_rotl32(w[i - 3] ^ w[i - 8] ^ w[i - 14] ^ w[i - 16], 1))
    a, b, c, d, e = state
    for i in range(80):
        if i < 20:
            f = (b & c) | ((~b & 0xFFFFFFFF) & d)
            k = _SHA1_K[0]
        elif i < 40:
            f = b ^ c ^ d
            k = _SHA1_K[1]
        elif i < 60:
            f = (b & c) | (b & d) | (c & d)
            k = _SHA1_K[2]
        else:
            f = b ^ c ^ d
            k = _SHA1_K[3]
        tmp = (_rotl32(a, 5) + f + e + k + w[i]) & 0xFFFFFFFF
        e, d, c, b, a = d, c, _rotl32(b, 30), a, tmp
    return [(v + s) & 0xFFFFFFFF for v, s in zip([a, b, c, d, e], state)]


def _glue_padding(msg_len, bs, algo):
    pad = b'\x80'
    while (msg_len + len(pad)) % bs != bs - 8:
        pad += b'\x00'
    bitlen = msg_len * 8
    if algo == 'sha1':
        pad += struct.pack('>Q', bitlen)
    else:
        pad += struct.pack('<Q', bitlen)
    return pad


def length_extend(algo, known_hash_hex, known_data, extra, secret_len):
    """从 known_hash（H(secret||known_data) 摘要）续算 forged 的 MAC。返回 (forged_msg, forged_mac_hex)。"""
    bs = 64
    kh = bytes.fromhex(known_hash_hex)
    if algo == 'md5':
        state = list(struct.unpack('<4I', kh))
        compress = _md5_compress
    elif algo == 'sha1':
        state = list(struct.unpack('>5I', kh))
        compress = _sha1_compress
    else:
        raise ValueError('unsupported algo: %s' % algo)

    glue1 = _glue_padding(secret_len + len(known_data), bs, algo)
    forged = known_data + glue1 + extra
    glue2 = _glue_padding(secret_len + len(forged), bs, algo)
    tofeed = (extra + glue2).encode() if isinstance(extra, str) else extra + glue2
    st = list(state)
    for off in range(0, len(tofeed), bs):
        st = compress(st, tofeed[off:off + bs])
    if algo == 'md5':
        digest = struct.pack('<4I', *st)
    else:
        digest = struct.pack('>5I', *st)
    return forged, digest.hex()


# ───────────────────────── 问题解析（镜像 Go 侧正则） ─────────────────────────

_RE_HASH = re.compile(r'(?:known[_\s]?hash|known[_\s]?mac|hash|mac)\s*[:=]\s*([0-9a-fA-F]{40}|[0-9a-fA-F]{32})', re.I)
_RE_DATA = re.compile(r'(?:known[_\s]?message|known[_\s]?data|message|data)\s*[:=]\s*([^\r\n]+)', re.I)
_RE_EXTRA = re.compile(r'(?:append|extra|add|suffix|new[_\s]?message|forged[_\s]?message)\s*[:=]\s*([^\r\n]+)', re.I)
_RE_SECRET = re.compile(r'(?:secret[_\s]?length|length[_\s]?of[_\s]?secret|secret[_\s]?len|secret[_\s]?is)\s*[:=]?\s*(\d+)', re.I)
_RE_ALGO = re.compile(r'\b(sha-?1|md5)\b', re.I)
_RE_SIGNAL = re.compile(r'(length[_\s-]?extension|hash[_\s-]?ext|secret[_\s-]?prefix|glue[_\s-]?padding|append[_\s-]?data)', re.I)


def solve_from_text(text):
    if not _RE_SIGNAL.search(text):
        return []
    algo = 'md5'
    am = _RE_ALGO.search(text)
    if am:
        algo = 'sha1' if am.group(1).lower().startswith('sha') else 'md5'
    hm = _RE_HASH.search(text)
    dm = _RE_DATA.search(text)
    em = _RE_EXTRA.search(text)
    if not (hm and dm and em):
        return []
    algo = 'sha1' if len(hm.group(1)) == 40 else ('md5' if len(hm.group(1)) == 32 else algo)
    secret_len = None
    sm = _RE_SECRET.search(text)
    if sm:
        secret_len = int(sm.group(1))
    known_hash = hm.group(1)
    known_data = dm.group(1).strip().encode()
    extra = em.group(1).strip().encode()
    lens = [secret_len] if secret_len else list(range(1, 65))
    out = set()
    for L in lens:
        try:
            _, mac = length_extend(algo, known_hash, known_data, extra, L)
        except Exception:
            continue
        out.add(mac)
    return list(out)


# ───────────────────────── 校验入口 ─────────────────────────

def run():
    with open(BENCH, 'r', encoding='utf-8') as f:
        data = json.load(f)
    total = len(data['problems'])
    hit = 0
    for name, p in data['problems'].items():
        cands = solve_from_text(p['description'])
        want = p['flag_sha256'].lower()
        ok = any(hashlib.sha256(c.encode()).hexdigest() == want for c in cands)
        print(('HIT  ' if ok else 'MISS ') + name)
        hit += 1 if ok else 0
    print('HLE %d/%d' % (hit, total))
    return total, hit


def selfcheck():
    """与标准库交叉验证手动压缩逐字节一致 + 攻击在服务端通过。"""
    for algo in ('md5', 'sha1'):
        iv = _SHA1_IV if algo == 'sha1' else _MD5_IV
        compress = _sha1_compress if algo == 'sha1' else _md5_compress
        for s in ('', 'abc', 'The quick brown fox jumps over the lazy dog',
                 'x' * 55, 'y' * 64, 'z' * 100):
            ref = (hashlib.sha1(s.encode()) if algo == 'sha1' else hashlib.md5(s.encode())).digest()
            msg = s.encode() + _glue_padding(len(s), 64, algo)
            st = list(iv)
            for off in range(0, len(msg), 64):
                st = compress(st, msg[off:off + 64])
            got = (struct.pack('>5I', *st) if algo == 'sha1' else struct.pack('<4I', *st))
            assert got == ref, 'manual %s mismatch for %r' % (algo, s)
    # 攻击端到端
    for algo, secret, known, extra in (
            ('md5', b'flag{l3ngth_ext_m4d5_w1ns}', b'user=guest', b';role=admin'),
            ('sha1', b'flag{l3ngth_ext_sh4_w1ns}', b'role=user', b'&admin=1')):
        km = (hashlib.sha1(secret + known) if algo == 'sha1' else hashlib.md5(secret + known)).hexdigest()
        forged, mac = length_extend(algo, km, known, extra, len(secret))
        ref = (hashlib.sha1(secret + forged) if algo == 'sha1' else hashlib.md5(secret + forged)).hexdigest()
        assert mac == ref, 'forged MAC rejected by server (%s)' % algo
        print('selfcheck OK: %s forged_mac=%s' % (algo, mac))
    print('ALL SELFCHECK PASS')


if __name__ == '__main__':
    ap = argparse.ArgumentParser()
    ap.add_argument('--selfcheck', action='store_true')
    args = ap.parse_args()
    if args.selfcheck:
        selfcheck()
        sys.exit(0)
    run()
