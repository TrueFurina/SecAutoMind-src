#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
AES-GCM nonce 复用攻击 · 双语言镜像 (Python 侧, 纯标准库)

与 Go 侧 internal/ctfplatform/gcm_nonce_reuse.go 独立实现、互相印证：
- 同密钥 + 同 96-bit nonce 加密两条明文 → 共享同一条 CTR keystream
- 已知明文 m1 与其密文 C1 → 还原 keystream KS = C1 ⊕ m1
- 复原 m2 = C2 ⊕ KS = C2 ⊕ C1 ⊕ m1（无需密钥、无需 AES）
- 全基准集中只存 flag_sha256，绝不存明文

运行：
    python judge_gcm_nr.py                 # 校验 gcm_nonce_reuse_benchmark.json
    python judge_gcm_nr.py --selfcheck    # 构造随机场景验证 keystream 复原正确性
"""
import argparse
import hashlib
import json
import os
import re
import sys

HERE = os.path.dirname(os.path.abspath(__file__))
BENCH = os.path.join(HERE, "gcm_nonce_reuse_benchmark.json")

_RE_SIGNAL = re.compile(r'(?i)\b(gcm|nonce[_\s-]?reuse|reused[_\s-]?nonce|same[_\s-]?nonce|same[_\s-]?iv|keystream|aes-?gcm|ctr[_\s-]?mode)\b')
_RE_NONCE = re.compile(r'(?i)\bnonce\s*[:=]\s*([0-9a-fA-F]+)')
_RE_CT1 = re.compile(r'(?i)\b(?:ct1|ciphertext1)\s*[:=]\s*([0-9a-fA-F]+)')
_RE_CT2 = re.compile(r'(?i)\b(?:ct2|ciphertext2)\s*[:=]\s*([0-9a-fA-F]+)')
_RE_KNOWN = re.compile(r'(?i)known[_\s-]?plaintext\s*[:=]\s*([0-9a-fA-F]+)')
_RE_BLOB1 = re.compile(r'(?i)\bblob1\s*[:=]\s*([0-9a-fA-F]+)')
_RE_BLOB2 = re.compile(r'(?i)\bblob2\s*[:=]\s*([0-9a-fA-F]+)')


def _xor(a, b):
    n = min(len(a), len(b))
    return bytes(x ^ y for x, y in zip(a[:n], b[:n]))


def _decode_known(s):
    s = s.strip()
    if len(s) % 2 == 0:
        try:
            return bytes.fromhex(s)
        except ValueError:
            pass
    return s.encode()


def _split_blob(b):
    if len(b) < 12 + 16 + 1:
        return None, None, None
    return b[:12], b[12:len(b) - 16], b[len(b) - 16:]


def solve_from_text(text):
    """从题目描述解析并复原第二条明文，返回 [bytes(m2)] 或 []。"""
    if not _RE_SIGNAL.search(text):
        return []
    # 形态 1：显式字段
    if m1 := _RE_CT1.search(text):
        m2 = _RE_CT2.search(text)
        km = _RE_KNOWN.search(text)
        if not (m2 and km):
            return []
        try:
            ct1 = bytes.fromhex(m1.group(1))
            ct2 = bytes.fromhex(m2.group(1))
        except ValueError:
            return []
        known = _decode_known(km.group(1))
        ks = _xor(ct1, known)
        return [_xor(ct2, ks)]
    # 形态 2：完整 GCM blob（nonce‖ciphertext‖tag）
    if b1 := _RE_BLOB1.search(text):
        b2 = _RE_BLOB2.search(text)
        km = _RE_KNOWN.search(text)
        if not (b2 and km):
            return []
        try:
            raw1 = bytes.fromhex(b1.group(1))
            raw2 = bytes.fromhex(b2.group(1))
        except ValueError:
            return []
        _, c1, _ = _split_blob(raw1)
        _, c2, _ = _split_blob(raw2)
        if c1 is None or c2 is None:
            return []
        known = _decode_known(km.group(1))
        ks = _xor(c1, known)
        return [_xor(c2, ks)]
    return []


def run():
    with open(BENCH, 'r', encoding='utf-8') as f:
        data = json.load(f)
    total = len(data['problems'])
    hit = 0
    for name, p in data['problems'].items():
        cands = solve_from_text(p['description'])
        want = p['flag_sha256'].lower()
        ok = False
        for c in cands:
            if isinstance(c, bytes):
                if hashlib.sha256(c).hexdigest() == want:
                    ok = True
                    break
            else:
                if hashlib.sha256(c.encode()).hexdigest() == want:
                    ok = True
                    break
        print(('HIT  ' if ok else 'MISS ') + name)
        hit += 1 if ok else 0
    print('GCMNR %d/%d' % (hit, total))
    return total, hit


def selfcheck():
    """构造随机 keystream 场景，验证 keystream 复原逐字节正确。"""
    import os as _os
    for i in range(5):
        ks = _os.urandom(64)
        known = ('known plaintext block %d with plenty of bytes to cover!!!' % i).encode()
        secret = ('flag{gcm_nr_selfcheck_%d_abcdefghijklmnop}' % i).encode()
        if len(ks) < max(len(known), len(secret)):
            ks = ks + _os.urandom(64)
        ct1 = _xor(known, ks[:len(known)])
        ct2 = _xor(secret, ks[:len(secret)])
        desc = ("AES-GCM reused nonce scenario #%d.\n" % i) + \
               "nonce=" + _os.urandom(12).hex() + "\n" + \
               "ct1=" + ct1.hex() + "\n" + \
               "known_plaintext=" + known.hex() + "\n" + \
               "ct2=" + ct2.hex() + "\n"
        cands = solve_from_text(desc)
        assert cands and bytes(cands[0]) == secret, "selfcheck failed #%d: %r" % (i, cands)
    print('SELFCHECK PASS (keystream recovery, 5 rounds)')


if __name__ == '__main__':
    ap = argparse.ArgumentParser()
    ap.add_argument('--selfcheck', action='store_true')
    args = ap.parse_args()
    if args.selfcheck:
        selfcheck()
        sys.exit(0)
    run()
