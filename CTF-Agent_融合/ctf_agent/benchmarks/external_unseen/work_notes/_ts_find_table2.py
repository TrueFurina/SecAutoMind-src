#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""Find the printX function-pointer table by trying candidate load bases B.

For each candidate B, the table entry for a function at file-offset OFF is the
virtual address V = B + OFF. Because ALL NUL bytes were stripped per integer
field (high-order zero bytes removed, low-order zero bytes kept), the stored
form of V is: LE bytes [0 .. h] where h is the highest byte index that is
non-zero. We greedily match a permutation of the 17 such strings anywhere in
the file; a full 17-match gives the flag order.
"""
import hashlib

PATH = r"E:/Program/西湖论剑/ctf_agent/data/questions_ext/_attachments/forensics/2017f-for-thoroughlystripped/thoroughlyStripped"
TARGET_SHA = "4f8f5c5944ea9bd62946f8be2f98aac6259b6937a5f72339504cf8ad5c5169b1"

with open(PATH, "rb") as f:
    data = f.read()


def strip_high(V):
    """LE bytes of V with highest-order zero bytes removed (low zeros kept)."""
    bs = V.to_bytes(8, "little")
    h = 7
    while h > 0 and bs[h] == 0:
        h -= 1
    return bs[:h + 1]


# derive printX (offset, char)
PROLOGUE = b"\x55\x48\x89\xe5"
funcs = []
i = 0
while True:
    j = data.find(PROLOGUE, i)
    if j < 0:
        break
    win = data[j:j + 18]
    k = win.find(b"\xbe")
    while k >= 0 and k + 6 <= len(win):
        if win[k + 2] == 0x48 and win[k + 3] == 0x8D and win[k + 4] == 0x3D:
            funcs.append((j, win[k + 1]))
            break
        k = win.find(b"\xbe", k + 1)
    i = j + 1
assert len(funcs) == 17, len(funcs)

BASES = [0, 0x1000, 0x2000, 0x4000, 0x8000, 0x10000, 0x20000, 0x40000,
         0x80000, 0x100000, 0x200000, 0x400000, 0x600000, 0x800000,
         0x1000000, 0x2000000, 0x4000000, 0x8000000, 0x10000000,
         0x40000000, 0x80000000, 0x555555554000 & 0xffffffffffffffff]
# also a PIE-ish range near common bases
for extra in (0x100000000, 0x200000000, 0x400000000, 0x800000000):
    BASES.append(extra)

found = []
for B in BASES:
    entries = {}  # stripped bytes -> char
    ok = True
    for off, ch in funcs:
        s = strip_high((B + off) & 0xffffffffffffffff)
        if s in entries:
            ok = False
            break
        entries[s] = chr(ch)
    if not ok or len(entries) != 17:
        continue
    L = max(len(v) for v in entries)
    # greedy scan: for each start offset, consume a permutation
    for p in range(0, len(data)):
        pos = p
        used = set()
        order = []
        good = True
        for _ in range(17):
            matched = None
            for s, ch in entries.items():
                if ch in used:
                    continue
                if data[pos:pos + len(s)] == s:
                    matched = (s, ch)
                    break
            if matched is None:
                good = False
                break
            s, ch = matched
            used.add(ch)
            order.append(ch)
            pos += len(s)
        if good and len(used) == 17:
            cand = "".join(order)
            h = hashlib.sha256(cand.encode()).hexdigest()
            found.append((B, p, cand, h))
            print(f"[BASE=0x{B:012x}] table@0x{p:04x} order={cand!r} sha={h[:12]} {'MATCH' if h==TARGET_SHA else ''}")
            if h == TARGET_SHA:
                print(f">>> FLAG = {cand}")

if not found:
    print("[!] no table found for any candidate base")
