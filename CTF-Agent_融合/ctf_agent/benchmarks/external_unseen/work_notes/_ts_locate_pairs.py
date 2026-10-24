#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""Locate every occurrence of the 17 printX 2-byte LE address pairs in the file,
and try strided-array detection (stride 2..80, any base) for a full permutation."""
import sys

PATH = r"E:/Program/西湖论剑/ctf_agent/data/questions_ext/_attachments/forensics/2017f-for-thoroughlystripped/thoroughlyStripped"
TARGET_SHA = "4f8f5c5944ea9bd62946f8be2f98aac6259b6937a5f72339504cf8ad5c5169b1"

with open(PATH, "rb") as f:
    data = f.read()

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

enc2char = {}
for addr, ch in funcs:
    enc2char[bytes([addr & 0xff, (addr >> 8) & 0xff])] = chr(ch)
pairs = list(enc2char.keys())
print(f"[*] {len(funcs)} funcs, {len(pairs)} distinct pairs")

# 1) dump all occurrence offsets of each pair
print("\n[*] occurrence offsets of each address pair:")
occ = {p: [] for p in pairs}
for off in range(0, len(data) - 1):
    p = data[off:off + 2]
    if p in occ:
        occ[p].append(off)
for p in pairs:
    ch = enc2char[p]
    print(f"    {p.hex()} ('{ch}') @ {[hex(o) for o in occ[p]]}")

# 2) strided array detection
print("\n[*] strided-array scan (stride 2..80):")
found_any = False
for S in range(2, 81):
    # base candidates: any offset where a known pair appears
    for B in range(0, len(data) - 16 * S - 1):
        if data[B:B + 2] not in enc2char:
            continue
        seq = []
        ok = True
        seen = set()
        for idx in range(17):
            o = B + idx * S
            if o + 2 > len(data):
                ok = False
                break
            p = data[o:o + 2]
            if p not in enc2char or p in seen:
                ok = False
                break
            seen.add(p)
            seq.append(enc2char[p])
        if ok and len(seen) == 17:
            order = "".join(seq)
            found_any = True
            import hashlib
            h = hashlib.sha256(order.encode()).hexdigest()
            print(f"    STRIDE={S} BASE=0x{B:04x} order={order!r} sha={h[:12]} {'MATCH' if h==TARGET_SHA else ''}")
            if h == TARGET_SHA:
                print(f"    >>> FLAG = {order}")
if not found_any:
    print("    (no strided full permutation found)")
