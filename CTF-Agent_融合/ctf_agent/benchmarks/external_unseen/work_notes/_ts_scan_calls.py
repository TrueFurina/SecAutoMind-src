#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""Scan raw bytes for `e8` (call rel32) instructions, parse the rel32 as a
variable-length little-endian integer (null bytes stripped globally), compute
the call target, and keep calls whose target is one of the 17 printX functions.
The file-offset order of matching call sites == flag character order."""
import hashlib

PATH = r"E:/Program/西湖论剑/ctf_agent/data/questions_ext/_attachments/forensics/2017f-for-thoroughlystripped/thoroughlyStripped"
TARGET_SHA = "4f8f5c5944ea9bd62946f8be2f98aac6259b6937a5f72339504cf8ad5c5169b1"

with open(PATH, "rb") as f:
    data = f.read()

# 1) derive printX (entry, char)
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

addr2char = {a: chr(c) for a, c in funcs}
print(f"[*] {len(funcs)} printX functions")
assert len(funcs) == 17, funcs

# 2) scan for e8
calls = []  # (e8_offset, target_addr)
n = len(data)
for p in range(n - 1):
    if data[p] != 0xe8:
        continue
    # try rel32 lengths 1..4 (high null bytes stripped -> variable length)
    for L in (1, 2, 3, 4):
        if p + 1 + L > n:
            break
        rel = int.from_bytes(data[p + 1:p + 1 + L], "little")
        # rel is signed 32-bit in reality; accept either signed or unsigned
        target = p + 5 + rel
        if target in addr2char:
            calls.append((p, target, L))
            break

# de-dup by offset (keep first length match)
seen = set()
uniq = []
for p, t, L in calls:
    if p in seen:
        continue
    seen.add(p)
    uniq.append((p, t))

print(f"[*] {len(uniq)} direct call sites to printX functions")
uniq.sort()
order = "".join(addr2char[t] for _, t in uniq)
print(f"[*] reconstructed order (by file offset): {order!r}")
h = hashlib.sha256(order.encode()).hexdigest()
print(f"[*] sha256={h}  {'MATCH' if h==TARGET_SHA else 'mismatch'}")
if h == TARGET_SHA:
    print(f">>> FLAG = {order}")
else:
    # also try reverse and other simple transforms
    print(f"[*] reversed: {order[::-1]!r} sha={hashlib.sha256(order[::-1].encode()).hexdigest()[:12]}")
