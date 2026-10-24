#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""Search thoroughlyStripped for the printX function-pointer table.

The binary has ALL NUL bytes removed, so addresses stored as 8-byte LE
pointers collapse to just their non-zero low bytes. The 17 printX functions
live at fixed 20-byte (0x14) strides starting at 0x374, each printing one char
(mov esi, imm8  ->  BE <char> ...). main calls them via a function-pointer
table (callq *(rsp,rbx,8)). We:
  1) byte-derive (entry_addr, char) for the 17 printX functions,
  2) build the 2-byte LE encoding of each entry address,
  3) scan every 34-byte window for a permutation of those 17 distinct pairs,
  4) for each hit, reconstruct the char order and test sha256 == target.
"""
import hashlib
import sys

PATH = r"E:/Program/西湖论剑/ctf_agent/data/questions_ext/_attachments/forensics/2017f-for-thoroughlystripped/thoroughlyStripped"
TARGET_SHA = "4f8f5c5944ea9bd62946f8be2f98aac6259b6937a5f72339504cf8ad5c5169b1"

with open(PATH, "rb") as f:
    data = f.read()

print(f"[*] file size = {len(data)} bytes; null count = {data.count(0)}")

# ---- 1) locate printX functions -------------------------------------------
# prologue: 55 48 89 e5  (push rbp ; mov rbp, rsp)
# inside:   BE <char> 48 8D 3D  -> mov esi, imm8 ; lea rdi, [rip+...]
PROLOGUE = b"\x55\x48\x89\xe5"
funcs = []  # (entry_addr, char)
i = 0
while True:
    j = data.find(PROLOGUE, i)
    if j < 0:
        break
    # scan up to 16 bytes after prologue for 'BE <c> 48 8D 3D'
    win = data[j:j + 18]
    k = win.find(b"\xbe")
    while k >= 0 and k + 6 <= len(win):
        # BE c 48 8D 3D  (c = char)
        if win[k + 2] == 0x48 and win[k + 3] == 0x8D and win[k + 4] == 0x3D:
            ch = win[k + 1]
            funcs.append((j, ch))
            break
        k = win.find(b"\xbe", k + 1)
    i = j + 1

print(f"[*] found {len(funcs)} printX candidates")
for addr, ch in sorted(funcs):
    print(f"    0x{addr:04x} -> {chr(ch)!r}")

if len(funcs) != 17:
    print("[!] expected 17 functions; aborting")
    sys.exit(1)

# ---- 2) build 2-byte LE encodings -----------------------------------------
pairs = {}  # 2-byte LE bytes -> char
for addr, ch in funcs:
    enc = bytes([addr & 0xff, (addr >> 8) & 0xff])
    pairs[enc] = ch
expected_set = set(pairs.keys())
print(f"[*] {len(expected_set)} distinct address-pair encodings")

# ---- 3) scan 34-byte windows for a permutation ---------------------------
W = 2 * len(funcs)  # 34
hits = []
for off in range(0, len(data) - W + 1):
    window = data[off:off + W]
    if len(window) % 2 != 0:
        continue
    seq = [window[t:t + 2] for t in range(0, W, 2)]
    if set(seq) == expected_set and len(set(seq)) == len(seq):
        # exact permutation, no repeated pair
        order = "".join(chr(pairs[s]) for s in seq)
        hits.append((off, order))

print(f"[*] {len(hits)} candidate table window(s)")
for off, order in hits:
    h = hashlib.sha256(order.encode()).hexdigest()
    ok = (h == TARGET_SHA)
    print(f"    off=0x{off:04x} order={order!r} sha256={h[:12]}... {'MATCH' if ok else ''}")
    if ok:
        print(f"    >>> FLAG = {order}")
