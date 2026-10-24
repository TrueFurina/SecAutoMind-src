#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""Find the printX function-pointer table.

Correct ELF mapping: vaddr(func at file-offset OFF) = TEXT_VADDR + (OFF - TEXT_OFF)
where TEXT_OFF = 0x374 (first printX) and TEXT_VADDR is the .text load address.
So V = B + OFF  with  B = TEXT_VADDR - 0x374.

Each table entry is stored as an 8-byte vaddr with high-order NULs stripped
(low-order zeros KEPT). We DFS-match a permutation of the 17 entry strings
anywhere in the file. 17 distinct matches -> flag order.
"""
import hashlib, itertools

PATH = r"E:/Program/西湖论剑/ctf_agent/data/questions_ext/_attachments/forensics/2017f-for-thoroughlystripped/thoroughlyStripped"
TARGET_SHA = "4f8f5c5944ea9bd62946f8be2f98aac6259b6937a5f72339504cf8ad5c5169b1"

with open(PATH, "rb") as f:
    data = f.read()

def strip_high(V):
    bs = V.to_bytes(8, "little")
    h = 7
    while h > 0 and bs[h] == 0:
        h -= 1
    return bs[:h + 1]

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

# candidate bases B = T - 0x374
def bases():
    seen = set()
    candidates = []
    def add(b):
        b &= 0xffffffffffffffff
        if b not in seen and -0x1000 <= b < 0x80000000:
            seen.add(b); candidates.append(b)
    # common .text vaddrs
    for T in (0, 0x400000, 0x800000, 0x1000000, 0x4000000, 0x10000000,
             0x40000000, 0x80000000, 0x555555554000 & 0xffffffffffffffff,
             0x400000000, 0x1000000000):
        add(T - 0x374)
    # fine grid
    for T in range(0, 0x420000, 0x1000):
        add(T - 0x374)
    for T in range(0, 0x2000, 0x8):
        add(T - 0x374)
    return candidates

def dfs(pos, used, order, entries):
    if len(used) == 17:
        return order
    for s, ch in entries:
        if ch in used:
            continue
        if data[pos:pos + len(s)] == s:
            r = dfs(pos + len(s), used | {ch}, order + ch, entries)
            if r:
                return r
    return None

found = []
for B in bases():
    entry_map = []  # (bytes, char)
    ok = True
    for off, ch in funcs:
        s = strip_high((B + off) & 0xffffffffffffffff)
        if not s:
            ok = False; break
        entry_map.append((s, chr(ch)))
    if not ok:
        continue
    # dedupe: if two same strings -> can't uniquely assign, still try (rare)
    firstbyte_entries = {}
    for s, ch in entry_map:
        firstbyte_entries.setdefault(s[0:1], []).append((s, ch))
    # quick pre-check: every entry's first byte must appear
    if not all(any(data[o:o+1] == s[0:1] for o in range(len(data))) for s, _ in entry_map):
        continue
    # try every start offset whose byte matches some entry first byte
    for p in range(len(data)):
        if data[p:p+1] not in firstbyte_entries:
            continue
        order = dfs(p, set(), "", entry_map)
        if order and len(order) == 17 and len(set(order)) == 17:
            cand = order
            h = hashlib.sha256(cand.encode()).hexdigest()
            found.append((B, p, cand, h))
            print(f"[B=0x{B:012x}] table@0x{p:04x} order={cand!r} sha={h[:12]} {'MATCH' if h==TARGET_SHA else ''}")
            if h == TARGET_SHA:
                print(f">>> FLAG = {cand}")
            break  # one hit per base enough

if not found:
    print("[!] no table found")
