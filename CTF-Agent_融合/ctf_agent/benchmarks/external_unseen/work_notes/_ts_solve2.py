#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""Solve thoroughlystripped.

main (0x4c8..0x54d) makes 26 `e8 rel32` calls to 17 wrapper functions laid on a
0x18-byte grid (0x330 + 0x18*k). Each wrapper invokes a leaf function whose body
is `55 48 89 e5 ... be <char> 48 8d 3d ...` (mov esi, 0x3d8d48<CHAR>). The leaf's
char is the flag char. Wrappers and leaves are emitted in the same order, so
wrapper rank k <-> leaf rank k. The call order in main == flag character order.
"""
import hashlib, struct

PATH = r"E:/Program/西湖论剑/ctf_agent/data/questions_ext/_attachments/forensics/2017f-for-thoroughlystripped/thoroughlyStripped"
TARGET_SHA = "4f8f5c5944ea9bd62946f8be2f98aac6259b6937a5f72339504cf8ad5c5169b1"

with open(PATH, "rb") as f:
    data = f.read()

# 1) leaf functions: prologue + 'be <char> 48 8d 3d'
PROLOGUE = b"\x55\x48\x89\xe5"
leaves = []  # (offset, char)
i = 0
while True:
    j = data.find(PROLOGUE, i)
    if j < 0:
        break
    win = data[j:j + 32]
    k = win.find(b"\xbe")
    while k >= 0 and k + 6 <= len(win):
        if win[k + 2] == 0x48 and win[k + 3] == 0x8D and win[k + 4] == 0x3D:
            leaves.append((j, chr(win[k + 1])))
            break
        k = win.find(b"\xbe", k + 1)
    i = j + 1
leaves.sort()
# keep only the true leaf grid: 0x374 + 0x14*k for k in 0..16
GRID = [0x374 + 0x14 * k for k in range(17)]
by_off = {o: c for o, c in leaves}
leaves = [(o, by_off[o]) for o in GRID if o in by_off]
print(f"[*] {len(leaves)} true leaf functions (chars by offset):")
print("    " + " ".join(f"0x{o:03x}:{c!r}" for o, c in leaves))

# 2) main e8 calls
MAIN = 0x4c8
END = 0x54d  # main ends with b8 5d c3
calls = []
i = MAIN
while i < END and i < len(data) - 5:
    if data[i] == 0xe8 and data[i + 1:i + 5] != b"\x00\x00\x00\x00":
        rel = struct.unpack("<i", data[i + 1:i + 5])[0]
        tgt = i + 5 + rel  # naive (shifted) target file offset
        calls.append((i, tgt))
        i += 5
    else:
        i += 1
print(f"[*] {len(calls)} e8 calls in main")
targets = [t for _, t in calls]
unique_targets = sorted(set(targets))
print(f"[*] {len(unique_targets)} unique targets: " + " ".join(f"0x{t:03x}" for t in unique_targets))

# 3) rank pairing: wrapper rank k <-> leaf rank k
#    unique targets sorted ascending give wrapper ranks; leaves sorted by offset give leaf ranks
leaf_chars = [c for _, c in leaves]
assert len(unique_targets) == len(leaf_chars), (len(unique_targets), len(leaf_chars))
target_rank = {t: r for r, t in enumerate(unique_targets)}

# build flag = chars in call order, mapped via rank
flag = "".join(leaf_chars[target_rank[t]] for t in targets)
print(f"[*] candidate flag ({len(flag)}): {flag!r}")
h = hashlib.sha256(flag.encode()).hexdigest()
print(f"[*] sha256={h}")
print(f"[*] match: {h == TARGET_SHA}")
if h == TARGET_SHA:
    print(f">>> FLAG = {flag}")

# Also try the 17-unique (dedup) version in call order, in case repeats are artifacts
seen = set()
uniq_flag = ""
for t in targets:
    if t not in seen:
        seen.add(t)
        uniq_flag += leaf_chars[target_rank[t]]
print(f"[*] dedup-by-target flag ({len(uniq_flag)}): {uniq_flag!r}")
h2 = hashlib.sha256(uniq_flag.encode()).hexdigest()
print(f"[*] sha256={h2} match={h2==TARGET_SHA}")
