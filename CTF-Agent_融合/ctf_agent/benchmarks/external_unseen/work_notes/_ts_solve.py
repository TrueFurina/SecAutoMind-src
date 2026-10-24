#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""Solve thoroughlystripped by following main's real `e8` calls.

main starts at 0x4c8. It is a sequence of `e8 rel32` direct calls whose
targets (file offsets) are the 17 char-printing functions laid out on a
0x18-byte grid starting at 0x330. The order of calls == flag character order.
For each call target we read the function body and extract the printed char
(`be <char> 48 8d 3d`  ==  mov esi, 0x3d8d48<char>).
"""
import hashlib, struct

PATH = r"E:/Program/西湖论剑/ctf_agent/data/questions_ext/_attachments/forensics/2017f-for-thoroughlystripped/thoroughlyStripped"
TARGET_SHA = "4f8f5c5944ea9bd62946f8be2f98aac6259b6937a5f72339504cf8ad5c5169b1"

with open(PATH, "rb") as f:
    data = f.read()

# 1) find main: first 'e8' after the last printX function region. Use known: main @ 0x4c8.
#    locate all e8 calls from 0x4c8 until we hit the epilogue (b8 5d c3 = mov eax,0x5d; ret).
MAIN = 0x4c8
calls = []
i = MAIN
while i < len(data) - 5:
    if data[i] == 0xe8:
        rel = struct.unpack("<i", data[i + 1:i + 5])[0]
        tgt = i + 5 + rel  # real target file offset (base-independent)
        # stop at epilogue
        if data[i + 1:i + 5] == b"\x00\x00\x00\x00":
            break
        calls.append((i, tgt))
        i += 5
    else:
        i += 1
    # stop if we reach the function epilogue of main
    if data[i - 5:i] == b"\xb8\x5d\xc3" or (i > MAIN + 5 and data[i - 3:i] == b"\xc3\x55\x48" and data[i-1]==0xc3):
        # crude: stop once we pass 0x540
        pass

print(f"[*] {len(calls)} e8 calls in main")

# 2) for each target, extract the printed char
def char_of(tgt):
    # function should start with prologue 55 48 89 e5
    if data[tgt:tgt + 4] != b"\x55\x48\x89\xe5":
        # maybe target is +4 (prologue skipped); scan a bit before/after
        for cand in (tgt, tgt - 4, tgt - 3, tgt + 4):
            if data[cand:cand + 4] == b"\x55\x48\x89\xe5":
                tgt = cand
                break
    win = data[tgt:tgt + 18]
    k = win.find(b"\xbe")
    while k >= 0 and k + 6 <= len(win):
        if win[k + 2] == 0x48 and win[k + 3] == 0x8D and win[k + 4] == 0x3D:
            return chr(win[k + 1])
        k = win.find(b"\xbe", k + 1)
    return "?"

chars = [char_of(t) for _, t in calls]
flag = "".join(chars)
print(f"[*] char sequence ({len(flag)}): {flag!r}")
h = hashlib.sha256(flag.encode()).hexdigest()
print(f"[*] sha256={h}")
print(f"[*] match target: {h == TARGET_SHA}")
if h == TARGET_SHA:
    print(f">>> FLAG = {flag}")

# also print target offsets for verification
print("[*] call targets:")
print("    " + " ".join(f"0x{t:03x}" for _, t in calls))
