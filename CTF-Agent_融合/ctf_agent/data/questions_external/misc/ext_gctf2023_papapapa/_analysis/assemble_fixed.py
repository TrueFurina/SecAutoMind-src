# -*- coding: utf-8 -*-
"""开发期：按 (my,bx) 坐标正确装配 strip（含 DC-only 均匀块），验证中间区对齐。"""
import pickle
import numpy as np

d = pickle.load(open("_analysis/blocks2.pkl", "rb"))
blocks = d["blocks"]
dqt = d["dqt"]
ZIGZAG = [0,1,8,16,9,2,3,10,17,24,32,25,18,11,4,5,12,19,26,33,40,48,41,34,27,20,13,6,7,14,21,28,35,42,49,56,57,50,43,36,29,22,15,23,30,37,44,51,58,59,52,45,38,31,39,46,53,60,61,54,47,55,62,63]
Q = np.array(dqt[0], dtype=np.float64).reshape(8, 8)
A = np.zeros((8, 8))
for x in range(8):
    for u in range(8):
        cu = (1 / np.sqrt(2)) if u == 0 else 1.0
        A[x, u] = 0.5 * cu * np.cos((2 * x + 1) * u * np.pi / 16)

def block_to_pixels(dc, acs):
    coef = np.zeros(64); coef[0] = dc; pos = 0
    for (run, v) in acs:
        pos += run + 1
        if pos < 64:
            coef[pos] = v
    F = np.zeros((8, 8))
    for k in range(64):
        nat = ZIGZAG[k]
        F[nat // 8][nat % 8] = coef[k] * Q[nat // 8][nat % 8]
    s = A @ F @ A.T
    if not acs:
        return np.clip(np.round(s + 128), 0, 255).astype(np.uint8)  # 均匀块
    return np.clip(np.round(s + 128), 0, 255).astype(np.uint8)

# 全部 Y padding 块（含无 AC 的）
pad = [b for b in blocks if b[2] == 1 and b[8]]
print(f"Y padding blocks (incl DC-only): {len(pad)}")
mys = sorted({b[1] for b in pad})
print("my range:", mys[0], "..", mys[-1], " count:", len(mys))
missing = [(my, bx) for my in mys for bx in (1, 2) if not any(b[1] == my and b[3] == bx for b in pad)]
print("missing (DC-only, rendered uniform):", missing)
for my, bx in missing:
    b = next(b for b in pad if b[1] == my and b[3] == bx)
    v = block_to_pixels(b[5], [])
    print(f"  ({my},{bx}) dc={b[5]&0xFF} uniform={v[0,0]}")

MY0 = mys[0]
H = mys[-1] - MY0 + 1
img = np.zeros((H * 8, 16), dtype=np.uint8)
for b in pad:
    r, c = b[1] - MY0, b[3] - 1
    img[r*8:(r+1)*8, c*8:(c+1)*8] = block_to_pixels(b[5], b[6])
strip = np.rot90(img, 1)
print("strip:", strip.shape)

RAMP = " .:-=+*#%@"
def ch(v):
    if v >= 250: return " "
    if v >= 238: return "."
    if v >= 226: return ":"
    if v >= 214: return "-"
    if v >= 202: return "="
    if v >= 190: return "+"
    if v >= 178: return "*"
    if v >= 160: return "#"
    if v >= 120: return "%"
    return "@"

import sys
LO = int(sys.argv[1]) if len(sys.argv) > 1 else 0
HI = int(sys.argv[2]) if len(sys.argv) > 2 else strip.shape[1]
for c0 in range(LO, HI, 60):
    c1 = min(c0 + 60, HI)
    print(f"\n===== cols {c0}-{c1-1} =====")
    for r in range(16):
        print("".join(ch(strip[r, c]) for c in range(c0, c1)))
