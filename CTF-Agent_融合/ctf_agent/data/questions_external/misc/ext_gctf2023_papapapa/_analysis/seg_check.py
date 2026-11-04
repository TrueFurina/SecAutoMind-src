# -*- coding: utf-8 -*-
"""开发期：新装配 strip 的分段检查 —— 段数 vs 47 字符，逐段打印。"""
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
    return np.clip(np.round(A @ F @ A.T + 128), 0, 255).astype(np.uint8)

pad = [b for b in blocks if b[2] == 1 and b[8]]
MY0 = min(b[1] for b in pad)
H = max(b[1] for b in pad) - MY0 + 1
img = np.zeros((H * 8, 16), dtype=np.uint8)
for b in pad:
    r, c = b[1] - MY0, b[3] - 1
    img[r*8:(r+1)*8, c*8:(c+1)*8] = block_to_pixels(b[5], b[6])
strip = np.rot90(img, 1)
print("strip:", strip.shape)

for THR in (200, 220, 235, 245):
    mask = strip < THR
    col_ink = mask.any(axis=0)
    segs = []
    i = 0; n = len(col_ink)
    while i < n:
        if col_ink[i]:
            j = i; last = i
            while j < n:
                if col_ink[j]:
                    last = j; j += 1
                else:
                    if j + 1 < n and col_ink[j+1]:
                        j += 2
                    else:
                        break
            segs.append((i, last + 1))
            i = last + 1
        else:
            i += 1
    # 噪声过滤：墨量 < 4 的段
    kept = [(a, b) for a, b in segs if mask[:, a:b].sum() >= 4]
    print(f"THR={THR}: raw segs={len(segs)} kept={len(kept)} (flag chars=47)")
    if THR == 235:
        print("  widths:", [b - a for a, b in kept])
        print("  ink:", [int(mask[:, a:b].sum()) for a, b in kept])
