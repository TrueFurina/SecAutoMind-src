# -*- coding: utf-8 -*-
"""开发期：定位中间区垂直位移 —— 逐 block 行打印墨行剖面 + block 元数据。"""
import pickle
import numpy as np

d = pickle.load(open("_analysis/blocks2.pkl", "rb"))
blocks = d["blocks"]
print("block tuple fields:", len(blocks[0]))
for i, b in enumerate(blocks[:12]):
    print(i, b[:9])

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

db = [b for b in blocks if b[2] == 1 and b[8] and b[6]]
print(f"\npadding data blocks: {len(db)}")
# 每个 block 的 8x8 像素 → 行剖面（每行墨量，阈值 245 细）
print("\nblk#  mx my bx  dc  | per-row ink counts (thr=245), 8 rows of the block")
for i, b in enumerate(db):
    px = block_to_pixels(b[5], b[6])
    cnt = [(px[r] < 245).sum() for r in range(8)]
    print(f"{i:3d} {b[0]:3d} {b[1]:3d} {b[3]} {b[5]&0xFF:5d} | {' '.join(f'{c:2d}' for c in cnt)}")
