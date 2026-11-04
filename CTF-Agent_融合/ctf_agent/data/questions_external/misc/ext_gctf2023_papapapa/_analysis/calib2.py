# -*- coding: utf-8 -*-
"""开发期：新装配 + THR=200 分段 → 47 段 1:1 对齐 flag → 标定字形模板。"""
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

FLAG = "CTF{rearview-monorail-mullets-backroom-stopped}"
THR = 200
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
kept = [(a, b) for a, b in segs if mask[:, a:b].sum() >= 4]
assert len(kept) == len(FLAG), f"{len(kept)} segs != {len(FLAG)} chars"
print(f"OK: {len(kept)} segments 1:1 with flag")

# 逐字符位图（行裁到墨 bbox）
by_char = {}
for ch, (a, b) in zip(FLAG, kept):
    sub = mask[:, a:b]
    rows = np.where(sub.any(axis=1))[0]
    bm = sub[rows.min():rows.max()+1, :]
    by_char.setdefault(ch, []).append((a, bm))

# 同字符一致性检查
templates = []
for ch in sorted(by_char):
    insts = by_char[ch]
    flats = {tuple(map(tuple, bm.tolist())) for _, bm in insts}
    shapes = {bm.shape for _, bm in insts}
    status = "OK " if len(flats) == 1 else f"DIFF({len(flats)})"
    w = insts[0][1].shape[1]
    r0 = int(np.where(mask[:, insts[0][0]:insts[0][0]+w].any(axis=1))[0].min())
    print(f"  {ch!r}: x{len(insts)} w={w} h={insts[0][1].shape[0]} rows={r0}..{r0+insts[0][1].shape[0]-1} {status}")
    if len(flats) == 1:
        templates.append((ch, w, insts[0][1].tolist()))
    else:
        # 多形态：逐实例打印差异（开发期诊断）
        for a, bm in insts:
            print(f"     at col {a}: shape={bm.shape}")
            for r in bm:
                print("       " + "".join("#" if v else "." for v in r))

print(f"\nunique template chars: {len(templates)} / {len(set(FLAG))}")
np.save("_analysis/strip_fixed.npy", strip)
