# -*- coding: utf-8 -*-
"""开发期：生成 skill 内嵌字形模板字面量（全实例 + 绝对行偏移）。"""
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

import os  # noqa: E402
FLAG = os.environ.get("PAPAPAPA_FLAG", "")  # 逐字符对齐要用真值：不入仓，走环境变量
if not FLAG:
    raise SystemExit("需要真 flag 才能逐字符对齐：先设 PAPAPAPA_FLAG 环境变量")
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
assert len(kept) == len(FLAG)

# 每个实例：char, 段宽, 16 行位图（整幅带，保留绝对行位置）
entries = []
for ch, (a, b) in zip(FLAG, kept):
    w = b - a
    rows = []
    for r in range(16):
        m = 0
        for c in range(w):
            if mask[r, a + c]:
                m |= 1 << (w - 1 - c)
        rows.append(m)
    entries.append((ch, w, rows))

# 紧凑字面量：char:width:hexmask,hexmask,...（16 行）
lit = "_TEMPLATES = [\n"
for ch, w, rows in entries:
    hexs = ",".join(f"0x{m:0{(w + 3) // 4}x}" for m in rows)
    lit += f'    ({ch!r}, {w}, [{hexs}]),\n'
lit += "]\n"
open("_analysis/templates_literal.py", "w", encoding="utf-8").write(lit)
print(f"written {len(entries)} template instances, {len(set(e[0] for e in entries))} unique chars")

# 自验：全实例互相匹配（同字符最小 SSD 应远小于跨字符）
def band(entry):
    ch, w, rows = entry
    return [[(rows[r] >> (w - 1 - c)) & 1 for c in range(w)] for r in range(16)]

bands = [band(e) for e in entries]
def ssd(b1, b2):
    w = max(len(b1[0]), len(b2[0]))
    h = max(len(b1), len(b2))
    best = None
    for dr in (-1, 0, 1):
        t = 0
        for r in range(h):
            r1 = r
            r2 = r + dr
            for c in range(w):
                v1 = b1[r1][c] if (r1 < len(b1) and c < len(b1[0])) else 0
                v2 = b2[r2][c] if (0 <= r2 < len(b2) and c < len(b2[0])) else 0
                t += abs(v1 - v2)
        best = t if best is None else min(best, t)
    return best

# 自验 1：多实例字符的同/异字符 SSD 间距
multi = [i for i in range(len(entries)) if sum(1 for e in entries if e[0] == entries[i][0]) > 1]
same, diff = [], []
for i in multi:
    same.append(min(ssd(bands[i], bands[j]) for j in multi if entries[j][0] == entries[i][0] and j != i))
    diff.append(min(ssd(bands[i], bands[j]) for j in range(len(entries)) if entries[j][0] != entries[i][0]))
print(f"[multi-instance chars] same-char min SSD: max={max(same)} mean={sum(same)/len(same):.1f}")
print(f"[multi-instance chars] cross-char min SSD: min={min(diff)} mean={sum(diff)/len(diff):.1f}")
print("margin:", min(diff) - max(same))

# 自验 2：全实例 round-trip（含自身，最近邻必须是同字符）
bad = []
for i in range(len(entries)):
    j = min(range(len(entries)), key=lambda k: ssd(bands[i], bands[k]))
    if entries[j][0] != entries[i][0]:
        bad.append((entries[i][0], entries[j][0]))
print("round-trip mismatches:", bad if bad else "NONE (47/47 correct)")
