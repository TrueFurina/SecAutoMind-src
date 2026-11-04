# -*- coding: utf-8 -*-
"""开发期脚本：从 papapapa payload 标定 OCR 字形模板（仅开发用，不入 skills/）。

流程：blocks2.pkl（已验证解码工件）→ 2 宽布局 → rot90 CCW → 阈值 180 二值化
→ 列墨剖面分段（合并 ≤1px 间隙）→ 用已知 flag 对齐拆分粘连段 → 逐唯一字符
提取墨位图 → 校验同字符多实例一致性 → 吐出紧凑 Python 字面量。
"""
import pickle
import numpy as np

FLAG = "CTF{rearview-monorail-mullets-backroom-stopped}"  # 仅开发期对齐用

d = pickle.load(open("_analysis/blocks2.pkl", "rb"))
blocks = d["blocks"]
dqt = d["dqt"]

ZIGZAG = [
     0,  1,  8, 16,  9,  2,  3, 10,
    17, 24, 32, 25, 18, 11,  4,  5,
    12, 19, 26, 33, 40, 48, 41, 34,
    27, 20, 13,  6,  7, 14, 21, 28,
    35, 42, 49, 56, 57, 50, 43, 36,
    29, 22, 15, 23, 30, 37, 44, 51,
    58, 59, 52, 45, 38, 31, 39, 46,
    53, 60, 61, 54, 47, 55, 62, 63]

Q = np.array(dqt[0], dtype=np.float64).reshape(8, 8)
A = np.zeros((8, 8))
for x in range(8):
    for u in range(8):
        cu = (1 / np.sqrt(2)) if u == 0 else 1.0
        A[x, u] = 0.5 * cu * np.cos((2 * x + 1) * u * np.pi / 16)

def block_to_pixels(dc, acs):
    coef = np.zeros(64)
    coef[0] = dc
    pos = 0
    for (run, v) in acs:
        pos += run + 1
        if pos < 64:
            coef[pos] = v
    F = np.zeros((8, 8))
    for k in range(64):
        nat = ZIGZAG[k]
        F[nat // 8][nat % 8] = coef[k] * Q[nat // 8][nat % 8]
    s = A @ F @ A.T
    return np.clip(np.round(s + 128), 0, 255).astype(np.uint8)

data_blocks = [b for b in blocks if b[2] == 1 and b[8] and b[6]]
print(f"data blocks: {len(data_blocks)}")

W = 2
H = len(data_blocks) // 2
img = np.zeros((H * 8, W * 8), dtype=np.uint8)
for i, b in enumerate(data_blocks):
    r, c = divmod(i, W)
    img[r*8:(r+1)*8, c*8:(c+1)*8] = block_to_pixels(b[5], b[6])

img = np.rot90(img, 1)  # CCW → 16 tall x 456 wide
print("strip:", img.shape)
mask = img < 180
print("ink px:", mask.sum())

# 列墨剖面分段（合并 <=1px 间隙）
col_ink = mask.any(axis=0)
segs = []
i = 0
n = len(col_ink)
while i < n:
    if col_ink[i]:
        j = i
        last_ink = i
        while j < n:
            if col_ink[j]:
                last_ink = j
                j += 1
            else:
                # 允许 <=1px 间隙
                if j + 1 < n and col_ink[j+1]:
                    j += 2
                else:
                    break
        segs.append((i, last_ink + 1))
        i = last_ink + 1
    else:
        i += 1
print(f"segments: {len(segs)}  flag chars: {len(FLAG)}")
print("segment widths:", [b - a for a, b in segs])

# 用已知 flag 对齐：DFS 把每段拆成字符序列（段内间隙 0 或 1 px）
def char_bitmap(ch, x0, x1):
    sub = mask[:, x0:x1]
    rows = np.where(sub.any(axis=1))[0]
    return sub[rows.min():rows.max()+1, :]

# 先取每字符的墨宽（从段拆分递归获得）
widths = {}
def split_segment(a, b, chars):
    """把 [a,b) 段拆成 chars 序列；返回每字符 (x0,x1)。"""
    res = []
    x = a
    for k, ch in enumerate(chars):
        w = widths[ch]
        if k == 0:
            res.append((x, x + w))
            x += w
        else:
            # 段内间隙：0 或 1（由剩余宽度决定）
            remaining = b - x
            rest = chars[k:]
            need = sum(widths[c] for c in rest)
            gap = remaining - need
            assert gap in (0, len(rest) - 1), f"bad gap {gap} at {ch} seg=({a},{b})"
            # 间隙优先放在每个字符前 1px（比例字体，保守取 0 除非被迫）
            x += 0 if gap < len(rest) else 1
            res.append((x, x + w))
            x += w
    assert x <= b, f"overflow {x} > {b}"
    return res

# 第一遍：前 12 段精确对应 "CTF{rearview" → 建 widths
first12 = FLAG[:12]
assert len(segs) >= 12
for (a, b), ch in zip(segs[:12], first12):
    widths[ch] = b - a
print("widths from first 12:", widths)

# 全 flag 拆分（逐段 DFS 简化：顺序消费）
assign = []  # (char, x0, x1)
ci = 0
for si, (a, b) in enumerate(segs):
    if si < 12:
        for k, ch in enumerate(first12):
            assign.append((ch, a + widths[ch] * 0, 0))  # placeholder, 下面重算
        # 直接按 widths 切
        assign = assign[:len(assign) - 12]
        x = a
        for ch in first12:
            assign.append((ch, x, x + widths[ch]))
            x += widths[ch]
        ci = 12
        continue
    # 后续段：显式栈 DFS 找字符组合使 sum(widths)+内部间隙 == 段宽
    seg_w = b - a
    found = None
    stack = [(0, a, [])]
    while stack:
        k, x, acc = stack.pop()
        if found is not None:
            break
        if x == b and acc:
            found = acc
            break
        for L in range(1, 6):
            if ci + L > len(FLAG):
                break
            chars = FLAG[ci:ci+L]
            if any(c not in widths for c in chars):
                continue
            import itertools
            for gcombo in itertools.product((0, 1), repeat=L-1):
                total = sum(widths[c] for c in chars) + sum(gcombo)
                if x + total > b:
                    continue
                xx = x
                acc2 = []
                for idx, c in enumerate(chars):
                    if idx > 0:
                        xx += gcombo[idx-1]
                    acc2.append((c, xx, xx + widths[c]))
                    xx += widths[c]
                if x + total == b:
                    found = acc + acc2
                    stack = []
                    break
                else:
                    stack.append((k+1, xx, acc + acc2))
            if found is not None:
                break
    assert found, f"segment {si} ({a},{b}) w={seg_w} cannot align at ci={ci} (next char {FLAG[ci]!r})"
    assign.extend(found)
    ci += len(found)

assert "".join(c for c, _, _ in assign) == FLAG, "alignment mismatch"
print(f"aligned {len(assign)} chars")

# 提取每字符墨位图（按行也裁到墨bbox），校验同字符一致性
by_char = {}
for ch, x0, x1 in assign:
    bm = char_bitmap(ch, x0, x1)
    by_char.setdefault(ch, []).append((bm.shape, bm.tolist()))

templates = []
for ch in sorted(by_char):
    insts = by_char[ch]
    shapes = {s for s, _ in insts}
    assert len(shapes) == 1, f"char {ch!r} inconsistent shapes: {shapes}"
    rows = insts[0][1]
    uniq = {tuple(r) for _, bm in insts for r in bm}
    # 展平校验：同字符所有实例逐行一致
    flat = {tuple(tuple(r) for r in bm) for _, bm in insts}
    assert len(flat) == 1, f"char {ch!r} has {len(flat)} distinct bitmaps"
    w = len(rows[0])
    templates.append((ch, w, rows))
    print(f"  {ch!r}: w={w} h={len(rows)} x{len(insts)}")

print(f"\nunique chars: {len(templates)}")
# 吐紧凑字面量
lit = "_TEMPLATES = [\n"
for ch, w, rows in templates:
    rowstr = ",".join("0b" + "".join("1" if v else "0" for v in r) for r in rows)
    lit += f'    ({ch!r}, {w}, [{rowstr}]),\n'
lit += "]\n"
open("_analysis/templates_literal.py", "w", encoding="utf-8").write(lit)
print("written _analysis/templates_literal.py")
