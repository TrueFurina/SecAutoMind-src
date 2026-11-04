import pickle
import numpy as np
from PIL import Image

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

# IDCT matrix
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
    # coef is in zigzag order; place at natural position ZIGZAG[k]
    F = np.zeros((8, 8))
    for k in range(64):
        nat = ZIGZAG[k]
        F[nat // 8][nat % 8] = coef[k] * Q[nat // 8][nat % 8]
    s = A @ F @ A.T
    px = np.clip(np.round(s + 128), 0, 255).astype(np.uint8)
    return px

data_blocks = [b for b in blocks if b[2] == 1 and b[8] and b[6]]
print(f"{len(data_blocks)} data blocks")

pixels_list = [block_to_pixels(b[5], b[6]) for b in data_blocks]

# render at several widths
for W in (2, 3, 6, 19, 38, 57):
    H = (len(pixels_list) + W - 1) // W
    img = np.zeros((H * 8, W * 8), dtype=np.uint8)
    for i, px in enumerate(pixels_list):
        r, c = divmod(i, W)
        img[r*8:(r+1)*8, c*8:(c+1)*8] = px
    im = Image.fromarray(img, "L")
    im.save(f"_analysis/render_w{W}.png")
    print(f"saved render_w{W}.png ({W*8}x{H*8})")

# also the natural 2-wide strip, scaled up 4x for visibility
W = 2
H = len(pixels_list) // 2
img = np.zeros((H * 8, W * 8), dtype=np.uint8)
for i, px in enumerate(pixels_list):
    r, c = divmod(i, W)
    img[r*8:(r+1)*8, c*8:(c+1)*8] = px
im = Image.fromarray(img, "L").resize((W * 8 * 4, H * 8 * 4), Image.NEAREST)
im.save("_analysis/render_strip_2wide.png")
print("saved render_strip_2wide.png")
