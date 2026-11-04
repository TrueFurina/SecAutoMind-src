import pickle
import numpy as np
from PIL import Image, ImageDraw, ImageFont

d = pickle.load(open("_analysis/blocks2.pkl", "rb"))
blocks = d["blocks"]
ZIGZAG = [0,1,8,16,9,2,3,10,17,24,32,25,18,11,4,5,12,19,26,33,40,48,41,34,27,20,13,6,7,14,21,28,35,42,49,56,57,50,43,36,29,22,15,23,30,37,44,51,58,59,52,45,38,31,39,46,53,60,61,54,47,55,62,63]
Q = np.array(d["dqt"][0]).reshape(8, 8)
A = np.zeros((8, 8))
for x in range(8):
    for u in range(8):
        cu = (1 / np.sqrt(2)) if u == 0 else 1.0
        A[x, u] = 0.5 * cu * np.cos((2 * x + 1) * u * np.pi / 16)

def b2p(dc, acs):
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
    return np.clip(np.round(A @ F @ A.T + 128), 0, 255).astype(np.uint8)

db = [b for b in blocks if b[2] == 1 and b[8] and b[6]]
img = np.zeros((len(db) // 2 * 8, 16), dtype=np.uint8)
for i, b in enumerate(db):
    r, c = divmod(i, 2)
    img[r*8:(r+1)*8, c*8:(c+1)*8] = b2p(b[5], b[6])
img = np.rot90(img, 1)
strip = (img < 200)

FLAG = "CTF{rearview-monorail-mullets-backroom-stopped}"
FONTS = [
    "/c/Windows/Fonts/times.ttf",
    "/c/Windows/Fonts/constan.ttf",
    "/c/Windows/Fonts/georgia.ttf",
    "/c/Windows/Fonts/cambria.ttc",
    "/c/Windows/Fonts/BOOKOS.TTF",
    "/c/Windows/Fonts/arial.ttf",
    "/c/Windows/Fonts/calibri.ttf",
    "/c/Windows/Fonts/segoeui.ttf",
    "/c/Windows/Fonts/verdana.ttf",
    "/c/Windows/Fonts/tahoma.ttf",
    "/c/Windows/Fonts/SegoeUI.ttf",
]

best = []
for fp in FONTS:
    try:
        for size in range(13, 23):
            font = ImageFont.truetype(fp, size)
            bbox = font.getbbox(FLAG)
            w, h = bbox[2] - bbox[0], bbox[3] - bbox[1]
            if abs(w - 442) > 60:
                continue
            # render
            im = Image.new("L", (w + 20, h + 20), 255)
            dr = ImageDraw.Draw(im)
            dr.text((10 - bbox[0], 10 - bbox[1]), FLAG, font=font, fill=0)
            a = np.array(im) < 200
            rows = np.where(a.any(axis=1))[0]
            cols = np.where(a.any(axis=0))[0]
            g = a[rows.min():rows.max()+1, cols.min():cols.max()+1]
            # scale glyph to strip text bbox size (442 x 16) and compare
            gi = Image.fromarray((g * 255).astype(np.uint8)).resize((442, 16), Image.LANCZOS)
            gb = np.array(gi) > 128
            # strip text bbox
            srows = np.where(strip.any(axis=1))[0]
            scols = np.where(strip.any(axis=0))[0]
            sb = strip[srows.min():srows.max()+1, scols.min():scols.max()+1]
            inter = (gb & sb).sum()
            union = (gb | sb).sum()
            iou = inter / union if union else 0
            best.append((iou, fp, size, w, h))
    except Exception as ex:
        pass

best.sort(reverse=True)
for iou, fp, size, w, h in best[:10]:
    print(f"{iou:.3f}  {fp}  size={size}  textbox={w}x{h}")
