import pickle, sys
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

INK = 200
bw = (img < INK)
colsum = bw.sum(axis=0)
# raw segments
segs = []
ing = False
for x, v in enumerate(colsum):
    if v > 0 and not ing:
        start = x; ing = True
    elif v == 0 and ing:
        segs.append([start, x]); ing = False
if ing:
    segs.append([start, len(colsum)])
# merge segments with gap <= 2
merged = [segs[0]]
for s, e in segs[1:]:
    if s - merged[-1][1] <= 2:
        merged[-1][1] = e
    else:
        merged.append([s, e])
print(f"segments after merge: {len(merged)}")

glyphs = []
for (s, e) in merged:
    sub = bw[:, s:e]
    rows = np.where(sub.any(axis=1))[0]
    glyphs.append((s, e, sub[rows.min():rows.max()+1, :]))

FONTS = [
    "/c/Windows/Fonts/times.ttf",
    "/c/Windows/Fonts/constan.ttf",
    "/c/Windows/Fonts/georgia.ttf",
    "/c/Windows/Fonts/cambria.ttc",
    "/c/Windows/Fonts/BOOKOS.TTF",
    "/c/Windows/Fonts/GARA.ttf",
    "/c/Windows/Fonts/arial.ttf",
    "/c/Windows/Fonts/calibri.ttf",
    "/c/Windows/Fonts/segoeui.ttf",
]
CHARS = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789_{}-"

def render_char(ch, font):
    im = Image.new("L", (60, 60), 255)
    dr = ImageDraw.Draw(im)
    dr.text((10, 10), ch, font=font, fill=0)
    a = np.array(im) < 128
    if not a.any():
        return None
    rows = np.where(a.any(axis=1))[0]
    cols = np.where(a.any(axis=0))[0]
    return a[rows.min():rows.max()+1, cols.min():cols.max()+1]

def match(glyph, tmpl):
    gh, gw = glyph.shape
    th, tw = tmpl.shape
    if abs(gh - th) > 3 or abs(gw - tw) > 3:
        return -1.0
    ti = Image.fromarray((tmpl * 255).astype(np.uint8)).resize((gw, gh), Image.LANCZOS)
    t = np.array(ti) > 128
    inter = (t & glyph).sum()
    union = (t | glyph).sum()
    return inter / union if union else 0

for fp in FONTS:
    try:
        for size in range(14, 22):
            font = ImageFont.truetype(fp, size)
            templates = {}
            ok = True
            for ch in CHARS:
                t = render_char(ch, font)
                if t is None:
                    ok = False
                    break
                templates[ch] = t
            if not ok:
                continue
            out = []
            total = 0
            for (s, e, g) in glyphs:
                best, bs = "?", -1
                for ch, t in templates.items():
                    sc = match(g, t)
                    if sc > bs:
                        bs, best = sc, ch
                out.append(best)
                total += max(bs, 0)
            text = "".join(out)
            if "CTF" in text or "rearview" in text or total / len(glyphs) > 0.7:
                print(f"{fp} size={size}: avg={total/len(glyphs):.3f}")
                print(f"   {text}")
    except Exception as ex:
        print(f"{fp}: ERR {ex}")
