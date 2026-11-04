import pickle
import numpy as np
from PIL import Image, ImageDraw, ImageFont

d = pickle.load(open("_analysis/blocks2.pkl", "rb"))
blocks = d["blocks"]
ZIGZAG = [0,1,8,16,9,2,3,10,17,24,32,25,18,11,4,5,12,19,26,33,40,48,41,34,27,20,13,6,7,14,21,28,35,42,49,56,57,50,43,36,29,22,15,23,30,37,44,51,58,59,52,45,38,31,39,46,53,60,61,54,47,55,62,63]
Q = np.array(d["dqt"][0]).reshape(8,8)
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
W = 2
H = len(db) // 2
img = np.zeros((H * 8, W * 8), dtype=np.uint8)
for i, b in enumerate(db):
    r, c = divmod(i, W)
    img[r*8:(r+1)*8, c*8:(c+1)*8] = b2p(b[5], b[6])
img = np.rot90(img, 1)  # CCW -> horizontal text
print("strip:", img.shape)

bw = (img < 128)
# segment glyphs by column projection
colsum = bw.sum(axis=0)
segs = []
in_g = False
for x, v in enumerate(colsum):
    if v > 0 and not in_g:
        start = x
        in_g = True
    elif v == 0 and in_g:
        segs.append((start, x))
        in_g = False
if in_g:
    segs.append((start, len(colsum)))
print(f"segments: {len(segs)}")

# glyph bitmaps
glyphs = []
for (s, e) in segs:
    sub = bw[:, s:e]
    rows = np.where(sub.any(axis=1))[0]
    glyphs.append((s, e, sub[rows.min():rows.max()+1, :]))

# render templates with times.ttf at candidate sizes
FONT = "/c/Windows/Fonts/times.ttf"
CHARS = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789_{}-"

def render_char(ch, size):
    font = ImageFont.truetype(FONT, size)
    im = Image.new("L", (size * 2, size * 2), 255)
    dr = ImageDraw.Draw(im)
    dr.text((size // 2, size // 2), ch, font=font, fill=0)
    a = np.array(im) < 128
    if not a.any():
        return None
    rows = np.where(a.any(axis=1))[0]
    cols = np.where(a.any(axis=0))[0]
    return a[rows.min():rows.max()+1, cols.min():cols.max()+1]

def match(glyph, tmpl):
    # resize template to glyph shape, compute IoU
    gh, gw = glyph.shape
    th, tw = tmpl.shape
    if abs(gh - th) > max(3, th * 0.35) or abs(gw - tw) > max(3, tw * 0.5):
        return -1.0
    ti = Image.fromarray((tmpl * 255).astype(np.uint8)).resize((gw, gh), Image.LANCZOS)
    t = np.array(ti) > 128
    inter = (t & glyph).sum()
    union = (t | glyph).sum()
    return inter / union if union else 0

for size in (19, 20, 21, 22):
    templates = {}
    for ch in CHARS:
        t = render_char(ch, size)
        if t is not None:
            templates[ch] = t
    out = []
    score_sum = 0
    for (s, e, g) in glyphs:
        best, bs = "?", -1
        for ch, t in templates.items():
            sc = match(g, t)
            if sc > bs:
                bs, best = sc, ch
        out.append(best)
        score_sum += bs
    text = "".join(out)
    print(f"size={size}: avg_score={score_sum/len(glyphs):.3f}")
    print(f"  text: {text}")
