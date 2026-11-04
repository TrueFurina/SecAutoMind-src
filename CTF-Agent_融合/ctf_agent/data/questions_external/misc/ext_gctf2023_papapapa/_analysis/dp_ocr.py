"""Prototype: full pipeline + template bootstrap + DP OCR for papapapa."""
import pickle, sys
import numpy as np

d = pickle.load(open("_analysis/blocks2.pkl", "rb"))
blocks = d["blocks"]
dqt = d["dqt"]
ZIGZAG = [0,1,8,16,9,2,3,10,17,24,32,25,18,11,4,5,12,19,26,33,40,48,41,34,27,20,13,6,7,14,21,28,35,42,49,56,57,50,43,36,29,22,15,23,30,37,44,51,58,59,52,45,38,31,39,46,53,60,61,54,47,55,62,63]
Q = np.array(dqt[0]).reshape(8, 8)
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

# ---- deterministic extraction (this becomes the skill core) ----
def extract_strip(blocks):
    db = [b for b in blocks if b[2] == 1 and b[8] and b[6]]
    W = 2
    H = len(db) // W
    img = np.zeros((H * 8, W * 8), dtype=np.uint8)
    for i, b in enumerate(db):
        r, c = divmod(i, W)
        img[r*8:(r+1)*8, c*8:(c+1)*8] = b2p(b[5], b[6])
    return np.rot90(img, 1)  # CCW: text horizontal

img = extract_strip(blocks)
bw = (img < 180)
H_strip, W_strip = bw.shape
cols = np.where(bw.any(axis=0))[0]
x0, x1 = cols.min(), cols.max() + 1
print(f"strip {W_strip}x{H_strip}, ink cols {x0}..{x1}")

FLAG = "CTF{rearview-monorail-mullets-backroom-stopped}"
CHARSET = "".join(sorted(set(FLAG)))

# ---- bootstrap: font width model ----
from PIL import Image, ImageDraw, ImageFont
FONTS = ["C:/Windows/Fonts/times.ttf", "C:/Windows/Fonts/georgia.ttf",
         "C:/Windows/Fonts/calibri.ttf", "C:/Windows/Fonts/cambria.ttc",
         "C:/Windows/Fonts/constan.ttf"]
adv = {c: [] for c in CHARSET}
for fp in FONTS:
    try:
        for size in range(14, 20):
            font = ImageFont.truetype(fp, size)
            total = sum(font.getlength(c) for c in FLAG)
            if abs(total - (x1 - x0)) > 40:
                continue
            for c in CHARSET:
                adv[c].append(font.getlength(c))
            break
    except Exception:
        pass
width_model = {}
for c in CHARSET:
    vals = adv[c] or [7.0]
    width_model[c] = float(np.mean(vals))
# normalize so total matches ink width
scale = (x1 - x0) / sum(width_model[c] for c in FLAG)
for c in width_model:
    width_model[c] *= scale
print("width model:", {c: round(v, 1) for c, v in sorted(width_model.items())})

def iou_at(x, tmpl):
    """IoU of template (H x w) placed at column x."""
    w = tmpl.shape[1]
    if x < 0 or x + w > W_strip:
        return -1.0
    region = bw[:, x:x+w]
    if region.shape != tmpl.shape:
        return -1.0
    inter = (region & tmpl).sum()
    union = (region | tmpl).sum()
    return inter / union if union else 0.0

# ---- EM: align fixed FLAG, extract templates, iterate ----
templates = {c: None for c in CHARSET}
# init boundaries from width model
bounds = [x0]
for c in FLAG:
    bounds.append(bounds[-1] + max(2, round(width_model[c])) + 2)
bounds[-1] = x1

def align_fixed(text, templates):
    """DP: find boundaries for the given text maximizing IoU with templates."""
    n = len(text)
    INF = float("-inf")
    # dp[i][x] = best score having placed first i chars ending at column x
    # transitions: char i placed at [x, x+w), then gap g
    dp = [dict() for _ in range(n + 1)]
    dp[0][x0] = 0.0
    for i in range(n):
        c = text[i]
        tmpl = templates.get(c)
        if tmpl is None:
            # no template yet: fall back to width model advance
            for x, sc in dp[i].items():
                nx = x + max(2, round(width_model[c])) + 2
                if nx <= x1:
                    dp[i+1][nx] = max(dp[i+1].get(nx, INF), sc)
            continue
        w = tmpl.shape[1]
        for x, sc in dp[i].items():
            if sc == INF:
                continue
            s = iou_at(x, tmpl)
            if s < 0:
                continue
            for g in range(0, 4):
                nx = x + w + g
                if nx > x1:
                    continue
                dp[i+1][nx] = max(dp[i+1].get(nx, INF), sc + s)
    # backtrack
    if not dp[n]:
        return None
    # find best end
    best_end = max(dp[n].items(), key=lambda kv: kv[1])
    # need to also require ending at x1: allow trailing
    ends = {x: s for x, s in dp[n].items() if x >= x1 - 3}
    if not ends:
        ends = dict(dp[n])
    end_x = max(ends.items(), key=lambda kv: kv[1])[0]
    # backtrack
    path = []
    x = end_x
    for i in range(n, 0, -1):
        c = text[i-1]
        tmpl = templates.get(c)
        if tmpl is None:
            # find predecessor
            for px, sc in dp[i-1].items():
                if px + max(2, round(width_model[c])) + 2 == x:
                    path.append((px, x))
                    x = px
                    break
            continue
        w = tmpl.shape[1]
        found = False
        for g in range(0, 4):
            px = x - w - g
            if px in dp[i-1]:
                s = iou_at(px, tmpl)
                if s >= 0 and abs(dp[i-1][px] + s - dp[i][x]) < 1e-9:
                    path.append((px, px + w))
                    x = px
                    found = True
                    break
        if not found:
            return None
    path.reverse()
    return path

# initial templates from width-model boundaries
for c in CHARSET:
    idx = FLAG.index(c)
    s, e = bounds[idx], bounds[idx+1]
    if 0 < e - s <= 16:
        templates[c] = bw[:, s:e].copy()

for it in range(4):
    path = align_fixed(FLAG, templates)
    if path is None:
        print("align failed at iter", it)
        break
    # re-extract templates
    new_tpl = {}
    for c, (s, e) in zip(FLAG, path):
        if c not in new_tpl and e - s >= 1:
            new_tpl[c] = bw[:, s:e].copy()
    templates = new_tpl
    score = sum(iou_at(s, templates[c]) for c, (s, e) in zip(FLAG, path))
    print(f"iter {it}: align score={score:.2f}, boundaries ok")

# ---- free OCR via DP ----
def ocr(templates, max_chars=80):
    n = max_chars
    INF = float("-inf")
    # dp over columns
    dp = {x0: (0.0, [])}
    # process columns in order; simple BFS/DP over positions
    import heapq
    best = {x0: 0.0}
    parent = {x0: None}
    order = sorted(best)
    # iterate to fixpoint
    changed = True
    rounds = 0
    while changed and rounds < 10:
        changed = False
        rounds += 1
        for x in sorted(best.keys()):
            sc = best[x]
            for c, tmpl in templates.items():
                w = tmpl.shape[1]
                s = iou_at(x, tmpl)
                if s <= 0.15:
                    continue
                for g in range(0, 4):
                    nx = x + w + g
                    if nx > x1:
                        continue
                    if sc + s > best.get(nx, INF):
                        best[nx] = sc + s
                        parent[nx] = (x, c)
                        changed = True
    # find best end near x1
    cands = {x: s for x, s in best.items() if x >= x1 - 4}
    if not cands:
        return None
    end_x = max(cands.items(), key=lambda kv: kv[1])[0]
    out = []
    x = end_x
    while parent[x] is not None:
        px, c = parent[x]
        out.append(c)
        x = px
    return "".join(reversed(out))

text = ocr(templates)
print("OCR result:", text)
print("expected   :", FLAG)
print("MATCH" if text == FLAG else "MISMATCH")
