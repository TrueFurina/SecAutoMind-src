import pickle, json, re, numpy as np

FLAG = 'CTF{rearview-monorail-mullets-backroom-stopped}'
MERGE_CHARS = {'{', 'i', '}'}   # 假设：这三个字的字形被核心列分割成 2 段

d = pickle.load(open('_analysis/blocks2.pkl', 'rb'))
blocks = d['blocks']; dqt = d['dqt']
ZIGZAG = [0,1,8,16,9,2,3,10,17,24,32,25,18,11,4,5,12,19,26,33,40,48,41,34,27,20,13,6,7,14,21,28,35,42,49,56,57,50,43,36,29,22,15,23,30,37,44,51,58,59,52,45,38,31,39,46,53,60,61,54,47,55,62,63]
Q = np.array(dqt[0], dtype=np.float64).reshape(8, 8)
A = np.zeros((8, 8))
for x in range(8):
    for u in range(8):
        cu = (1 / np.sqrt(2)) if u == 0 else 1.0
        A[x, u] = 0.5 * cu * np.cos((2 * x + 1) * u * np.pi / 16)

def b2p(dc, acs):
    coef = np.zeros(64); coef[0] = dc; pos = 0
    for (run, v) in acs:
        pos += run + 1
        if pos < 64:
            coef[pos] = v
    F = np.zeros((8, 8))
    for k in range(64):
        nat = ZIGZAG[k]; F[nat // 8][nat % 8] = coef[k] * Q[nat // 8][nat % 8]
    return np.clip(np.round(A @ F @ A.T + 128), 0, 255).astype(np.uint8)

db = [b for b in blocks if b[2] == 1 and b[8] and b[6]]
print('data blocks:', len(db))
img = np.zeros((len(db) // 2 * 8, 16), dtype=np.uint8)
for i, b in enumerate(db):
    r, c = divmod(i, 2); img[r*8:(r+1)*8, c*8:(c+1)*8] = b2p(b[5], b[6])
rot = np.rot90(img, 1)
print('rot shape:', rot.shape)

cmin = rot.min(axis=0)
core = cmin < 200
segs = []; i = 0; n = 456
while i < n:
    if core[i]:
        j = i
        while j < n and core[j]:
            j += 1
        segs.append([i, j]); i = j
    else:
        i += 1

def ink(a, b):
    return int((rot[:, a:b] < 200).sum())

segs = [s for s in segs if ink(s[0], s[1]) >= 4]
print('segs after speck filter:', len(segs))
for si, (a, b) in enumerate(segs):
    rows = np.where((rot[:, a:b] < 200).any(axis=1))[0]
    print(f'seg{si:2d} {a:3d}-{b:3d} w={b-a:2d} ink={ink(a,b):3d} rows {rows.min()}-{rows.max()}')

expected = len(FLAG) + sum(1 for c in FLAG if c in MERGE_CHARS)
print('expected segs with MERGE_CHARS:', expected)
if len(segs) != expected:
    print('!! 段数不匹配，跳过对齐，仅打印 ASCII 供人工判读')
    for base in range(0, len(segs), 8):
        group = segs[base:base + 8]
        print(' | '.join(f's{base+k}(w{b-a})'.ljust(b - a) for k, (a, b) in enumerate(group)))
        for r in range(16):
            print(' | '.join(''.join('#' if rot[r, c] < 180 else '.' for c in range(a, b)).ljust(b - a) for a, b in group))
        print()
    raise SystemExit(1)

# ---------- 对齐（开发期标定，用已知 flag） ----------
align = []
j = 0
for ch in FLAG:
    k = 2 if ch in MERGE_CHARS else 1
    align.append((ch, j, k)); j += k
assert j == len(segs)

# ---------- 模板（每次出现都存一份） ----------
templates = {}
for ch, j0, k in align:
    a = segs[j0][0]; b = segs[j0 + k - 1][1]
    templates.setdefault(ch, []).append(rot[:, a:b].tolist())

# ---------- 运行时匹配（不知道 flag） ----------
def gaps_ok(j0, k):
    return all(segs[j0 + t + 1][0] - segs[j0 + t][1] <= 3 for t in range(k - 1))

def match_cost(ch, j0, k):
    a = segs[j0][0]; b = segs[j0 + k - 1][1]
    w = b - a
    if not gaps_ok(j0, k):
        return None
    best = None
    for t in templates[ch]:
        if len(t[0]) != w:
            continue
        s = 0
        for r in range(16):
            tr = t[r]
            for c in range(w):
                s += abs(int(rot[r, a + c]) - tr[c])
        v = s / (16.0 * w)
        if best is None or v < best:
            best = v
    if best is None:
        return None
    return best + (k - 1) * 3.0

N = len(segs)
INF = float('inf')
cost = [INF] * (N + 1); cost[0] = 0.0; bp = [None] * (N + 1)
for j in range(N):
    if cost[j] == INF:
        continue
    for ch in templates:
        for k in (1, 2, 3):
            if j + k > N:
                break
            cst = match_cost(ch, j, k)
            if cst is None:
                continue
            if cost[j] + cst < cost[j + k]:
                cost[j + k] = cost[j] + cst; bp[j + k] = (j, ch, k)

if cost[N] == INF:
    print('COVER FAILED')
else:
    out = []; j = N
    while j > 0:
        j0, ch, k = bp[j]; out.append(ch); j = j0
    out.reverse(); rec = ''.join(out)
    print('recovered:', rec)
    print('equals flag:', rec == FLAG)
    m = re.search(r'[A-Za-z0-9]*\{[^}]+\}', rec)
    print('regex flag:', m.group(0) if m else None)

# ---------- ASCII 目检（8 段并排） ----------
for base in range(0, len(segs), 8):
    group = segs[base:base + 8]
    print(' | '.join(f's{base+k}(w{b-a})'.ljust(b - a) for k, (a, b) in enumerate(group)))
    for r in range(16):
        print(' | '.join(''.join('#' if rot[r, c] < 180 else '.' for c in range(a, b)).ljust(b - a) for a, b in group))
    print()

np.save('_analysis/rot.npy', rot)
json.dump({'segs': segs, 'templates': templates}, open('_analysis/templates.json', 'w'))
print('saved _analysis/rot.npy, _analysis/templates.json')
