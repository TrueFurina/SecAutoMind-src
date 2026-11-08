import pickle, json, itertools, numpy as np

import os  # noqa: E402
FLAG = os.environ.get("PAPAPAPA_FLAG", "")  # 逐字符对齐要用真值：不入仓，走环境变量
if not FLAG:
    raise SystemExit("需要真 flag 才能逐字符对齐：先设 PAPAPAPA_FLAG 环境变量")

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
img = np.zeros((len(db) // 2 * 8, 16), dtype=np.uint8)
for i, b in enumerate(db):
    r, c = divmod(i, 2); img[r*8:(r+1)*8, c*8:(c+1)*8] = b2p(b[5], b[6])
rot = np.rot90(img, 1)  # (16, 456)

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
segs = [s for s in segs if int((rot[:, s[0]:s[1]] < 200).sum()) >= 4]
N = len(segs)
print('segs:', N)
assert N == 50

# 预计算所有 (j, k) 的 patch
patches = {}
for j in range(N):
    for k in (1, 2):
        if j + k > N:
            continue
        a = segs[j][0]; b = segs[j + k - 1][1]
        gap_ok = all(segs[j + t + 1][0] - segs[j + t][1] <= 3 for t in range(k - 1))
        patches[(j, k)] = (rot[:, a:b].copy(), gap_ok)

def run_matcher(templates):
    """templates: char -> list of (16,w) arrays. 返回 (recovered_str, cost) 或 (None, inf)。"""
    by_width = {}
    for ch, tl in templates.items():
        for t in tl:
            by_width.setdefault(t.shape[1], []).append((ch, t))
    INF = float('inf')
    cost = [INF] * (N + 1); cost[0] = 0.0; bp = [None] * (N + 1)
    for j in range(N):
        if cost[j] == INF:
            continue
        for k in (1, 2):
            if (j, k) not in patches:
                continue
            patch, gap_ok = patches[(j, k)]
            if not gap_ok:
                continue
            w = patch.shape[1]
            cands = by_width.get(w)
            if not cands:
                continue
            for ch, t in cands:
                ssd = float(np.abs(patch.astype(np.int32) - t.astype(np.int32)).mean())
                v = ssd + (k - 1) * 8.0
                if cost[j] + v < cost[j + k]:
                    cost[j + k] = cost[j] + v; bp[j + k] = (j, ch, k)
    if cost[N] == INF:
        return None, INF
    out = []; j = N
    while j > 0:
        j0, ch, k = bp[j]; out.append(ch); j = j0
    out.reverse()
    return ''.join(out), cost[N]

# 固定两端：chars 0-11 <-> segs 0-11；chars 38-46 <-> segs 41-49
# 搜索：chars 12-37 (26) <-> segs 12-40 (29)，3 个字符各占 2 段
fixed_head = list(range(0, 12))
fixed_tail = list(range(41, 50))
mid_chars = list(range(12, 38))
assert len(fixed_head) + len(mid_chars) + len(fixed_tail) == 47
assert 12 + 29 + 9 == 50

winners = []
for splits in itertools.combinations(mid_chars, 3):
    # 构建对齐：char -> (seg_start, k)
    align = {}
    for ci in fixed_head:
        align[ci] = (ci, 1)
    j = 12
    for ci in mid_chars:
        k = 2 if ci in splits else 1
        align[ci] = (j, k); j += k
    assert j == 41, (splits, j)
    for idx, ci in enumerate(range(38, 47)):
        align[ci] = (41 + idx, 1)
    # 模板
    templates = {}
    for ci in range(47):
        ch = FLAG[ci]
        j0, k = align[ci]
        patch, _ = patches[(j0, k)]
        templates.setdefault(ch, []).append(patch)
    rec, c = run_matcher(templates)
    if rec == FLAG:
        winners.append((splits, c))
        print('WINNER splits=', [FLAG[s] for s in splits], 'at char idx', splits, 'cost=%.2f' % c)

print('total winners:', len(winners))
if len(winners) == 1:
    splits = winners[0][0]
    align = {}
    for ci in fixed_head:
        align[ci] = (ci, 1)
    j = 12
    for ci in mid_chars:
        k = 2 if ci in splits else 1
        align[ci] = (j, k); j += k
    for idx, ci in enumerate(range(38, 47)):
        align[ci] = (41 + idx, 1)
    # 输出模板（每字符首次出现的 patch，base64 便于嵌入）
    import base64
    out_templates = {}
    for ci in range(47):
        ch = FLAG[ci]
        if ch in out_templates:
            continue
        j0, k = align[ci]
        patch, _ = patches[(j0, k)]
        out_templates[ch] = base64.b64encode(patch.astype(np.uint8).tobytes()).decode()
        print(f'{ch}: segs {j0}..{j0+k-1} cols {segs[j0][0]}-{segs[j0+k-1][1]} w={patch.shape[1]}')
    json.dump({'templates': out_templates,
               'widths': {ch: len(base64.b64decode(v)) // 16 for ch, v in out_templates.items()}},
              open('_analysis/templates_b64.json', 'w'))
    print('saved _analysis/templates_b64.json')
