import pickle, collections, sys

d = pickle.load(open("_analysis/blocks.pkl", "rb"))
blocks = d["blocks"]
print(f"total decoded: {len(blocks)}")

by_comp = collections.defaultdict(list)
for b in blocks:
    by_comp[b[2]].append(b)

for cs, bl in sorted(by_comp.items()):
    dcs = collections.Counter(b[5] for b in bl)
    nac = collections.Counter(len(b[6]) for b in bl)
    print(f"comp {cs}: {len(bl)} blocks, DC values: {dict(dcs)}, AC-count dist: {dict(sorted(nac.items()))}")

# padding blocks decoded so far
pads = [b for b in blocks if b[8]]
print(f"\npadding blocks decoded: {len(pads)}")
for b in pads[:20]:
    print(f"  mcu=({b[0]},{b[1]}) comp={b[2]} bx={b[3]} dc={b[5]} acs={b[6][:12]}{'...' if len(b[6])>12 else ''}")

# Y blocks with AC data
y_acs = [b for b in by_comp.get(1, []) if b[6]]
print(f"\nY blocks with AC data: {len(y_acs)}")
for b in y_acs[:15]:
    padmark = "PAD" if b[8] else "grid"
    print(f"  mcu=({b[0]},{b[1]}) bx={b[3]} [{padmark}] dc={b[5]} acs={b[6][:12]}{'...' if len(b[6])>12 else ''}")

# bits per block distribution
bits_used = []
prev = 0
for b in blocks:
    bits_used.append(b[7] - prev)
    prev = b[7]
c = collections.Counter(bits_used)
print(f"\nbits-per-block distribution: {dict(sorted(c.items()))}")

# raw scan bytes near failure
data = open("_attachments/white.jpg", "rb").read()
scan = data[319:]
print(f"\nscan[940:1010]: {scan[940:1010].hex()}")
print(f"scan[860:940]:  {scan[860:940].hex()}")
