import pickle

d = pickle.load(open("_analysis/blocks.pkl", "rb"))
blocks = d["blocks"]

# find phantom blocks: Y blocks with nonzero DC and no ACs
phantoms = [b for b in blocks if b[2] == 1 and b[5] != 0 and not b[6]]
print("phantom Y blocks (nonzero DC, no AC):")
for b in phantoms:
    print(f"  mcu=({b[0]},{b[1]}) bx={b[3]} dc={b[5]} pad={b[8]}")

# bit positions: bits_before of each block; compute per-block bit cost
print("\nper-MCU-row bit accounting:")
rows = {}
for b in blocks:
    my = b[1]
    rows.setdefault(my, []).append(b)

zero_starts = [223, 379, 528, 679, 827, 979, 1129, 1280, 1438, 1590]  # byte offsets of zero runs (row k+1 flat start)
for my in sorted(rows):
    bl = rows[my]
    if my > 8:
        break
    first = bl[0][7]
    last = bl[-1]
    # bit position after last block = bits_before of last + its cost; approximate via next block's bits_before
    print(f"row {my}: {len(bl)} blocks, first bit={first}, last block ctx={last[:6]}")
    if my >= 2:
        data_mcu = [b for b in bl if b[0] == 21]
        costs = []
        prev = None
        for b in data_mcu:
            if prev is not None:
                costs.append(b[7] - prev)
            prev = b[7]
        print(f"   mx=21 blocks: dc={[b[5] for b in data_mcu]}, nac={[len(b[6]) for b in data_mcu]}")
        print(f"   intra-costs: {costs}")
