import pickle

d = pickle.load(open("_analysis/blocks2.pkl", "rb"))
blocks = d["blocks"]
total_bits = d["total_bits"]

# last 14 blocks with bit ranges
print("last 14 blocks (bit_start, bit_end, ctx, dc, nac):")
for b in blocks[-14:]:
    print(f"  [{b[7]:5d},{b[9]:5d}) mcu=({b[0]},{b[1]}) c{b[2]} bx={b[3]} dc={b[5]} nac={len(b[6])} pad={b[8]}")

# predictor trace for rows 2-8, mx=0 blocks and mx=21 blocks
print("\npredictor trace (Y blocks with nonzero dc-diff effect):")
prev_pred = 0
for b in blocks:
    if b[2] != 1:
        continue
    if b[1] > 8:
        break
    if b[5] != prev_pred or (b[0] in (0, 21)):
        tag = "PAD" if b[8] else ""
        print(f"  mcu=({b[0]},{b[1]}) bx={b[3]} pred={b[5]} nac={len(b[6])} {tag}")
    prev_pred = b[5]

# bits after the last decoded block
print(f"\ntotal bits decoded: {total_bits}")
print("bits 7760-7790:")
# reconstruct from ranges: last block ends at 7789
