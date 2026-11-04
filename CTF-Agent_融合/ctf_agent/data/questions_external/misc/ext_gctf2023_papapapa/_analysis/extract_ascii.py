import pickle

d = pickle.load(open("_analysis/blocks.pkl", "rb"))
blocks = d["blocks"]

data_blocks = [b for b in blocks if b[2] == 1 and b[6]]
print(f"data blocks: {len(data_blocks)}")

# all AC values as signed bytes, in stream order
vals = []
for b in data_blocks:
    for (run, v) in b[6]:
        vals.extend([0] * run)
        vals.append(v & 0xFF)
print(f"total AC values: {len(vals)}")

# try as ASCII directly
s = "".join(chr(v) if 32 <= v < 127 else "." for v in vals)
print("as ASCII:")
for i in range(0, len(s), 80):
    print(" ", s[i:i+80])

# also DC diffs
dcs = [b[5] & 0xFF for b in data_blocks]
print("\nDC diffs:", dcs)
print("DC as ASCII:", "".join(chr(v) if 32 <= v < 127 else "." for v in dcs))

# interleaved: dc then acs per block?
seq = []
for b in data_blocks:
    seq.append(b[5] & 0xFF)
    for (run, v) in b[6]:
        seq.extend([0] * run)
        seq.append(v & 0xFF)
s2 = "".join(chr(v) if 32 <= v < 127 else "." for v in seq)
print("\ndc+ac interleaved as ASCII:")
for i in range(0, len(s2), 80):
    print(" ", s2[i:i+80])
