import pickle, collections

d = pickle.load(open("_analysis/blocks2.pkl", "rb"))
blocks = d["blocks"]
dqt = d["dqt"]

data_blocks = [b for b in blocks if b[2] == 1 and b[8] and b[6]]
print(f"data blocks: {len(data_blocks)}")
rows = collections.Counter(b[1] for b in data_blocks)
print(f"rows with data: {sorted(rows.keys())}")
print(f"blocks per row: {collections.Counter(rows.values())}")

# DC predictor values of data blocks
print("\nDC (cumulative) sequence:")
for i in range(0, len(data_blocks), 2):
    pair = data_blocks[i:i+2]
    print(f"  row {pair[0][1]:2d}: dc={[b[5] for b in pair]}, nac={[len(b[6]) for b in pair]}")

# try numpy availability
try:
    import numpy as np
    print("\nnumpy available:", np.__version__)
except ImportError:
    print("\nno numpy")
