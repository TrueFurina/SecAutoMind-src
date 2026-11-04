import pickle
import numpy as np

d = pickle.load(open("_analysis/blocks2.pkl", "rb"))
blocks = d["blocks"]

# 1. sanity check IDCT on the first block (dc=339, no AC) -> should be 255
ZIGZAG = [
     0,  1,  8, 16,  9,  2,  3, 10, 17, 24, 32, 25, 18, 11,  4,  5,
    12, 19, 26, 33, 40, 48, 41, 34, 27, 20, 13,  6,  7, 14, 21, 28,
    35, 42, 49, 56, 57, 50, 43, 36, 29, 22, 15, 23, 30, 37, 44, 51,
    58, 59, 52, 45, 38, 31, 39, 46, 53, 60, 61, 54, 47, 55, 62, 63]
Q = np.array(d["dqt"][0], dtype=np.float64).reshape(8, 8)
A = np.zeros((8, 8))
for x in range(8):
    for u in range(8):
        cu = (1 / np.sqrt(2)) if u == 0 else 1.0
        A[x, u] = 0.5 * cu * np.cos((2 * x + 1) * u * np.pi / 16)

def block_to_pixels(dc, acs):
    coef = np.zeros(64)
    coef[0] = dc
    pos = 0
    for (run, v) in acs:
        pos += run + 1
        if pos < 64:
            coef[pos] = v
    F = np.zeros((8, 8))
    for i in range(64):
        F[i // 8][i % 8] = coef[ZIGZAG[i]] * Q[i // 8][i % 8]
    s = A.T @ F @ A
    return np.clip(np.round(s + 128), 0, 255).astype(np.uint8)

first = next(b for b in blocks if b[0] == 0 and b[1] == 0 and b[2] == 1 and b[3] == 0)
px = block_to_pixels(first[5], first[6])
print("first block pixel range:", px.min(), px.max(), "(expect 255,255)")

# 2. byte stream from AC values
data_blocks = [b for b in blocks if b[2] == 1 and b[8] and b[6]]
vals = []
for b in data_blocks:
    for (run, v) in b[6]:
        vals.extend([0] * run)
        vals.append(v)
print(f"\ntotal coefficient values: {len(vals)}")

stream = bytes(v & 0xFF for v in vals)
print("first 64 bytes:", stream[:64].hex())
print("last 32 bytes:", stream[-32:].hex())

# magic checks
magics = {
    b"\x1f\x8b": "gzip", b"\x78\x01": "zlib", b"\x78\x9c": "zlib", b"\x78\xda": "zlib",
    b"PK\x03\x04": "zip", b"BZh": "bzip2", b"\xfd7zXZ": "xz", b"\x89PNG": "png",
    b"GIF8": "gif", b"RIFF": "riff/wav", b"Salted__": "openssl", b"CTF{": "flag!",
    b"flag{": "flag!", b"\x04\x22\x4d\x18": "lz4",
}
for mg, name in magics.items():
    idx = stream.find(mg)
    if idx >= 0:
        print(f"MAGIC {name} at offset {idx}")

# entropy estimate
import collections, math
c = collections.Counter(stream)
ent = -sum((n / len(stream)) * math.log2(n / len(stream)) for n in c.values())
print(f"byte entropy: {ent:.2f} bits/byte (8 = random)")

# 3. also with DC interleaved
seq = []
for b in data_blocks:
    seq.append(b[5] & 0xFF)
    for (run, v) in b[6]:
        seq.extend([0] * run)
        seq.append(v & 0xFF)
s2 = bytes(seq)
print("\nwith-DC stream first 64:", s2[:64].hex())
