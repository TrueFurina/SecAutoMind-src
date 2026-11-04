import collections

data = open("_attachments/white.jpg", "rb").read()
# find EOI
eoi = data.rfind(b"\xff\xd9")
print(f"file size {len(data)}, EOI at {eoi}, trailing after EOI: {len(data)-eoi-2}")
print(f"last 32 bytes: {data[-32:].hex()}")

scan = data[319:eoi]
print(f"scan length: {len(scan)}")

# zero run analysis
runs = []
i = 0
while i < len(scan):
    if scan[i] == 0:
        j = i
        while j < len(scan) and scan[j] == 0:
            j += 1
        runs.append((i, j - i))
        i = j
    else:
        i += 1
big = [r for r in runs if r[1] >= 8]
print(f"zero runs >= 8 bytes: {len(big)}")
for off, ln in big[:20]:
    print(f"  offset {off} (file {off+319}), length {ln}")
print(f"total zero bytes: {sum(r[1] for r in runs)} / {len(scan)}")

# nonzero region map: which byte ranges have data
nz = [i for i in range(len(scan)) if scan[i] != 0]
print(f"nonzero bytes: {len(nz)}, first {nz[0]}, last {nz[-1]}")
# gaps > 16 between nonzero bytes
gaps = []
prev = nz[0]
for x in nz[1:]:
    if x - prev > 16:
        gaps.append((prev, x))
    prev = x
print(f"nonzero gaps > 16: {gaps}")
