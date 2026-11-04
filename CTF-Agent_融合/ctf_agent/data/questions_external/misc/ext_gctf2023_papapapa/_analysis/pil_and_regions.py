from PIL import Image
import collections

im = Image.open("_attachments/white.jpg")
im.load()
print("mode:", im.mode, "size:", im.size)
px = list(im.getdata())
c = collections.Counter(px)
print("distinct pixel values:", len(c))
print("most common:", c.most_common(5))
if len(c) <= 10:
    print("all:", c.most_common())

# raw data regions
data = open("_attachments/white.jpg", "rb").read()
scan = data[319:9238]
regions = [(148, 223), (271, 379), (426, 528), (576, 679), (726, 827), (875, 979)]
for s, e in regions:
    chunk = scan[s:e]
    print(f"\nregion [{s}:{e}] len={len(chunk)}")
    print("  hex:", chunk.hex())
    printable = "".join(chr(b) if 32 <= b < 127 else "." for b in chunk)
    print("  asc:", printable)
