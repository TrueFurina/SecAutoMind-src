import struct, sys, collections
import pickle

path = sys.argv[1] if len(sys.argv) > 1 else "_attachments/white.jpg"
data = open(path, "rb").read()

i = 2
dht = {}
dqt = {}
sof = None
sos = None
scan_start = scan_end = None
while i < len(data):
    m = data[i+1]
    if m == 0xD9:
        scan_end = i
        break
    if m == 0xDA:
        ln = struct.unpack(">H", data[i+2:i+4])[0]
        sos = data[i+4:i+2+ln]
        scan_start = i + 2 + ln
        break
    if 0xD0 <= m <= 0xD7 or m == 0x01:
        i += 2
        continue
    ln = struct.unpack(">H", data[i+2:i+4])[0]
    payload = data[i+4:i+2+ln]
    if m == 0xC0:
        w, h = struct.unpack(">HH", payload[1:5])
        n = payload[5]
        comps = []
        for c in range(n):
            comps.append((payload[6+c*3], payload[7+c*3] >> 4, payload[7+c*3] & 15, payload[8+c*3]))
        sof = (w, h, comps)
    elif m == 0xC4:
        p = 0
        while p < len(payload):
            tc_th = payload[p]
            counts = list(payload[p+1:p+17])
            p += 17
            syms = list(payload[p:p+sum(counts)])
            p += sum(counts)
            dht[(tc_th >> 4, tc_th & 15)] = (counts, syms)
    elif m == 0xDB:
        p = 0
        while p < len(payload):
            pq_tq = payload[p]
            n = 64 if (pq_tq >> 4) == 0 else 128
            dqt[pq_tq & 15] = list(payload[p+1:p+1+n])
            p += 1 + n
    i += 2 + ln

W, H, comps = sof
maxH = max(c[1] for c in comps)
maxV = max(c[2] for c in comps)
print(f"image {W}x{H}, comps={comps}, maxH={maxH} maxV={maxV}")

# parse SOS
ns = sos[0]
scan_comps = []
for c in range(ns):
    cs, td_ta = sos[1+c*2], sos[2+c*2]
    scan_comps.append((cs, td_ta >> 4, td_ta & 15))
print("scan components:", scan_comps)

# build huffman lookup: code -> symbol, plus (length, symbol) list for fast table
def build_huff(counts, syms):
    # canonical codes
    table = {}
    code = 0
    k = 0
    for length in range(1, 17):
        for _ in range(counts[length-1]):
            table[(length, code)] = syms[k]
            k += 1
            code += 1
        code <<= 1
    return table

huff_tables = {k: build_huff(v[0], v[1]) for k, v in dht.items()}
# max code length per table for safety
maxlen = {k: max(l for (l, c) in v) for k, v in huff_tables.items()}

scan = data[scan_start:scan_end]
# strip stuffing: FF 00 -> FF; note positions of real markers
bits = []  # not building a list, use index-based reader

class BitReader:
    def __init__(self, buf):
        self.buf = buf
        self.pos = 0  # byte position
        self.bitpos = 0  # bits consumed in current byte (0-7)
        self.marker_hit = False
    def _next_byte(self):
        while self.pos < len(self.buf):
            b = self.buf[self.pos]
            if b == 0xFF:
                if self.pos + 1 < len(self.buf):
                    nxt = self.buf[self.pos+1]
                    if nxt == 0x00:
                        self.pos += 2
                        return 0xFF
                    elif 0xD0 <= nxt <= 0xD7:
                        self.marker_hit = True
                        raise EOFError("restart marker")
                    else:
                        self.marker_hit = True
                        raise EOFError("marker %02x" % nxt)
                else:
                    raise EOFError("truncated FF")
            else:
                self.pos += 1
                return b
        raise EOFError("end of scan")
    def read_bit(self):
        if self.bitpos == 0:
            self.cur = self._next_byte()
        b = (self.cur >> (7 - self.bitpos)) & 1
        self.bitpos = (self.bitpos + 1) % 8
        return b
    def read_bits(self, n):
        v = 0
        for _ in range(n):
            v = (v << 1) | self.read_bit()
        return v
    def huff(self, tkey):
        code = 0
        for length in range(1, maxlen[tkey] + 1):
            code = (code << 1) | self.read_bit()
            if (length, code) in huff_tables[tkey]:
                return huff_tables[tkey][(length, code)]
        raise ValueError("bad huffman code")

def extend(v, size):
    if size == 0:
        return 0
    if v < (1 << (size - 1)):
        return v - (1 << size) + 1
    return v

br = BitReader(scan)

mcu_cols = (W + 8*maxH - 1) // (8*maxH)
mcu_rows = (H + 8*maxV - 1) // (8*maxV)
print(f"MCUs: {mcu_cols} x {mcu_rows} = {mcu_cols*mcu_rows}")

blocks = []  # (mcu_x, mcu_y, comp_id, bx, by, dc, acs, bits_before)
grid_w = {c[0]: (W * c[1] + 8*maxH - 1) // (8*maxH) for c in comps}
grid_h = {c[0]: (H * c[2] + 8*maxV - 1) // (8*maxV) for c in comps}
print("component grids:", {c[0]: (grid_w[c[0]], grid_h[c[0]]) for c in comps})

total_blocks = 0
padding_blocks = []
cur_ctx = {"mx": 0, "my": 0, "cs": 0, "bx": 0, "by": 0}
try:
    for my in range(mcu_rows):
        for mx in range(mcu_cols):
            for (cs, td, ta) in scan_comps:
                comp = next(c for c in comps if c[0] == cs)
                Hc, Vc = comp[1], comp[2]
                for by in range(Vc):
                    for bx in range(Hc):
                        cur_ctx.update(mx=mx, my=my, cs=cs, bx=bx, by=by)
                        bits_before = br.pos * 8 - (0 if br.bitpos == 0 else 8 - br.bitpos)
                        dc_size = br.huff((0, td))
                        dc = extend(br.read_bits(dc_size), dc_size) if dc_size else 0
                        acs = []
                        while True:
                            rs = br.huff((1, ta))
                            if rs == 0x00:
                                break
                            if rs == 0xF0:
                                continue
                            run, size = rs >> 4, rs & 15
                            val = extend(br.read_bits(size), size) if size else 0
                            acs.append((run, val))
                        total_blocks += 1
                        col = mx * Hc + bx
                        row = my * Vc + by
                        is_pad = (col >= grid_w[cs]) or (row >= grid_h[cs])
                        rec = (mx, my, cs, bx, by, dc, acs, bits_before, is_pad)
                        blocks.append(rec)
                        if is_pad:
                            padding_blocks.append(rec)
except EOFError as e:
    print("decode stopped:", e)
except ValueError as e:
    print(f"!! bad huffman code at block {total_blocks}, ctx={cur_ctx}, byte pos={br.pos}, bitpos={br.bitpos}")
    print(f"   next 16 bytes: {scan[max(0,br.pos-8):br.pos+16].hex()}")
    pickle.dump({"blocks": blocks, "scan_comps": scan_comps, "grid_w": grid_w, "grid_h": grid_h,
                 "mcu_cols": mcu_cols, "mcu_rows": mcu_rows, "sof": sof, "dqt": dqt, "failed": True},
                open("_analysis/blocks.pkl", "wb"))
    print("saved partial _analysis/blocks.pkl")
    sys.exit(2)

print(f"decoded blocks: {total_blocks}, padding blocks: {len(padding_blocks)}")
bits_used = br.pos * 8 + (br.bitpos if br.bitpos else 0)
print(f"scan bytes consumed: {br.pos} / {len(scan)}")

# stats
grid_blocks = [b for b in blocks if not b[8]]
nonflat = [b for b in grid_blocks if b[6]]
print(f"grid blocks: {len(grid_blocks)}, grid blocks with AC data: {len(nonflat)}")
pad_nonflat = [b for b in padding_blocks if b[6]]
print(f"padding blocks with AC data: {len(pad_nonflat)}")

# DC stats
dcs = collections.Counter(b[5] for b in grid_blocks)
print("grid DC values:", dcs.most_common(10))
pdcs = collections.Counter(b[5] for b in padding_blocks)
print("padding DC values:", pdcs.most_common(10))

import pickle
pickle.dump({"blocks": blocks, "scan_comps": scan_comps, "grid_w": grid_w, "grid_h": grid_h,
             "mcu_cols": mcu_cols, "mcu_rows": mcu_rows, "sof": sof, "dqt": dqt},
            open("_analysis/blocks.pkl", "wb"))
print("saved _analysis/blocks.pkl")
