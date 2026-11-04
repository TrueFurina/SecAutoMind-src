import struct, sys, pickle

path = "_attachments/white.jpg"
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
        comps = [(payload[6+c*3], payload[7+c*3] >> 4, payload[7+c*3] & 15, payload[8+c*3]) for c in range(n)]
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
ns = sos[0]
scan_comps = [(sos[1+c*2], sos[2+c*2] >> 4, sos[2+c*2] & 15) for c in range(ns)]

def build_huff(counts, syms):
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
maxlen = {k: max(l for (l, c) in v) for k, v in huff_tables.items()}

scan = data[scan_start:scan_end]

class BitReader:
    def __init__(self, buf):
        self.buf = buf
        self.pos = 0
        self.bitpos = 0
        self.log = []  # every bit read
    def _next_byte(self):
        while self.pos < len(self.buf):
            b = self.buf[self.pos]
            if b == 0xFF:
                if self.pos + 1 < len(self.buf):
                    nxt = self.buf[self.pos+1]
                    if nxt == 0x00:
                        self.pos += 2
                        return 0xFF
                    else:
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
        self.log.append(b)
        return b
    def read_bits(self, n):
        v = 0
        for _ in range(n):
            v = (v << 1) | self.read_bit()
        return v
    def huff(self, tkey):
        code = 0
        start = len(self.log)
        for length in range(1, maxlen[tkey] + 1):
            code = (code << 1) | self.read_bit()
            if (length, code) in huff_tables[tkey]:
                return huff_tables[tkey][(length, code)]
        raise ValueError("bad huffman code, bits so far: " + "".join(map(str, self.log[start:])))

def extend(v, size):
    if size == 0:
        return 0
    if v < (1 << (size - 1)):
        return v - (1 << size) + 1
    return v

br = BitReader(scan)
mcu_cols = (W + 8*maxH - 1) // (8*maxH)
mcu_rows = (H + 8*maxV - 1) // (8*maxV)
grid_w = {c[0]: (W * c[1] + 8*maxH - 1) // (8*maxH) for c in comps}
grid_h = {c[0]: (H * c[2] + 8*maxV - 1) // (8*maxV) for c in comps}

blocks = []
pred = {}
cur_ctx = {}
try:
    for my in range(mcu_rows):
        for mx in range(mcu_cols):
            for (cs, td, ta) in scan_comps:
                comp = next(c for c in comps if c[0] == cs)
                Hc, Vc = comp[1], comp[2]
                for by in range(Vc):
                    for bx in range(Hc):
                        cur_ctx.update(mx=mx, my=my, cs=cs, bx=bx, by=by)
                        bit_start = len(br.log)
                        dc_size = br.huff((0, td))
                        dc = extend(br.read_bits(dc_size), dc_size) if dc_size else 0
                        pred[cs] = pred.get(cs, 0) + dc
                        acs = []
                        pos = 0
                        while True:
                            rs = br.huff((1, ta))
                            if rs == 0x00:
                                break
                            if rs == 0xF0:
                                pos += 16
                                if pos >= 63:
                                    break
                                continue
                            run, size = rs >> 4, rs & 15
                            val = extend(br.read_bits(size), size) if size else 0
                            acs.append((run, val))
                            pos += run + 1
                            if pos >= 63:
                                break  # block full: encoder omits EOB (libjpeg behavior)
                        col = mx * Hc + bx
                        row = my * Vc + by
                        is_pad = (col >= grid_w[cs]) or (row >= grid_h[cs])
                        blocks.append((mx, my, cs, bx, by, pred[cs], acs, bit_start, is_pad, len(br.log)))
except EOFError as e:
    print("EOF:", e)
except ValueError as e:
    print(f"FAIL at block {len(blocks)}, ctx={cur_ctx}")
    print(e)
    # dump bits around failure
    n = len(br.log)
    lo = max(0, n - 120)
    bits = "".join(map(str, br.log[lo:n]))
    print(f"last 120 bits (bit {lo}..{n}):")
    for i in range(0, len(bits), 60):
        print(f"  [{lo+i:6d}] {bits[i:i+60]}")

pickle.dump({"blocks": blocks, "scan_comps": scan_comps, "grid_w": grid_w, "grid_h": grid_h,
             "mcu_cols": mcu_cols, "mcu_rows": mcu_rows, "sof": sof, "dqt": dqt, "total_bits": len(br.log)},
            open("_analysis/blocks2.pkl", "wb"))
print(f"decoded {len(blocks)} blocks, {len(br.log)} bits")
