import struct, sys

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

for k, (counts, syms) in sorted(dht.items()):
    code = 0
    codes = []
    for L in range(1, 17):
        for _ in range(counts[L-1]):
            codes.append((L, code, syms[len(codes)]))
            code += 1
        code <<= 1
    print(f"table {k}: counts={counts}")
    print(f"  codes: {codes}")

print("DQT0:", dqt[0])
print("DQT1:", dqt[1])
