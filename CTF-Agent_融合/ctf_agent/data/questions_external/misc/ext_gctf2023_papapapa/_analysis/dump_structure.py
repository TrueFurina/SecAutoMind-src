import struct, sys, collections

path = sys.argv[1] if len(sys.argv) > 1 else "_attachments/white.jpg"
data = open(path, "rb").read()
print(f"file size: {len(data)} bytes")
assert data[:2] == b"\xff\xd8", "not JPEG"

i = 2
markers = []
sof = None
dht = {}
dqt = {}
dri = None
sos = None
scan_start = None
while i < len(data):
    if data[i] != 0xFF:
        print(f"!! desync at {i}: {data[i:i+4].hex()}")
        break
    m = data[i+1]
    if m == 0xD9:
        markers.append((i, "EOI"))
        scan_end = i
        break
    if m == 0xDA:
        ln = struct.unpack(">H", data[i+2:i+4])[0]
        sos = data[i+4:i+2+ln]
        scan_start = i + 2 + ln
        markers.append((i, "SOS"))
        break
    if 0xD0 <= m <= 0xD7 or m in (0x01,):
        i += 2
        continue
    ln = struct.unpack(">H", data[i+2:i+4])[0]
    payload = data[i+4:i+2+ln]
    name = {0xC0:"SOF0",0xC2:"SOF2",0xC4:"DHT",0xDB:"DQT",0xDD:"DRI",0xFE:"COM",0xE0:"APP0",0xE1:"APP1",0xEE:"APP14"}.get(m, hex(m))
    markers.append((i, name, ln))
    if m in (0xC0, 0xC2):
        prec = payload[0]
        h, w = struct.unpack(">HH", payload[1:5])
        ncomp = payload[5]
        comps = []
        for c in range(ncomp):
            cid, hv, tq = payload[6+c*3], payload[7+c*3], payload[8+c*3]
            comps.append((cid, hv >> 4, hv & 15, tq))
        sof = (name, prec, w, h, comps)
    elif m == 0xC4:
        p = 0
        while p < len(payload):
            tc_th = payload[p]
            counts = list(payload[p+1:p+17])
            p += 17
            total = sum(counts)
            syms = list(payload[p:p+total])
            p += total
            dht[(tc_th >> 4, tc_th & 15)] = (counts, syms)
    elif m == 0xDB:
        p = 0
        while p < len(payload):
            pq_tq = payload[p]
            pq, tq = pq_tq >> 4, pq_tq & 15
            n = 64 if pq == 0 else 128
            dqt[tq] = list(payload[p+1:p+1+n])
            p += 1 + n
    elif m == 0xDD:
        dri = struct.unpack(">H", payload[:2])[0]
    i += 2 + ln

print("markers:", [(x[0], x[1]) for x in markers])
print("SOF:", sof)
print("DRI:", dri)
print("DQT tables:", {k: (len(v), min(v), max(v)) for k, v in dqt.items()})
print("DHT tables:", {k: sum(v[0]) for k, v in dht.items()})
print("SOS:", sos.hex())
print("scan starts at", scan_start, "scan bytes:", len(data) - scan_start)

# check trailing bytes after EOI
print("trailing after EOI:", len(data) - scan_end - 2)

# count FF markers inside scan (stuffing / restarts)
scan = data[scan_start:scan_end]
ffpos = []
j = 0
while j < len(scan) - 1:
    if scan[j] == 0xFF:
        nxt = scan[j+1]
        if nxt == 0x00:
            ffpos.append(("stuff", j))
        elif 0xD0 <= nxt <= 0xD7:
            ffpos.append(("RST", j))
        else:
            ffpos.append((hex(nxt), j))
        j += 2
    else:
        j += 1
print("FF events in scan:", collections.Counter(x[0] for x in ffpos))
