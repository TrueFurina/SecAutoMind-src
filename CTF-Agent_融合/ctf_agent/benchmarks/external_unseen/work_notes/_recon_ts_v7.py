import re, os, hashlib

BASE = r"E:\Program\西湖论剑\ctf_agent"
PATH = os.path.join(BASE, r"data/questions_ext\_attachments\forensics\2017f-for-thoroughlystripped\thoroughlyStripped")
data = open(PATH,'rb').read()
n = len(data)
STRTAB_OFF = 2857

pat = re.compile(rb'_Z\d+print([A-Za-z0-9_]+?)v')
name_off = {}
for m in pat.finditer(data):
    nm = m.group().decode()
    char = '{' if nm=='_Z10printOBrakv' else ('}' if nm=='_Z10printCBrakv' else m.group(1).decode())
    name_off[m.start()] = (nm, char)
print("printX:", len(name_off))

# st_name value = offset into .strtab (empirically matches for printcv: 3381-2857=524 -> bytes 0c 02 at 2494)
def nz_le(value, width):
    return bytes(b for b in value.to_bytes(width,'little') if b!=0)

# --- quick test: .strtab order ---
order_strtab = [name_off[o][1] for o in sorted(name_off)]
candA = "".join(order_strtab)
print("strtab-order:", candA, "sha:", hashlib.sha256(candA.encode()).hexdigest())

# --- targeted search for each printX's st_name sequence in the whole file ---
print("\n=== targeted search for each printX entry ===")
results = {}  # name -> list of (hit_pos, st_value_candidates)
for o,(nm,char) in sorted(name_off.items()):
    sn = o - STRTAB_OFF
    stored = nz_le(sn, 4)
    hits = []
    p = data.find(stored)
    while p != -1:
        hits.append(p)
        p = data.find(stored, p+1)
    # parse entry at each hit
    for hp in hits:
        # st_name consumes len(stored); then st_info(1), st_other(0/1), st_shndx(1/2), st_value(1..8), st_size(1..8)
        pos = hp + len(stored)
        cands = []
        for ko in (0,1):
            if pos+ko > n: continue
            if ko==1 and data[pos] not in (0,):  # st_other usually 0 -> stripped; if present must be small
                so = data[pos]; 
                if so>0x1f: continue
            else:
                so = 0
            for ks in (1,2):
                if pos+ko+ks > n: continue
                sh = int.from_bytes(data[pos+ko:pos+ko+ks],'little')
                if sh>=80 and not (0xff00<=sh<=0xffff): continue
                for kv in range(1,9):
                    if pos+ko+ks+kv > n: break
                    sv = int.from_bytes(data[pos+ko+ks:pos+ko+ks+kv],'little')
                    if not (0x400 <= sv <= 0x1000000): continue
                    for kz in range(0,9):
                        if pos+ko+ks+kv+kz > n: break
                        sz = int.from_bytes(data[pos+ko+ks+kv:pos+ko+ks+kv+kz],'little') if kz else 0
                        if kz and sz>0x4000: continue
                        cands.append((sv,sz,ko,ks,kv,kz,hp))
        if cands:
            results.setdefault(nm, []).append((hp, cands))
            # print a few
    print(f"{nm:18s} sn={sn:4d} stored={stored.hex()} hits={hits}")
    for hp,cands in results.get(nm,[]):
        svs = sorted(set(c[0] for c in cands))
        print(f"    hit@{hp}: st_value candidates={[hex(x) for x in svs[:8]]}")

# --- build flag by address order using a chosen st_value per name ---
# choose the smallest st_value that looks like a code address (prefer tight range)
print("\n=== attempt address-order flag ===")
chosen = {}
for nm, entries in results.items():
    best_sv = None
    for hp,cands in entries:
        for sv,sz,ko,ks,kv,kz,hp2 in cands:
            if best_sv is None or (0x1000 <= sv <= 0x5000 and not (0x1000<=best_sv<=0x5000)) or (0x1000<=sv<=0x5000 and 0x1000<=best_sv<=0x5000 and sv<best_sv):
                if 0x1000<=sv<=0x5000:
                    best_sv = sv
    if best_sv is not None:
        chosen[nm]=best_sv
print("chosen addresses:", {nm:hex(v) for nm,v in chosen.items()})
if len(chosen)==17:
    ordered = sorted(chosen.items(), key=lambda kv:kv[1])
    flag = "".join(name_off[[o for o in name_off if name_off[o][0]==nm][0]][1] for nm,_ in ordered)
    print("address-order flag:", flag, "sha:", hashlib.sha256(flag.encode()).hexdigest())
    print("MATCH" if hashlib.sha256(flag.encode()).hexdigest()=="4f8f5c5944ea9bd62946f8be2f98aac6259b6937a5f72339504cf8ad5c5169b1" else "no")
else:
    print("only", len(chosen), "names resolved")
