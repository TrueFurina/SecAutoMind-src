import re, os, hashlib

BASE = r"E:\Program\西湖论剑\ctf_agent"
PATH = os.path.join(BASE, r"data/questions_ext\_attachments\forensics\2017f-for-thoroughlystripped\thoroughlyStripped")
data = open(PATH,'rb').read()
n = len(data)
STRTAB_OFF = 2857

import sys
sys.setrecursionlimit(10000)

# ---- 17 printX names + char mapping ----
pat = re.compile(rb'_Z\d+print([A-Za-z0-9_]+?)v')
name_off = {}
for m in pat.finditer(data):
    name_off[m.start()] = m.group().decode()
print("printX count:", len(name_off))
for o, nm in sorted(name_off.items()):
    print("  ", o, nm)

# charset mapping
def char_of(name):
    if name == "_Z10printOBrakv": return "{"
    if name == "_Z10printCBrakv": return "}"
    mm = re.match(r'_Z\d+print([A-Za-z0-9_])v$', name)
    return mm.group(1) if mm else None

# ---- extract all name runs in .strtab for validation ----
strtab = data[STRTAB_OFF:STRTAB_OFF+1300]
runs = {}
for m in re.finditer(rb'[A-Za-z_$][A-Za-z0-9_$.@]*', strtab):
    runs[STRTAB_OFF + m.start()] = m.group().decode()
def is_name_start(abs_off):
    if abs_off in runs: return True
    if 0 <= abs_off < len(data) and data[abs_off] in b'ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz_$':
        return True
    return False

def val_from(bs):
    return int.from_bytes(bs,'little') if bs else 0

# ---- recursive .symtab parser over a byte region ----
# Elf64_Sym padded: st_name(4) st_info(1) st_other(1) st_shndx(2) st_value(8) st_size(8)
def parse_region(region):
    memo = {}
    nodes = [0]
    NODE_CAP = 800000
    def rec(pos):
        if pos == len(region):
            return []
        if pos in memo:
            return memo[pos]
        nodes[0]+=1
        if nodes[0] > NODE_CAP:
            return None
        rem = region[pos:]
        best = None
        # st_name width 0..4
        for kn in range(0,5):
            if kn>len(rem): break
            sn = val_from(rem[:kn])
            if kn==0:
                sn_ok = True
            else:
                if sn>=len(strtab): continue
                if not is_name_start(STRTAB_OFF+sn): continue
            # st_info 0..1
            for ki in range(0,2):
                if ki>len(rem)-kn: break
                si = val_from(rem[kn:kn+ki])
                if ki==0:
                    if si!=0: continue
                else:
                    if si>0x1f: continue
                    if (si&0xf) not in (0,1,2,3,4): continue
                    if (si>>4) not in (0,1,2): continue
                # st_other 0..1
                for ko in range(0,2):
                    if ko>len(rem)-kn-ki: break
                    so = val_from(rem[kn+ki:kn+ki+ko])
                    if ko==0:
                        if so!=0: continue
                    else:
                        if so>0x1f: continue
                    # st_shndx 0..2
                    for ks in range(0,3):
                        if ks>len(rem)-kn-ki-ko: break
                        sh = val_from(rem[kn+ki+ko:kn+ki+ko+ks])
                        if ks==0:
                            if sh!=0: continue
                        else:
                            if sh!=0 and not (0xff00<=sh<=0xffff) and sh>=80: continue
                        # st_value 0..8
                        for kv in range(0,9):
                            if kv>len(rem)-kn-ki-ko-ks: break
                            sv = val_from(rem[kn+ki+ko+ks:kn+ki+ko+ks+kv])
                            if kv==0:
                                if sv!=0: continue
                            else:
                                if sv>0x200000: continue
                            # st_size 0..8
                            for kz in range(0,9):
                                end = kn+ki+ko+ks+kv+kz
                                if kz>len(rem)-end: break
                                sz = val_from(rem[end:end+kz])
                                if kz==0:
                                    if sz!=0: continue
                                else:
                                    if sz>0x4000: continue
                                if end < 1:  # forbid 0-byte entries (infinite recursion)
                                    continue
                                sub = rec(pos+end)
                                if sub is not None:
                                    ent = (sn,si,sh,sv,sz)
                                    cand = [ent]+sub
                                    # prefer parse where every non-null st_name resolves
                                    ok = all((e[0]==0) or is_name_start(STRTAB_OFF+e[0]) for e in cand)
                                    if ok:
                                        memo[pos]=cand
                                        return cand
        memo[pos]=None
        return None
    return rec(0)

# try several .symtab start candidates, keep the one with most printX resolved
best = None
for start in range(2480, 2520):
    region = data[start:2857]
    res = parse_region(region)
    if res is None: continue
    px = [(name_off.get(STRTAB_OFF+s, None), s, si, sh, sv, sz) for (s,si,sh,sv,sz) in res if STRTAB_OFF+s in name_off]
    print(f"start={start} entries={len(res)} printX_resolved={len(px)}")
    if best is None or len(px)>best[1]:
        best = (start, len(px), res, px)

if best is None:
    print("NO PARSE FOUND")
else:
    start, cnt, res, px = best
    print(f"\n=== BEST start={start} printX={cnt} ===")
    # sort printX by st_value
    px_sorted = sorted([p for p in px if p[0]], key=lambda p:p[4])
    flag_chars = [char_of(p[0]) for p in px_sorted]
    candidate = "".join(flag_chars)
    print("candidate flag (by st_value order):", candidate)
    h = hashlib.sha256(candidate.encode()).hexdigest()
    print("sha256:", h, "target: 4f8f5c5944ea9bd62946f8be2f98aac6259b6937a5f72339504cf8ad5c5169b1")
    print("MATCH" if h=="4f8f5c5944ea9bd62946f8be2f98aac6259b6937a5f72339504cf8ad5c5169b1" else "no match")
    # also show .symtab order
    print("\n.symtab order of printX (file order):", [p[0] for p in px])
    print("strtab order chars:", [char_of(name_off[o]) for o in sorted(name_off)])
