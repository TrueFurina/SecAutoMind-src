import re, os

BASE = r"E:\Program\西湖论剑\ctf_agent"
PATH = os.path.join(BASE, r"data/questions_ext/_attachments/forensics/2017f-for-thoroughlystripped/thoroughlyStripped")
data = open(PATH,'rb').read()
n=len(data)
print("FILE", PATH)
print("len",n,"nulls",data.count(0))

# find all mangled names
pat = re.compile(rb'_Z\d+print[A-Za-z0-9_]*v')
found=[]
for m in pat.finditer(data):
    found.append((m.start(), m.group().decode()))
print("=== mangled names (count %d) ==="%len(found))
for off,name in found:
    print(off, name)

# also find section-name-like strings (these live in .shstrtab)
print("=== section name tokens ===")
for tok in [b'.symtab',b'.strtab',b'.shstrtab',b'.text',b'.dynsym',b'.dynstr',b'.rodata',b'.comment',b'.interp',b'.note',b'.data',b'.bss',b'.init',b'.fini']:
    idx=0
    hits=[]
    while True:
        i=data.find(tok,idx)
        if i<0: break
        hits.append(i)
        idx=i+1
    if hits:
        print(tok.decode(), hits)

def dump(lo,hi):
    print("=== dump %d..%d ==="%(lo,hi))
    for i in range(lo,min(hi,n),16):
        chunk=data[i:i+16]
        hexs=' '.join('%02x'%b for b in chunk)
        asc=''.join(chr(b) if 32<=b<127 else '.' for b in chunk)
        print("%5d  %-48s  %s"%(i,hexs,asc))

dump(0, 64)
dump(216, 320)
dump(2480, 2880)
dump(n-220, n)
