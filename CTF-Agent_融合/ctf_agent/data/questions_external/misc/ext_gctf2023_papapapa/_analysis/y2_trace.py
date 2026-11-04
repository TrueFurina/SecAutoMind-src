import pickle

d = pickle.load(open("_analysis/blocks2.pkl", "rb"))
blocks = d["blocks"]

# find row7 Y bx=2 block and dump its ACs with positions
for b in blocks:
    if b[0] == 21 and b[1] == 7 and b[2] == 1 and b[3] == 2:
        print(f"block (21,7) Y bx=2: bits [{b[7]},{b[9]}), dc={b[5]}, nac={len(b[6])}")
        pos = 0
        maxpos = 0
        zrl = 0
        for i, (run, v) in enumerate(b[6]):
            pos += run + 1
            maxpos = max(maxpos, pos)
            if run == 15:
                zrl += 1
            if i >= len(b[6]) - 6 or run > 0:
                print(f"  ac[{i}] run={run} val={v} -> pos {pos}")
        print(f"  max position: {maxpos}, ZRL count: {zrl}")
        break

# check ALL data blocks for run>0 and max position
print("\nall data blocks position check:")
for b in blocks:
    if b[2] == 1 and b[6] and b[8]:
        pos = 0
        mx = 0
        runs = set()
        for (run, v) in b[6]:
            pos += run + 1
            mx = max(mx, pos)
            runs.add(run)
        print(f"  mcu=({b[0]},{b[1]}) bx={b[3]}: nac={len(b[6])}, maxpos={mx}, runs={sorted(runs)[:5]}{'...' if len(runs)>5 else ''}")
