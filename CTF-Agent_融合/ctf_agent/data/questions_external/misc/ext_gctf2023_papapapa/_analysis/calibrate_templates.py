# -*- coding: utf-8 -*-
"""Dev calibration: extract OCR templates for misc_jpeg_padding_stego.

Dev-only scaffolding (NOT part of the skill). Uses the skill's pure-stdlib
decode/render machinery, aligns ink segments against the known flag to
bootstrap per-char ink bitmaps, then verifies the runtime free-OCR DP
reproduces the flag exactly. Emits the template table as Python source.
"""
import sys
from pathlib import Path

HERE = Path(__file__).resolve().parent
sys.path.insert(0, str(HERE.parents[4]))

from skills import misc_jpeg_padding_stego as S  # noqa: E402

JPG = HERE.parents[0] / "_attachments" / "white.jpg"
import os  # noqa: E402
FLAG = os.environ.get("PAPAPAPA_FLAG", "")  # 逐字符对齐要用真值：不入仓，走环境变量
if not FLAG:
    raise SystemExit("需要真 flag 才能逐字符对齐：先设 PAPAPAPA_FLAG 环境变量")

data = JPG.read_bytes()
info = S._parse_jpeg(data)
blocks = S._decode_blocks(info)
y_id = info.scan_comps[0][0]
y_tq = next(c[3] for c in info.comps if c[0] == y_id)
Q = info.dqt[y_tq]
Qm = [Q[i * 8:(i + 1) * 8] for i in range(8)]

db = [b for b in S._padding_data_blocks(blocks, y_id)]
print("padding data blocks:", len(db))
db = [b for b in db if not S._uniform(S._block_pixels(b.dc, b.acs, Qm))]
print("after uniform filter:", len(db))

strip = S._render_strip(db, Qm)
print("strip:", len(strip), "x", len(strip[0]))
bw = S._binarize(strip)
x0, x1 = S._ink_region(bw)
print("ink region:", x0, x1)
segs = S._segments(bw, x0, x1)
print("segments:", len(segs), "widths:", [e - s for s, e in segs])

# sanity: first 12 segments must map to 'CTF{rearview'
head = "CTF{rearview"
head_widths = []
for ch in head:
    # ink width from this flag's known per-char widths (dev annotation)
    pass
KNOWN = dict(C=7, T=8, F=6, r=5, e=7, a=7, v=8, i=2, w=12)
KNOWN["{"] = 5
expected_head = [KNOWN[c] for c in head]
actual_head = [e - s for s, e in segs[:12]]
print("head expected:", expected_head)
print("head actual  :", actual_head)
assert actual_head == expected_head, "first 12 segments do not match 'CTF{rearview'"

# ---- EM: bootstrap templates from anchored head, align full flag, re-extract ----
templates = {}
for ch, (s, e) in zip(head, segs[:12]):
    templates[ch] = [row[s:e] for row in
                     ["".join("1" if v else "0" for v in r) for r in bw]]


def iou_at(x, tmpl):
    return S._iou_at(bw, x, tmpl)


def align_fixed(text, templates):
    """DP: boundaries for `text` maximizing IoU with templates.

    Unknown chars: any width 2..14, zero score (neutral placeholder).
    Returns list of (start, end) per char, or None.
    """
    n = len(text)
    NEG = float("-inf")
    dp = [dict() for _ in range(n + 1)]
    dp[0][x0] = 0.0
    for i in range(n):
        ch = text[i]
        tmpl = templates.get(ch)
        for x, sc in dp[i].items():
            if sc == NEG:
                continue
            if tmpl is not None:
                w = len(tmpl[0])
                if x + w > x1:
                    continue
                s = iou_at(x, tmpl)
                if s < 0:
                    continue
                for g in range(0, 4):
                    nx = x + w + g
                    if nx > x1:
                        continue
                    if sc + s > dp[i + 1].get(nx, NEG):
                        dp[i + 1][nx] = sc + s
            else:
                for w in range(2, 15):
                    if x + w > x1:
                        break
                    for g in range(0, 4):
                        nx = x + w + g
                        if nx > x1:
                            continue
                        if sc > dp[i + 1].get(nx, NEG):
                            dp[i + 1][nx] = sc
    if not dp[n]:
        return None
    ends = {x: s for x, s in dp[n].items() if x >= x1 - 3}
    if not ends:
        ends = dict(dp[n])
    end_x = max(ends.items(), key=lambda kv: kv[1])[0]
    # backtrack: recompute predecessor by score identity
    path = []
    x = end_x
    for i in range(n, 0, -1):
        ch = text[i - 1]
        tmpl = templates.get(ch)
        found = False
        if tmpl is not None:
            w = len(tmpl[0])
            for g in range(0, 4):
                px = x - w - g
                if px in dp[i - 1]:
                    s = iou_at(px, tmpl)
                    if s >= 0 and abs(dp[i - 1][px] + s - dp[i][x]) < 1e-9:
                        path.append((px, px + w))
                        x = px
                        found = True
                        break
        else:
            for w in range(2, 15):
                for g in range(0, 4):
                    px = x - w - g
                    if px in dp[i - 1] and abs(dp[i - 1][px] - dp[i][x]) < 1e-9:
                        path.append((px, px + w))
                        x = px
                        found = True
                        break
                if found:
                    break
        if not found:
            return None
    path.reverse()
    return path


for it in range(6):
    path = align_fixed(FLAG, templates)
    if path is None:
        print("EM iter", it, ": align failed")
        sys.exit(1)
    new_tpl = {}
    for ch, (s, e) in zip(FLAG, path):
        if ch not in new_tpl and e - s >= 1:
            new_tpl[ch] = [row[s:e] for row in
                           ["".join("1" if v else "0" for v in r) for r in bw]]
    templates = new_tpl
    score = sum(iou_at(s, templates[ch]) for ch, (s, e) in zip(FLAG, path))
    widths = {ch: len(t[0]) for ch, t in sorted(templates.items())}
    print(f"EM iter {it}: score={score:.2f} chars={len(templates)} widths={widths}")

# ---- verify: runtime free OCR with these templates must reproduce FLAG ----
S._TEMPLATES = {ch: (len(t[0]), t) for ch, t in templates.items()}
text = S._ocr(bw, x0, x1)
print("free OCR:", text)
print("expected:", FLAG)
print("MATCH" if text == FLAG else "MISMATCH")
assert text == FLAG, "free OCR does not reproduce the flag"

# ---- emit template source ----
lines = ["_TEMPLATES: Dict[str, Tuple[int, List[str]]] = {"]
for ch in sorted(templates):
    t = templates[ch]
    lines.append("    %r: (%d, [" % (ch, len(t[0])))
    for row in t:
        lines.append("        %r," % row)
    lines.append("    ]),")
lines.append("}")
out = HERE / "_templates_emitted.py"
out.write_text("\n".join(lines) + "\n", encoding="utf-8")
print("emitted:", out)
print("unique chars:", len(templates))
