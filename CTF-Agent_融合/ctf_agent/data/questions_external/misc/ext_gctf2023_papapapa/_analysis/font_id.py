# -*- coding: utf-8 -*-
"""开发期：字体识别 —— 候选斜体衬线字体渲染宽度 vs 实测段宽。"""
import numpy as np
from PIL import Image, ImageDraw, ImageFont

import os  # noqa: E402
FLAG = os.environ.get("PAPAPAPA_FLAG", "")  # 逐字符对齐要用真值：不入仓，走环境变量
if not FLAG:
    raise SystemExit("需要真 flag 才能逐字符对齐：先设 PAPAPAPA_FLAG 环境变量")
# 实测段宽（THR=200, 新装配）
OBS = {"C":7, "T":8, "F":6, "r":5, "e":7, "a":8, "v":8, "i":2, "w":12, "m":12, "o":7, "n":7,
       "l":2, "s":6, "b":7, "c":5, "k":7, "p":7, "d":7, "u":7, "t":5, "{":5, "-":3, "}":4}

FONTS = [
    "/c/Windows/Fonts/timesi.ttf",
    "/c/Windows/Fonts/times.ttf",
    "/c/Windows/Fonts/georgiai.ttf",
    "/c/Windows/Fonts/georgia.ttf",
    "/c/Windows/Fonts/constani.ttf",
    "/c/Windows/Fonts/cambria.ttc",
    "/c/Windows/Fonts/BOOKOS.TTF",
    "/c/Windows/Fonts/ariali.ttf",
    "/c/Windows/Fonts/segoeuii.ttf",
    "/c/Windows/Fonts/verdana.ttf",
    "/c/Windows/Fonts/DejaVuSerif-Italic.ttf",
    "/c/Windows/Fonts/DejaVuSerif.ttf",
    "E:/Program/西湖论剑/ctf_agent/data/questions_external/misc/ext_gctf2023_papapapa/_analysis/DejaVuSerif.ttf",
]

def char_widths(font, chars):
    out = {}
    for ch in chars:
        bbox = font.getbbox(ch)
        out[ch] = bbox[2] - bbox[0]
    return out

results = []
for fp in FONTS:
    try:
        for size in range(13, 24):
            font = ImageFont.truetype(fp, size)
            cw = char_widths(font, OBS.keys())
            err = sum(abs(cw[c] - OBS[c]) for c in OBS) / len(OBS)
            results.append((err, fp, size))
    except Exception as ex:
        print("skip", fp, ex)

results.sort()
for err, fp, size in results[:12]:
    print(f"{err:.2f}  {fp}  size={size}")
