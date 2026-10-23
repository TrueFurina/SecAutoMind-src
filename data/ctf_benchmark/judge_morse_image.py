#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
judge_morse_image.py —— Morse 时序图判定器（Python 侧）。

真题对照：SpookyCTF 2024 - whispers-in-morse（public_morse_image 能力面）。
判定路径：PNG 像素 → 中间行 run-length → dot/dash 与符号/字符/词间隔分类 → Morse 解码
          → flag{解码内容小写} → SHA-256 比对。
反注水：图中无任何可读文字；分类必须同时满足 run 宽度与间隔语义，任何一步错乱即 miss。

用法：  python judge_morse_image.py
"""
import hashlib
import json
import os
import sys

from PIL import Image

HERE = os.path.dirname(os.path.abspath(__file__))
BENCH = os.environ.get("MORSE_IMG_BENCH", os.path.join(HERE, "morse_image_benchmark.json"))
ART = os.path.join(HERE, "artifacts")

MORSE_TABLE = {
    "A": ".-", "B": "-...", "C": "-.-.", "D": "-..", "E": ".", "F": "..-.",
    "G": "--.", "H": "....", "I": "..", "J": ".---", "K": "-.-", "L": ".-..",
    "M": "--", "N": "-.", "O": "---", "P": ".--.", "Q": "--.-", "R": ".-.",
    "S": "...", "T": "-", "U": "..-", "V": "...-", "W": ".--", "X": "-..-",
    "Y": "-.--", "Z": "--..",
    "0": "-----", "1": ".----", "2": "..---", "3": "...--", "4": "....-",
    "5": ".....", "6": "-....", "7": "--...", "8": "---..", "9": "----.",
}
DOT, DASH = 2, 6
GAP_SYM, GAP_CHAR = 2, 6
RUN_T = 4      # dot/dash 阈值：w <= 4 -> dot，w > 4 -> dash
GAP_T = 5      # symbol/char 间隔阈值：g <= 5 -> symbol，否则 -> char


def decode_image(path: str):
    img = Image.open(path).convert("RGB")
    w, h = img.size
    y = h // 2
    row = [img.getpixel((x, y))[0] > 127 for x in range(w)]
    # run-length（真值段）
    runs = []
    i = 0
    while i < w:
        if row[i]:
            j = i
            while j < w and row[j]:
                j += 1
            runs.append((True, j - i))
            i = j
        else:
            j = i
            while j < w and not row[j]:
                j += 1
            runs.append((False, j - i))
            i = j
    # 组装 token：on-run 为符号，off-run 按宽度区分「符号间隔」(同一字符内) 与「字符间隔」
    tokens = []
    cur = ""
    for on, ln in runs:
        if on:
            cur += "-" if ln > RUN_T else "."
        else:
            if cur and ln > GAP_T:      # 字符间隔：收尾当前字符
                tokens.append(cur)
                cur = ""
            # 符号间隔（ln <= GAP_T）：继续拼接当前字符
    if cur:
        tokens.append(cur)
    morse_to_char = {v: k for k, v in MORSE_TABLE.items()}
    text = "".join(morse_to_char.get(t, "") for t in tokens)
    return text


def main():
    bench = json.load(open(BENCH, encoding="utf-8"))["problems"]
    path = os.path.join(ART, "morse_timing.png")
    if not os.path.exists(path):
        print("工件缺失，先跑 python gen_morse_image.py")
        return 1
    dec = decode_image(path)
    cand = "flag{" + dec.lower() + "}"
    hits = 0
    total = len(bench)
    for scene, p in bench.items():
        if hashlib.sha256(cand.encode()).hexdigest() == p["flag_sha256"]:
            hits += 1
            print("✅ HIT  %-12s decoded=%s" % (scene, cand))
        else:
            print("❌ MISS %-12s decoded=%s" % (scene, cand))
    print("=== [Python] Morse 时序图识别命中率: %d/%d = %.1f%% ===" % (hits, total, 100 * hits / total))
    return 0 if hits == total else 1


if __name__ == "__main__":
    sys.exit(main())
