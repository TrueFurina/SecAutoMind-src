#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
gen_morse_image.py —— 生成 Morse 时序图工件 + morse_image_benchmark.json。

真题对照：SpookyCTF 2024 - whispers-in-morse（public_morse_image，static 集 MISS 的能力面）。
诚实设计：
  - 图内只有黑底白条，Morse 以 run-length 编码：dot=2px、dash=6px、
    symbol-gap=2px、char-gap=6px、word-gap=14px（经典 OOK 时序图语义）。
  - 图像本身不含任何文字/注释；flag 必须经「像素 → run-length → Morse → 解码」才可得。
  - 与 exec_morse（文本 Morse）同表、同 flag 组合约定：flag{解码内容小写}。

用法：  python gen_morse_image.py [--out-dir artifacts]
"""
import argparse
import hashlib
import json
import os

from PIL import Image

HERE = os.path.dirname(os.path.abspath(__file__))
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
# 与 judge_exec.py 保持同一张表（双语言镜像的 Python 侧同一权威源）

SCENE = {
    "morse_image": "flag{m0rs31m4g3t1m1ngch4rt}",  # 内层: m0rs31m4g3t1m1ngch4rt（仅字母数字）
}
MORSE_CONTENT = "m0rs31m4g3t1m1ngch4rt"

DOT, DASH = 2, 6
GAP_SYM, GAP_CHAR, GAP_WORD = 2, 6, 14
H = 21   # 图高
MARGIN = 6


def content_to_runs(text: str):
    """把内容编码为 (is_on, width) 序列。"""
    runs = []
    first = True
    for ch in text:
        if not first:
            runs.append((False, GAP_CHAR))
        first = False
        for i, sym in enumerate(MORSE_TABLE[ch.upper()]):
            if i:
                runs.append((False, GAP_SYM))
            runs.append((True, DASH if sym == "-" else DOT))
    return runs


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--out-dir", default=ART)
    args = ap.parse_args()
    os.makedirs(args.out_dir, exist_ok=True)

    runs = content_to_runs(MORSE_CONTENT)
    total_w = MARGIN * 2 + sum(w for _, w in runs)
    img = Image.new("RGB", (total_w, H), (0, 0, 0))
    px = img.load()
    x = MARGIN
    top, bot = 3, H - 3
    for on, w in runs:
        if on:
            for xx in range(x, x + w):
                for yy in range(top, bot):
                    px[xx, yy] = (255, 255, 255)
        x += w

    path = os.path.join(args.out_dir, "morse_timing.png")
    img.save(path)

    out = {"problems": {
        k: {"category": "misc", "flag_sha256": hashlib.sha256(v.encode()).hexdigest()}
        for k, v in SCENE.items()
    }}
    bench_path = os.path.join(HERE, "morse_image_benchmark.json")
    with open(bench_path, "w", encoding="utf-8", newline="\n") as fh:
        json.dump(out, fh, ensure_ascii=False, indent=2)
        fh.write("\n")
    print("artifact -> %s (w=%d)" % (path, total_w))
    print("benchmark -> %s" % bench_path)


if __name__ == "__main__":
    main()
