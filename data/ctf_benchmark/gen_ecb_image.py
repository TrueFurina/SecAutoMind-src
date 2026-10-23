#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
gen_ecb_image.py —— 生成 AES-ECB「企鹅图」基准工件 + ecb_benchmark.json。

真题对照：CTF 公开题 - AES ECB 企鹅（相同明文块 → 相同密文块的块状纹理）。
诚实设计：
  - 生成两张同构图像：AES-ECB 加密 与 AES-CBC 加密（对照）。
  - ECB 图：相同明文块 → 相同密文块 → 像素级出现大量重复 16B 块（块状噪声纹理）。
  - CBC 图：相同明文块 → 不同密文块 → 重复块率极低（雪崩）。
  - judge 必须**同时**满足「ECB 图重复块 ≥ 阈值 且 CBC 图重复块 < 阈值」才命中，
    杜绝「无脑数重复块」的朴素正则式虚报（反注水，与附件集同一纪律）。

用法：  python gen_ecb_image.py [--out-dir artifacts]
"""
import argparse
import hashlib
import json
import os

from Crypto.Cipher import AES
from PIL import Image

HERE = os.path.dirname(os.path.abspath(__file__))
ART = os.path.join(HERE, "artifacts")

SCENE = {
    "ecb_penguin": "flag{aes_ecb_bl0ck_r3p34t_t3xtur3}",
}

KEY = bytes(range(16))  # 固定密钥（基准工件，公开即可）
IV = bytes(range(16))   # 固定 IV（CBC 对照图用）


def pad16(b: bytes) -> bytes:
    n = 16 - (len(b) % 16)
    return b + bytes([n]) * n


def make_pattern_image(size=96):
    """画一张含大量重复色块的图案（模拟"企鹅图"的平坦色块语义）。"""
    img = Image.new("RGB", (size, size))
    px = img.load()
    for y in range(size):
        for x in range(size):
            # 四个大色块 + 棋盘细格：保证大量相邻像素完全相同（明文块高度冗余）
            block = 16
            bx, by = x // block, y // block
            if (bx + by) % 2 == 0:
                c = (40 + 16 * by, 60 + 20 * bx, 120 + 8 * (bx + by))
            else:
                c = (200, 180, 160)
            if (x % 4 == 0) or (y % 4 == 0):
                c = (c[0] ^ 0x08, c[1] ^ 0x08, c[2] ^ 0x08)
            px[x, y] = c
    return img


def encrypt_mode(img: Image.Image, mode):
    """对图像原始 RGB 像素流按 16B 块加密后还原为同尺寸图像。"""
    raw = img.tobytes()  # RGB interleaved
    pad = pad16(raw)
    cipher = AES.new(KEY, mode) if mode == AES.MODE_ECB else AES.new(KEY, mode, IV)
    enc = cipher.encrypt(pad)
    enc = enc[: len(raw)]
    out = Image.frombytes("RGB", img.size, enc)
    return out


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--out-dir", default=ART)
    args = ap.parse_args()
    os.makedirs(args.out_dir, exist_ok=True)

    base = make_pattern_image(96)
    ecb = encrypt_mode(base, AES.MODE_ECB)
    cbc = encrypt_mode(base, AES.MODE_CBC)
    ecb_path = os.path.join(args.out_dir, "ecb_penguin.png")
    cbc_path = os.path.join(args.out_dir, "cbc_penguin.png")
    ecb.save(ecb_path)
    cbc.save(cbc_path)

    # 反注水校验：ECB 重复块率应显著高于 CBC
    def dup_ratio(p):
        img = Image.open(p).convert("RGB")
        raw = img.tobytes()
        blocks = [raw[i:i + 16] for i in range(0, len(raw) - 15, 16)]
        uniq = len(set(blocks))
        return 1 - uniq / len(blocks)

    r_ecb, r_cbc = dup_ratio(ecb_path), dup_ratio(cbc_path)
    assert r_ecb >= 0.3, "ECB 重复块率过低: %.3f" % r_ecb
    assert r_cbc <= 0.05, "CBC 重复块率过高: %.3f" % r_cbc
    print("ECB dup=%.3f CBC dup=%.3f (assert OK)" % (r_ecb, r_cbc))

    out = {"problems": {
        k: {"category": "crypto", "flag_sha256": hashlib.sha256(v.encode()).hexdigest()}
        for k, v in SCENE.items()
    }}
    bench_path = os.path.join(HERE, "ecb_benchmark.json")
    with open(bench_path, "w", encoding="utf-8", newline="\n") as fh:
        json.dump(out, fh, ensure_ascii=False, indent=2)
        fh.write("\n")
    print("artifacts -> %s, %s" % (ecb_path, cbc_path))
    print("benchmark -> %s" % bench_path)


if __name__ == "__main__":
    main()
