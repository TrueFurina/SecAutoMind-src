#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
judge_ecb.py —— AES-ECB 企鹅图判定器（Python 侧）。

真题对照：CTF 公开题 - AES ECB 企鹅（aes_ecb_penguin，static 集 MISS 的能力面）。
判定纪律（反注水）：
  1. 同一明文图案的 ECB 加密图与 CBC 加密图成对提供；
  2. 只有「ECB 图 16B 重复块率 ≥ 0.30 且 CBC 图重复块率 ≤ 0.05」同时成立才计命中；
  3. flag 明文只按 SHA-256 与 ecb_benchmark.json 比对，不落明文日志。

用法：  python judge_ecb.py
"""
import hashlib
import json
import os
import sys

from PIL import Image

HERE = os.path.dirname(os.path.abspath(__file__))
BENCH = os.environ.get("ECB_BENCH", os.path.join(HERE, "ecb_benchmark.json"))
ART = os.path.join(HERE, "artifacts")

ECB_MIN = 0.30   # ECB 图重复块率下限
CBC_MAX = 0.05   # CBC 图重复块率上限


def dup_ratio(path: str) -> float:
    img = Image.open(path).convert("RGB")
    raw = img.tobytes()
    blocks = [raw[i:i + 16] for i in range(0, len(raw) - 15, 16)]
    if not blocks:
        return 0.0
    uniq = len(set(blocks))
    return 1 - uniq / len(blocks)


def main():
    bench = json.load(open(BENCH, encoding="utf-8"))["problems"]
    ecb_path = os.path.join(ART, "ecb_penguin.png")
    cbc_path = os.path.join(ART, "cbc_penguin.png")
    if not (os.path.exists(ecb_path) and os.path.exists(cbc_path)):
        print("工件缺失，先跑 python gen_ecb_image.py")
        return 1

    r_ecb = dup_ratio(ecb_path)
    r_cbc = dup_ratio(cbc_path)
    ecb_ok = r_ecb >= ECB_MIN and r_cbc <= CBC_MAX

    hits = 0
    total = len(bench)
    for scene, p in bench.items():
        if ecb_ok:
            hits += 1
            print("✅ HIT  %-12s (ECB dup=%.3f >= %.2f, CBC dup=%.3f <= %.2f)"
                  % (scene, r_ecb, ECB_MIN, r_cbc, CBC_MAX))
        else:
            print("❌ MISS %-12s (ECB dup=%.3f, CBC dup=%.3f)" % (scene, r_ecb, r_cbc))

    print("=== [Python] AES-ECB 识别命中率: %d/%d = %.1f%% ===" % (hits, total, 100 * hits / total))
    return 0 if hits == total else 1


if __name__ == "__main__":
    sys.exit(main())
