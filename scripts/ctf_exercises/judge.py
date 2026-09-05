# -*- coding: utf-8 -*-
"""演练判分器：提交 flag → sha256 对 ground truth → 出报告
用法: python judge.py "flag{...}"            # 同一 flag 判所有题
      python judge.py --check               # 校验题目文件完整性
"""
import hashlib, json, os, sys

HERE = os.path.dirname(os.path.abspath(__file__))
GT = json.load(open(os.path.join(HERE, "ground_truth.json"), encoding="utf-8"))

REQUIRED = {
    "c1_zip_chain":   ["challenge.b64"],
    "c2_xor_prefix":  ["cipher.bin", "hint.txt"],
    "c3_rsa_fermat":  ["task.txt"],
    "c4_log_forensics": ["access.log"],
    "c5_png_lsb":     ["stego.png", "readme.txt"],
}

def check_files():
    ok = True
    for cid, files in REQUIRED.items():
        for fn in files:
            p = os.path.join(HERE, cid, fn)
            if not os.path.exists(p):
                print(f"❌ 缺失 {cid}/{fn}"); ok = False
    print("题目文件完整性:", "✅ 全部在位" if ok else "❌ 有缺失（先跑 generate_exercises.py）")
    return ok

def judge(submitted: str):
    h = hashlib.sha256(submitted.encode()).hexdigest()
    solved = [cid for cid, v in GT.items() if v["flag_sha256"] == h]
    print(f"提交: {submitted[:20]}... sha256={h[:12]}")
    if solved:
        for cid in solved:
            print(f"  ✅ 命中 {cid}")
    else:
        print("  ❌ 未命中任何题")
    print(f"总计: {len(solved)}/{len(GT)} 题使用了该 flag")
    return solved

if __name__ == "__main__":
    if "--check" in sys.argv:
        check_files()
    elif len(sys.argv) > 1:
        judge(sys.argv[1].strip())
    else:
        print(__doc__)
