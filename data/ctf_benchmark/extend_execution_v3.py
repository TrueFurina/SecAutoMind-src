# -*- coding: utf-8 -*-
"""执行基准集 v3：幂等追加 crypto 经典攻击三题（参数合成自 gen_crypto_attack_params.py）。"""
import hashlib
import json
import os

BASE = os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
os.chdir(BASE)

params = json.load(open("data/ctf_benchmark/crypto_attack_params.json", encoding="utf-8"))

FLAG_CM = params["common_modulus"]["flag"]
FLAG_HB = params["hastad_broadcast"]["flag"]
FLAG_WN = params["wiener"]["flag"]
cm, hb, wn = params["common_modulus"], params["hastad_broadcast"], params["wiener"]

doc = json.load(open("data/ctf_benchmark/execution_benchmark.json", encoding="utf-8"))
probs = doc["problems"]

# ── 生成参数工件文件（真实 CTF 场景：RSA 参数在附件中） ──
EXEC_DIR = "data/ctf_benchmark/execution"
os.makedirs(EXEC_DIR, exist_ok=True)
ART = {
    "exec_common_modulus.txt": (
        "Alice 加密同一消息用了两个公钥指数（同一模数 n）：\n"
        f"n = {cm['n']}\ne1 = {cm['e1']}\ne2 = {cm['e2']}\n"
        f"c1 = {cm['c1']}\nc2 = {cm['c2']}\n"
        "恢复原始明文消息。"
    ),
    "exec_hastad_broadcast.txt": (
        "同一明文用 e=3 与三个不同模数加密后分发给三个接收者：\n"
        f"e = {hb['e']}\nn1 = {hb['n1']}\nn2 = {hb['n2']}\nn3 = {hb['n3']}\n"
        f"c1 = {hb['c1']}\nc2 = {hb['c2']}\nc3 = {hb['c3']}\n"
        "恢复原始明文消息。"
    ),
    "exec_rsa_wiener.txt": (
        "该 RSA 实现的私钥指数 d 生成过小（Wiener 攻击条件）：\n"
        f"n = {wn['n']}\ne = {wn['e']}\nc = {wn['c']}\n"
        "恢复原始明文消息。"
    ),
}
for fn, content in ART.items():
    with open(os.path.join(EXEC_DIR, fn), "w", encoding="utf-8") as f:
        f.write(content)

def att(fn):
    return {fn: fn}

probs["exec_common_modulus"] = {
    "id": "exec_common_modulus",
    "category": "crypto",
    "sub": "common_modulus",
    "difficulty": "medium",
    "description": "Alice 用同一模数 n 和两个不同的公钥指数加密了同一明文（等价真题：相同的模数下发两份密文），附件给出 n/e1/e2/c1/c2，恢复明文。",
    "attachments": att("exec_common_modulus.txt"),
    "flag_sha256": hashlib.sha256(FLAG_CM.encode()).hexdigest(),
    "presolve_skill": "common_modulus_attack",
}
probs["exec_hastad_broadcast"] = {
    "id": "exec_hastad_broadcast",
    "category": "crypto",
    "sub": "hastad_broadcast",
    "difficulty": "medium",
    "description": "同一明文用 e=3 和三个不同模数分别加密后广播（等价真题：Hastad 广播攻击），附件给出 e/n1-n3/c1-c3，恢复明文。",
    "attachments": att("exec_hastad_broadcast.txt"),
    "flag_sha256": hashlib.sha256(FLAG_HB.encode()).hexdigest(),
    "presolve_skill": "hastad_broadcast_attack",
}
probs["exec_rsa_wiener"] = {
    "id": "exec_rsa_wiener",
    "category": "crypto",
    "sub": "rsa_wiener",
    "difficulty": "hard",
    "description": "RSA 私钥指数 d 过小（Wiener 条件），附件给出 n/e/c，恢复明文（等价真题：Wiener 连分数攻击）。",
    "attachments": att("exec_rsa_wiener.txt"),
    "flag_sha256": hashlib.sha256(FLAG_WN.encode()).hexdigest(),
    "presolve_skill": "rsa_wiener_attack",
}

doc["version"] = "v3-exec"
json.dump(doc, open("data/ctf_benchmark/execution_benchmark.json", "w", encoding="utf-8"),
          indent=1, ensure_ascii=False)
print("执行集扩容:", len(probs), "题 (v3-exec)")
for k in ("exec_common_modulus", "exec_hastad_broadcast", "exec_rsa_wiener"):
    v = probs[k]
    print(" ", k, "| att:", v["attachments"], "| sha256:", v["flag_sha256"][:16])
