# -*- coding: utf-8 -*-
"""生成 SecAutoMind 实战赛演练题库（5 道 CTF 风格模拟题 + ground truth）
方法论移植自西湖论剑 CTF-Agent 验证过的解题套路（zip 链/已知前缀 XOR/Fermat 分解/日志取证/LSB 隐写）。
只生成题目与判分器，不写任何解题引擎。运行一次即可。
"""
import base64, hashlib, io, json, os, random, struct, zipfile

HERE = os.path.dirname(os.path.abspath(__file__))
random.seed(20260905)

def sha(s): return hashlib.sha256(s.encode()).hexdigest()

FLAG = "flag{SecAutoMind_practice_2026}"
flags = {}

# ---------- C1 misc_zip_chain：嵌套 zip + base64 链 ----------
F1 = "flag{zip_chain_layer3_secret}"
d1 = os.path.join(HERE, "c1_zip_chain"); os.makedirs(d1, exist_ok=True)
buf = io.BytesIO()
with zipfile.ZipFile(buf, "w") as z:
    z.writestr("secret.txt", F1)
data = buf.getvalue()
# 外层再包两层 zip + 最外壳做 base64
for name in ("layer2.zip", "layer1.zip"):
    nb = io.BytesIO()
    with zipfile.ZipFile(nb, "w") as z:
        z.writestr(name, data)
    data = nb.getvalue()
open(os.path.join(d1, "challenge.b64"), "w").write(base64.b64encode(data).decode())
flags["c1_zip_chain"] = F1

# ---------- C2 crypto_xor_prefix：XOR 已知前缀攻击 ----------
F2 = "flag{xor_known_prefix_attack}"
d2 = os.path.join(HERE, "c2_xor_prefix"); os.makedirs(d2, exist_ok=True)
key = bytes([0x5A])
ct = bytes(b ^ key[i % len(key)] for i, b in enumerate(F2.encode()))
open(os.path.join(d2, "cipher.bin"), "wb").write(ct)
open(os.path.join(d2, "hint.txt"), "w").write("密钥为单字节，且已知明文以 'flag{' 开头。")
flags["c2_xor_prefix"] = F2

# ---------- C3 crypto_rsa_fermat：Fermat 分解（相近素数） ----------
F3 = "flag{f3rma7}"  # 12 字节，保证 m < n（n 为 128-bit）
d3 = os.path.join(HERE, "c3_rsa_fermat"); os.makedirs(d3, exist_ok=True)
def is_prime(n):
    """Miller-Rabin（确定性底数，覆盖 < 3.3e24 的 64-bit 区间足够强）"""
    if n < 2: return False
    for sp in (2,3,5,7,11,13,17,19,23,29,31,37):
        if n % sp == 0: return n == sp
    d, s = n-1, 0
    while d % 2 == 0: d //= 2; s += 1
    for a in (2,3,5,7,11,13,17,19,23,29,31,37):
        x = pow(a, d, n)
        if x in (1, n-1): continue
        for _ in range(s-1):
            x = x*x % n
            if x == n-1: break
        else: return False
    return True
# 64-bit 相近素数：q = p+2（Fermat 一步分解）
p = random.getrandbits(63) | 1
while not is_prime(p): p += 2
q = p + 2
while not is_prime(q): q += 2
n, e = p*q, 65537
phi = (p-1)*(q-1)
d = pow(e, -1, phi)
m = int.from_bytes(F3.encode(), "big")
assert m < n, "message must be < n"
c = pow(m, e, n)
open(os.path.join(d3, "task.txt"), "w").write(f"n = {n}\ne = {e}\nc = {c}\n提示：p 与 q 相距极近（相邻奇素数）。")
flags["c3_rsa_fermat"] = F3

# ---------- C4 misc_log_forensics：日志取证 ----------
F4 = "flag{log_forensics_exfil_found}"
d4 = os.path.join(HERE, "c4_log_forensics"); os.makedirs(d4, exist_ok=True)
lines = []
for i in range(200):
    ip = f"10.0.0.{random.randint(1,254)}"
    path = random.choice(["/index.html", "/login", "/static/app.js", "/api/data"])
    lines.append(f'{ip} - - [05/Sep/2026:0{i%9}:22:33 +0800] "GET {path} HTTP/1.1" 200 512 "-" "Mozilla/5.0"')
# 注入 3 条可疑（含 flag 的外带请求）
lines.insert(57, f'10.0.0.66 - - [05/Sep/2026:03:22:33 +0800] "GET /api/data?x={F4} HTTP/1.1" 200 12 "-" "curl/8.0"')
lines.insert(120, f'10.0.0.66 - - [05/Sep/2026:04:10:11 +0800] "POST /login HTTP/1.1" 401 220 "-" "{F4}"')
lines.insert(180, f'10.0.0.66 - - [05/Sep/2026:05:55:05 +0800] "GET /admin HTTP/1.1" 403 0 "-" "{F4}"')
open(os.path.join(d4, "access.log"), "w").write("\n".join(lines))
flags["c4_log_forensics"] = F4

# ---------- C5 misc_png_lsb：PNG LSB 隐写 ----------
F5 = "flag{png_lsb_stego_hidden}"
d5 = os.path.join(HERE, "c5_png_lsb"); os.makedirs(d5, exist_ok=True)
from PIL import Image
img = Image.new("RGB", (120, 60), (30, 60, 120))
bits = "".join(format(b, "08b") for b in F5.encode() + b"\x00")
px = img.load()
idx = 0
for y in range(60):
    for x in range(120):
        if idx >= len(bits): break
        r, g, b = px[x, y]
        b = (b & 0xFE) | int(bits[idx]); idx += 1
        px[x, y] = (r, g, b)
img.save(os.path.join(d5, "stego.png"))
open(os.path.join(d5, "readme.txt"), "w").write("图片 LSB 隐写，低位按行序承载 ASCII，以 NUL 结尾。")
flags["c5_png_lsb"] = F5

# ---------- ground truth ----------
gt = {k: {"flag": v, "flag_sha256": sha(v)} for k, v in flags.items()}
with open(os.path.join(HERE, "ground_truth.json"), "w", encoding="utf-8") as f:
    json.dump(gt, f, ensure_ascii=False, indent=2)
print("generated:", json.dumps({k: v["flag_sha256"][:12] for k, v in gt.items()}, indent=1))
print("FILES OK")
