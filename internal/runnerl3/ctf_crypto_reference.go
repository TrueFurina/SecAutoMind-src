package runnerl3

// ctfCryptoAPIRef 是注入给 L3 模型的 ctf_crypto 即用原语**签名级**参考（R3 opt1 配套件）。
//
// 为什么需要它：buildSystemPrompt 只告诉模型「可直接 import ctf_crypto as C」，但若不给
// 精确签名，V3 这类非推理模型会凭空猜参数名/顺序 → AttributeError / 调用失败 → 等于白注入库。
// 本常量逐条对齐 crypto_lib/ctf_crypto.py 的公开签名（由本地 `inspect` 提取，非手写）。
//
// 🔴 同步纪律：crypto_lib/ctf_crypto.py 增删或改签名时，必须同步更新本常量，否则模型
// 拿到的签名是假的（比没有参考更糟——会坚定地调错）。改库后跑一次
//
//	python3 -c "import inspect,importlib.util as u; ..." 复校即可。
const ctfCryptoAPIRef = `ctf_crypto 即用原语（import ctf_crypto as C 后直接调用；参数名/顺序如下，勿改）：
- rsa_wiener(e, n) -> d                  # 小私钥维纳攻击 (d < n^0.25/3)
- rsa_fermat(n, rounds=20000) -> (p, q)  # 两素数接近时费马分解
- rsa_common_modulus(c1, c2, e1, e2, n) -> m  # 同模数不同指数
- rsa_common_factor(n1, n2) -> (p, q)    # 两模数共享素因子
- rsa_broadcast(e, pairs) -> M           # 同明文低指数广播(Hastad)，pairs=[(n,c),...]
- modinv(a, m) -> x                      # 模逆
- crt(rems, mods) -> x                   # 中国剩余定理
- egcd(a, b) -> (g, x, y)                # 扩展欧几里得 (g = a*x + b*y)
- factor(n) -> dict / prime_factors(n) -> list  # 整数分解
- iroot(x, n) -> (r, exact)             # 整数 n 次根
- isqrt(n) / isqrt_floor(n) -> int       # 整数平方根
- lll(B, delta=0.75) -> list             # 纯 Python LLL 格基规约，B = 行向量矩阵(list[list[int]])
- identify_hash(s) -> str|None           # 按字节长度识别常见哈希('sha256'/'sha1'/.../None)
- hash_bytes(data: bytes, algo='sha256') -> str  # 计算十六进制哈希
- xor_bytes(a, b) -> bytes               # 等长异或
- aes_ecb_decrypt(ct, key) -> bytes      # AES-ECB 解密
- aes_cbc_decrypt(ct, key, iv) -> bytes  # AES-CBC 解密
- des_decrypt(ct, key) -> bytes          # DES 解密
- ECPoint(x, y, a, b, p)                 # 椭圆曲线点；支持 +、-、k*P (k 为 int)
- bsgs(base, target, p, order=None) -> int|None  # 大步小步离散对数
- idea_encrypt_block(key, block) -> bytes  # IDEA 加密单块(64-bit 块/128-bit 密钥)，key/block 各 16 字节
- idea_decrypt_block(key, block) -> bytes  # IDEA 解密单块
- lcg_recover_modulus(outputs) -> int|None      # 由 LCG 输出序列恢复模数 m(相邻差 GCD)
- lcg_recover_params(outputs) -> (a,c,m,state0)|None  # 恢复 LCG 全参数 a,c,m 与初态
- lcg_next(state, a, c, m) -> int                 # 推进一步 LCG: state=(a*state+c)%m
- mhk_decrypt(ciphertext, w, r, m) -> int         # Merkle-Hellman 背包私有钥解密(w 超递增,r=m^{-1} mod m)
- merkle_root(leaves, hashfn='sha256') -> str     # 计算 Merkle 根(奇数层复制末节点)，返回 hex`
