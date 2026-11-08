"""长安杯2021 Crypto ezpy 校验器。
原题为 20 进制(字母表 0-9A-J)编码后乘 233 mod 256 的混淆; 官方给出 sha256。
真值不入仓：只存官方 sha256；复核时把 flag 放进环境变量即可逐字对上。
"""
import hashlib
import os

EXPECT_SHA256 = "f7494167e4c3fc8e6b36525c5c12a5c73077b5f6fdd6f75dd205903b0779b181"
flag = os.environ.get("CHANGAN_EZPY_FLAG", "")
if not flag:
    raise SystemExit("需要真 flag 才能复核：先设 CHANGAN_EZPY_FLAG 环境变量")
assert hashlib.sha256(flag.encode()).hexdigest() == EXPECT_SHA256, "sha256 mismatch"
print("VERIFIED changan2021_ezpy: sha256 与记录一致" )
