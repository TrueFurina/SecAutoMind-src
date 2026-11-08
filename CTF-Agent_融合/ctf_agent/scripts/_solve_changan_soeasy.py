"""长安杯2021 Web soeasy 校验器。
考点: jwt secret 爆破(CTf4r) + user 处 SSTI 读 /flag; 响应回显 flag。
真值不入仓：只存该 flag 的 sha256；复核时把 flag 放进环境变量。
"""
import hashlib
import os

EXPECT_SHA256 = "95a8f144fd20374d4231e799f4d281c62e3802ae47c11deed9c004e4dba45a9c"
flag = os.environ.get("CHANGAN_SOEASY_FLAG", "")
if not flag:
    raise SystemExit("需要真 flag 才能复核：先设 CHANGAN_SOEASY_FLAG 环境变量")
assert hashlib.sha256(flag.encode()).hexdigest() == EXPECT_SHA256, "sha256 mismatch"
print("VERIFIED changan2021_soeasy: sha256 与记录一致 (jwt secret=CTf4r, SSTI->/flag)")
