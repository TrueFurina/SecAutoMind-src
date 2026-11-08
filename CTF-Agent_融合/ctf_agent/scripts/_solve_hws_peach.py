"""HWS DASCTF 2022 Jan PWN peach 校验器。
考点: UAF 改 tcache 结构体劫持 __free_hook; 真值不入仓：只存该 flag 的 sha256。
"""
import hashlib
import os

EXPECT_SHA256 = "13c42279aade7f573945437b0b3a46d5a1fcf6f143d2ac19d2b8274e591ee37f"
flag = os.environ.get("HWS_PEACH_FLAG", "")
if not flag:
    raise SystemExit("需要真 flag 才能复核：先设 HWS_PEACH_FLAG 环境变量")
assert hashlib.sha256(flag.encode()).hexdigest() == EXPECT_SHA256, "sha256 mismatch"
print("VERIFIED hws2022_peach: sha256 与记录一致" )
