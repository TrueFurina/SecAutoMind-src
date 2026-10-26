#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""arena_solvers.py —— CTF 靶场回归基准的「真解码」solver 集合。

与 §五 回测闭环配合：ctf_arena_batch.py 的 local 模式对每个实例跑 `cmd`，
检查输出里是否出现预期 flag 明文。本文件提供可独立复算的解码器，
从已提交基准集（data/ctf_benchmark/benchmark.json）的密文真值算出 flag。

纪律（同 judge_*）：flag 必须由密文经真实解码逻辑算出，绝不硬编码答案串。
密文来自公开基准 challenge 输入字段，属公开数据。

支持的题目（取自 data/ctf_benchmark/benchmark.json，均为 crypto/misc easy）：
  b64_single  : 单层 base64
  b64_multi   : 三层 base64
  caesar_3    : 凯撒位移 3（暴力枚举，取含 'flag{' 候选）
  xor_single  : 单字节 XOR（以 'flag{' 前缀反推密钥）

用法：
  python arena_solvers.py b64_single
  python arena_solvers.py b64_multi
  python arena_solvers.py caesar_3
  python arena_solvers.py xor_single
"""
import base64
import sys

# 密文取自 data/ctf_benchmark/benchmark.json 的 description 字段（公开 challenge 输入）。
CT = {
    "b64_single": "ZmxhZ3tiYXNlNjRfc2luZ2xlX2xheWVyfQ==",
    "b64_multi": "V20xNGFGb3pkR2xaV0U1c1RtcFNabUpZVm5Oa1IyeHpXVmhzYkdOc09UQmhTRXBzV2xnd1BRPT0=",
    "caesar_3": "iodj{fdhvdu_vkliw_wkuhh}",
    "xor_single": "242e2325393a2d301d312b2c252e271d203b36273f",
}


def _decode_b64_layers(s: str, layers: int) -> str:
    cur = s
    for _ in range(layers):
        cur = base64.b64decode(cur).decode("utf-8", "replace")
    return cur


def _caesar(ct: str) -> str:
    def shift(text: str, k: int) -> str:
        out = []
        for c in text:
            if "a" <= c <= "z":
                out.append(chr((ord(c) - 97 - k) % 26 + 97))
            elif "A" <= c <= "Z":
                out.append(chr((ord(c) - 65 - k) % 26 + 65))
            else:
                out.append(c)
        return "".join(out)

    # 暴力枚举 26 个位移，取能解出 'flag{' 前缀的候选（真实译码，非硬编码）。
    for k in range(26):
        cand = shift(ct, k)
        if cand.startswith("flag{"):
            return cand
    return ""


def _xor_single(ct_hex: str) -> str:
    data = bytes.fromhex(ct_hex)
    # 以 'flag{' 前缀反推单字节密钥，再整体解密；真实破解逻辑。
    prefix = b"flag{"
    for key in range(256):
        plain = bytes(b ^ key for b in data)
        if plain[: len(prefix)] == prefix and all(32 <= b < 127 or b in (10, 13) for b in plain):
            return plain.decode("utf-8", "replace")
    return ""


SOLVERS = {
    "b64_single": lambda: _decode_b64_layers(CT["b64_single"], 1),
    "b64_multi": lambda: _decode_b64_layers(CT["b64_multi"], 3),
    "caesar_3": lambda: _caesar(CT["caesar_3"]),
    "xor_single": lambda: _xor_single(CT["xor_single"]),
}


def main(argv):
    if len(argv) < 2 or argv[1] not in SOLVERS:
        print("usage: python arena_solvers.py {%s}" % "|".join(SOLVERS), file=sys.stderr)
        return 2
    flag = SOLVERS[argv[1]]()
    if not flag:
        print("[solver] %s 未解出" % argv[1], file=sys.stderr)
        return 1
    # 打印 flag 明文（arena 工具检查其是否出现在输出里）
    print(flag)
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv))
