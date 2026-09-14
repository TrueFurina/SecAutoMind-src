#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
生成 lcg_benchmark.json（LCG 预测三形态，仅存 flag_sha256，绝不存明文 flag）

形态① lcg_known_params   : 参数全知，求 K 步后状态
形态② lcg_recover_ac     : 模数已知 + 连续输出，反解 a,c 后预测下一个
形态③ lcg_recover_modulus: 模数亦未知 + 8 个连续输出，gcd 恢复后预测

运行：python gen_lcg.py
"""
import hashlib
import json
import os
import sys

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from judge_lcg import _gen, advance, recover_ac, recover_modulus, solve_from_text, step  # noqa: E402

HERE = os.path.dirname(os.path.abspath(__file__))
BENCH = os.path.join(HERE, "lcg_benchmark.json")

CASES = [
    {
        "name": "lcg_known_params",
        "a": 6364136223846793005,
        "c": 1442695040888963407,
        "m": 1 << 64,
        "seed": 2026,
        "steps": 1000,
    },
    {
        "name": "lcg_recover_ac",
        "a": 48271,
        "c": 0,
        "m": 2147483647,
        "seed": 1,
        "n": 5,
    },
    {
        "name": "lcg_recover_modulus",
        "a": 48271,
        "c": 11,
        "m": 2147483647,
        "seed": 999,
        "n": 8,
    },
]


def main():
    problems = {}
    for cs in CASES:
        name = cs["name"]
        if "steps" in cs:
            val = advance(cs["seed"], cs["a"], cs["c"], cs["m"], cs["steps"])
            desc = (
                "A service emits authentication tokens with a Linear Congruential "
                "Generator (LCG). Its parameters are known:\n"
                "modulus = %d\nmultiplier = %d\nincrement = %d\nseed = %d\n"
                "Predict the generator state after %d steps and submit it as flag{value}.\n"
                % (cs["m"], cs["a"], cs["c"], cs["seed"], cs["steps"])
            )
        else:
            outs = _gen(cs["seed"], cs["a"], cs["c"], cs["m"], cs["n"])
            val = step(outs[-1], cs["a"], cs["c"], cs["m"])
            if name == "lcg_recover_ac":
                desc = (
                    "An LCG (linear congruential generator) is used to produce one-time "
                    "passwords. The modulus is known: modulus = %d\n"
                    "It leaked these consecutive outputs = [%s]\n"
                    "The multiplier and increment are unknown. Recover them and predict "
                    "the next output as flag{value}.\n"
                    % (cs["m"], ", ".join(str(x) for x in outs))
                )
            else:
                # 模数也不给：确保 gcd 恢复命中真实 m
                g = recover_modulus(outs)
                assert g is not None and g % cs["m"] == 0, \
                    "gcd 未含真实 m，需调整用例: g=%r m=%r" % (g, cs["m"])
                desc = (
                    "A vulnerable service uses an LCG (linear congruential generator) "
                    "whose parameters (modulus, multiplier, increment) are all unknown.\n"
                    "It leaked these consecutive outputs = [%s]\n"
                    "Recover the generator and predict the next output as flag{value}.\n"
                    % ", ".join(str(x) for x in outs)
                )

        flag = "flag{%d}" % val
        # 生成即自检：解析路径必须命中该 flag
        got = solve_from_text(desc)
        assert got == [flag], "selfcheck failed for %s: got %r want %r" % (name, got, [flag])
        problems[name] = {
            "description": desc,
            "flag_sha256": hashlib.sha256(flag.encode()).hexdigest(),
        }

    with open(BENCH, 'w', encoding='utf-8') as f:
        json.dump({"problems": problems}, f, ensure_ascii=False, indent=2)
    print("wrote %d problems -> %s" % (len(problems), os.path.basename(BENCH)))
    for name in problems:
        print("  -", name)


if __name__ == '__main__':
    main()
