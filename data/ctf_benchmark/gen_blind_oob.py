#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
gen_blind_oob.py —— 确定性合成 Web 盲打 / OOB 外带攻击基准参数。

两个场景：
  1) 时间盲注：靶机对「条件成立」的查询显著延迟，攻击方仅凭耗时差异逐字符还原密钥。
  2) OOB 外带：靶机把密钥回连到攻击方控制的监听器（带外通道），从中捕获密钥。
本脚本固定密钥常量，导出其 SHA-256；与 Go（TestBlindOOB*）/ judge_blind_oob.py 双语言镜像。

用法: python gen_blind_oob.py
"""
import hashlib
import json
import os

HERE = os.path.dirname(os.path.abspath(__file__))

TIME_SECRET = "t1m3b1"          # 时间盲注还原目标（6 字符）
OOB_SECRET = "flag{o0b_3xfil_7k}"  # OOB 外带还原目标（flag）


def main():
    bench = {
        "problems": {
            "time_blind_basic": {
                "flag_sha256": hashlib.sha256(TIME_SECRET.encode()).hexdigest(),
                "note": "时间盲注逐字符还原（仅依响应耗时差异，无响应回显）",
            },
            "oob_exfil_basic": {
                "flag_sha256": hashlib.sha256(OOB_SECRET.encode()).hexdigest(),
                "note": "OOB 外带还原（靶机把密钥回连到内置监听器，攻击方从回调捕获）",
            },
        }
    }
    out = os.path.join(HERE, "blind_oob_benchmark.json")
    with open(out, "w", encoding="utf-8") as f:
        json.dump(bench, f, ensure_ascii=False, indent=2)
    print("生成基准: %s" % out)
    print("  time_secret_sha = %s" % bench["problems"]["time_blind_basic"]["flag_sha256"])
    print("  oob_secret_sha  = %s" % bench["problems"]["oob_exfil_basic"]["flag_sha256"])


if __name__ == "__main__":
    main()
