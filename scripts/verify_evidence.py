#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""SecAutoMind 证据 / 口径一致性门禁（CI 用，纯工程，不解析任何对外材料）。

校验两件事，任一失败 exit(1)：
  1. 单一真值源健康：scripts/count_stats.py --json 可运行、产出合法非空 JSON、
     关键结构性指标不低于安全下限（防止求解器/文件被误删导致口径塌缩）。
  2. 双语言机验证据包健康：data/ctf_benchmark/all_benchmarks_summary.json
     （由 run_all_benchmarks.py 重新生成）内部一致且全绿——
        ・冠军差异点十八大利用层（jwt/deser/xxe/upload/graphql/ssrf/sqli_deep/
          ssti_deep/ecdsa_nonce_reuse/padding_oracle/blind_oob/hash_ext/gcm_nonce_reuse/
          mt19937_recover/lfsr_predict/lcg_predict/crc32_forge）hit==total，无未命中、无注水；
        ・附件集反注水门禁 water_filled==0；
        ・静态/执行/Web/附件 四项 total>0、miss>=0。

设计原则：只校验「代码产物自身的内部一致性」，不读取/不比对任何 PPT/文档材料数字，
与「口径先行 / 反注水 / 证据先行」冠军战略一致。
"""
import os
import sys
import json
import subprocess

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))

# 冠军差异点：必须 100% 命中、零注水的利用层（双语言机验）。
MUST_FULL = [
    "jwt", "deser", "xxe", "upload", "graphql", "ssrf",
    "sqli_deep", "ssti_deep", "ecdsa_nonce_reuse",
    "padding_oracle", "blind_oob",
    "hash_ext", "gcm_nonce_reuse", "mt19937_recover", "lfsr_predict", "lcg_predict",
    "crc32_forge",
]

# 计数口径安全下限（远低于真值，仅拦截灾难性塌缩/脚本损坏）。
# runtime_tools/builtin_tools 为后续新增键，旧版可能无，缺失时跳过而非失败。
CALIBER_FLOORS = {
    "ctf_solvers": 150,
    "go_files": 600,
    "test_files": 200,
    "total_lines": 100000,
    "im_adapters": 5,
    "skills": 20,
    "roles_yaml": 10,
    "agents_md": 10,
    "tools_yaml": 90,
    "runtime_tools": 90,
    "builtin_tools": 0,
}

# 新增键白名单：旧版 count_stats 可能不存在，缺失不报错。
OPTIONAL_KEYS = {"runtime_tools", "builtin_tools"}


def _run(cmd):
    try:
        r = subprocess.run(cmd, cwd=ROOT, shell=True, capture_output=True,
                           encoding="utf-8", errors="ignore", timeout=300)
        return r.returncode, r.stdout, r.stderr
    except Exception as e:  # pragma: no cover
        return 1, "", str(e)


def check_caliber():
    print("[1/2] 校验单一真值源 count_stats.py --json ...")
    rc, out, err = _run('%s scripts/count_stats.py --json' % sys.executable)
    if rc != 0:
        raise AssertionError("count_stats.py 执行失败 (rc=%d): %s" % (rc, err[-400:]))
    try:
        d = json.loads(out)
    except Exception as e:
        raise AssertionError("count_stats.py JSON 解析失败: %s\n尾部: %s" % (e, out[-400:]))
    if not isinstance(d, dict) or not d:
        raise AssertionError("count_stats.py JSON 为空或非对象")
    for key, floor in CALIBER_FLOORS.items():
        if key not in d:
            if key in OPTIONAL_KEYS:
                continue
            raise AssertionError("count_stats 缺少关键键: %s" % key)
        v = d[key]
        if isinstance(v, bool) or not isinstance(v, int):
            raise AssertionError("count_stats 键 %s 非整数: %r" % (key, v))
        if v < floor:
            raise AssertionError("count_stats 键 %s=%s 低于安全下限 %s（口径可能塌缩）" % (key, v, floor))
    print("      HEAD=%s solvers=%s go_files=%s total_lines=%s runtime_tools=%s OK" % (
        d.get("head"), d.get("ctf_solvers"), d.get("go_files"),
        d.get("total_lines"), d.get("runtime_tools")))
    return d


def check_evidence(summary_path):
    print("[2/2] 校验双语言机验证据包 %s ..." % os.path.relpath(summary_path, ROOT))
    if not os.path.isfile(summary_path):
        raise AssertionError("证据汇总缺失：%s\n（CI 应先执行 `python data/ctf_benchmark/run_all_benchmarks.py`）" % summary_path)
    try:
        s = json.load(open(summary_path, "r", encoding="utf-8"))
    except Exception as e:
        raise AssertionError("证据汇总 JSON 解析失败: %s" % e)
    if not isinstance(s, dict):
        raise AssertionError("证据汇总非对象")

    # 四类基础集：total>0, miss>=0
    for k in ("static", "execution", "web", "attachment"):
        blk = s.get(k)
        if not isinstance(blk, dict):
            raise AssertionError("证据缺块 %s" % k)
        if blk.get("total", 0) <= 0:
            raise AssertionError("%s.total 必须 >0" % k)
        if blk.get("miss", 0) < 0:
            raise AssertionError("%s.miss 不可为负" % k)

    # 附件反注水门禁
    if s["attachment"].get("water_filled", 0) != 0:
        raise AssertionError("附件集反注水门禁触发：water_filled=%s（存在注水命中）" % s["attachment"].get("water_filled"))

    # 冠军差异点十六大利用层：必须全命中，零未命中
    for k in MUST_FULL:
        blk = s.get(k)
        if not isinstance(blk, dict):
            raise AssertionError("证据缺冠军差异点块 %s" % k)
        total = blk.get("total", 0)
        hit = blk.get("hit", 0)
        miss = blk.get("miss", total - hit)
        if total <= 0:
            raise AssertionError("%s.total 必须 >0" % k)
        if miss != 0 or hit != total:
            raise AssertionError("冠军差异点 %s 未全绿：hit=%s/%s miss=%s（存在未命中=能力回退/注水）" % (k, hit, total, miss))

    # §2.3 诚信铁律：来源标注必须存在且自洽（真题 vs 自产题）
    # 为什么必须门禁化：本项目一批「100%」来自 gen_*.py 自产题，若不显式标注来源，
    # 对外引用时极易被误读为真实赛场能力（答辩追问"你这 100% 怎么来的"就答不上来）。
    prov = s.get("provenance")
    if not isinstance(prov, dict):
        raise AssertionError(
            "证据汇总缺 provenance 段（§2.3 诚信铁律：必须标注真题/自产题来源）。\n"
            "  请重跑 `python data/ctf_benchmark/run_all_benchmarks.py` 重新生成汇总。")
    real_n = (prov.get("real") or {}).get("problems")
    synth_n = (prov.get("synthetic") or {}).get("problems")
    total_n = prov.get("total_problems")
    ratio = prov.get("synthetic_ratio_pct")
    if not all(isinstance(x, (int, float)) for x in (real_n, synth_n, total_n, ratio)):
        raise AssertionError("provenance 字段不完整：real/synthetic/total_problems/synthetic_ratio_pct 均需为数值")
    if real_n + synth_n != total_n:
        raise AssertionError("provenance 不自洽：real(%s)+synthetic(%s) != total(%s)" % (real_n, synth_n, total_n))
    expect_ratio = round(100.0 * synth_n / total_n, 1) if total_n else 0.0
    if abs(ratio - expect_ratio) > 0.15:
        raise AssertionError("provenance 占比不自洽：记录 %s%% vs 实算 %.1f%%" % (ratio, expect_ratio))

    print("      四大基础集 + 十八大利用层（含 HLE/GCM-NR/MT19937/LFSR/LCG/CRC32）全绿，反注水门禁通过 OK")
    print("      来源标注（§2.3）：真题 %d 题 / 自产题 %d 题（自产占比 %.1f%%）—— "
          "自产题仅证明工程链路可跑通，对外引用须标注来源" % (real_n, synth_n, ratio))
    return s


def main():
    ok = True
    try:
        check_caliber()
    except AssertionError as e:
        print("  ✗ 口径校验失败: %s" % e)
        ok = False
    summary = os.path.join(ROOT, "data", "ctf_benchmark", "all_benchmarks_summary.json")
    try:
        check_evidence(summary)
    except AssertionError as e:
        print("  ✗ 证据校验失败: %s" % e)
        ok = False
    if not ok:
        print("\n证据/口径门禁：FAIL")
        sys.exit(1)
    print("\n证据/口径门禁：PASS")


if __name__ == "__main__":
    main()
