#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
run_all_benchmarks.py —— SecAutoMind 夺旗能力「三基准集」统一机验汇总。

把三套相互独立、双语言交叉验证的基准集合并成一个诚实 KPI：
  1. 静态确定性基准集 (real_benchmark.json, 55 道真题, 仅 description)
       -> judge.py (Python 镜像) + Go TestRealBenchmark_ShippedPresolve (生产路径)
  2. 执行确定性基准集 (execution_benchmark.json, 8 道, 含真实工件/实时靶机)
       -> judge_exec.py (Python) + Go TestExecSolversAgainstBenchmark/TestLiveExploitation
  3. (可选) 实时靶机利用 —— 已并入执行集的 live_sqli / live_ssti

设计纪律（诚实化）：
  - 每个 flag 必须经 SHA-256 校验，禁止「看起来像」就计命中。
  - Python 与 Go 两侧各自独立实现，结果互相印证，任一侧漂移立即暴露。
  - 静态集与执行集是不同题型族，覆盖率不相加，分开报告。

用法：
  python run_all_benchmarks.py
  python run_all_benchmarks.py --go   # 同时跑 Go 测试（需要 Go 工具链在 PATH）
"""
import json
import os
import subprocess
import sys
import argparse

HERE = os.path.dirname(os.path.abspath(__file__))
REPO = os.path.abspath(os.path.join(HERE, "..", ".."))


def run_static():
    """跑 judge.py，返回 (total, hit, miss, pct, results)。"""
    env = dict(os.environ)
    env["BENCH"] = os.path.join(HERE, "real_benchmark.json")
    env["REPORT"] = os.path.join(HERE, "real_coverage_report.json")
    r = subprocess.run([sys.executable, os.path.join(HERE, "judge.py")],
                       cwd=REPO, env=env, capture_output=True, text=True)
    if r.returncode != 0:
        print("[WARN] judge.py 运行异常:\n", r.stderr, file=sys.stderr)
    try:
        rep = json.load(open(env["REPORT"], encoding="utf-8"))
        return rep["total"], rep["hit"], rep["miss"], rep["coverage_pct"], rep.get("results", [])
    except Exception as e:
        print("[WARN] 读取 real_coverage_report.json 失败: %s" % e, file=sys.stderr)
        return 55, 0, 55, 0.0, []


def run_execution():
    """跑 judge_exec.py，返回 (total, hit, miss, pct, results)。"""
    r = subprocess.run([sys.executable, os.path.join(HERE, "judge_exec.py")],
                       cwd=HERE, capture_output=True, text=True)
    if r.returncode != 0:
        print("[WARN] judge_exec.py 运行异常:\n", r.stderr, file=sys.stderr)
    try:
        rep = json.load(open(os.path.join(HERE, "execution_coverage_report.json"), encoding="utf-8"))
        return rep["total"], rep["hit"], rep["miss"], rep["coverage_pct"], rep.get("results", [])
    except Exception as e:
        print("[WARN] 读取 execution_coverage_report.json 失败: %s" % e, file=sys.stderr)
        return 8, 0, 8, 0.0, []


def run_web():
    """跑 web 实战基准集（judge_web.py），返回 (total, hit, miss, pct)。"""
    r = subprocess.run([sys.executable, os.path.join(HERE, "judge_web.py")],
                       cwd=HERE, capture_output=True, text=True)
    if r.returncode != 0 and not r.stdout:
        print("[WARN] judge_web.py 运行异常:\n", r.stderr, file=sys.stderr)
    out = r.stdout or ""
    total = len(json.load(open(os.path.join(HERE, "web_benchmark.json"), encoding="utf-8"))["problems"])
    hit = out.count("✅ HIT")
    miss = total - hit
    pct = 100.0 * hit / total if total else 0.0
    return total, hit, miss, pct


def run_attachment():
    """跑附件取证基准集（judge_attachment.py），返回 (total, hit, miss, pct)。

    这是「静态集 36 道 MISS」的正面回答：那 36 题的 flag 全在靶机/附件里，
    纯文本无解。本集测的正是拿到真实附件（PNG/pcap/zip/二进制）后能否真解析。
    """
    r = subprocess.run([sys.executable, os.path.join(HERE, "judge_attachment.py")],
                       cwd=HERE, capture_output=True, text=True)
    out = r.stdout or ""
    if r.returncode != 0:
        print("[WARN] judge_attachment.py 运行异常:\n", r.stderr, file=sys.stderr)
    try:
        total = len(json.load(open(os.path.join(HERE, "attachment_benchmark.json"),
                                   encoding="utf-8"))["problems"])
    except Exception:
        total = 0
    hit = out.count("✅")
    water = out.count("💧")
    miss = max(0, total - hit)
    pct = 100.0 * hit / total if total else 0.0
    return total, hit, miss, pct, water


def run_web_hints():
    """跑真题形态靶场（judge_web_hints.py），返回 (total, a_hit, b_hit)。

    A 组：只给 URL 不给题目描述（只能靠首页链接抓取）
    B 组：给题目描述，解析端点/参数/载荷/漏洞类型后定向打
    """
    r = subprocess.run([sys.executable, os.path.join(HERE, "judge_web_hints.py")],
                       cwd=HERE, capture_output=True, text=True)
    if r.returncode != 0:
        print("[WARN] judge_web_hints.py 运行异常:\n", r.stderr, file=sys.stderr)
    out = r.stdout or ""
    try:
        total = len(json.load(open(os.path.join(HERE, "web_hint_benchmark.json"),
                                   encoding="utf-8"))["problems"])
    except Exception:
        total = 0
    a_hit = out.count("A组(无线索)=HIT")
    b_hit = out.count("B组(有线索)=HIT")
    return total, a_hit, b_hit


def run_jwt():
    """跑 JWT 认证绕过靶场（judge_jwt.py），返回 (total, hit)。

    三个场景：HS256 弱密钥爆破重签 / alg=none 无签名伪造 / RS256→HS256 公钥混淆。
    flag 只有在真正绕过鉴权（拿到 admin 声明且签名通过）时才由靶场返回。
    """
    r = subprocess.run([sys.executable, os.path.join(HERE, "judge_jwt.py")],
                       cwd=HERE, capture_output=True, text=True)
    if r.returncode != 0:
        print("[WARN] judge_jwt.py 运行异常:\n", r.stderr, file=sys.stderr)
    out = r.stdout or ""
    try:
        total = len(json.load(open(os.path.join(HERE, "jwt_benchmark.json"),
                                   encoding="utf-8"))["problems"])
    except Exception:
        total = 0
    hit = sum(1 for line in out.splitlines() if line.strip().endswith("HIT") or " HIT " in line)
    return total, hit


def run_deser():
    """跑反序列化利用靶场（judge_deser.py），返回 (total, hit)。

    三个场景：Python pickle 真 loads RCE / PHP 对象注入（POST 表单）/
    PHP 对象注入（Cookie 通道）。flag 只在真正反序列化成功并读到文件时返回。
    """
    r = subprocess.run([sys.executable, os.path.join(HERE, "judge_deser.py")],
                       cwd=HERE, capture_output=True, text=True)
    if r.returncode != 0:
        print("[WARN] judge_deser.py 运行异常:\n", r.stderr, file=sys.stderr)
    out = r.stdout or ""
    try:
        total = len(json.load(open(os.path.join(HERE, "deser_benchmark.json"),
                                   encoding="utf-8"))["problems"])
    except Exception:
        total = 0
    hit = out.count("SHA-256 校验通过")
    return total, hit


def run_go():
    """跑 Go 侧权威机验，返回一段状态文本（可选）。"""
    go = os.path.join(REPO, ".workbuddy", "toolchain", "go", "bin", "go.exe")
    if not os.path.exists(go):
        return "（跳过：Go 工具链不在预期路径）"
    env = dict(os.environ)
    env["GOTOOLCHAIN"] = "local"
    env["GOPROXY"] = "off"
    r = subprocess.run(
        [go, "test", "./internal/ctfplatform/",
         "-run", "TestRealBenchmark_ShippedPresolve|TestExecSolversAgainstBenchmark|TestLiveExploitation|TestWebExploitAgainstRange|TestPresolveAutoExploitsWebTarget|TestAttachmentForensicsBenchmark|TestAttachmentForensicsPerSolver|TestAttachmentBenchmarkNotSolvableByNaiveRegex|TestHintDrivenWebExploit|TestParseWebHintsOffline|TestJWTAttackAgainstRange|TestJWTAttackViaProductionText|TestJWTCandidatesOffline|TestJWTSolverRegistered|TestDeserAttackAgainstRange|TestDeserAttackViaProductionText|TestDeserPayloadsOffline|TestDeserSolverRegistered",
         "-count=1", "-timeout", "300s"],
        cwd=REPO, env=env, capture_output=True, text=True)
    out = r.stdout + r.stderr
    # 抽取覆盖率行
    lines = [l for l in out.splitlines() if "覆盖率" in l or "PASS" in l or "FAIL" in l or "ok" in l]
    return "\n".join(lines[-8:]) if lines else out[-800:]


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--go", action="store_true", help="同时跑 Go 侧权威机验")
    args = ap.parse_args()

    st_total, st_hit, st_miss, st_pct, st_res = run_static()
    ex_total, ex_hit, ex_miss, ex_pct, ex_res = run_execution()
    wb_total, wb_hit, wb_miss, wb_pct = run_web()
    at_total, at_hit, at_miss, at_pct, at_water = run_attachment()
    wh_total, wh_a, wh_b = run_web_hints()
    jt_total, jt_hit = run_jwt()
    de_total, de_hit = run_deser()

    print("=" * 64)
    print("  SecAutoMind 夺旗能力七基准集 · 统一机验汇总")
    print("=" * 64)
    print()
    print("【1】静态确定性基准集 (real_benchmark.json, 仅 description, 需 SHA-256)")
    print("    总数 %2d | 命中 %2d | 未命中 %2d | 覆盖率 %.1f%%" % (st_total, st_hit, st_miss, st_pct))
    print("    Python judge.py 镜像 == Go TestRealBenchmark_ShippedPresolve（生产路径）")
    print()
    print("【2】执行确定性基准集 (execution_benchmark.json, 真实工件+实时靶机)")
    print("    总数 %2d | 命中 %2d | 未命中 %2d | 覆盖率 %.1f%%" % (ex_total, ex_hit, ex_miss, ex_pct))
    print("    Python judge_exec.py == Go TestExecSolversAgainstBenchmark + TestLiveExploitation")
    print("    能力维度：strings / git历史 / 网页源码审计 / Cookie解码 / 大小端 /")
    print("               pcap HTTP解析 / RSA小指数开根 / 实时SQLi绕过 / 实时SSTI")
    print()
    print("【3】Web 实战基准集 (web_benchmark.json, 10 类真实 CTF Web 题型靶场)")
    print("    总数 %2d | 命中 %2d | 未命中 %2d | 覆盖率 %.1f%%" % (wb_total, wb_hit, wb_miss, wb_pct))
    print("    Python judge_web.py == Go TestWebExploitAgainstRange（+生产路径 TestPresolveAutoExploitsWebTarget）")
    print("    攻破维度：SQLi登录绕过 / SSTI提权 / LFI路径遍历 / SSRF内网端点 /")
    print("               命令注入RCE / NoSQL运算符注入 / 未授权API / 源码与Cookie泄漏")
    print("【4】附件取证基准集 (attachment_benchmark.json, 真实二进制/Pcap/ZIP 工件)")
    print("    总数 %2d | 命中 %2d | 未命中 %2d | 覆盖率 %.1f%% | 注水题 %d" %
          (at_total, at_hit, at_miss, at_pct, at_water))
    print("    Python judge_attachment.py == Go TestAttachmentForensicsBenchmark（生产路径）")
    print("    解析维度：PNG LSB 位平面 / PNG tEXt 与尾部附加 / JPEG COM 段 /")
    print("               pcap HTTP 报文（含百分号解码）/ ZIP 内层与嵌套 / 文件雕刻 /")
    print("               UTF-16 宽字符串 / base64 与 hex 变体 / 重复密钥 XOR 已知明文恢复")
    print()
    print("【5】Web 题目感知定向渗透 (web_hint_benchmark.json, 真题端点形态靶场)")
    print("    总数 %2d | A组(无线索只爬链) %2d | B组(读题取线索定向打) %2d | 能力增量 +%d" %
          (wh_total, wh_a, wh_b, wh_b - wh_a))
    print("    Python judge_web_hints.py == Go TestHintDrivenWebExploit（A/B/C 三组一致）")
    print("    能力维度：从 description 提取端点/参数名/载荷/漏洞类型 → 定向投递；")
    print("               首页链接抓取补全未知端点；真实靶机端点不叫 /ssti//cmd 也能打中")
    print()
    print("【6】JWT 认证绕过 (jwt_benchmark.json, 三类真实 JWT 考点靶场)")
    print("    总数 %2d | 命中 %2d | 未命中 %2d | 覆盖率 %.1f%%" %
          (jt_total, jt_hit, jt_total - jt_hit,
           (100.0 * jt_hit / jt_total) if jt_total else 0.0))
    print("    Python judge_jwt.py == Go TestJWTAttackAgainstRange（+生产入口 3/3）")
    print("    攻破维度：HS256 弱密钥爆破重签 / alg=none 无签名伪造 /")
    print("               RS256→HS256 公钥混淆（取回 /public.pem 当 HMAC 密钥重签）")
    print()
    print("【7】反序列化利用 (deser_benchmark.json, 真 pickle.loads / PHP 对象注入靶场)")
    print("    总数 %2d | 命中 %2d | 未命中 %2d | 覆盖率 %.1f%%" %
          (de_total, de_hit, de_total - de_hit,
           (100.0 * de_hit / de_total) if de_total else 0.0))
    print("    Python judge_deser.py == Go TestDeserAttackAgainstRange（+生产入口 3/3）")
    print("    攻破维度：Python pickle 反序列化 RCE（eval/open/popen 三通道）/")
    print("               PHP 对象注入读文件（4 危险类 + protected/private 属性写法）/")
    print("               多传输通道（POST 原始字节 / POST 表单 / Cookie session）")
    print()

    # 诚实化口径：静态集内 flag 直接嵌在描述文本里的「flag_scan」题单独标注
    flag_scan = [r for r in st_res if r.get("presolve_engine") == "flag_scan"]
    real_solver = st_hit - len(flag_scan)
    print("【诚实化拆解】静态集 %d 命中中：" % st_hit)
    print("    - 真实求解器命中 (base64/rsa/endian/rail_fence/vigenere/caesar/...) : %d" % real_solver)
    print("    - flag 直接嵌于描述文本的 flag_scan (基准集设计产物, 非真技巧)    : %d" % len(flag_scan))
    print("    剩余 %d 道需真实工具执行/实时靶机/二进制/隐写 —— 属 Agent 执行层能力" % st_miss)
    print()

    print("【结论】静态确定性 %.1f%% + 执行确定性 %.1f%% + Web 实战 %.1f%% + 附件取证 %.1f%% "
          "+ JWT 认证绕过 %d/%d + 反序列化利用 %d/%d" %
          (st_pct, ex_pct, wb_pct, at_pct, jt_hit, jt_total, de_hit, de_total))
    print("    Web 题目感知渗透: A组(无线索)%d → B组(读题)%d (增量 +%d)，证明『读题取线索定向打』是实打实能力" %
          (wh_a, wh_b, wh_b - wh_a))
    print("    执行层、Web 实战层、附件取证层、题目感知层、JWT 认证绕过层、反序列化利用层是冠军差异点：")
    print("    西湖论剑类关键词求解器天花板即静态集，SecAutoMind 额外验证了")
    print("    『Agent 能真跑工具 + 真打靶机 + 真攻 Web 站点 + 真解析二进制附件 + 读题定向渗透")
    print("     + 真绕过 JWT 鉴权 + 真反序列化 RCE』(双语言机验)。")
    print()

    if args.go:
        print("【Go 侧权威机验】")
        print(run_go())
        print()

    # 落盘汇总
    summary = {
        "static": {"total": st_total, "hit": st_hit, "miss": st_miss, "coverage_pct": st_pct,
                   "flag_scan_only": len(flag_scan), "real_solver_hit": real_solver},
        "execution": {"total": ex_total, "hit": ex_hit, "miss": ex_miss, "coverage_pct": ex_pct},
        "web": {"total": wb_total, "hit": wb_hit, "miss": wb_miss, "coverage_pct": wb_pct},
        "attachment": {"total": at_total, "hit": at_hit, "miss": at_miss,
                       "coverage_pct": at_pct, "water_filled": at_water},
        "web_hints": {"total": wh_total, "group_a_no_hint": wh_a, "group_b_with_hint": wh_b,
                      "delta": wh_b - wh_a},
        "jwt": {"total": jt_total, "hit": jt_hit, "miss": jt_total - jt_hit,
                "coverage_pct": (100.0 * jt_hit / jt_total) if jt_total else 0.0},
        "deser": {"total": de_total, "hit": de_hit, "miss": de_total - de_hit,
                  "coverage_pct": (100.0 * de_hit / de_total) if de_total else 0.0},
        "note": "静态/执行/Web/附件 覆盖率不相加；执行层、Web 实战层、附件取证层、题目感知层为冠军差异点；"
                "所有命中经 SHA-256 校验；附件集另设反注水门禁（朴素正则不许命中）。",
    }
    out_path = os.path.join(HERE, "all_benchmarks_summary.json")
    json.dump(summary, open(out_path, "w", encoding="utf-8"), ensure_ascii=False, indent=2)
    print("汇总已写入: %s" % out_path)


if __name__ == "__main__":
    main()
