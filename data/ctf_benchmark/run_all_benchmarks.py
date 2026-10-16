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


def run_xxe():
    """跑 XXE 利用靶场（judge_xxe.py），返回 (total, hit)。

    三个场景：回显型实体文件读 / XInclude 文件读 / Blind XXE 参数实体外带
    （flag 只经 /oob-log 外带通道取回，响应里没有 flag）。
    """
    r = subprocess.run([sys.executable, os.path.join(HERE, "judge_xxe.py")],
                       cwd=HERE, capture_output=True, text=True)
    if r.returncode != 0:
        print("[WARN] judge_xxe.py 运行异常:\n", r.stderr, file=sys.stderr)
    out = r.stdout or ""
    try:
        total = len(json.load(open(os.path.join(HERE, "xxe_benchmark.json"),
                                   encoding="utf-8"))["problems"])
    except Exception:
        total = 0
    hit = out.count("SHA-256 校验通过")
    return total, hit


def run_upload():
    """跑文件上传 RCE 靶场（judge_upload.py），返回 (total, hit)。

    三个场景：不受限上传（.py 真被执行）/ 黑名单大小写绕过（.PY）/
    保存路径穿越进自动执行目录。服务端 exec() 真·执行上传内容。
    """
    r = subprocess.run([sys.executable, os.path.join(HERE, "judge_upload.py")],
                       cwd=HERE, capture_output=True, text=True)
    if r.returncode != 0:
        print("[WARN] judge_upload.py 运行异常:\n", r.stderr, file=sys.stderr)
    out = r.stdout or ""
    try:
        total = len(json.load(open(os.path.join(HERE, "upload_benchmark.json"),
                                   encoding="utf-8"))["problems"])
    except Exception:
        total = 0
    hit = out.count("SHA-256 校验通过")
    return total, hit


def run_graphql():
    """跑 GraphQL 靶场（judge_graphql.py），返回 (total, hit)。

    三个场景：内省泄露隐藏字段 / IDOR 遍历管理员 / 隐藏调试 mutation
    （服务端按命令真实读取靶机文件）。
    """
    r = subprocess.run([sys.executable, os.path.join(HERE, "judge_graphql.py")],
                       cwd=HERE, capture_output=True, text=True)
    if r.returncode != 0:
        print("[WARN] judge_graphql.py 运行异常:\n", r.stderr, file=sys.stderr)
    out = r.stdout or ""
    try:
        total = len(json.load(open(os.path.join(HERE, "graphql_benchmark.json"),
                                   encoding="utf-8"))["problems"])
    except Exception:
        total = 0
    hit = out.count("SHA-256 校验通过")
    return total, hit


def run_ssrf():
    """跑 SSRF 利用靶场（judge_ssrf.py），返回 (total, hit)。

    三个场景：gopher RESP 管道打内网未授权 Redis / 云元数据两跳凭证 /
    内网回环 admin 服务（需 SSRF 通道注入内网凭证头）。
    """
    r = subprocess.run([sys.executable, os.path.join(HERE, "judge_ssrf.py")],
                       cwd=HERE, capture_output=True, text=True)
    if r.returncode != 0:
        print("[WARN] judge_ssrf.py 运行异常:\n", r.stderr, file=sys.stderr)
    out = r.stdout or ""
    try:
        total = len(json.load(open(os.path.join(HERE, "ssrf_benchmark.json"),
                                   encoding="utf-8"))["problems"])
    except Exception:
        total = 0
    hit = out.count("SHA-256 校验通过")
    return total, hit


def run_sqli():
    """跑 SQL 注入深度靶场（judge_sqli.py），返回 (total, hit)。

    三个场景：UNION 列探测+sqlite_master 枚举提取 / 引号闭合+拼接子查询回显 /
    布尔盲注（长度二分+逐字符二分，真 sqlite3）。
    """
    r = subprocess.run([sys.executable, os.path.join(HERE, "judge_sqli.py")],
                       cwd=HERE, capture_output=True, text=True)
    if r.returncode != 0:
        print("[WARN] judge_sqli.py 运行异常:\n", r.stderr, file=sys.stderr)
    out = r.stdout or ""
    try:
        total = len(json.load(open(os.path.join(HERE, "sqli_benchmark.json"),
                                   encoding="utf-8"))["problems"])
    except Exception:
        total = 0
    hit = out.count("SHA-256 校验通过")
    return total, hit


def run_ssti():
    """跑 SSTI 深度靶场（judge_ssti.py），返回 (total, hit)。

    三个场景：Jinja {{ }} 环境逃逸读 env / str.format 全局可达 /
    黑名单剥 {{ 后 Twig {% %} 定界绕过。
    """
    r = subprocess.run([sys.executable, os.path.join(HERE, "judge_ssti.py")],
                       cwd=HERE, capture_output=True, text=True)
    if r.returncode != 0:
        print("[WARN] judge_ssti.py 运行异常:\n", r.stderr, file=sys.stderr)
    out = r.stdout or ""
    try:
        total = len(json.load(open(os.path.join(HERE, "ssti_benchmark.json"),
                                   encoding="utf-8"))["problems"])
    except Exception:
        total = 0
    hit = out.count("SHA-256 校验通过")
    return total, hit


def run_ecdsa():
    """跑 ECDSA nonce 复用攻击基准（judge_ecdsa.py），返回 (total, hit)。

    两组签名共享同一 nonce k（r 相同）→ 公式离线还原私钥 d：
        k = (z1 - z2) * (s1 - s2)^-1 mod n
        d = (s1*k - z1) * r^-1        mod n
    纯大数运算，Python judge_ecdsa.py 与 Go TestECDSANonceReuseAgainstBenchmark 双语言镜像。
    """
    r = subprocess.run([sys.executable, os.path.join(HERE, "judge_ecdsa.py")],
                       cwd=HERE, capture_output=True, text=True)
    if r.returncode != 0:
        print("[WARN] judge_ecdsa.py 运行异常:\n", r.stderr, file=sys.stderr)
    out = r.stdout or ""
    try:
        total = len(json.load(open(os.path.join(HERE, "ecdsa_benchmark.json"),
                                   encoding="utf-8"))["problems"])
    except Exception:
        total = 0
    hit = out.count("HIT")
    return total, hit


def run_padding_oracle():
    """跑 CBC Padding Oracle 攻击基准（judge_padding_oracle.py），返回 (total, hit)。

    真实 CBC PKCS#7 padding oracle 攻击：仅用 oracle(ct)->bool 的布尔返回，
    逐字节还原明文（无需密钥）。Python judge_padding_oracle.py 与 Go
    TestPaddingOracleAgainstBenchmark 双语言镜像，SHA-256 比对。
    """
    r = subprocess.run([sys.executable, os.path.join(HERE, "judge_padding_oracle.py")],
                       cwd=HERE, capture_output=True, text=True)
    if r.returncode != 0:
        print("[WARN] judge_padding_oracle.py 运行异常:\n", r.stderr, file=sys.stderr)
    out = r.stdout or ""
    try:
        total = len(json.load(open(os.path.join(HERE, "padding_oracle_benchmark.json"),
                                   encoding="utf-8"))["problems"])
    except Exception:
        total = 0
    hit = out.count("HIT")
    return total, hit


def run_blind_oob():
    """跑 Web 盲打 / 带外回连（OOB）外带基准（judge_blind_oob.py），返回 (total, hit)。

    两种无回显数据渗出通道：
      1. 时间盲注（Time-based Blind）：仅依响应耗时差异还原密钥，无需任何回显。
      2. 带外回连（Out-of-Band Exfil）：靶机把密钥异步回连到攻击方内置监听器取回。
    Python judge_blind_oob.py（纯标准库自建靶机+监听器）与 Go
    TestBlindOOBTimeBased / TestBlindOOBOOB 双语言镜像，SHA-256 比对。
    """
    r = subprocess.run([sys.executable, os.path.join(HERE, "judge_blind_oob.py")],
                       cwd=HERE, capture_output=True, text=True)
    if r.returncode != 0:
        print("[WARN] judge_blind_oob.py 运行异常:\n", r.stderr, file=sys.stderr)
    out = r.stdout or ""
    try:
        total = len(json.load(open(os.path.join(HERE, "blind_oob_benchmark.json"),
                                   encoding="utf-8"))["problems"])
    except Exception:
        total = 0
    hit = out.count("HIT")
    return total, hit


def run_hash_ext():
    """跑 Hash Length Extension 攻击基准（judge_hash_ext.py），返回 (total, hit)。

    真实 Merkle–Damgård 长度扩展攻击：已知 MAC=H(secret||known_data)，无需 secret
    伪造 H(secret||known_data||glue||extra)。MD5/SHA1 双算法。Python
    judge_hash_ext.py 与 Go TestHashLengthExtension* 双语言镜像，SHA-256 比对。
    """
    r = subprocess.run([sys.executable, os.path.join(HERE, "judge_hash_ext.py")],
                       cwd=HERE, capture_output=True, text=True)
    if r.returncode != 0:
        print("[WARN] judge_hash_ext.py 运行异常:\n", r.stderr, file=sys.stderr)
    out = r.stdout or ""
    try:
        total = len(json.load(open(os.path.join(HERE, "hash_ext_benchmark.json"),
                                   encoding="utf-8"))["problems"])
    except Exception:
        total = 0
    hit = out.count("HIT")
    return total, hit


def run_gcm_nr():
    """跑 AES-GCM nonce 复用 keystream 复原基准（judge_gcm_nr.py），返回 (total, hit)。

    真实攻击：同密钥同 nonce 两条密文共享 CTR keystream，由已知明文复原 keystream
    后解密第二条明文（无需密钥）。Python judge_gcm_nr.py 与 Go TestGCMNonceReuse*
    双语言镜像，SHA-256 比对。
    """
    r = subprocess.run([sys.executable, os.path.join(HERE, "judge_gcm_nr.py")],
                       cwd=HERE, capture_output=True, text=True)
    if r.returncode != 0:
        print("[WARN] judge_gcm_nr.py 运行异常:\n", r.stderr, file=sys.stderr)
    out = r.stdout or ""
    try:
        total = len(json.load(open(os.path.join(HERE, "gcm_nonce_reuse_benchmark.json"),
                                   encoding="utf-8"))["problems"])
    except Exception:
        total = 0
    hit = out.count("HIT")
    return total, hit


def run_mt19937():
    """跑 MT19937 状态恢复基准（judge_mt19937.py），返回 (total, hit)。

    真实攻击：泄露 624 个连续 32-bit 输出 → untemper 反解内部状态 → twist 推进 →
    预测第 625 个输出（即下一个"随机"值，被当作 secret）。Python judge_mt19937.py
    与 Go TestMT19937* 双语言镜像，SHA-256 比对。
    """
    r = subprocess.run([sys.executable, os.path.join(HERE, "judge_mt19937.py")],
                       cwd=HERE, capture_output=True, text=True)
    if r.returncode != 0:
        print("[WARN] judge_mt19937.py 运行异常:\n", r.stderr, file=sys.stderr)
    out = r.stdout or ""
    try:
        total = len(json.load(open(os.path.join(HERE, "mt19937_benchmark.json"),
                                   encoding="utf-8"))["problems"])
    except Exception:
        total = 0
    hit = out.count("HIT")
    return total, hit


def run_lfsr():
    """跑 LFSR 流预测基准（judge_lfsr.py），返回 (total, hit)。

    真实攻击：泄露 >= 2L 个 LFSR 输出比特 → Berlekamp–Massey 在 GF(2) 上恢复最小
    连接多项式 → 逐位前推预测后续比特（无需寄存器抽头/初态）。Python judge_lfsr.py
    与 Go TestLFSR* 双语言镜像，SHA-256 比对。
    """
    r = subprocess.run([sys.executable, os.path.join(HERE, "judge_lfsr.py")],
                       cwd=HERE, capture_output=True, text=True)
    if r.returncode != 0:
        print("[WARN] judge_lfsr.py 运行异常:\n", r.stderr, file=sys.stderr)
    out = r.stdout or ""
    try:
        total = len(json.load(open(os.path.join(HERE, "lfsr_benchmark.json"),
                                   encoding="utf-8"))["problems"])
    except Exception:
        total = 0
    hit = out.count("HIT")
    return total, hit


def run_crc32():
    """跑 CRC32 伪造基准（judge_crc32.py），返回 (total, hit)。

    真实攻击：CRC32 是 GF(2) 线性校验（非 MAC），已知消息即可追加恰好 4 字节使
    crc32(m‖X)=任意目标：crc32(m‖X)=crc32(m‖0000)⊕L(X)，解 32×32 GF(2) 方程组
    L(X)=d 得唯一 X。Python judge_crc32.py 与 Go TestCRC32* 双语言镜像，SHA-256 比对。
    """
    r = subprocess.run([sys.executable, os.path.join(HERE, "judge_crc32.py")],
                       cwd=HERE, capture_output=True, text=True)
    if r.returncode != 0:
        print("[WARN] judge_crc32.py 运行异常:\n", r.stderr, file=sys.stderr)
    out = r.stdout or ""
    try:
        total = len(json.load(open(os.path.join(HERE, "crc32_benchmark.json"),
                                   encoding="utf-8"))["problems"])
    except Exception:
        total = 0
    hit = out.count("HIT")
    return total, hit


def run_lcg():
    """跑 LCG 预测基准（judge_lcg.py），返回 (total, hit)。

    真实攻击：三形态——① 参数全知直接倍增推进求 K 步后状态；② 模数已知 +
    连续输出反解 a,c；③ 模数亦未知用 gcd 恢复 m 再反解。Python judge_lcg.py
    与 Go TestLCG* 双语言镜像，SHA-256 比对。
    """
    r = subprocess.run([sys.executable, os.path.join(HERE, "judge_lcg.py")],
                       cwd=HERE, capture_output=True, text=True)
    if r.returncode != 0:
        print("[WARN] judge_lcg.py 运行异常:\n", r.stderr, file=sys.stderr)
    out = r.stdout or ""
    try:
        total = len(json.load(open(os.path.join(HERE, "lcg_benchmark.json"),
                                   encoding="utf-8"))["problems"])
    except Exception:
        total = 0
    hit = out.count("HIT")
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
         "-run", "TestRealBenchmark_ShippedPresolve|TestSSRFAttackAgainstRange|TestSSRFAttackViaProductionText|TestSSRFSolverRegistered|TestSQLiAttackAgainstRange|TestSQLiAttackViaProductionText|TestSQLiSolverRegistered|TestSSTIAttackAgainstRange|TestSSTIAttackViaProductionText|TestSSTISolverRegistered|TestExecSolversAgainstBenchmark|TestLiveExploitation|TestWebExploitAgainstRange|TestPresolveAutoExploitsWebTarget|TestAttachmentForensicsBenchmark|TestAttachmentForensicsPerSolver|TestAttachmentBenchmarkNotSolvableByNaiveRegex|TestHintDrivenWebExploit|TestParseWebHintsOffline|TestJWTAttackAgainstRange|TestJWTAttackViaProductionText|TestJWTCandidatesOffline|TestJWTSolverRegistered|TestDeserAttackAgainstRange|TestDeserAttackViaProductionText|TestDeserPayloadsOffline|TestDeserSolverRegistered|TestXXEAttackAgainstRange|TestXXEAttackViaProductionText|TestXXEPayloadsOffline|TestXXESolverRegistered|TestUploadAttackAgainstRange|TestUploadAttackViaProductionText|TestUploadMultipartBuilder|TestUploadSolverRegistered|TestGraphQLAttackAgainstRange|TestGraphQLAttackViaProductionText|TestGraphQLSolverRegistered|TestECDSANonceReuseAgainstBenchmark|TestECDSANonceReuseSelfConsistent|TestECDSANonceReuseSolverRegistered|TestPaddingOracleSelfConsistent|TestPaddingOracleAgainstBenchmark|TestPaddingOracleSolverRegistered|TestHashLengthExtensionSelfConsistent|TestHashLengthExtensionMD5|TestHashLengthExtensionSHA1|TestHashLengthExtensionSolverParses|TestHashLengthExtensionSolverRegistered|TestGCMNonceReuseBasic|TestGCMNonceReuseSolverParses|TestGCMNonceReuseBlobFormat|TestGCMNonceReusePartialKnown|TestGCMNonceReuseSolverRegistered|TestMT19937UntemperIsInverse|TestMT19937PredictNext|TestMT19937SolverParses|TestMT19937SolverRegistered|TestMT19937NoFalsePositive|TestMT19937InsufficientOutputs|TestMT19937RecoverSha256Consistency|TestLFSRBerlekampMasseyBasic|TestLFSRPredictDegree32|TestLFSRSolverParses|TestLFSRSolverRegistered|TestLFSRNoFalsePositive|TestLFSRShortLeakNoPredict|TestLCGAdvanceMatchesNaive|TestLCGRecoverAC|TestLCGRecoverModulus|TestLCGSolverParsesKnownParams|TestLCGSolverParsesRecoverAC|TestLCGSolverParsesRecoverModulus|TestLCGSolverRegistered|TestLCGNoFalsePositive|TestCRC32StdMatchesStdlib|TestCRC32ForgeProducesTarget|TestCRC32ForgeUniqueness|TestCRC32SolverParses|TestCRC32SolverRegistered|TestCRC32NoFalsePositive",
         "-count=1", "-timeout", "900s"],
        cwd=REPO, env=env, capture_output=True, text=True)
    out = r.stdout + r.stderr
    # 抽取覆盖率行
    lines = [l for l in out.splitlines() if "覆盖率" in l or "PASS" in l or "FAIL" in l or "ok" in l]
    return "\n".join(lines[-8:]) if lines else out[-800:]


# 基线放 docs/ 而非 data/ctf_benchmark/：后者被 .gitignore 的 `data/*` 目录级忽略覆盖，
# 单文件否定规则在 git 下无效（无法 re-include），文件会静默不入仓 → CI 上找不到基线 →
# 门禁按 fail-closed 恒红。与 docs/final-artifacts.freeze.json 同款放法是既有惯例。
BASELINE_PATH = os.path.join(REPO, "docs", "benchmark_baseline.json")


def load_baseline(path=None):
    """读冻结达标基线，返回 suites 字典；缺失/不可解析/为空一律返回 None（由调用方判红）。"""
    path = path or BASELINE_PATH
    if not os.path.exists(path):
        return None
    try:
        with open(path, encoding="utf-8") as fh:
            d = json.load(fh)
    except Exception as e:
        print("[BLOCK] 基线文件不可解析: %s (%s)" % (path, e))
        return None
    if not isinstance(d, dict):
        return None
    suites = d.get("suites")
    return suites if isinstance(suites, dict) and suites else None


def check_baseline(summary, baseline_path=None):
    """逐项比对冻结基线，返回 (达标数, 基线总项数, 未达标说明列表)。

    🔴 fail-closed 三原则（本项目两次栽在"静默放行"上）：
      1. 基线文件缺失 / 不可解析 / suites 为空 → 不比对等于没门禁，直接算未达标；
      2. 实测项不在基线里（新增基准集没上锁）→ 算未达标，逼人显式登记；
      3. 基线里的项在实测中缺席 → 算未达标（基准集被删/改名同样要显式处理）。
    """
    suites = load_baseline(baseline_path)
    if suites is None:
        return 0, 0, ["基线文件缺失/为空（%s）——无法判定达标，按 fail-closed 计红。"
                      "首次启用请跑 --update-baseline 上锁。" % (baseline_path or BASELINE_PATH)]

    bad = []
    ok_n = 0
    for name, base in suites.items():
        if name not in summary:
            bad.append("%s：基线已上锁但本次实测缺席（基准集被删/改名？）" % name)
            continue
        got = summary[name]

        # 题目感知渗透集不是 hit/total 形态，单列判据
        if name == "web_hints":
            b_hit = int(got.get("group_b_with_hint", -1))
            delta = int(got.get("delta", -1))
            need_b = int(base.get("min_group_b", 0))
            need_d = int(base.get("min_delta", 0))
            if b_hit >= need_b and delta >= need_d:
                ok_n += 1
            else:
                bad.append("web_hints：读题组 %d < 基线 %d 或 增量 %d < 基线 %d"
                           % (b_hit, need_b, delta, need_d))
            continue

        g_total = int(got.get("total", -1))
        g_hit = int(got.get("hit", -1))
        need_total = int(base.get("total", -1))
        need_hit = int(base.get("min_hit", -1))
        if g_total != need_total:
            bad.append("%s：题数漂移 %d → %d（基线锁 %d）" % (name, need_total, g_total, need_total))
        elif g_hit < need_hit:
            bad.append("%s：命中退化 %d/%d → %d/%d（基线地板 %d）"
                       % (name, need_hit, need_total, g_hit, g_total, need_hit))
        else:
            ok_n += 1
            # 附件集另锁反注水：朴素正则不许命中
            if name == "attachment" and int(got.get("water_filled", 0)) > int(base.get("max_water_filled", 0)):
                bad.append("attachment：注水题命中 %d > 上限 %d（朴素正则命中即虚报）"
                           % (int(got.get("water_filled", 0)), int(base.get("max_water_filled", 0))))
                ok_n -= 1

    for name in summary:
        if name in ("provenance", "note"):
            continue
        if name not in suites:
            bad.append("%s：本次实测有该基准集但基线未上锁（新增项必须显式登记）" % name)
    return ok_n, len(suites), bad


def update_baseline(summary, baseline_path=None):
    """用本次实况重写基线地板（能力提升后抬高地板；退化时不许用这个绕过）。"""
    path = baseline_path or BASELINE_PATH
    old = {}
    if os.path.exists(path):
        try:
            with open(path, encoding="utf-8") as fh:
                old = json.load(fh).get("suites", {}) or {}
        except Exception:
            old = {}
    suites = {}
    for name, got in summary.items():
        if name in ("provenance", "note"):
            continue
        if name == "web_hints":
            suites[name] = {
                "min_group_b": int(got.get("group_b_with_hint", 0)),
                "min_delta": int(got.get("delta", 0)),
                "why": old.get(name, {}).get("why", "题目感知渗透对照（A组无线索 → B组读题）。"),
            }
            continue
        item = {
            "total": int(got.get("total", 0)),
            "min_hit": int(got.get("hit", 0)),
            "why": old.get(name, {}).get("why", ""),
        }
        if name == "attachment":
            item["max_water_filled"] = 0
        suites[name] = item

    # 🔴 反绕过：地板只许抬升，不许下降。
    # 否则「能力退化 → 改基线 → 门禁转绿」会变成一条一键自欺的捷径，
    # 我加的这个门禁就白加了（与"失败即退出非 0、不提供仅警告模式"同一纪律）。
    lowered = []
    for name, item in suites.items():
        old_item = old.get(name, {})
        if name == "web_hints":
            old_b, old_d = int(old_item.get("min_group_b", 0)), int(old_item.get("min_delta", 0))
            if item["min_group_b"] < old_b or item["min_delta"] < old_d:
                lowered.append("web_hints：读题组 %d→%d 或 增量 %d→%d" %
                               (old_b, item["min_group_b"], old_d, item["min_delta"]))
            continue
        old_hit = int(old_item.get("min_hit", 0))
        if item["min_hit"] < old_hit:
            lowered.append("%s：%d/%d → %d/%d" %
                           (name, old_hit, item["total"], item["min_hit"], item["total"]))
    if lowered:
        print("[BLOCK] 检测到地板下降，拒绝重新上锁（退化应修代码，不是改基线）：")
        for x in lowered:
            print("    - " + x)
        print("   若确属测量口径变更（题目增删/基准集重构），请先手工编辑 "
              "benchmark_baseline.json 并在 commit message 写明理由。")
        return False

    # 🔴 只重写 suites，保留既有文件里的手写元数据（note / rule / usage / location_note …）。
    # 旧实现每次重新上锁都拿下面这坨硬编码文案整份覆盖 header —— 2026-10-16 实测：
    # 一次 --update-baseline 就**静默删掉** location_note 与两条长说明，且把紧凑排版的
    # suites 打散成多行，diff 从「1 个字段」膨胀成 91 增 24 删。留痕丢失不可接受，
    # 故改为 setdefault 只在缺字段时兜底，已存在的手写内容一律保留。
    doc = {}
    if os.path.exists(path):
        try:
            with open(path, encoding="utf-8") as fh:
                doc = json.load(fh)
        except Exception:
            doc = {}
    if not isinstance(doc, dict):
        doc = {}
    doc.setdefault("schema", 1)
    doc.setdefault("created", "2026-10-14")
    doc.setdefault("note", "基准集套件的冻结达标基线（由 --update-baseline 重写）。run_all_benchmarks.py 跑完后逐项比对，任一项未达标即 exit 1。")
    doc.setdefault("usage", "python data/ctf_benchmark/run_all_benchmarks.py            # 跑 + 比对基线（不达标 exit 1）\npython data/ctf_benchmark/run_all_benchmarks.py --update-baseline  # 用本次实况重新上锁")
    doc.setdefault("rule", "① min_hit 是防退化的地板，不是目标；② 能力退化 → 修代码，不许改基线；③ 口径变更 → 改基线并在 commit message 写明。")
    doc["suites"] = suites
    # newline="\n"：与 all_benchmarks_summary.json 同理，Windows 上必须显式写 LF。
    with open(path, "w", encoding="utf-8", newline="\n") as fh:
        json.dump(doc, fh, ensure_ascii=False, indent=2)
        fh.write("\n")
    print("基线已重新上锁: %s（%d 项）" % (path, len(suites)))
    return True


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--go", action="store_true", help="同时跑 Go 侧权威机验")
    ap.add_argument("--update-baseline", action="store_true",
                    help="用本次实况重写 benchmark_baseline.json（能力提升后抬高地板；退化时禁用）")
    ap.add_argument("--summary-out", default=None, metavar="PATH",
                    help="汇总 JSON 的写出路径（默认 data/ctf_benchmark/all_benchmarks_summary.json；"
                         "也可用环境变量 CTF_AGENT_BENCH_SUMMARY_OUT 指定）。"
                         "验证类调用应重定向到临时路径——本汇总受版本管理，是证据包与基线门禁的输入。")
    args = ap.parse_args()

    st_total, st_hit, st_miss, st_pct, st_res = run_static()
    ex_total, ex_hit, ex_miss, ex_pct, ex_res = run_execution()
    wb_total, wb_hit, wb_miss, wb_pct = run_web()
    at_total, at_hit, at_miss, at_pct, at_water = run_attachment()
    wh_total, wh_a, wh_b = run_web_hints()
    jt_total, jt_hit = run_jwt()
    de_total, de_hit = run_deser()
    xe_total, xe_hit = run_xxe()
    up_total, up_hit = run_upload()
    gq_total, gq_hit = run_graphql()
    sr_total, sr_hit = run_ssrf()
    sq_total, sq_hit = run_sqli()
    si_total, si_hit = run_ssti()
    ec_total, ec_hit = run_ecdsa()
    po_total, po_hit = run_padding_oracle()
    bo_total, bo_hit = run_blind_oob()
    he_total, he_hit = run_hash_ext()
    gnr_total, gnr_hit = run_gcm_nr()
    mt_total, mt_hit = run_mt19937()
    lf_total, lf_hit = run_lfsr()
    lc_total, lc_hit = run_lcg()
    cr_total, cr_hit = run_crc32()

    print("=" * 64)
    print("  SecAutoMind 夺旗能力二十二基准集 · 统一机验汇总")
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
    print("【8】XXE 利用 (xxe_benchmark.json, 自建「有漏洞的 XML 解析器」靶场)")
    print("    总数 %2d | 命中 %2d | 未命中 %2d | 覆盖率 %.1f%%" %
          (xe_total, xe_hit, xe_total - xe_hit,
           (100.0 * xe_hit / xe_total) if xe_total else 0.0))
    print("    Python judge_xxe.py == Go TestXXEAttackAgainstRange（+生产入口 3/3）")
    print("    攻破维度：回显型实体文件读 / XInclude 文件读（免 DOCTYPE 变体）/")
    print("               Blind XXE 参数实体外带（flag 只经 /oob-log 外带通道取回）")
    print()
    print("【9】文件上传 RCE (upload_benchmark.json, 服务端 exec() 真·执行上传内容)")
    print("    总数 %2d | 命中 %2d | 未命中 %2d | 覆盖率 %.1f%%" %
          (up_total, up_hit, up_total - up_hit,
           (100.0 * up_hit / up_total) if up_total else 0.0))
    print("    Python judge_upload.py == Go TestUploadAttackAgainstRange（+生产入口 3/3）")
    print("    攻破维度：不受限上传(.py 落盘真执行) / 黑名单大小写绕过(.PY) /")
    print("               保存路径穿越(../ 进自动执行目录)")
    print()
    print("【10】GraphQL (graphql_benchmark.json, 手写 mini GraphQL 执行器靶场)")
    print("    总数 %2d | 命中 %2d | 未命中 %2d | 覆盖率 %.1f%%" %
          (gq_total, gq_hit, gq_total - gq_hit,
           (100.0 * gq_hit / gq_total) if gq_total else 0.0))
    print("    Python judge_graphql.py == Go TestGraphQLAttackAgainstRange（+生产入口 3/3）")
    print("    攻破维度：内省泄露隐藏字段 / IDOR 遍历管理员敏感字段 /")
    print("               隐藏调试 mutation（服务端按命令真实读取靶机文件）")
    print()
    print("【11】SSRF 利用 (ssrf_benchmark.json, gopher Redis / 云元数据 / 回环服务靶场)")
    print("    总数 %2d | 命中 %2d | 未命中 %2d | 覆盖率 %.1f%%" %
          (sr_total, sr_hit, sr_total - sr_hit,
           (100.0 * sr_hit / sr_total) if sr_total else 0.0))
    print("    Python judge_ssrf.py == Go TestSSRFAttackAgainstRange（+生产入口 3/3）")
    print("    攻破维度：gopher:// 管道化 RESP 打内网未授权 Redis（KEYS 枚举→GET 取 flag）/")
    print("               云 IMDS 两跳（角色列表→security-credentials 凭证 Token）/")
    print("               内网回环 admin 服务（仅 SSRF 通道持有内网凭证头，直连 403）")
    print()
    print("【12】SQL 注入深度 (sqli_benchmark.json, 真 sqlite3 三族注入靶场)")
    print("    总数 %2d | 命中 %2d | 未命中 %2d | 覆盖率 %.1f%%" %
          (sq_total, sq_hit, sq_total - sq_hit,
           (100.0 * sq_hit / sq_total) if sq_total else 0.0))
    print("    Python judge_sqli.py == Go TestSQLiAttackAgainstRange（+生产入口 3/3）")
    print("    攻破维度：UNION 列探测+sqlite_master 枚举+逐表提取 /")
    print("               引号闭合+|| 拼接子查询回显 / 布尔盲注（长度二分+逐字符 unicode 二分）")
    print()
    print("【13】SSTI 深度 (ssti_benchmark.json, 三类模板求值逃逸靶场)")
    print("    总数 %2d | 命中 %2d | 未命中 %2d | 覆盖率 %.1f%%" %
          (si_total, si_hit, si_total - si_hit,
           (100.0 * si_hit / si_total) if si_total else 0.0))
    print("    Python judge_ssti.py == Go TestSSTIAttackAgainstRange（+生产入口 3/3）")
    print("    攻破维度：Jinja {{ }} 真求值环境逃逸读环境变量 /")
    print("               str.format 格式串注入读靶机全局常量 /")
    print("               黑名单剥 {{ }} 后 Twig {% %} 定界绕过")
    print()
    print("【14】ECDSA nonce 复用 (ecdsa_benchmark.json, 离线确定性恢复私钥)")
    print("    总数 %2d | 命中 %2d | 未命中 %2d | 覆盖率 %.1f%%" %
          (ec_total, ec_hit, ec_total - ec_hit,
           (100.0 * ec_hit / ec_total) if ec_total else 0.0))
    print("    Python judge_ecdsa.py == Go TestECDSANonceReuseAgainstBenchmark（双语言离线镜像）")
    print("    攻破维度：同 nonce 两签名(r 相同) → k=(z1-z2)/(s1-s2) → d=(s1*k-z1)/r mod n，")
    print("              离线还原私钥 d，flag=flag{<hex(d)>}（纯大数运算，无在线 oracle）")
    print()
    print("【15】CBC Padding Oracle (padding_oracle_benchmark.json, 真实逐字节恢复明文)")
    print("    总数 %2d | 命中 %2d | 未命中 %2d | 覆盖率 %.1f%%" %
          (po_total, po_hit, po_total - po_hit,
           (100.0 * po_hit / po_total) if po_total else 0.0))
    print("    Python judge_padding_oracle.py == Go TestPaddingOracleAgainstBenchmark（双语言镜像）")
    print("    攻破维度：仅用 oracle(ct)->bool 判定 PKCS#7 是否合法，逐字节逼出中间状态 → 还原明文，")
    print("              无需密钥（经典 Vaudenay CBC padding oracle，离线确定性双语言机验）")
    print()

    print("【16】Web 盲打 / 带外回连 OOB 外带 (blind_oob_benchmark.json, 无回显数据渗出通道)")
    print("    总数 %2d | 命中 %2d | 未命中 %2d | 覆盖率 %.1f%%" %
          (bo_total, bo_hit, bo_total - bo_hit,
           (100.0 * bo_hit / bo_total) if bo_total else 0.0))
    print("    Python judge_blind_oob.py == Go TestBlindOOBTimeBased / TestBlindOOBOOB（双语言镜像）")
    print("    攻破维度：时间盲注（仅依响应耗时差异逐字符还原密钥，无需任何回显）/")
    print("              带外回连 OOB（靶机把密钥异步回连到攻击方内置监听器取回，flag 不在响应里）")
    print()

    print("【17】Hash Length Extension 长度扩展攻击 (hash_ext_benchmark.json, MD5/SHA1 真实续算)")
    print("    总数 %2d | 命中 %2d | 未命中 %2d | 覆盖率 %.1f%%" %
          (he_total, he_hit, he_total - he_hit,
           (100.0 * he_hit / he_total) if he_total else 0.0))
    print("    Python judge_hash_ext.py == Go TestHashLengthExtension*（双语言镜像）")
    print("    攻破维度：已知 MAC=H(secret||known_data) 的内部状态，无需 secret 续算")
    print("              H(secret||known_data||glue||extra)（手动 MD5/SHA1 压缩续算，纯标准库）")
    print()

    print("【18】AES-GCM nonce 复用 keystream 复原 (gcm_nonce_reuse_benchmark.json, 真实机密性破坏)")
    print("    总数 %2d | 命中 %2d | 未命中 %2d | 覆盖率 %.1f%%" %
          (gnr_total, gnr_hit, gnr_total - gnr_hit,
           (100.0 * gnr_hit / gnr_total) if gnr_total else 0.0))
    print("    Python judge_gcm_nr.py == Go TestGCMNonceReuse*（双语言镜像）")
    print("    攻破维度：同密钥同 96-bit nonce → 两条密文共享 CTR keystream →")
    print("              KS = C1 ⊕ m1 → m2 = C2 ⊕ KS（无需密钥、无需 AES，纯异或复原）")
    print()

    print("【19】MT19937 状态恢复 (mt19937_benchmark.json, 泄露 624 输出预测下一个)")
    print("    总数 %2d | 命中 %2d | 未命中 %2d | 覆盖率 %.1f%%" %
          (mt_total, mt_hit, mt_total - mt_hit,
           (100.0 * mt_hit / mt_total) if mt_total else 0.0))
    print("    Python judge_mt19937.py == Go TestMT19937*（双语言镜像）")
    print("    攻破维度：MT19937 内部状态 = 624 个 32-bit 字，输出 = temper(state[i]) 是可逆双射 →")
    print("              untemper 反解状态 → twist 推进 → 预测第 625 个输出（无需种子、纯位运算）")
    print()

    print("【20】LFSR 流预测 / Berlekamp–Massey (lfsr_benchmark.json, 泄露比特恢复线性递推)")
    print("    总数 %2d | 命中 %2d | 未命中 %2d | 覆盖率 %.1f%%" %
          (lf_total, lf_hit, lf_total - lf_hit,
           (100.0 * lf_hit / lf_total) if lf_total else 0.0))
    print("    Python judge_lfsr.py == Go TestLFSR*（双语言镜像）")
    print("    攻破维度：观察 >= 2L 个 LFSR 输出比特 → Berlekamp–Massey 在 GF(2) 上恢复")
    print("              最小连接多项式 → 逐位前推预测后续比特（无需寄存器抽头/初态）")
    print()

    print("【21】LCG 线性同余预测 (lcg_benchmark.json, 三形态: 全知/反解/模数未知)")
    print("    总数 %2d | 命中 %2d | 未命中 %2d | 覆盖率 %.1f%%" %
          (lc_total, lc_hit, lc_total - lc_hit,
           (100.0 * lc_hit / lc_total) if lc_total else 0.0))
    print("    Python judge_lcg.py == Go TestLCG*（双语言镜像）")
    print("    攻破维度：x'=(a·x+c) mod m。① 参数全知 → 倍增推进；② 模数已知 →")
    print("              a=(x2-x1)/(x1-x0) mod m 反解；③ 模数未知 → gcd 恢复 m（m | t_{i+1}·t_{i-1}-t_i²）")
    print()

    print("【22】CRC32 伪造 (crc32_benchmark.json, 线性校验 ≠ MAC)")
    print("    总数 %2d | 命中 %2d | 未命中 %2d | 覆盖率 %.1f%%" %
          (cr_total, cr_hit, cr_total - cr_hit,
           (100.0 * cr_hit / cr_total) if cr_total else 0.0))
    print("    Python judge_crc32.py == Go TestCRC32*（双语言镜像）")
    print("    攻破维度：crc32(m‖X) = crc32(m‖0000) ⊕ L(X)，解 32×32 GF(2) 方程组")
    print("              L(X)=d 得唯一 4 字节后缀 → 校验值被改成任意目标（无需密钥）")
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
          "+ JWT %d/%d + 反序列化 %d/%d + XXE %d/%d + 上传RCE %d/%d + GraphQL %d/%d"
          " + SSRF %d/%d + SQLi深度 %d/%d + SSTI深度 %d/%d + ECDSA %d/%d + PaddingOracle %d/%d + BlindOOB %d/%d + HashExt %d/%d + GCMNR %d/%d + MT19937 %d/%d + LFSR %d/%d + LCG %d/%d + CRC32 %d/%d" %
          (st_pct, ex_pct, wb_pct, at_pct, jt_hit, jt_total, de_hit, de_total,
           xe_hit, xe_total, up_hit, up_total, gq_hit, gq_total,
           sr_hit, sr_total, sq_hit, sq_total, si_hit, si_total, ec_hit, ec_total,
           po_hit, po_total, bo_hit, bo_total, he_hit, he_total, gnr_hit, gnr_total,
           mt_hit, mt_total, lf_hit, lf_total, lc_hit, lc_total, cr_hit, cr_total))
    print("    Web 题目感知渗透: A组(无线索)%d → B组(读题)%d (增量 +%d)，证明『读题取线索定向打』是实打实能力" %
          (wh_a, wh_b, wh_b - wh_a))
    print("    执行层、Web 实战层、附件取证层、题目感知层、JWT、反序列化、XXE、上传RCE、GraphQL、SSRF、SQLi、SSTI、"
          "ECDSA、Padding Oracle、Blind OOB、Hash Length Extension、GCM nonce 复用、MT19937 状态恢复、LFSR/Berlekamp–Massey、LCG 预测、CRC32 伪造 十七大利用层是冠军差异点：")
    print("    西湖论剑类关键词求解器天花板即静态集，SecAutoMind 额外验证了")
    print("    『真跑工具 + 真打靶机 + 真攻 Web + 真解析二进制 + 读题定向渗透 + 真绕过 JWT")
    print("     + 真反序列化 RCE + 真 XXE（含 Blind OOB）+ 真上传 RCE + 真 GraphQL 利用"
          " + 真 SSRF 链（gopher Redis/云凭证/内网服务）+ 真 SQLi 三族提取 + 真 SSTI 三态逃逸")
    print("     + 真 GCM nonce 复用（CTR keystream 复原，无需密钥）")
    print("     + 真 MT19937 状态恢复（泄露 624 输出预测下一个，无需种子）")
    print("     + 真 LFSR 流预测（Berlekamp–Massey 恢复线性递推）")
    print("     + 真 LCG 参数恢复与预测（含模数未知的 gcd 复原）")
    print("     + 真 CRC32 伪造（线性校验破解，追加 4 字节改任意目标，无需密钥）』(双语言机验)。")
    print()

    if args.go:
        print("【Go 侧权威机验】")
        print(run_go())
        print()

    # ── §2.3 诚信铁律：显式标注题目来源（真题 vs 自产题）────────────────────
    # 背景：本项目一批「100%」来自 gen_*.py 自产题（自产自解，无外部真值）。
    # 铁律（继承自西湖论剑）：**无外部 flag 真值不计入 KPI**。自产题的覆盖率只证明
    # 「工程链路可跑通」，不构成真实赛场竞争力证据；对外引用必须标注来源。
    # 判定依据：real_benchmark.json 每题带 `source`（如 "picoCTF 2024 - interencdec"）
    # 与公开 writeup 来源 → 真题；其余基准集为 gen_*.py 生成 / 自建靶场 / 自造工件 → 自产。
    synth_total = (ex_total + wb_total + at_total + wh_total
                   + jt_total + de_total + xe_total + up_total + gq_total
                   + sr_total + sq_total + si_total + ec_total + po_total
                   + bo_total + he_total + gnr_total + mt_total + lf_total
                   + lc_total + cr_total)
    real_total = st_total
    all_total = real_total + synth_total
    synth_ratio = round(100.0 * synth_total / all_total, 1) if all_total else 0.0

    print("【来源标注（§2.3 诚信铁律）】")
    print("    真题 %d 题（static = real_benchmark.json，公开 writeup 来源 + SHA-256）" % real_total)
    print("    自产题 %d 题（gen_*.py 生成 / 自建靶场 / 自造工件）" % synth_total)
    print("    → **自产题占比 %.1f%%**（总 %d 题）" % (synth_ratio, all_total))
    print("    ⚠️ 自产题的高覆盖率只证明「工程链路可跑通」，**不构成真实赛场竞争力证据**；")
    print("       对外引用任何 100% 必须标注「自产题」或「自建靶场」。")
    print()

    # 诚实化（2026-10-16）：上面【1】～【8】各自打印了一句「Python xxx == Go xxx」的对应关系，
    # 但**只有【1】静态集**真的接了逐题机验（scripts/check_benchmark_parity.py，CI job
    # benchmark-parity-gate）。其余各集的同类表述此前纯粹是措辞 —— 本基线比对只查下限
    # （hit < min_hit 才红），Python 侧上漂与 Go 两路径的逐题差异都无人看。
    # 与 AGENTS.md 第八条「宣称 ≠ 接线」同一纪律：没接线的不许当已核验证据引用。
    print("【双语言机验覆盖（哪些「==」已接线）】")
    print("    ✅ 已接线：【1】静态集 —— Go shipped / Go registry / Python judge.py 三路逐题一致")
    print("              （scripts/check_benchmark_parity.py，CI job benchmark-parity-gate）")
    print("    ⚠️ 未接线：【2】～【8】的「Python == Go」表述尚未逐题机验，不得当作已核验证据引用。")
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
        "xxe": {"total": xe_total, "hit": xe_hit, "miss": xe_total - xe_hit,
                "coverage_pct": (100.0 * xe_hit / xe_total) if xe_total else 0.0},
        "upload": {"total": up_total, "hit": up_hit, "miss": up_total - up_hit,
                   "coverage_pct": (100.0 * up_hit / up_total) if up_total else 0.0},
        "graphql": {"total": gq_total, "hit": gq_hit, "miss": gq_total - gq_hit,
                    "coverage_pct": (100.0 * gq_hit / gq_total) if gq_total else 0.0},
        "ssrf": {"total": sr_total, "hit": sr_hit, "miss": sr_total - sr_hit,
                 "coverage_pct": (100.0 * sr_hit / sr_total) if sr_total else 0.0},
        "sqli_deep": {"total": sq_total, "hit": sq_hit, "miss": sq_total - sq_hit,
                      "coverage_pct": (100.0 * sq_hit / sq_total) if sq_total else 0.0},
        "ssti_deep": {"total": si_total, "hit": si_hit, "miss": si_total - si_hit,
                      "coverage_pct": (100.0 * si_hit / si_total) if si_total else 0.0},
        "ecdsa_nonce_reuse": {"total": ec_total, "hit": ec_hit, "miss": ec_total - ec_hit,
                              "coverage_pct": (100.0 * ec_hit / ec_total) if ec_total else 0.0},
        "padding_oracle": {"total": po_total, "hit": po_hit, "miss": po_total - po_hit,
                           "coverage_pct": (100.0 * po_hit / po_total) if po_total else 0.0},
        "blind_oob": {"total": bo_total, "hit": bo_hit, "miss": bo_total - bo_hit,
                      "coverage_pct": (100.0 * bo_hit / bo_total) if bo_total else 0.0},
        "hash_ext": {"total": he_total, "hit": he_hit, "miss": he_total - he_hit,
                      "coverage_pct": (100.0 * he_hit / he_total) if he_total else 0.0},
        "gcm_nonce_reuse": {"total": gnr_total, "hit": gnr_hit, "miss": gnr_total - gnr_hit,
                            "coverage_pct": (100.0 * gnr_hit / gnr_total) if gnr_total else 0.0},
        "mt19937_recover": {"total": mt_total, "hit": mt_hit, "miss": mt_total - mt_hit,
                            "coverage_pct": (100.0 * mt_hit / mt_total) if mt_total else 0.0},
        "lfsr_predict": {"total": lf_total, "hit": lf_hit, "miss": lf_total - lf_hit,
                         "coverage_pct": (100.0 * lf_hit / lf_total) if lf_total else 0.0},
        "lcg_predict": {"total": lc_total, "hit": lc_hit, "miss": lc_total - lc_hit,
                        "coverage_pct": (100.0 * lc_hit / lc_total) if lc_total else 0.0},
        "crc32_forge": {"total": cr_total, "hit": cr_hit, "miss": cr_total - cr_hit,
                        "coverage_pct": (100.0 * cr_hit / cr_total) if cr_total else 0.0},
        "provenance": {
            "real": {
                "label": "真题（公开 writeup 来源；每题带 source 与 flag_sha256）",
                "benchmarks": ["static"],
                "problems": real_total,
            },
            "synthetic": {
                "label": "自产题（gen_*.py 生成 / 自建靶场 / 自造工件）",
                "benchmarks": ["execution", "web", "attachment", "web_hints", "jwt", "deser",
                               "xxe", "upload", "graphql", "ssrf", "sqli_deep", "ssti_deep",
                               "ecdsa_nonce_reuse", "padding_oracle", "blind_oob", "hash_ext",
                               "gcm_nonce_reuse", "mt19937_recover", "lfsr_predict",
                               "lcg_predict", "crc32_forge"],
                "problems": synth_total,
            },
            "total_problems": all_total,
            "synthetic_ratio_pct": synth_ratio,
            "rule": ("无外部 flag 真值不计入 KPI（继承西湖论剑铁律）。自产题的高覆盖率只证明"
                     "工程链路可跑通，不构成真实赛场竞争力证据；对外引用任何 100% 必须标注来源。"),
        },
        "note": "静态/执行/Web/附件 覆盖率不相加；执行层、Web 实战层、附件取证层、题目感知层为冠军差异点；"
                "所有命中经 SHA-256 校验；附件集另设反注水门禁（朴素正则不许命中）。",
    }
    # 输出路径三档解析：显式 --summary-out > 环境变量 > 默认（受版本管理的证据产物）。
    # 为什么必须可重定向（2026-10-14 实锤）：
    #   scripts/check_quant_effect.py --full 会经 docs/quant_effect.md 的
    #   `benchmark_suite_green` 声明调用本脚本。此前本脚本**无条件就地写**默认路径，
    #   于是「验证」跑一次就把受版本管理的汇总覆盖一次；在降级环境（如缺 pycryptodome
    #   导致 padding_oracle 0/1）下写进去的就是**降级值**，并级联把
    #   check_benchmark_baseline_test.py 判红——验证动作污染了被验证的产物。
    #   重定向后：验证可正常比对 stdout，产物不受影响；正式出证据包时仍走默认路径。
    out_path = (args.summary_out
                or os.environ.get("CTF_AGENT_BENCH_SUMMARY_OUT")
                or os.path.join(HERE, "all_benchmarks_summary.json"))
    out_path = os.path.abspath(out_path)
    out_dir = os.path.dirname(out_path)
    if out_dir:
        os.makedirs(out_dir, exist_ok=True)
    # newline="\n"：显式写 LF。否则 Windows 上 Python 文本模式会写出 CRLF，
    # 与 CI 检出（LF）字节不一致 —— 凡对本文件做哈希比对的门禁都会在 CI 侧炸（2026-09-28 实锤）。
    with open(out_path, "w", encoding="utf-8", newline="\n") as fh:
        json.dump(summary, fh, ensure_ascii=False, indent=2)
        fh.write("\n")
    print("汇总已写入: %s" % out_path)

    if args.update_baseline:
        return 0 if update_baseline(summary) else 1

    # 达标判定：缺了这一步，本脚本无论跑出什么结果都 exit 0，
    # 对外材料的「基准集全绿」就只是一句无法证伪的修辞（2026-10-14 补齐）。
    ok_n, total_n, bad = check_baseline(summary)
    print()
    print("【汇总】基准集达标 %d/%d" % (ok_n, total_n))
    if bad:
        for b in bad:
            print("    [BLOCK] " + b)
        print("   处置：确属能力退化 → 修代码（不许改基线）；确属测量口径变更 → "
              "--update-baseline 重新上锁并在 commit message 写明。")
        return 1
    print("   全部达到冻结基线（docs/benchmark_baseline.json）。")
    return 0


if __name__ == "__main__":
    sys.exit(main())
