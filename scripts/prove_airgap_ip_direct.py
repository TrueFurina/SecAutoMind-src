#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""断网闸（seccomp）IP 直连证据 —— 自动生成 / 本地复核 / 变异自测。

为什么必须 IP 直连：DNS 失败（``Temporary failure in name resolution``）与
「这台机器本来就没配 DNS / 本来就没外网」完全同形，无法证明闸门生效。
``cmd/airgaptest/main.go`` 的判定契约：

  基线（不开闸）：AF_INET 必须 CONNECTED-NOT-BLOCKED
                  —— 否则「断网」是环境属性，不能归因给 seccomp
  开闸（CTF_AIRGAP=1）：AF_INET 必须 PermissionError errno=1 (EPERM)
                  —— ENETUNREACH(101) / DNS 失败一律不算
                  AF_UNIX 必须仍然 OK（不能误伤本地 IPC）

本脚本的三条硬纪律（与项目既有判据一致）：
  1. **自动生成**：``ip_direct_blocked`` / ``af_unix_ok`` 不许人填，
     由 ``--run`` 真跑 ssh A/B 后从原始输出解析；证据里存两份原始 stdout。
  2. **重算复核**：``--check`` 从原始输出重新解析，逐字段比对存盘值；
     并校验 4 份 Go 源码 sha256 与本机当前文件一致（防源码漂移后旧证据仍绿）。
     纯本地、不联网，CI checkout 下可跑。
  3. **fail-closed**：缺字段 / 解析不出 / 基线本来就断网 / AF_UNIX 被误伤
     / 开闸报的是 ENETUNREACH 或 DNS 失败 ⇒ 一律 NOT_PROVEN。

用法：
  python scripts/prove_airgap_ip_direct.py --run      # 需 ssh 可达服务器
  python scripts/prove_airgap_ip_direct.py --check   # 纯本地复核（CI 用）
  python scripts/prove_airgap_ip_direct.py --selftest
退出码：证明成立 = 0；不成立 / 缺件 / 被篡改 = 1；--run 环境不可用 = 2。

证据被 ``run_capability_eval.py --preflight --mode agentic --airgap-proof``
消费（要求 ip_direct_blocked=true 且 af_unix_ok=true）。注意 pure_llm 路径
没有解题子进程，该证据在 preflight 里标 N/A，不参与放行 —— 别拿来冒充
pure_llm 的能力证明。
"""
from __future__ import annotations

import argparse
import datetime
import hashlib
import io
import json
import os
import re
import shutil
import subprocess
import sys
import tarfile

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
EVIDENCE_DIR = os.path.join(ROOT, "docs", "evidence", "capability_eval_20261105")
DEFAULT_PROOF = os.path.join(EVIDENCE_DIR, "airgap_ip_direct_proof_20261106.json")
DEFAULT_HOST = "user@172.16.222.99"
DEFAULT_GOBIN = "/home/user/go1.25.4/bin"
REMOTE_DIR = "/tmp/wb_airgap_probe"

# 只带编译所需文件；_test.go 不参与 go build。顺序固定，便于指纹复现。
SOURCE_FILES = (
    "cmd/airgaptest/main.go",
    "internal/airgap/airgap.go",
    "internal/airgap/seccomp_linux.go",
    "internal/airgap/seccomp_other.go",
)

PROBE_RE = re.compile(r"^(AF_INET6|AF_INET-UDP|AF_INET|AF_UNIX)\s+(.+?)\s*$", re.M)
EPERM_RE = re.compile(r"PermissionError\s+1\b")

# 远端脚本：隔离临时目录编译，绝不触碰服务器既有部署树。
# 服务器的 /home/user/SecAutoMind 不是 git 副本（实测缺 cmd/airgaptest、
# airgap.go 指纹与本机不同），因此只信本次从本机 tar 传过去的源码。
REMOTE_SCRIPT = (
    "mkdir -p " + REMOTE_DIR + " && tar xzf - -C " + REMOTE_DIR + " && "
    r"printf 'module secautomind-ai\n\ngo 1.25.0\n' > " + REMOTE_DIR + "/go.mod && "
    "cd " + REMOTE_DIR + " && export PATH=$PATH:{gobin} && "
    "echo WB_SRC_SHA && sha256sum " + " ".join(SOURCE_FILES) + " && "
    "go build -o " + REMOTE_DIR + "/wb_airgaptest ./cmd/airgaptest && "
    "echo WB_BUILD_OK && sha256sum " + REMOTE_DIR + "/wb_airgaptest && "
    "echo WB_A_BEGIN && " + REMOTE_DIR + "/wb_airgaptest && echo WB_A_END && "
    "echo WB_B_BEGIN && CTF_AIRGAP=1 " + REMOTE_DIR + "/wb_airgaptest && echo WB_B_END"
)


def _sha256_file(path):
    with open(path, "rb") as f:
        return hashlib.sha256(f.read()).hexdigest()


def local_source_sha():
    out = {}
    for rel in SOURCE_FILES:
        p = os.path.join(ROOT, rel.replace("/", os.sep))
        out[rel] = _sha256_file(p) if os.path.isfile(p) else None
    return out


def _make_tar():
    buf = io.BytesIO()
    with tarfile.open(fileobj=buf, mode="w:gz") as tf:
        for rel in SOURCE_FILES:
            p = os.path.join(ROOT, rel.replace("/", os.sep))
            tf.add(p, arcname=rel)
    return buf.getvalue()


def _parse_probes(text):
    return {m.group(1): m.group(2) for m in PROBE_RE.finditer(text or "")}


def assess(baseline_output, gated_output):
    """从两份原始 stdout 判定。纯函数，便于变异自测。返回 (fields, reasons)。"""
    a = _parse_probes(baseline_output)
    b = _parse_probes(gated_output)
    reasons = []

    baseline_egress = "CONNECTED-NOT-BLOCKED" in a.get("AF_INET", "")
    if not baseline_egress:
        reasons.append("baseline_af_inet_not_connected(服务器本来就断网，不能归因给闸门)")

    g_inet = b.get("AF_INET", "")
    ip_direct_blocked = bool(EPERM_RE.search(g_inet))
    if not ip_direct_blocked:
        reasons.append("gated_af_inet_not_eperm(EPERM errno=1 才是 seccomp 生效证据)")
    if "Network is unreachable" in g_inet or "name resolution" in g_inet:
        reasons.append("gated_result_is_environment_error_not_gate")

    af_unix_ok = b.get("AF_UNIX", "") == "OK"
    if not af_unix_ok:
        reasons.append("gated_af_unix_broken(误伤本地 IPC)")

    udp = b.get("AF_INET-UDP", "")
    udp_blocked = bool(EPERM_RE.search(udp))
    if not udp_blocked:
        reasons.append("gated_af_inet_udp_not_eperm(UDP 出口未拦)")

    fields = {
        "baseline_egress_proven": baseline_egress,
        "ip_direct_blocked": ip_direct_blocked,
        "af_unix_ok": af_unix_ok,
        "udp_blocked": udp_blocked,
        "baseline_probes": a,
        "gated_probes": b,
    }
    verdict = "PROVEN" if not reasons else "NOT_PROVEN"
    return dict(fields, verdict=verdict, reasons=reasons), reasons


def run_remote(host, gobin, timeout=300):
    ssh = shutil.which("ssh")
    if not ssh:
        return None, "本机找不到 ssh（--run 需要服务器取证；CI 请只跑 --check）"
    cmd = [ssh, "-o", "BatchMode=yes", "-o", "ConnectTimeout=8", host,
           REMOTE_SCRIPT.format(gobin=gobin)]
    try:
        r = subprocess.run(cmd, input=_make_tar(), capture_output=True,
                           timeout=timeout)
    except subprocess.TimeoutExpired as exc:
        return None, "ssh 探测超时: %s" % exc
    out = r.stdout.decode("utf-8", "replace")
    err = r.stderr.decode("utf-8", "replace")
    if r.returncode != 0:
        return None, "远端执行失败 rc=%d stderr=%s" % (r.returncode, err[-400:])
    return {"out": out, "stderr": err}, None


def build_payload(raw, host, gobin):
    out = raw["out"]

    def section(begin, end):
        if begin not in out or end not in out:
            return None
        return out.split(begin, 1)[1].split(end, 1)[0].strip()

    baseline = section("WB_A_BEGIN", "WB_A_END")
    gated = section("WB_B_BEGIN", "WB_B_END")
    if baseline is None or gated is None:
        return {"verdict": "NOT_PROVEN", "reasons": ["missing_A_or_B_section"],
                "generated_at": datetime.datetime.now().astimezone().isoformat(timespec="seconds")}

    fields, _ = assess(baseline, gated)
    server_src = {}
    if "WB_SRC_SHA" in out:
        chunk = out.split("WB_SRC_SHA", 1)[1].split("WB_BUILD_OK", 1)[0]
        for m in re.finditer(r"([0-9a-f]{64})\s+(cmd/\S+|internal/\S+)", chunk):
            server_src[m.group(2)] = m.group(1)
    binary_sha = ""
    if "WB_BUILD_OK" in out:
        chunk = out.split("WB_BUILD_OK", 1)[1].split("WB_A_BEGIN", 1)[0]
        m = re.search(r"\b([0-9a-f]{64})\b", chunk)
        binary_sha = m.group(1) if m else ""

    local = local_source_sha()
    drift = sorted(rel for rel, sha in local.items()
                   if server_src.get(rel) != sha)
    if drift:
        fields["verdict"] = "NOT_PROVEN"
        fields["reasons"] = list(fields["reasons"]) + [
            "server_source_sha_mismatch(传输被改或远端解包异常): %s" % ",".join(drift)]

    return {
        "schema": "airgap_ip_direct_proof_v1",
        "generated_by": "scripts/prove_airgap_ip_direct.py --run (自动生成，非人工填写)",
        "generated_at": datetime.datetime.now().astimezone().isoformat(timespec="seconds"),
        "host": host,
        "go_bin": gobin,
        "probe": "cmd/airgaptest (IP 直连 1.1.1.1/2606:4700:4700::1111:80，绕开 DNS)",
        "airgap_scope": "解题子进程 python_session/skill/流式 shell；LLM API 通道必须联网，不在隔离范围",
        "baseline_output_raw": baseline,
        "gated_output_raw": gated,
        "baseline_probes": fields["baseline_probes"],
        "gated_probes": fields["gated_probes"],
        "baseline_egress_proven": fields["baseline_egress_proven"],
        "ip_direct_blocked": fields["ip_direct_blocked"],
        "af_unix_ok": fields["af_unix_ok"],
        "udp_blocked": fields["udp_blocked"],
        "verdict": fields["verdict"],
        "reasons": fields["reasons"],
        "local_source_sha256": local,
        "server_source_sha256": server_src,
        "binary_sha256": binary_sha,
        "server_stderr": raw["stderr"][-500:],
        "consumer": "run_capability_eval.py --preflight --mode agentic --airgap-proof (要求 ip_direct_blocked && af_unix_ok)",
        "caveats": [
            "只证明 seccomp 闸门在该服务器该二进制上生效，不证明任何一次跑批真的开了闸",
            "pure_llm 路径无解题子进程，本证据在 --mode pure_llm 下为 N/A，不参与放行",
            "题源仍全公开、私有性锚点未建立；本证据不构成可引用能力率",
        ],
    }


def check_payload(payload, root=ROOT):
    """纯本地复核：从原始输出重算 + 源码指纹比对。返回违规描述列表（空 = 通过）。"""
    if not isinstance(payload, dict):
        return ["证据不是 dict"]
    bad = []
    required = ("schema", "generated_at", "baseline_output_raw", "gated_output_raw",
                "ip_direct_blocked", "af_unix_ok", "udp_blocked",
                "baseline_egress_proven", "verdict", "local_source_sha256",
                "binary_sha256", "host")
    for k in required:
        if k not in payload:
            bad.append("missing_field:%s" % k)
    if bad:
        return bad
    if payload["schema"] != "airgap_ip_direct_proof_v1":
        bad.append("schema_mismatch")
    if payload["verdict"] != "PROVEN":
        bad.append("verdict_not_PROVEN")
    # 核心：从原始 stdout 重算，不接受人改的 True。
    rec, _ = assess(payload["baseline_output_raw"], payload["gated_output_raw"])
    for k in ("baseline_egress_proven", "ip_direct_blocked", "af_unix_ok", "udp_blocked"):
        if payload.get(k) is not True:
            bad.append("field_false:%s" % k)
        if rec.get(k) is not True:
            bad.append("recompute_false:%s" % k)
        if payload.get(k) != rec.get(k):
            bad.append("field_vs_raw_output_mismatch:%s" % k)
    for side in ("baseline", "gated"):
        stored = payload.get(side + "_probes") or {}
        fresh = rec[side + "_probes"]
        if stored != fresh:
            bad.append("probes_vs_raw_output_mismatch:%s" % side)
    # 源码漂移后旧证据不许继续发绿。
    now = local_source_sha()
    for rel, sha in now.items():
        if payload["local_source_sha256"].get(rel) != sha:
            bad.append("source_sha256_drift:%s" % rel)
    if not re.fullmatch(r"[0-9a-f]{64}", str(payload["binary_sha256"])):
        bad.append("binary_sha256_malformed")
    return bad


def selftest():
    """合成 A/B 输出的变异验证：该绿的绿，该红的一律红。"""
    good_a = ("[airgaptest] CTF_AIRGAP=\"\" Enabled=false IsChild=false\n"
              "AF_INET CONNECTED-NOT-BLOCKED\n"
              "AF_INET6 OSError 101 [Errno 101] Network is unreachable\n"
              "AF_UNIX OK\nAF_INET-UDP OK\n")
    good_b = ("[airgaptest] CTF_AIRGAP=\"1\" Enabled=true IsChild=false\n"
              "AF_INET PermissionError 1 [Errno 1] Operation not permitted\n"
              "AF_INET6 PermissionError 1 [Errno 1] Operation not permitted\n"
              "AF_UNIX OK\n"
              "AF_INET-UDP PermissionError 1 [Errno 1] Operation not permitted\n")
    cases = [
        ("真实 A/B 形态 → PROVEN", good_a, good_b, "PROVEN"),
        ("基线本来就断网 → 不可归因", good_a.replace("CONNECTED-NOT-BLOCKED", "OSError 101 [Errno 101] Network is unreachable"), good_b, "NOT_PROVEN"),
        ("开闸报 ENETUNREACH 而非 EPERM → 不可归因", good_a, good_b.replace("PermissionError 1 [Errno 1]", "OSError 101 [Errno 101] Network is unreachable"), "NOT_PROVEN"),
        ("DNS 失败不算闸门生效", good_a, good_b.replace("AF_INET PermissionError 1 [Errno 1] Operation not permitted", "AF_INET gaierror -2 Temporary failure in name resolution"), "NOT_PROVEN"),
        ("AF_UNIX 被误伤 → 不可归因", good_a, good_b.replace("AF_UNIX OK", "AF_UNIX FAIL"), "NOT_PROVEN"),
        ("UDP 出口没拦 → 不可归因", good_a, good_b.replace("AF_INET-UDP PermissionError 1 [Errno 1] Operation not permitted", "AF_INET-UDP OK"), "NOT_PROVEN"),
        ("A/B 只有一侧 → 不可归因", "", good_b, "NOT_PROVEN"),
    ]
    _pass = 0
    for label, a, b, want in cases:
        got, _ = assess(a, b)
        ok = got["verdict"] == want
        _pass += int(ok)
        print("  %s %-46s verdict=%s" % ("PASS" if ok else "FAIL", label, got["verdict"]))
    # 字段篡改变异：把 True 改掉 / 把原始输出改掉，--check 必须红。
    payload = dict(build_payload(
        {"out": "WB_SRC_SHA\n%s\nWB_BUILD_OK\n%s\nWB_A_BEGIN\n%s\nWB_A_END\nWB_B_BEGIN\n%s\nWB_B_END\n" % (
            "\n".join("%s  %s" % (v, k) for k, v in local_source_sha().items()),
            "0" * 64 + "  /tmp/wb_airgaptest", good_a, good_b),
         "stderr": ""}, DEFAULT_HOST, DEFAULT_GOBIN))
    muts = [
        ("合规证据 → check 为空", lambda d: d),
        ("手改 ip_direct_blocked=False", lambda d: d.update(ip_direct_blocked=False)),
        ("手改 verdict", lambda d: d.update(verdict="PROVEN", ip_direct_blocked=False)),
        ("抹掉开闸原始输出", lambda d: d.update(gated_output_raw="")),
        ("源码指纹漂移", lambda d: d["local_source_sha256"].update({SOURCE_FILES[0]: "0" * 64})),
    ]
    print("  --- --check 篡改变异 ---")
    for label, mut in muts:
        import copy
        d = copy.deepcopy(payload)
        mut(d)
        bad = check_payload(d)
        want_empty = label.startswith("合规")
        ok = (not bad) if want_empty else bool(bad)
        _pass += int(ok)
        print("  %s %-46s violations=%d" % ("PASS" if ok else "FAIL", label, len(bad)))
    total = len(cases) + len(muts)
    print("=== 通过 %d / %d ===" % (_pass, total))
    return 0 if _pass == total else 1


def main():
    ap = argparse.ArgumentParser(description="airgap IP 直连证据")
    g = ap.add_mutually_exclusive_group(required=True)
    g.add_argument("--run", action="store_true", help="ssh 到服务器真跑 A/B 并生成证据")
    g.add_argument("--check", action="store_true", help="纯本地复核已有证据")
    g.add_argument("--selftest", action="store_true", help="合成变异自测（不联网）")
    ap.add_argument("--proof", default=DEFAULT_PROOF)
    ap.add_argument("--host", default=DEFAULT_HOST)
    ap.add_argument("--go-bin", default=DEFAULT_GOBIN)
    args = ap.parse_args()

    if args.selftest:
        return selftest()

    if args.run:
        raw, err = run_remote(args.host, args.go_bin)
        if err:
            print("[FAIL] %s" % err, file=sys.stderr)
            return 2
        payload = build_payload(raw, args.host, args.go_bin)
        os.makedirs(os.path.dirname(args.proof), exist_ok=True)
        with open(args.proof, "w", encoding="utf-8") as f:
            json.dump(payload, f, ensure_ascii=False, indent=2)
        print("证据写入: %s" % args.proof)
        print("verdict=%s  baseline_egress=%s  ip_direct_blocked=%s  af_unix_ok=%s  udp_blocked=%s"
              % (payload["verdict"], payload.get("baseline_egress_proven"),
                 payload.get("ip_direct_blocked"), payload.get("af_unix_ok"),
                 payload.get("udp_blocked")))
        for r in payload.get("reasons", []):
            print("  reason:", r)
        return 0 if payload["verdict"] == "PROVEN" else 1

    if not os.path.isfile(args.proof):
        print("[FAIL] 证据文件不存在（fail-closed，不许用空证明放行）: %s" % args.proof,
              file=sys.stderr)
        return 1
    try:
        payload = json.load(open(args.proof, encoding="utf-8"))
    except Exception as exc:
        print("[FAIL] 证据解析失败: %s" % exc, file=sys.stderr)
        return 1
    bad = check_payload(payload)
    if bad:
        print("=== IP 直连证据复核：FAIL ===")
        for b in bad:
            print("  -", b)
        return 1
    print("=== IP 直连证据复核：PASS ===")
    print("  host=%s  generated_at=%s  binary=%s"
          % (payload["host"], payload["generated_at"], payload["binary_sha256"][:16]))
    print("  基线有外网 / 开闸 EPERM errno=1 / AF_UNIX 未误伤 / UDP 亦被拦 —— 均从原始输出重算一致")
    return 0


if __name__ == "__main__":
    sys.exit(main())
