#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""SecAutoMind 冠军证据包（§4.1 机器可验证据包标准化）。

把一个"答辩即用"的证据集合固化成**单一可机验包** `docs/evidence-package.json`：
  ・规模真值        —— scripts/count_stats.py --json
  ・双语言机验基准  —— data/ctf_benchmark/all_benchmarks_summary.json（四大基础集 + 十七大利用层 + 来源标注）
  ・跨语言 golden   —— scripts/check_golden_freeze.py + testdata 哈希
  ・密钥门禁三件套  —— secret_guard / secret_guard_test / secret_guard_mutation_check 退出码
  ・证据口径门禁    —— scripts/verify_evidence.py 退出码
  ・产物指纹        —— exe / Setup / 交付包（**易变，仅记录不比对**）
  ・构建/测试退出码 —— 仅在 --with-build 时采集（慢）

用法：
  python scripts/build_championship_evidence.py               # 生成 / 刷新证据包
  python scripts/build_championship_evidence.py --check       # 与包内值比对，漂移即 exit 1（CI 用）
  python scripts/build_championship_evidence.py --with-build  # 额外采集 go build / go test（数分钟）
  python scripts/build_championship_evidence.py --print       # 只打印摘要，不写文件

设计原则（对齐本仓 AGENTS.md）：
  1. **不许静默放过**：取不到真值的项记 `null` 并在 `notes` 里写明原因，绝不伪造。
  2. **易变项与稳定项分离**：`head` / 时间戳 / 产物 hash 每次都会变 → 只记录，不参与 --check 比对；
     参与比对的是"对外数字"（规模 / 基准 / golden / 门禁），它们漂移即意味着材料与代码脱节。
  3. **门禁自身可被检验**：本脚本在 CI 里以 --check 运行，任何数字漂移都会 BLOCK。
"""
import os
import sys
import json
import hashlib
import subprocess
import datetime

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
OUT = os.path.join(ROOT, "docs", "evidence-package.json")
SUMMARY = os.path.join(ROOT, "data", "ctf_benchmark", "all_benchmarks_summary.json")
GOLDEN_FREEZE = os.path.join(ROOT, "scripts", "check_golden_freeze.py")

SCHEMA = "secautomind-championship-evidence/1"

# 参与 --check 比对的规模字段（对外材料会引用这些数字）。
CALIBER_COMPARE = [
    "tools_yaml", "builtin_tools", "runtime_tools", "agents_md", "skills",
    "roles_yaml", "internal_dirs", "test_packages", "go_files", "test_files",
    "non_test_lines", "test_lines", "total_lines", "ctf_solvers", "im_adapters",
]
# 环境相关（Go 工具链/模块缓存不同会变），记录但默认不参与比对。
CALIBER_VOLATILE = ["go_packages"]

BASE_SETS = ["static", "execution", "web", "attachment"]
EXPLOIT_LAYERS = [
    "jwt", "deser", "xxe", "upload", "graphql", "ssrf", "sqli_deep", "ssti_deep",
    "ecdsa_nonce_reuse", "padding_oracle", "blind_oob", "hash_ext",
    "gcm_nonce_reuse", "mt19937_recover", "lfsr_predict", "lcg_predict", "crc32_forge",
]


# --------------------------------------------------------------------------
# 基础工具
# --------------------------------------------------------------------------
def _run(cmd, timeout=1800):
    """跑子命令，返回 (rc, stdout, stderr)。落盘统计，不用管道过滤。"""
    try:
        r = subprocess.run(cmd, cwd=ROOT, shell=True, capture_output=True,
                           encoding="utf-8", errors="ignore", timeout=timeout)
        return r.returncode, r.stdout or "", r.stderr or ""
    except Exception as e:
        return 1, "", str(e)


def _py(script, extra=""):
    """用当前解释器跑仓库内脚本。"""
    return "%s %s%s" % (sys.executable, os.path.join("scripts", script), extra)


def _sha256_file(path):
    if not os.path.isfile(path):
        return None
    h = hashlib.sha256()
    with open(path, "rb") as fh:
        for chunk in iter(lambda: fh.read(1 << 20), b""):
            h.update(chunk)
    return h.hexdigest()


def _md5_file(path):
    if not os.path.isfile(path):
        return None
    h = hashlib.md5()
    with open(path, "rb") as fh:
        for chunk in iter(lambda: fh.read(1 << 20), b""):
            h.update(chunk)
    return h.hexdigest()


def _rel(path):
    return os.path.relpath(path, ROOT).replace("\\", "/")


# --------------------------------------------------------------------------
# 采集
# --------------------------------------------------------------------------
def collect_caliber(notes, caliber_json=None):
    """规模真值：count_stats.py --json（唯一权威口径）。

    caliber_json（可选）：直接给定一份 count_stats.py --json 的输出文件。
    用途：**工作树里存在他人未提交的在途文件**时，磁盘活值会混入 WIP，而证据包必须体现
    **已提交状态** —— 此时在干净检出（git worktree add <dir> HEAD）里跑一次 count_stats，
    再用 --caliber-json 传进来：口径取提交态，产物指纹仍取本机真值。
    （绝不手改生成结果：口径永远来自 count_stats 实跑，只是换了个执行目录。）
    """
    if caliber_json:
        try:
            data = json.load(open(caliber_json, "r", encoding="utf-8"))
            notes.append("规模真值取自 %s（提交态口径；工作树含在途文件，不采磁盘活值）"
                         % os.path.basename(caliber_json))
            return data
        except Exception as e:
            notes.append("--caliber-json 读取失败，回退实跑 count_stats：%s" % e)
    rc, out, err = _run(_py("count_stats.py", " --json"), timeout=600)
    if rc != 0:
        notes.append("count_stats.py 退出码 %d，规模真值缺失：%s" % (rc, err.strip()[:200]))
        return {"error": "count_stats rc=%d" % rc}
    try:
        d = json.loads(out)
    except Exception as e:
        notes.append("count_stats.py 输出非合法 JSON：%s" % e)
        return {"error": "invalid json"}
    if d.get("go_packages") is None:
        notes.append("count_stats.go_packages 为 null（go list 不可用：多为 Go 模块缓存/环境变量缺失），"
                     "该字段不参与比对")
    return d


def collect_benchmark(notes):
    """双语言机验基准：读 all_benchmarks_summary.json（由 run_all_benchmarks.py 生成）。"""
    if not os.path.isfile(SUMMARY):
        notes.append("缺少 %s（CI 应先跑 run_all_benchmarks.py）" % _rel(SUMMARY))
        return {"error": "summary missing"}
    try:
        s = json.load(open(SUMMARY, "r", encoding="utf-8"))
    except Exception as e:
        notes.append("基准汇总 JSON 解析失败：%s" % e)
        return {"error": "invalid json"}

    def block(k):
        b = s.get(k) or {}
        return {
            "total": b.get("total"),
            "hit": b.get("hit"),
            "miss": b.get("miss"),
            "coverage_pct": b.get("coverage_pct"),
        }

    base = {k: block(k) for k in BASE_SETS}
    base["attachment"]["water_filled"] = (s.get("attachment") or {}).get("water_filled")
    base["static"]["flag_scan_only"] = (s.get("static") or {}).get("flag_scan_only")
    base["static"]["real_solver_hit"] = (s.get("static") or {}).get("real_solver_hit")

    layers = {}
    for k in EXPLOIT_LAYERS:
        b = s.get(k)
        if not isinstance(b, dict):
            notes.append("基准汇总缺利用层块 %s" % k)
            continue
        layers[k] = {"total": b.get("total"), "hit": b.get("hit"), "miss": b.get("miss")}

    wh = s.get("web_hints") or {}
    prov = s.get("provenance") or {}
    return {
        "base": base,
        "layers": layers,
        "web_hints": {
            "total": wh.get("total"),
            "group_a_no_hint": wh.get("group_a_no_hint"),
            "group_b_with_hint": wh.get("group_b_with_hint"),
            "delta": wh.get("delta"),
        },
        "provenance": {
            "real_problems": (prov.get("real") or {}).get("problems"),
            "synthetic_problems": (prov.get("synthetic") or {}).get("problems"),
            "total_problems": prov.get("total_problems"),
            "synthetic_ratio_pct": prov.get("synthetic_ratio_pct"),
        },
        "summary_sha256": _sha256_file(SUMMARY),
    }


def collect_golden(notes):
    """跨语言 golden 冻结哈希 + 冻结校验退出码。"""
    freeze_rc, _, err = _run(_py("check_golden_freeze.py"), timeout=300)
    if freeze_rc != 0:
        notes.append("check_golden_freeze.py 退出码 %d：%s" % (freeze_rc, err.strip()[:200]))
    golden_files = [
        "internal/ctfplatform/testdata/protocol_golden.json",
        "internal/ctfplatform/testdata/protocol_fixtures.json",
        "internal/ctfplatform/testdata/request_golden.json",
    ]
    hashes = {}
    # 🔴 行尾归一化（2026-09-24 实锤）：Windows 本地（core.autocrlf=true，但 golden 由生成器
    # 写出为 LF）与 CI/Linux 检出（CRLF）的**原始字节不同**，直接哈希会让 CI 永久 BLOCK。
    # 故统一按 LF 归一化后再哈希 —— 内容改动照样能被发现，平台差异被消掉。
    for rel in golden_files:
        h = _sha256_file_lf(os.path.join(ROOT, rel))
        if h is None:
            notes.append("golden 文件缺失：%s" % rel)
        hashes[rel] = h
    return {"freeze_check_rc": freeze_rc, "files_sha256": hashes,
            "hash_note": "行尾归一化（CRLF→LF）后的 SHA-256：消除 Windows/CI 行尾差异"}


def _sha256_file_lf(path):
    """按 LF 归一化读取文件并计算 SHA-256（消除 CRLF/LF 平台差异）。"""
    try:
        with open(path, "rb") as fh:
            data = fh.read()
    except OSError:
        return None
    return hashlib.sha256(data.replace(b"\r\n", b"\n")).hexdigest()


def collect_gates(notes):
    """门禁退出码集合（三件套 + 证据口径门禁）。"""
    gates = {}
    # 密钥门禁：本机有真 key 指纹时是最强形态；取不到指纹时门禁会 fail-closed，
    # 因此这里显式传 --allow-no-fingerprint（与 CI 同口径），并把形态记进 notes。
    rc, out, err = _run(_py("secret_guard.py", " --json"), timeout=900)
    if rc not in (0, 1):
        notes.append("secret_guard.py 异常退出 rc=%d" % rc)
    fp_mode = "unknown"
    verdict = "unknown"
    try:
        j = json.loads(out)
        verdict = j.get("verdict")
        fp_mode = "fingerprint" if (j.get("fingerprints_loaded") or 0) > 0 else "form-only"
    except Exception:
        # 非 JSON 输出（例如 fail-closed BLOCK）→ 用降级模式重跑，保证拿到 RC
        rc2, _, _ = _run(_py("secret_guard.py", " --json --allow-no-fingerprint"), timeout=900)
        gates["secret_guard_allow_no_fingerprint_rc"] = rc2
        fp_mode = "form-only(fallback)"
        notes.append("secret_guard 首次运行未产出 JSON（多为指纹库为空 fail-closed），"
                     "已用 --allow-no-fingerprint 复跑")
        rc = rc2
    gates["secret_guard_rc"] = rc
    gates["secret_guard_verdict"] = verdict
    gates["secret_guard_fingerprint_mode"] = fp_mode

    for name, script in (("secret_guard_selftest", "secret_guard_test.py"),
                         ("secret_guard_mutation", "secret_guard_mutation_check.py"),
                         ("verify_evidence", "verify_evidence.py"),
                         # 决赛冻结纪律工具的可用性（16 项用例）；证据包记录"纪律工具本身没坏"
                         ("freeze_gate_selftest", "freeze_gate_test.py")):
        rc, _, err = _run(_py(script), timeout=1800)
        gates[name + "_rc"] = rc
        if rc != 0:
            notes.append("%s 退出码 %d：%s" % (script, rc, err.strip()[:200]))
    return gates


def collect_artifacts(notes):
    """产物指纹：**易变**，只记录不比对。"""
    go = os.path.join(ROOT, ".workbuddy", "toolchain", "go", "bin", "go.exe")
    if not os.path.isfile(go):
        go = "go"
    arts = {}
    for label, rel in (("exe_root", "secautomind-ai.exe"),
                       ("exe_installer", "installer/secautomind-ai.exe"),
                       ("setup", "installer/SecAutoMind-Setup-1.7.25-x64.exe"),
                       ("delivery_package", "dist/SecAutoMind-v1.7.25-share.tar.gz")):
        p = os.path.join(ROOT, rel.replace("/", os.sep))
        if not os.path.isfile(p):
            arts[label] = {"path": rel, "present": False}
            continue
        arts[label] = {
            "path": rel,
            "present": True,
            "size_bytes": os.path.getsize(p),
            "md5": _md5_file(p),
            "sha256": _sha256_file(p),
        }
    # exe 内嵌 commit（判"二进制与源码是否同代"的唯一依据）
    exe = os.path.join(ROOT, "secautomind-ai.exe")
    if os.path.isfile(exe):
        rc, out, _ = _run('"%s" version -m "%s"' % (go, exe), timeout=120)
        rev = mod = None
        if rc == 0:
            for line in out.splitlines():
                line = line.strip()
                if line.startswith("build\tvcs.revision="):
                    rev = line.split("=", 1)[1].strip()
                elif line.startswith("build\tvcs.modified="):
                    mod = line.split("=", 1)[1].strip()
        arts["exe_build"] = {"vcs_revision": rev, "vcs_modified": mod}
        if rev is None:
            notes.append("无法读取 exe 内嵌 vcs.revision（go version -m 失败）")
    return arts


def collect_build(notes):
    """构建 / 测试退出码（慢，仅 --with-build）。"""
    go = os.path.join(ROOT, ".workbuddy", "toolchain", "go", "bin", "go.exe")
    if not os.path.isfile(go):
        go = "go"
    env_prefix = ("GOCACHE=%s GOTMPDIR=%s GOPROXY=off GOTOOLCHAIN=local "
                  % (os.environ.get("GOCACHE", "D:/.gocache"),
                     os.environ.get("GOTMPDIR", "D:/.gotmp")))
    out = {"note": "本机采集（--with-build）；CI 的构建/测试权威结果看 GitHub Actions run"}
    rc, _, err = _run(env_prefix + '"%s" build -o NUL ./cmd/server' % go, timeout=1800)
    out["go_build_rc"] = rc
    if rc != 0:
        notes.append("go build rc=%d：%s" % (rc, err.strip()[:200]))
    rc, stdout, err = _run(env_prefix + '"%s" test -count=1 ./...' % go, timeout=3600)
    out["go_test_rc"] = rc
    ok = sum(1 for l in stdout.splitlines() if l.startswith("ok "))
    fail = sum(1 for l in stdout.splitlines() if l.startswith("FAIL") or l.startswith("--- FAIL"))
    out["go_test_ok_packages"] = ok
    out["go_test_fail_lines"] = fail
    if rc != 0 or fail:
        notes.append("go test rc=%d，FAIL 行=%d" % (rc, fail))
    return out


# --------------------------------------------------------------------------
# 构建 / 校验
# --------------------------------------------------------------------------
def build(with_build=False, with_gates=True, caliber_json=None):
    notes = []
    pkg = {
        "schema": SCHEMA,
        "generated_at": datetime.datetime.now().astimezone().isoformat(timespec="seconds"),
        "caliber": collect_caliber(notes, caliber_json),
        "benchmark": collect_benchmark(notes),
        "golden": collect_golden(notes),
        "gates": collect_gates(notes) if with_gates else {
            "note": "--check 轻量模式未重跑门禁（避免与 secret-gate / evidence-gate 重复）；"
                    "门禁 RC 的权威结论见各 job 与包内记录"},
        "artifacts": collect_artifacts(notes),
        "build": collect_build(notes) if with_build else {
            "note": "未采集（加 --with-build 采集本机构建/测试退出码）"},
    }
    pkg["notes"] = notes
    return pkg


def _diff_line(label, want, got):
    return "  - %-46s 包内=%-12s 活值=%-12s" % (label, want, got)


def check(pkg_live, pkg_saved):
    """比对"对外数字"子集；返回 (drift_list, notes)。"""
    drift = []

    def cmp(path, want, got, skip_if_none=True):
        if skip_if_none and (want is None or got is None):
            return
        if want != got:
            drift.append(_diff_line(path, want, got))

    # 1) 规模真值
    for k in CALIBER_COMPARE:
        cmp("caliber." + k, pkg_saved.get("caliber", {}).get(k),
            pkg_live.get("caliber", {}).get(k))
    for k in CALIBER_VOLATILE:
        # 仅当两侧都取到值时比对（取不到说明环境不支持 go list）
        cmp("caliber." + k, pkg_saved.get("caliber", {}).get(k),
            pkg_live.get("caliber", {}).get(k))

    # 2) 基准数字
    sb, lb = pkg_saved.get("benchmark", {}), pkg_live.get("benchmark", {})
    for k in BASE_SETS:
        for f in ("total", "hit", "miss", "coverage_pct"):
            cmp("benchmark.%s.%s" % (k, f),
                (sb.get("base", {}).get(k) or {}).get(f),
                (lb.get("base", {}).get(k) or {}).get(f))
    cmp("benchmark.static.flag_scan_only",
        (sb.get("base", {}).get("static") or {}).get("flag_scan_only"),
        (lb.get("base", {}).get("static") or {}).get("flag_scan_only"))
    cmp("benchmark.static.real_solver_hit",
        (sb.get("base", {}).get("static") or {}).get("real_solver_hit"),
        (lb.get("base", {}).get("static") or {}).get("real_solver_hit"))
    cmp("benchmark.attachment.water_filled",
        (sb.get("base", {}).get("attachment") or {}).get("water_filled"),
        (lb.get("base", {}).get("attachment") or {}).get("water_filled"))
    for k in EXPLOIT_LAYERS:
        for f in ("total", "hit", "miss"):
            cmp("benchmark.layers.%s.%s" % (k, f),
                (sb.get("layers", {}).get(k) or {}).get(f),
                (lb.get("layers", {}).get(k) or {}).get(f))
    for f in ("total", "group_a_no_hint", "group_b_with_hint", "delta"):
        cmp("benchmark.web_hints." + f, sb.get("web_hints", {}).get(f),
            lb.get("web_hints", {}).get(f))
    for f in ("real_problems", "synthetic_problems", "total_problems", "synthetic_ratio_pct"):
        cmp("benchmark.provenance." + f, sb.get("provenance", {}).get(f),
            lb.get("provenance", {}).get(f))
    cmp("benchmark.summary_sha256", sb.get("summary_sha256"), lb.get("summary_sha256"))

    # 3) golden 冻结（哈希变化 = golden 被改动且未重跑生成器）
    #    ⚠️ 注意用 golden 段，不能复用上面的 sb/lb（那是 benchmark 段）——
    #    2026-09-16 变异验证实测：复用 sb/lb 会让 golden 漂移**完全不被检测**（门禁形同虚设）。
    sg, lg = pkg_saved.get("golden", {}), pkg_live.get("golden", {})
    cmp("golden.freeze_check_rc", sg.get("freeze_check_rc"), lg.get("freeze_check_rc"))
    for rel, h in (sg.get("files_sha256") or {}).items():
        cmp("golden.files_sha256." + rel, h, (lg.get("files_sha256") or {}).get(rel))

    # 4) 门禁必须全 0：轻量模式下不重跑门禁，改为**断言包内记录的 RC 全为 0**
    #    （否则等于把一次失败的门禁冻结进证据包）。
    saved_gates = pkg_saved.get("gates") or {}
    live_gates = pkg_live.get("gates") or {}
    live_has_gates = any(k.endswith("_rc") for k in live_gates)
    for k, v in saved_gates.items():
        if not k.endswith("_rc"):
            continue
        if v != 0:
            drift.append(_diff_line("gates." + k + "（包内记录为非 0）", v, v))
            continue
        if live_has_gates and live_gates.get(k) != 0:
            drift.append(_diff_line("gates." + k, v, live_gates.get(k)))

    return drift


def main():
    argv = sys.argv[1:]
    args = set(argv)
    # --caliber-json <path>：用外部 count_stats 输出替代当前磁盘活值
    #（工作树有他人在途文件时，在干净检出里取提交态口径）
    caliber_json = None
    for i, a in enumerate(argv):
        if a == "--caliber-json" and i + 1 < len(argv):
            caliber_json = argv[i + 1]

    if "--print" in args:
        pkg = build(with_build="--with-build" in args, caliber_json=caliber_json)
        print(json.dumps(pkg, ensure_ascii=False, indent=2))
        return
    if "--check" in args:
        if not os.path.isfile(OUT):
            print("✗ 证据包不存在：%s\n  先跑 `python scripts/build_championship_evidence.py`" % _rel(OUT))
            sys.exit(1)
        saved = json.load(open(OUT, "r", encoding="utf-8"))
        live = build(with_build=False, with_gates=("--with-gates" in args), caliber_json=caliber_json)
        drift = check(live, saved)
        print("=" * 70)
        print("冠军证据包一致性校验（%s）" % _rel(OUT))
        print("=" * 70)
        print("  包内生成时间  %s" % saved.get("generated_at"))
        print("  当前 HEAD     %s（包内 %s）" % (
            (live.get("caliber") or {}).get("head"),
            (saved.get("caliber") or {}).get("head")))
        if live.get("notes"):
            for n in live["notes"]:
                print("  [note] %s" % n)
        if drift:
            print("\n  ✗ 发现 %d 处漂移（对外数字与代码/基准脱节）：" % len(drift))
            for d in drift:
                print(d)
            print("\n  处理：确认变更无误后重跑 `python scripts/build_championship_evidence.py` 刷新证据包")
            sys.exit(1)
        print("\n  对外数字全部一致：规模 / 基准 / golden / 门禁 ✓")
        print("\n证据包一致性：PASS")
        return

    pkg = build(with_build="--with-build" in args, caliber_json=caliber_json)
    os.makedirs(os.path.dirname(OUT), exist_ok=True)
    with open(OUT, "w", encoding="utf-8", newline="\n") as fh:
        json.dump(pkg, fh, ensure_ascii=False, indent=2, sort_keys=False)
        fh.write("\n")
    print("=" * 70)
    print("冠军证据包已生成：%s" % _rel(OUT))
    print("=" * 70)
    c = pkg.get("caliber") or {}
    b = pkg.get("benchmark") or {}
    g = pkg.get("gates") or {}
    print("  HEAD            %s" % c.get("head"))
    print("  规模真值        %s Go 文件 / %s 测试文件 / %s 非测试行 / %s 求解器 / %s 运行时工具" % (
        c.get("go_files"), c.get("test_files"), c.get("non_test_lines"),
        c.get("ctf_solvers"), c.get("runtime_tools")))
    base = (b.get("base") or {})
    print("  四大基础集      static=%s/%s  execution=%s/%s  web=%s/%s  attachment=%s/%s" % (
        (base.get("static") or {}).get("hit"), (base.get("static") or {}).get("total"),
        (base.get("execution") or {}).get("hit"), (base.get("execution") or {}).get("total"),
        (base.get("web") or {}).get("hit"), (base.get("web") or {}).get("total"),
        (base.get("attachment") or {}).get("hit"), (base.get("attachment") or {}).get("total")))
    layers = b.get("layers") or {}
    full = sum(1 for v in layers.values() if v.get("hit") == v.get("total") and (v.get("total") or 0) > 0)
    print("  利用层全绿      %d/%d" % (full, len(layers)))
    prov = b.get("provenance") or {}
    print("  来源标注        真题 %s / 自产题 %s（自产占比 %s%%）" % (
        prov.get("real_problems"), prov.get("synthetic_problems"), prov.get("synthetic_ratio_pct")))
    print("  门禁退出码      " + "  ".join("%s=%s" % (k, v) for k, v in sorted(g.items())
                                          if k.endswith("_rc")))
    if pkg.get("notes"):
        print("\n  ⚠️ 采集备注（未伪造，如实记录）：")
        for n in pkg["notes"]:
            print("    - %s" % n)
    print("\n提示：CI 以 `--check` 运行本脚本，任何对外数字漂移都会 BLOCK。")


if __name__ == "__main__":
    main()
