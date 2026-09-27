#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""决赛赛前预检（go / no-go 结论）。

为什么需要：本轮冲刺发现的三处生产缺口（起靶机 / 附件 / 题干补全）都靠**配置开关**打开，
而开关默认关闭。赛时一忙漏设，能力就又回到"休眠"状态 —— 组件单测全绿也照样 0 分。
本脚本把"开没开、链通不通、门禁绿不绿"一次跑完并给出结论，避免靠人肉核对 runbook。

用法：
  python scripts/finals_preflight.py            # 快速预检（演练 + 门禁 + 开关检查，约 1 分钟）
  python scripts/finals_preflight.py --full     # 追加整包 go test（数分钟）
  python scripts/finals_preflight.py --json     # 机器可读输出（供 CI/复盘）

退出码：0 = GO（可上场）；1 = NO-GO（存在阻塞项）。
"""
import os
import sys
import json
import subprocess

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
PY = sys.executable


def find_go():
    """定位项目自带 Go 工具链（AGENTS.md 第五条：PATH 上的 go 可能不存在或版本不对）。"""
    base = os.path.join(ROOT, ".workbuddy", "toolchain", "go", "bin")
    for name in ("go.exe", "go"):
        p = os.path.join(base, name)
        if os.path.isfile(p):
            return '"%s"' % p
    return "go"


GO = find_go()


def run(cmd, timeout=900, cwd=None):
    try:
        env = dict(os.environ)
        # 三条必须独立设置（AGENTS.md 第五条）：否则 t.TempDir() 会生成非法路径
        tmpdir = env.get("SEC_TMPDIR") or "D:/tmp_gotest"
        try:
            os.makedirs(tmpdir, exist_ok=True)
        except OSError:
            pass
        env["TMP"] = tmpdir
        env["TEMP"] = tmpdir
        env["TMPDIR"] = tmpdir
        r = subprocess.run(cmd, cwd=cwd or ROOT, shell=True, encoding="utf-8",
                           errors="ignore", capture_output=True, timeout=timeout, env=env)
        return r.returncode, (r.stdout or "") + (r.stderr or "")
    except subprocess.TimeoutExpired:
        return 124, "超时（%ss）" % timeout
    except Exception as e:
        return 1, str(e)


def untracked_go_files():
    """未跟踪的 .go 文件（= 并行会话在途 WIP；会让磁盘活值偏离提交态）。"""
    rc, out = run("git status --porcelain", timeout=120)
    if rc != 0:
        return []
    return [l[3:].strip() for l in out.splitlines() if l.startswith("??") and l.endswith(".go")]


# 决赛推荐开关：(变量名, 是否阻塞, 说明)
SWITCHES = [
    ("CTF_POLL_ENABLED", True, "启动轮询器（不开等于不上场）"),
    ("CTF_AUTOSOLVE_SUBMIT", True, "解出即自动提交（不开要人工抄 flag）"),
    ("CTF_AUTO_BUILD_ENV", True, "需要靶机的题自动起靶机（09-17 缺口；不开 = web/pwn 主力 0 分）"),
    ("CTF_AUTO_FETCH_DETAIL", False, "题干用详情补全（列表可能是摘要）；取不到会静默回退，建议开"),
    ("CTF_AUTO_FETCH_ATTACHMENT", False, "附件题下载（依赖 DownloadAttachment 存根实现；未实现时无害）"),
    ("CTF_AUTO_RELEASE_ENV", False, "accepted 后回收靶机（省配额，不开不影响得分）"),
]


def check_switches():
    out = []
    for name, blocking, desc in SWITCHES:
        v = os.environ.get(name, "")
        on = v.strip().lower() in ("1", "true", "yes", "on")
        out.append({"name": name, "value": v, "on": on, "blocking": blocking, "desc": desc})
    return out


def main():
    argv = sys.argv[1:]
    want_json = "--json" in argv
    full = "--full" in argv

    results = {"checks": [], "switches": check_switches(),
               "wip_untracked_go": untracked_go_files()}
    blocking_fail = []
    warnings = []

    def add(name, rc, note=""):
        results["checks"].append({"name": name, "rc": rc, "note": note.strip()[:300]})
        return rc == 0

    # ① 演练台（整链路 + 起靶机 + 附件 + 详情 + 回收）
    rc, out = run("%s test -count=1 -run TestRehearsal ./internal/ctfplatform/" % GO, timeout=900)
    ok = add("rehearsal", rc, out)
    if not ok:
        blocking_fail.append("演练台未通过（决赛整链路不可用）")

    # ② 冻结闸门状态（未武装只是提示，不算阻塞）
    rc, out = run('"%s" scripts/freeze_gate.py --status' % PY, timeout=120)
    add("freeze_gate", rc, out)

    # ③ 材料口径门禁
    #    注意：磁盘上若有并行会话未跟踪的 .go 文件，磁盘活值会偏离提交态 → 门禁必红，
    #    但 CI（干净检出）会绿。这种情况降级为警告，并说清原因（不许假装没看见）。
    rc, out = run('"%s" scripts/check_material_numbers.py' % PY, timeout=600)
    ok = add("caliber_gate", rc, out)
    if not ok:
        if results["wip_untracked_go"]:
            warnings.append("材料口径红 %d 处，但磁盘含 %d 个未跟踪 .go（在途 WIP）→ "
                            "CI 干净检出会绿；其作者提交后需重刷一次口径"
                            % (len(results["wip_untracked_go"]), len(results["wip_untracked_go"])))
        else:
            blocking_fail.append("材料口径漂移（对外数字与真值不一致）")

    # ④ 密钥门禁（交付红线）
    rc, out = run('"%s" scripts/secret_guard.py' % PY, timeout=600)
    ok = add("secret_gate", rc, out)
    if not ok:
        blocking_fail.append("密钥门禁未通过（禁止打包/上场）")

    # ⑤ 冠军证据包一致性
    #    09-28 补：此前漏检 → CI 自 09-19 起 `evidence-package-gate` 连续红（其余 job 全绿，
    #    极易被误判为偶发）。证据包必须随任何改变对外数字的提交同步重生成。
    rc, out = run('"%s" scripts/build_championship_evidence.py --check' % PY, timeout=900)
    ok = add("evidence_package", rc, out)
    if not ok:
        if results["wip_untracked_go"]:
            warnings.append("证据包与磁盘活值不一致，但磁盘含 %d 个未跟踪 .go（在途 WIP）→ "
                            "CI 干净检出可能绿；WIP 提交后需重生成证据包"
                            % len(results["wip_untracked_go"]))
        else:
            blocking_fail.append("冠军证据包过期（CI evidence-package-gate 会 BLOCK）—— "
                                 "跑 `python scripts/build_championship_evidence.py` 重生成")

    # ⑤ 可选：整包 go test
    if full:
        rc, out = run("%s test -count=1 ./..." % GO, timeout=3600)
        ok = add("go_test_full", rc, out)
        if not ok:
            blocking_fail.append("整包测试未全绿")

    # ⑥ 开关检查结论
    missing_blocking = [s["name"] for s in results["switches"] if s["blocking"] and not s["on"]]
    for n in missing_blocking:
        blocking_fail.append("必需开关未设置：%s" % n)

    results["warnings"] = warnings
    go = not blocking_fail
    results["verdict"] = "GO" if go else "NO-GO"
    results["blocking"] = blocking_fail

    if want_json:
        print(json.dumps(results, ensure_ascii=False, indent=2))
        return 0 if go else 1

    print("=" * 74)
    print("决赛赛前预检 · %s" % results["verdict"])
    print("=" * 74)
    print("\n[开关]")
    for s in results["switches"]:
        mark = "ON " if s["on"] else "OFF"
        need = "必需" if s["blocking"] else "可选"
        print("  [%s/%s] %-28s %s" % (mark, need, s["name"], s["desc"]))
    print("\n[检查项]")
    for c in results["checks"]:
        print("  [%s] %-16s rc=%d" % ("OK" if c["rc"] == 0 else "FAIL", c["name"], c["rc"]))
    if warnings:
        print("\n[警告（不阻塞）]")
        for w in warnings:
            print("  ! %s" % w)
    if blocking_fail:
        print("\n[阻塞项]")
        for f in blocking_fail:
            print("  ✗ %s" % f)
    else:
        print("\n  无阻塞项 —— 可上场。")
    print("\n" + "=" * 74)
    return 0 if go else 1


if __name__ == "__main__":
    os.environ.setdefault("APPDATA", os.path.join(os.path.expanduser("~"), "AppData", "Roaming"))
    sys.exit(main())
